pub mod xpath;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};

use crate::correlator;
use crate::db::Database;
use crate::error::SentinelError;
use crate::models::{ImportHistoryResult, NewWindowsEvent, Severity, WindowsEventRecord, WsEnvelope};
use crate::telemetry::SharedRingBuffer;
use crate::translator::KnowledgeBase;
use xpath::{build_historical_xpath, parse_event_xml, APPLICATION_XPATH, SYSTEM_XPATH};

#[derive(Debug, Clone)]
pub struct RawEventMessage {
    pub channel: String,
    pub raw_xml: String,
}

pub fn process_raw_event(
    db: &Database,
    ring_buffer: &SharedRingBuffer,
    kb: &KnowledgeBase,
    msg: &RawEventMessage,
) -> Result<Option<WindowsEventRecord>, SentinelError> {
    let parsed = parse_event_xml(&msg.channel, &msg.raw_xml)?;
    let translated = kb.translate(&parsed.channel, &parsed.provider_name, parsed.event_id);

    let new_event = NewWindowsEvent {
        record_id: parsed.record_id,
        channel: parsed.channel,
        provider_name: parsed.provider_name,
        event_id: parsed.event_id,
        level: parsed.level,
        timestamp_utc: parsed.timestamp_utc,
        timestamp_ms: parsed.timestamp_ms,
        kb_id: translated.kb_id,
        category: translated.category,
        severity: translated.severity,
        friendly_title: translated.friendly_title,
        what_happened: translated.what_happened,
        probable_causes: translated.probable_causes,
        solutions: translated.solutions,
        raw_xml: parsed.raw_xml,
        correlation_snapshot_id: None,
        diagnostic_note: None,
    };

    let Some(mut inserted) = db.insert_windows_event(&new_event)? else {
        return Ok(None);
    };

    if let Ok(rb_guard) = ring_buffer.read() {
        match correlator::correlate_event(db, &rb_guard, &inserted) {
            Ok(Some(corr)) => {
                inserted.correlation_snapshot_id = corr.snapshot_id;
                inserted.diagnostic_note = Some(corr.diagnostic_note);
            }
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(error = %err, "Failed to correlate Windows event");
            }
        }
    }

    Ok(Some(inserted))
}

#[cfg(windows)]
mod win_evt {
    use core::ffi::c_void;
    use tokio::sync::mpsc::UnboundedSender;
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, HANDLE,
    };
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
        EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver, EvtSubscribeActionError,
        EvtSubscribeToFutureEvents, EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{build_historical_xpath, RawEventMessage, APPLICATION_XPATH, SYSTEM_XPATH};
    use crate::error::SentinelError;

    struct CallbackContext {
        channel: String,
        tx: UnboundedSender<RawEventMessage>,
    }

    pub struct EventLogWatcher {
        handles: Vec<EVT_HANDLE>,
        contexts: Vec<*mut CallbackContext>,
    }

    // Handles and context pointers are exclusively held until Drop closes subscriptions first.
    unsafe impl Send for EventLogWatcher {}
    unsafe impl Sync for EventLogWatcher {}

    impl EventLogWatcher {
        pub fn start(tx: UnboundedSender<RawEventMessage>) -> Result<Self, SentinelError> {
            let mut handles = Vec::new();
            let mut contexts = Vec::new();

            let specs = [
                ("System", SYSTEM_XPATH),
                ("Application", APPLICATION_XPATH),
            ];

            for (channel, query) in specs {
                let ctx = Box::into_raw(Box::new(CallbackContext {
                    channel: channel.to_string(),
                    tx: tx.clone(),
                }));
                let channel_h = HSTRING::from(channel);
                let query_h = HSTRING::from(query);

                let sub_res = unsafe {
                    EvtSubscribe(
                        None,
                        None,
                        &channel_h,
                        &query_h,
                        None,
                        Some(ctx.cast::<c_void>()),
                        Some(evt_callback),
                        EvtSubscribeToFutureEvents.0,
                    )
                };

                match sub_res {
                    Ok(handle) => {
                        handles.push(handle);
                        contexts.push(ctx);
                    }
                    Err(err) => {
                        unsafe {
                            drop(Box::from_raw(ctx));
                        }
                        for h in handles {
                            unsafe {
                                let _ = EvtClose(h);
                            }
                        }
                        for c in contexts {
                            unsafe {
                                drop(Box::from_raw(c));
                            }
                        }
                        return Err(SentinelError::EventLog(format!(
                            "EvtSubscribe failed for channel {channel}: {err}"
                        )));
                    }
                }
            }

            Ok(Self { handles, contexts })
        }
    }

    impl Drop for EventLogWatcher {
        fn drop(&mut self) {
            // Close subscriptions BEFORE freeing callback contexts so no callback fires post-free.
            for handle in self.handles.drain(..) {
                unsafe {
                    let _ = EvtClose(handle);
                }
            }
            for ctx in self.contexts.drain(..) {
                unsafe {
                    drop(Box::from_raw(ctx));
                }
            }
        }
    }

    unsafe extern "system" fn evt_callback(
        action: EVT_SUBSCRIBE_NOTIFY_ACTION,
        usercontext: *const c_void,
        event: EVT_HANDLE,
    ) -> u32 {
        if action == EvtSubscribeActionError || usercontext.is_null() {
            return 0;
        }
        if action != EvtSubscribeActionDeliver {
            return 0;
        }

        let ctx = &*(usercontext.cast::<CallbackContext>());
        if let Some(raw_xml) = render_event_xml(event) {
            let _ = ctx.tx.send(RawEventMessage {
                channel: ctx.channel.clone(),
                raw_xml,
            });
        }
        0
    }

    unsafe fn render_event_xml(event: EVT_HANDLE) -> Option<String> {
        let mut buffer_used: u32 = 0;
        let mut prop_count: u32 = 0;

        let first = EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut buffer_used,
            &mut prop_count,
        );

        if let Err(err) = first {
            if err.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult() || buffer_used == 0 {
                return None;
            }
        }

        let u16_len = (buffer_used as usize).div_ceil(2);
        let mut buf: Vec<u16> = vec![0; u16_len];
        let byte_cap = (buf.len() * 2) as u32;

        if EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            byte_cap,
            Some(buf.as_mut_ptr().cast::<c_void>()),
            &mut buffer_used,
            &mut prop_count,
        )
        .is_err()
        {
            return None;
        }

        let used_chars = ((buffer_used as usize) / 2).min(buf.len());
        let xml = String::from_utf16_lossy(&buf[..used_chars])
            .trim_end_matches('\0')
            .to_string();
        if xml.is_empty() {
            None
        } else {
            Some(xml)
        }
    }

    pub fn is_process_elevated() -> bool {
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut return_len: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_len,
            )
            .is_ok();
            let _ = CloseHandle(token);
            ok && elevation.TokenIsElevated != 0
        }
    }

    pub fn query_historical_events(
        days: u32,
        max_per_channel: usize,
    ) -> Result<Vec<RawEventMessage>, SentinelError> {
        let channels = ["Application", "System"];
        let mut results = Vec::new();
        let cap = max_per_channel.clamp(1, 500);

        for channel in channels {
            let query_str = build_historical_xpath(channel, days);
            let channel_h = HSTRING::from(channel);
            let query_h = HSTRING::from(query_str);

            let query_handle = match unsafe {
                EvtQuery(
                    None,
                    &channel_h,
                    &query_h,
                    EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
                )
            } {
                Ok(h) => h,
                Err(err) => {
                    tracing::warn!(
                        channel,
                        error = %err,
                        "EvtQuery historical import failed for channel"
                    );
                    continue;
                }
            };

            let mut collected = 0_usize;
            let mut batch = [0_isize; 32];
            while collected < cap {
                let remaining = (cap - collected).min(batch.len());
                let mut returned: u32 = 0;
                let res = unsafe {
                    EvtNext(query_handle, &mut batch[..remaining], 2000, 0, &mut returned)
                };

                let count = (returned as usize).min(remaining);
                for &raw_h in &batch[..count] {
                    let evt_h = EVT_HANDLE(raw_h);
                    if let Some(raw_xml) = unsafe { render_event_xml(evt_h) } {
                        results.push(RawEventMessage {
                            channel: channel.to_string(),
                            raw_xml,
                        });
                        collected += 1;
                    }
                    unsafe {
                        let _ = EvtClose(evt_h);
                    }
                }

                match res {
                    Ok(()) if count > 0 => continue,
                    Ok(()) => break,
                    Err(err) if err.code() == ERROR_NO_MORE_ITEMS.to_hresult() => break,
                    Err(err) => {
                        tracing::warn!(channel, error = %err, "EvtNext stopped early");
                        break;
                    }
                }
            }

            unsafe {
                let _ = EvtClose(query_handle);
            }
        }

        Ok(results)
    }
}

#[cfg(not(windows))]
mod win_evt {
    use tokio::sync::mpsc::UnboundedSender;

    use super::RawEventMessage;
    use crate::error::SentinelError;

    pub struct EventLogWatcher;

    impl EventLogWatcher {
        pub fn start(_tx: UnboundedSender<RawEventMessage>) -> Result<Self, SentinelError> {
            Err(SentinelError::EventLog(
                "Windows Event Log watcher is only supported on Windows".to_string(),
            ))
        }
    }

    pub fn is_process_elevated() -> bool {
        false
    }

    pub fn query_historical_events(
        _days: u32,
        _max_per_channel: usize,
    ) -> Result<Vec<RawEventMessage>, SentinelError> {
        Ok(Vec::new())
    }
}

pub use win_evt::{is_process_elevated, query_historical_events, EventLogWatcher};

pub fn import_historical_events(
    db: &Database,
    ring_buffer: &SharedRingBuffer,
    kb: &KnowledgeBase,
    days: u32,
    max_per_channel: usize,
) -> Result<ImportHistoryResult, SentinelError> {
    let clamped_days = days.clamp(1, 90);
    let raw_events = query_historical_events(clamped_days, max_per_channel)?;
    let scanned = raw_events.len();
    let mut imported = 0_usize;
    let mut skipped_duplicates = 0_usize;

    for msg in &raw_events {
        match process_raw_event(db, ring_buffer, kb, msg) {
            Ok(Some(_)) => imported += 1,
            Ok(None) => skipped_duplicates += 1,
            Err(err) => {
                tracing::debug!(error = %err, "Skipped malformed historical event XML");
            }
        }
    }

    Ok(ImportHistoryResult {
        scanned,
        imported,
        skipped_duplicates,
        days: clamped_days,
    })
}

pub fn spawn_eventlog_watcher<F>(
    db: Database,
    ring_buffer: SharedRingBuffer,
    kb: KnowledgeBase,
    paused: Arc<AtomicBool>,
    watcher_active: Arc<AtomicBool>,
    ws_tx: broadcast::Sender<WsEnvelope>,
    on_event: F,
) -> Option<EventLogWatcher>
where
    F: Fn(&WindowsEventRecord) + Send + Sync + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<RawEventMessage>();

    let watcher = match EventLogWatcher::start(tx) {
        Ok(w) => {
            watcher_active.store(true, Ordering::Relaxed);
            tracing::info!("Windows Event Log real-time EvtSubscribe active (System + Application)");
            Some(w)
        }
        Err(err) => {
            watcher_active.store(false, Ordering::Relaxed);
            tracing::warn!(error = %err, "EventLogWatcher inactive");
            None
        }
    };

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if paused.load(Ordering::Relaxed) {
                continue;
            }
            match process_raw_event(&db, &ring_buffer, &kb, &msg) {
                Ok(Some(record)) => {
                    if record.severity == Severity::Critical {
                        tracing::warn!(
                            event_id = record.event_id,
                            provider = %record.provider_name,
                            title = %record.friendly_title,
                            "Critical Windows Event captured"
                        );
                    }
                    on_event(&record);
                    let _ = ws_tx.send(WsEnvelope::WindowsEvent(record));
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::warn!(error = %err, "Failed to process incoming Windows Event Log XML");
                }
            }
        }
    });

    watcher
}
