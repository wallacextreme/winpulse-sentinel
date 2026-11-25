use crate::db::Database;
use crate::error::SentinelError;
use crate::models::{
    BottleneckSnapshot, TelemetrySample, ViolatedMetric, WindowsEventRecord,
};
use crate::telemetry::TelemetryRingBuffer;

pub const LOOKBACK_MS: i64 = 15_000;
pub const LOOKAHEAD_MS: i64 = 5_000;

#[derive(Debug, Clone)]
pub struct CorrelationResult {
    pub snapshot_id: Option<i64>,
    pub delta_ms: i64,
    pub offending_process: Option<String>,
    pub metric_summary: String,
    pub diagnostic_note: String,
}

pub fn format_diagnostic_note(
    delta_ms: i64,
    event_id: u32,
    metric: ViolatedMetric,
    peak_value: f32,
    offending_process: Option<&str>,
) -> String {
    let abs_secs = (delta_ms.abs() as f64 / 1000.0).round() as i64;
    let timing = if abs_secs == 0 {
        format!("No mesmo instante deste evento (ID {event_id})")
    } else if delta_ms >= 0 {
        let unit = if abs_secs == 1 { "segundo" } else { "segundos" };
        format!("{abs_secs} {unit} antes deste evento (ID {event_id})")
    } else {
        let unit = if abs_secs == 1 { "segundo" } else { "segundos" };
        format!("{abs_secs} {unit} após este evento (ID {event_id})")
    };

    let metric_desc = match metric {
        ViolatedMetric::DiskLatency => format!("{peak_value:.0} ms de {}", metric.label_pt()),
        _ => format!("{peak_value:.0}% de {}", metric.label_pt()),
    };

    match offending_process {
        Some(proc_name) if !proc_name.trim().is_empty() => {
            format!("{timing}, o processo `{proc_name}` registrou pico de {metric_desc}.")
        }
        _ => format!("{timing}, o sistema registrou pico de {metric_desc}."),
    }
}

fn select_closest_snapshot<'a>(
    event_ts: i64,
    snapshots: &'a [BottleneckSnapshot],
) -> Option<&'a BottleneckSnapshot> {
    snapshots.iter().min_by_key(|snap| {
        let delta = event_ts - snap.timestamp_ms;
        // Prefer snapshots that happened before or at the event (delta >= 0) on ties
        let tie_bias = if delta >= 0 { 0_i64 } else { 1_i64 };
        (delta.abs(), tie_bias)
    })
}

fn snapshot_summary(snap: &BottleneckSnapshot) -> String {
    match snap.violated_metric {
        ViolatedMetric::DiskLatency => {
            format!("{} ({:.0} ms)", snap.violated_metric.label_pt(), snap.peak_value)
        }
        _ => format!("{} ({:.1}%)", snap.violated_metric.label_pt(), snap.peak_value),
    }
}

pub fn correlate_event(
    db: &Database,
    ring_buffer: &TelemetryRingBuffer,
    event: &WindowsEventRecord,
) -> Result<Option<CorrelationResult>, SentinelError> {
    let start_ms = event.timestamp_ms.saturating_sub(LOOKBACK_MS);
    let end_ms = event.timestamp_ms.saturating_add(LOOKAHEAD_MS);

    let snapshots = db.find_snapshots_in_window(start_ms, end_ms)?;
    if let Some(snap) = select_closest_snapshot(event.timestamp_ms, &snapshots) {
        let delta_ms = event.timestamp_ms - snap.timestamp_ms;
        let offending_process = snap.top_processes.first().map(|p| p.name.clone());
        let metric_summary = snapshot_summary(snap);
        let note = format_diagnostic_note(
            delta_ms,
            event.event_id,
            snap.violated_metric,
            snap.peak_value,
            offending_process.as_deref(),
        );

        db.save_correlation(
            event.id,
            snap.id,
            delta_ms,
            offending_process.as_deref(),
            &metric_summary,
            &note,
        )?;

        return Ok(Some(CorrelationResult {
            snapshot_id: Some(snap.id),
            delta_ms,
            offending_process,
            metric_summary,
            diagnostic_note: note,
        }));
    }

    // Fallback: inspect in-memory Ring Buffer for brief spikes (< 5s) in [T - 15s, T + 5s]
    let samples = ring_buffer.find_in_window(start_ms, end_ms);
    if let Some((sample, metric, peak)) = find_peak_ring_spike(&samples) {
        let delta_ms = event.timestamp_ms - sample.timestamp_ms;
        let note = format_diagnostic_note(delta_ms, event.event_id, metric, peak, None);
        let metric_summary = match metric {
            ViolatedMetric::DiskLatency => format!("{} ({peak:.0} ms)", metric.label_pt()),
            _ => format!("{} ({peak:.1}%)", metric.label_pt()),
        };
        db.set_event_diagnostic_note(event.id, &note)?;
        return Ok(Some(CorrelationResult {
            snapshot_id: None,
            delta_ms,
            offending_process: None,
            metric_summary,
            diagnostic_note: note,
        }));
    }

    Ok(None)
}

pub fn correlate_new_snapshot(
    db: &Database,
    snapshot: &BottleneckSnapshot,
) -> Result<Vec<i64>, SentinelError> {
    // Event T correlates with Snapshot S iff S in [T - 15s, T + 5s] <=> T in [S - 5s, S + 15s]
    let event_start_ms = snapshot.timestamp_ms.saturating_sub(LOOKAHEAD_MS);
    let event_end_ms = snapshot.timestamp_ms.saturating_add(LOOKBACK_MS);

    let events = db.find_uncorrelated_events_in_window(event_start_ms, event_end_ms)?;
    let offending_process = snapshot.top_processes.first().map(|p| p.name.as_str());
    let metric_summary = snapshot_summary(snapshot);
    let mut linked_ids = Vec::with_capacity(events.len());

    for ev in events {
        let delta_ms = ev.timestamp_ms - snapshot.timestamp_ms;
        let note = format_diagnostic_note(
            delta_ms,
            ev.event_id,
            snapshot.violated_metric,
            snapshot.peak_value,
            offending_process,
        );
        db.save_correlation(
            ev.id,
            snapshot.id,
            delta_ms,
            offending_process,
            &metric_summary,
            &note,
        )?;
        linked_ids.push(ev.id);
    }

    Ok(linked_ids)
}

fn find_peak_ring_spike(
    samples: &[TelemetrySample],
) -> Option<(&TelemetrySample, ViolatedMetric, f32)> {
    let mut best: Option<(&TelemetrySample, ViolatedMetric, f32, f32)> = None;

    for sample in samples {
        let candidates = [
            (ViolatedMetric::Cpu, sample.cpu_percent, sample.cpu_percent / 90.0),
            (ViolatedMetric::Ram, sample.ram_percent, sample.ram_percent / 90.0),
            (
                ViolatedMetric::DiskActive,
                sample.disk_active_percent,
                sample.disk_active_percent / 90.0,
            ),
            (
                ViolatedMetric::DiskLatency,
                sample.disk_latency_ms,
                sample.disk_latency_ms / 100.0,
            ),
        ];

        for (metric, value, ratio) in candidates {
            if ratio > 1.0 {
                let replace = match best {
                    Some((_, _, _, best_ratio)) => ratio > best_ratio,
                    None => true,
                };
                if replace {
                    best = Some((sample, metric, value, ratio));
                }
            }
        }
    }

    best.map(|(sample, metric, value, _)| (sample, metric, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        HealthStatus, NewBottleneckSnapshot, NewWindowsEvent, OffendingProcess, Severity,
    };

    fn insert_test_snapshot(
        db: &Database,
        ts_ms: i64,
        metric: ViolatedMetric,
        peak: f32,
        proc_name: &str,
    ) -> BottleneckSnapshot {
        db.insert_snapshot(&NewBottleneckSnapshot {
            timestamp_utc: "2026-11-25T13:00:00Z".to_string(),
            timestamp_ms: ts_ms,
            violated_metric: metric,
            peak_value: peak,
            threshold_value: 90.0,
            duration_secs: 5,
            cpu_percent: 20.0,
            ram_percent: peak,
            ram_free_gb: 1.2,
            disk_active_percent: 10.0,
            disk_latency_ms: 5.0,
            net_rx_kbps: 50.0,
            net_tx_kbps: 20.0,
            net_latency_ms: None,
            net_loss_percent: None,
            top_processes: vec![OffendingProcess {
                pid: 1234,
                name: proc_name.to_string(),
                exe_path: None,
                cpu_percent: 15.0,
                memory_mb: 8192.0,
                memory_percent: peak,
                disk_read_kbps: 0.0,
                disk_write_kbps: 0.0,
            }],
            severity: Severity::High,
        })
        .expect("insert snapshot")
    }

    fn insert_test_event(db: &Database, ts_ms: i64, record_id: i64) -> WindowsEventRecord {
        db.insert_windows_event(&NewWindowsEvent {
            record_id: Some(record_id),
            channel: "Application".to_string(),
            provider_name: "Application Hang".to_string(),
            event_id: 1002,
            level: 2,
            timestamp_utc: "2026-11-25T13:00:03Z".to_string(),
            timestamp_ms: ts_ms,
            kb_id: Some("APP_1002".to_string()),
            category: "Aplicativos".to_string(),
            severity: Severity::Medium,
            friendly_title: "Um programa congelou".to_string(),
            what_happened: "Travou".to_string(),
            probable_causes: vec![],
            solutions: vec![],
            raw_xml: "<Event/>".to_string(),
            correlation_snapshot_id: None,
            diagnostic_note: None,
        })
        .expect("insert event")
        .expect("not duplicate")
    }

    #[test]
    fn correlates_event_with_snapshot_within_window() {
        let db = Database::open_in_memory().expect("db");
        let rb = TelemetryRingBuffer::new(60);

        let snap = insert_test_snapshot(&db, 100_000, ViolatedMetric::Ram, 94.0, "chrome.exe");
        let ev = insert_test_event(&db, 103_000, 1);

        let res = correlate_event(&db, &rb, &ev)
            .expect("correlate")
            .expect("match expected");

        assert_eq!(res.snapshot_id, Some(snap.id));
        assert_eq!(res.delta_ms, 3_000);
        assert!(res.diagnostic_note.contains("3 segundos antes"));
        assert!(res.diagnostic_note.contains("ID 1002"));
        assert!(res.diagnostic_note.contains("chrome.exe"));
        assert!(res.diagnostic_note.contains("94%"));

        let stored = db.get_windows_event(ev.id).expect("get").expect("found");
        assert_eq!(stored.correlation_snapshot_id, Some(snap.id));
        assert_eq!(stored.diagnostic_note, Some(res.diagnostic_note));
    }

    #[test]
    fn ignores_snapshot_outside_15s_before_5s_after_window() {
        let db = Database::open_in_memory().expect("db");
        let rb = TelemetryRingBuffer::new(60);

        insert_test_snapshot(&db, 100_000, ViolatedMetric::Cpu, 96.0, "compiler.exe");
        let ev_too_late = insert_test_event(&db, 116_000, 2); // 16s after snapshot
        let ev_too_early = insert_test_event(&db, 94_000, 3); // 6s before snapshot

        assert!(correlate_event(&db, &rb, &ev_too_late).expect("ok").is_none());
        assert!(correlate_event(&db, &rb, &ev_too_early).expect("ok").is_none());
    }

    #[test]
    fn correlates_retroactively_when_snapshot_arrives_up_to_5s_after_event() {
        let db = Database::open_in_memory().expect("db");
        let ev = insert_test_event(&db, 100_000, 4);
        let snap = insert_test_snapshot(&db, 104_000, ViolatedMetric::DiskLatency, 185.0, "setup.exe");

        let linked = correlate_new_snapshot(&db, &snap).expect("reverse correlate");
        assert_eq!(linked, vec![ev.id]);

        let stored = db.get_windows_event(ev.id).expect("get").expect("exists");
        assert_eq!(stored.correlation_snapshot_id, Some(snap.id));
        let note = stored.diagnostic_note.expect("note");
        assert!(note.contains("4 segundos após"));
        assert!(note.contains("185 ms"));
    }

    #[test]
    fn falls_back_to_ring_buffer_spike_when_no_snapshot_persisted() {
        let db = Database::open_in_memory().expect("db");
        let mut rb = TelemetryRingBuffer::new(60);
        rb.push(TelemetrySample {
            timestamp_utc: "2026-11-25T13:00:00Z".to_string(),
            timestamp_ms: 98_000,
            cpu_percent: 93.5,
            ram_percent: 55.0,
            ram_used_gb: 8.8,
            ram_free_gb: 7.2,
            ram_total_gb: 16.0,
            disk_active_percent: 12.0,
            disk_latency_ms: 6.0,
            net_rx_kbps: 10.0,
            net_tx_kbps: 5.0,
            net_latency_ms: None,
            net_loss_percent: None,
            health_status: HealthStatus::Critical,
        });

        let ev = insert_test_event(&db, 100_000, 5);
        let res = correlate_event(&db, &rb, &ev)
            .expect("correlate")
            .expect("ring buffer spike match");
        assert!(res.snapshot_id.is_none());
        assert!(res.diagnostic_note.contains("2 segundos antes"));
        assert!(res.diagnostic_note.contains("CPU"));
    }
}
