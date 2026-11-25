use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PROBE_HISTORY_LEN: usize = 10;

#[derive(Debug, Default)]
struct NetworkProbeState {
    outcomes: VecDeque<Option<f32>>,
}

impl NetworkProbeState {
    fn record(&mut self, rtt_ms: Option<f32>) {
        if self.outcomes.len() >= PROBE_HISTORY_LEN {
            self.outcomes.pop_front();
        }
        self.outcomes.push_back(rtt_ms);
    }

    fn summary(&self) -> (Option<f32>, Option<f32>) {
        if self.outcomes.is_empty() {
            return (None, None);
        }
        let total = self.outcomes.len() as f32;
        let failed = self.outcomes.iter().filter(|x| x.is_none()).count() as f32;
        let loss_pct = (failed / total) * 100.0;
        let last_rtt = self.outcomes.iter().rev().flatten().copied().next();
        (last_rtt, Some(loss_pct))
    }
}

#[derive(Clone)]
pub struct NetworkProbe {
    state: Arc<Mutex<NetworkProbeState>>,
}

impl NetworkProbe {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(NetworkProbeState::default())),
        }
    }

    pub fn latest_stats(&self) -> (Option<f32>, Option<f32>) {
        match self.state.lock() {
            Ok(guard) => guard.summary(),
            Err(_) => (None, None),
        }
    }

    pub fn spawn_background_probe(&self) {
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                let rtt = tokio::task::spawn_blocking(icmp_ping_once)
                    .await
                    .ok()
                    .flatten();
                if let Ok(mut guard) = state.lock() {
                    guard.record(rtt);
                }
            }
        });
    }
}

impl Default for NetworkProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
fn icmp_ping_once() -> Option<f32> {
    use core::ffi::c_void;
    use windows::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
    };

    unsafe {
        let handle = IcmpCreateFile().ok()?;
        let payload = b"winpulse";
        let reply_size = std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8;
        let mut reply_buf = vec![0_u8; reply_size];

        // 1.1.1.1 in network byte order
        let dest_ip = u32::from_ne_bytes([1, 1, 1, 1]);
        let replies = IcmpSendEcho(
            handle,
            dest_ip,
            payload.as_ptr().cast::<c_void>(),
            payload.len() as u16,
            None,
            reply_buf.as_mut_ptr().cast::<c_void>(),
            reply_size as u32,
            800,
        );
        let _ = IcmpCloseHandle(handle);

        if replies == 0 || reply_buf.len() < std::mem::size_of::<ICMP_ECHO_REPLY>() {
            return None;
        }

        let reply = std::ptr::read_unaligned(reply_buf.as_ptr().cast::<ICMP_ECHO_REPLY>());
        if reply.Status == 0 {
            Some(reply.RoundTripTime as f32)
        } else {
            None
        }
    }
}

#[cfg(not(windows))]
fn icmp_ping_once() -> Option<f32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_state_calculates_rolling_loss_and_last_rtt() {
        let mut state = NetworkProbeState::default();
        state.record(Some(14.0));
        state.record(None);
        state.record(Some(18.0));
        state.record(None);

        let (rtt, loss) = state.summary();
        assert_eq!(rtt, Some(18.0));
        assert_eq!(loss, Some(50.0));
    }
}
