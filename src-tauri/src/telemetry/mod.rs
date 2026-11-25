pub mod cpu;
pub mod network;
pub mod pdh;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use chrono::Utc;
use sysinfo::{
    CpuRefreshKind, MemoryRefreshKind, Networks, ProcessRefreshKind, ProcessesToUpdate,
    RefreshKind, System, UpdateKind,
};
use tokio::sync::broadcast;

use crate::correlator;
use crate::db::Database;
use crate::models::{
    BottleneckSnapshot, HealthStatus, NewBottleneckSnapshot, OffendingProcess, Severity,
    TelemetrySample, ViolatedMetric, WsEnvelope,
};
use cpu::CpuMonitor;
use network::NetworkProbe;
use pdh::PdhDiskMonitor;

pub const RING_BUFFER_CAPACITY: usize = 60;
pub const PERCENT_THRESHOLD: f32 = 90.0;
pub const DISK_LATENCY_THRESHOLD_MS: f32 = 100.0;
pub const REQUIRED_CONSECUTIVE_SECS: u32 = 5;

#[derive(Debug, Clone)]
pub struct TelemetryRingBuffer {
    capacity: usize,
    samples: VecDeque<TelemetrySample>,
}

impl TelemetryRingBuffer {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            samples: VecDeque::with_capacity(cap),
        }
    }

    pub fn push(&mut self, sample: TelemetrySample) {
        if self.samples.len() >= self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn latest(&self) -> Option<TelemetrySample> {
        self.samples.back().cloned()
    }

    pub fn as_vec(&self) -> Vec<TelemetrySample> {
        self.samples.iter().cloned().collect()
    }

    pub fn find_in_window(&self, start_ms: i64, end_ms: i64) -> Vec<TelemetrySample> {
        self.samples
            .iter()
            .filter(|s| s.timestamp_ms >= start_ms && s.timestamp_ms <= end_ms)
            .cloned()
            .collect()
    }
}

pub type SharedRingBuffer = Arc<RwLock<TelemetryRingBuffer>>;

pub fn new_shared_ring_buffer() -> SharedRingBuffer {
    Arc::new(RwLock::new(TelemetryRingBuffer::new(RING_BUFFER_CAPACITY)))
}

#[derive(Debug, Clone, Copy, Default)]
struct MetricStreak {
    streak: u32,
    peak: f32,
}

impl MetricStreak {
    fn update(&mut self, value: f32, threshold: f32) -> Option<f32> {
        if value > threshold {
            self.streak += 1;
            self.peak = self.peak.max(value);
            if self.streak >= REQUIRED_CONSECUTIVE_SECS {
                let peak = self.peak;
                self.streak = 0;
                self.peak = 0.0;
                return Some(peak);
            }
        } else {
            self.streak = 0;
            self.peak = 0.0;
        }
        None
    }

    fn approaching_trigger(&self) -> bool {
        self.streak >= REQUIRED_CONSECUTIVE_SECS.saturating_sub(1)
    }
}

#[derive(Debug, Clone)]
pub struct ThresholdTrigger {
    pub metric: ViolatedMetric,
    pub peak_value: f32,
    pub threshold_value: f32,
    pub duration_secs: u32,
    pub severity: Severity,
}

#[derive(Debug, Clone, Default)]
pub struct ThresholdEvaluation {
    pub triggers: Vec<ThresholdTrigger>,
    pub needs_process_sample: bool,
}

#[derive(Debug, Default)]
pub struct ThresholdDetector {
    cpu: MetricStreak,
    ram: MetricStreak,
    disk_active: MetricStreak,
    disk_latency: MetricStreak,
}

impl ThresholdDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn evaluate(&mut self, sample: &TelemetrySample) -> ThresholdEvaluation {
        let mut triggers = Vec::new();

        if let Some(peak) = self.cpu.update(sample.cpu_percent, PERCENT_THRESHOLD) {
            triggers.push(ThresholdTrigger {
                metric: ViolatedMetric::Cpu,
                peak_value: peak,
                threshold_value: PERCENT_THRESHOLD,
                duration_secs: REQUIRED_CONSECUTIVE_SECS,
                severity: if peak >= 97.0 {
                    Severity::Critical
                } else {
                    Severity::High
                },
            });
        }

        if let Some(peak) = self.ram.update(sample.ram_percent, PERCENT_THRESHOLD) {
            triggers.push(ThresholdTrigger {
                metric: ViolatedMetric::Ram,
                peak_value: peak,
                threshold_value: PERCENT_THRESHOLD,
                duration_secs: REQUIRED_CONSECUTIVE_SECS,
                severity: if peak >= 97.0 {
                    Severity::Critical
                } else {
                    Severity::High
                },
            });
        }

        if let Some(peak) = self
            .disk_active
            .update(sample.disk_active_percent, PERCENT_THRESHOLD)
        {
            triggers.push(ThresholdTrigger {
                metric: ViolatedMetric::DiskActive,
                peak_value: peak,
                threshold_value: PERCENT_THRESHOLD,
                duration_secs: REQUIRED_CONSECUTIVE_SECS,
                severity: if peak >= 98.0 {
                    Severity::Critical
                } else {
                    Severity::High
                },
            });
        }

        if let Some(peak) = self
            .disk_latency
            .update(sample.disk_latency_ms, DISK_LATENCY_THRESHOLD_MS)
        {
            triggers.push(ThresholdTrigger {
                metric: ViolatedMetric::DiskLatency,
                peak_value: peak,
                threshold_value: DISK_LATENCY_THRESHOLD_MS,
                duration_secs: REQUIRED_CONSECUTIVE_SECS,
                severity: if peak >= 250.0 {
                    Severity::Critical
                } else {
                    Severity::High
                },
            });
        }

        let needs_process_sample = !triggers.is_empty()
            || self.cpu.approaching_trigger()
            || self.ram.approaching_trigger()
            || self.disk_active.approaching_trigger()
            || self.disk_latency.approaching_trigger();

        ThresholdEvaluation {
            triggers,
            needs_process_sample,
        }
    }
}

pub fn compute_health_status(
    cpu_percent: f32,
    ram_percent: f32,
    disk_active_percent: f32,
    disk_latency_ms: f32,
    has_recent_critical_event: bool,
) -> HealthStatus {
    if has_recent_critical_event
        || cpu_percent > 95.0
        || ram_percent > 95.0
        || disk_active_percent > 95.0
        || disk_latency_ms > 150.0
    {
        HealthStatus::Critical
    } else if cpu_percent > 75.0
        || ram_percent > 80.0
        || disk_active_percent > 75.0
        || disk_latency_ms > 50.0
    {
        HealthStatus::Warning
    } else {
        HealthStatus::Stable
    }
}

pub fn collect_top_processes(
    sys: &System,
    total_memory_bytes: u64,
    metric: ViolatedMetric,
    elapsed_secs: f32,
) -> Vec<OffendingProcess> {
    let dt = elapsed_secs.max(0.5);
    let mut list: Vec<OffendingProcess> = sys
        .processes()
        .values()
        .map(|proc_info| {
            let mem_bytes = proc_info.memory();
            let memory_mb = (mem_bytes as f32) / (1024.0 * 1024.0);
            let memory_percent = if total_memory_bytes > 0 {
                ((mem_bytes as f64 / total_memory_bytes as f64) * 100.0) as f32
            } else {
                0.0
            };
            let disk = proc_info.disk_usage();
            let disk_read_kbps = (disk.read_bytes as f32 / 1024.0) / dt;
            let disk_write_kbps = (disk.written_bytes as f32 / 1024.0) / dt;

            OffendingProcess {
                pid: proc_info.pid().as_u32(),
                name: proc_info.name().to_string_lossy().into_owned(),
                exe_path: proc_info.exe().map(|p| p.to_string_lossy().into_owned()),
                cpu_percent: proc_info.cpu_usage(),
                memory_mb,
                memory_percent,
                disk_read_kbps,
                disk_write_kbps,
            }
        })
        .collect();

    list.sort_by(|a, b| {
        let score = |p: &OffendingProcess| -> f32 {
            match metric {
                ViolatedMetric::Cpu => p.cpu_percent,
                ViolatedMetric::Ram => p.memory_mb,
                ViolatedMetric::DiskActive | ViolatedMetric::DiskLatency => {
                    p.disk_read_kbps + p.disk_write_kbps
                }
                ViolatedMetric::Network => p.cpu_percent + p.memory_percent,
            }
        };
        score(b)
            .partial_cmp(&score(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    list.truncate(5);
    list
}

pub fn spawn_telemetry_loop<F>(
    db: Database,
    ring_buffer: SharedRingBuffer,
    paused: Arc<AtomicBool>,
    ws_tx: broadcast::Sender<WsEnvelope>,
    on_snapshot: F,
) where
    F: Fn(&BottleneckSnapshot) + Send + Sync + 'static,
{
    let net_probe = NetworkProbe::new();
    net_probe.spawn_background_probe();

    tokio::spawn(async move {
        let cpu_init_kind = if cfg!(windows) {
            CpuRefreshKind::nothing()
        } else {
            CpuRefreshKind::nothing().with_usage()
        };
        let initial_refresh = RefreshKind::nothing()
            .with_cpu(cpu_init_kind)
            .with_memory(MemoryRefreshKind::everything());
        let mut sys = match System::new_with_specifics(initial_refresh) {
            Ok(s) => s,
            Err(err) => {
                tracing::error!(error = %err, "Failed to initialize sysinfo::System");
                return;
            }
        };
        let mut cpu_monitor = CpuMonitor::new();
        let mut networks = match Networks::new_with_refreshed_list() {
            Ok(n) => n,
            Err(err) => {
                tracing::warn!(error = %err, "Failed to initialize sysinfo::Networks; continuing without network throughput");
                return;
            }
        };
        let mut pdh = PdhDiskMonitor::new();
        let mut detector = ThresholdDetector::new();
        let mut last_tick = Instant::now();
        let mut ticker = tokio::time::interval(Duration::from_secs(1));

        let process_refresh_kind = ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .with_disk_usage()
            .with_exe(UpdateKind::OnlyIfNotSet);

        loop {
            ticker.tick().await;
            if paused.load(Ordering::Relaxed) {
                last_tick = Instant::now();
                continue;
            }

            let now = Utc::now();
            let now_ms = now.timestamp_millis();
            let elapsed_secs = last_tick.elapsed().as_secs_f32().max(0.5);
            last_tick = Instant::now();

            sys.refresh_memory();
            networks.refresh(true);

            let cpu_percent = cpu_monitor.sample(&mut sys);
            let total_mem = sys.total_memory();
            let available_mem = sys.available_memory();
            let used_mem = total_mem.saturating_sub(available_mem);
            let ram_percent = if total_mem > 0 {
                ((used_mem as f64 / total_mem as f64) * 100.0) as f32
            } else {
                0.0
            };
            let gib = 1024.0_f64 * 1024.0 * 1024.0;
            let ram_used_gb = (used_mem as f64 / gib) as f32;
            let ram_free_gb = (available_mem as f64 / gib) as f32;
            let ram_total_gb = (total_mem as f64 / gib) as f32;

            let (disk_active_percent, disk_latency_ms) = match pdh.as_mut() {
                Some(mon) => mon.sample(),
                None => (0.0, 0.0),
            };

            let (rx_bytes, tx_bytes) = networks.values().fold((0_u64, 0_u64), |acc, data| {
                (acc.0.saturating_add(data.received()), acc.1.saturating_add(data.transmitted()))
            });
            let net_rx_kbps = ((rx_bytes as f32 * 8.0) / 1000.0) / elapsed_secs;
            let net_tx_kbps = ((tx_bytes as f32 * 8.0) / 1000.0) / elapsed_secs;
            let (net_latency_ms, net_loss_percent) = net_probe.latest_stats();

            let has_recent_critical = db
                .has_recent_critical_event(now_ms.saturating_sub(60_000))
                .unwrap_or(false);
            let health_status = compute_health_status(
                cpu_percent,
                ram_percent,
                disk_active_percent,
                disk_latency_ms,
                has_recent_critical,
            );

            let sample = TelemetrySample {
                timestamp_utc: now.to_rfc3339(),
                timestamp_ms: now_ms,
                cpu_percent,
                ram_percent,
                ram_used_gb,
                ram_free_gb,
                ram_total_gb,
                disk_active_percent,
                disk_latency_ms,
                net_rx_kbps,
                net_tx_kbps,
                net_latency_ms,
                net_loss_percent,
                health_status,
            };

            if let Ok(mut guard) = ring_buffer.write() {
                guard.push(sample.clone());
            }

            let eval = detector.evaluate(&sample);
            if eval.needs_process_sample {
                sys.refresh_processes_specifics(
                    ProcessesToUpdate::All,
                    true,
                    process_refresh_kind,
                );
            }

            for trigger in eval.triggers {
                let top_processes =
                    collect_top_processes(&sys, total_mem, trigger.metric, elapsed_secs);
                let new_snap = NewBottleneckSnapshot {
                    timestamp_utc: sample.timestamp_utc.clone(),
                    timestamp_ms: sample.timestamp_ms,
                    violated_metric: trigger.metric,
                    peak_value: trigger.peak_value,
                    threshold_value: trigger.threshold_value,
                    duration_secs: trigger.duration_secs,
                    cpu_percent: sample.cpu_percent,
                    ram_percent: sample.ram_percent,
                    ram_free_gb: sample.ram_free_gb,
                    disk_active_percent: sample.disk_active_percent,
                    disk_latency_ms: sample.disk_latency_ms,
                    net_rx_kbps: sample.net_rx_kbps,
                    net_tx_kbps: sample.net_tx_kbps,
                    net_latency_ms: sample.net_latency_ms,
                    net_loss_percent: sample.net_loss_percent,
                    top_processes,
                    severity: trigger.severity,
                };

                match db.insert_snapshot(&new_snap) {
                    Ok(snapshot) => {
                        if let Err(err) = correlator::correlate_new_snapshot(&db, &snapshot) {
                            tracing::warn!(error = %err, "Failed retroactive snapshot correlation");
                        }
                        on_snapshot(&snapshot);
                        let _ = ws_tx.send(WsEnvelope::Snapshot(snapshot));
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "Failed to persist bottleneck snapshot");
                    }
                }
            }

            let _ = ws_tx.send(WsEnvelope::Telemetry(sample));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sample(ts_ms: i64, cpu: f32, ram: f32, disk_act: f32, disk_lat: f32) -> TelemetrySample {
        TelemetrySample {
            timestamp_utc: "2026-11-25T13:00:00Z".to_string(),
            timestamp_ms: ts_ms,
            cpu_percent: cpu,
            ram_percent: ram,
            ram_used_gb: 8.0,
            ram_free_gb: 8.0,
            ram_total_gb: 16.0,
            disk_active_percent: disk_act,
            disk_latency_ms: disk_lat,
            net_rx_kbps: 100.0,
            net_tx_kbps: 25.0,
            net_latency_ms: Some(15.0),
            net_loss_percent: Some(0.0),
            health_status: HealthStatus::Stable,
        }
    }

    #[test]
    fn ring_buffer_caps_at_60_and_filters_window() {
        let mut rb = TelemetryRingBuffer::new(60);
        for i in 0..75 {
            rb.push(make_sample(i * 1000, 10.0, 40.0, 5.0, 2.0));
        }
        assert_eq!(rb.len(), 60);
        assert_eq!(rb.as_vec()[0].timestamp_ms, 15_000);
        assert_eq!(rb.latest().expect("latest").timestamp_ms, 74_000);

        let window = rb.find_in_window(55_000, 65_000);
        assert_eq!(window.len(), 11);
        assert_eq!(window[0].timestamp_ms, 55_000);
        assert_eq!(window[10].timestamp_ms, 65_000);
    }

    #[test]
    fn threshold_requires_5_consecutive_seconds_and_tracks_peak() {
        let mut detector = ThresholdDetector::new();

        for i in 1..=4 {
            let eval = detector.evaluate(&make_sample(i * 1000, 91.0 + i as f32, 50.0, 10.0, 5.0));
            assert!(eval.triggers.is_empty(), "tick {i} must not trigger yet");
            if i == 4 {
                assert!(eval.needs_process_sample, "tick 4 primes process delta");
            }
        }

        let eval_5 = detector.evaluate(&make_sample(5000, 92.5, 50.0, 10.0, 5.0));
        assert_eq!(eval_5.triggers.len(), 1);
        assert_eq!(eval_5.triggers[0].metric, ViolatedMetric::Cpu);
        assert_eq!(eval_5.triggers[0].peak_value, 95.0);
        assert_eq!(eval_5.triggers[0].duration_secs, 5);

        // Next tick above threshold starts a new streak (no immediate re-trigger)
        let eval_6 = detector.evaluate(&make_sample(6000, 93.0, 50.0, 10.0, 5.0));
        assert!(eval_6.triggers.is_empty());
    }

    #[test]
    fn threshold_resets_when_metric_dips_below_limit() {
        let mut detector = ThresholdDetector::new();
        for i in 1..=4 {
            assert!(detector
                .evaluate(&make_sample(i * 1000, 20.0, 94.0, 10.0, 5.0))
                .triggers
                .is_empty());
        }
        // Brief dip at tick 5
        assert!(detector
            .evaluate(&make_sample(5000, 20.0, 89.9, 10.0, 5.0))
            .triggers
            .is_empty());
        // Tick 6 back above 90% must NOT trigger (streak is 1, not 5)
        assert!(detector
            .evaluate(&make_sample(6000, 20.0, 96.0, 10.0, 5.0))
            .triggers
            .is_empty());
    }

    #[test]
    fn threshold_triggers_on_disk_latency_over_100ms_and_disk_active_over_90() {
        let mut detector = ThresholdDetector::new();
        for i in 1..=4 {
            assert!(detector
                .evaluate(&make_sample(i * 1000, 15.0, 45.0, 92.0, 120.0 + i as f32 * 10.0))
                .triggers
                .is_empty());
        }
        let eval = detector.evaluate(&make_sample(5000, 15.0, 45.0, 95.0, 180.0));
        assert_eq!(eval.triggers.len(), 2);
        assert_eq!(eval.triggers[0].metric, ViolatedMetric::DiskActive);
        assert_eq!(eval.triggers[0].peak_value, 95.0);
        assert_eq!(eval.triggers[1].metric, ViolatedMetric::DiskLatency);
        assert_eq!(eval.triggers[1].peak_value, 180.0);
    }

    #[test]
    fn sysinfo_cpu_initialization_loads_cpus_and_reports_usage() {
        let cpu_init_kind = if cfg!(windows) {
            CpuRefreshKind::nothing()
        } else {
            CpuRefreshKind::nothing().with_usage()
        };
        let refresh = RefreshKind::nothing()
            .with_cpu(cpu_init_kind)
            .with_memory(MemoryRefreshKind::everything());
        let mut sys = System::new_with_specifics(refresh).expect("init sysinfo");
        assert!(!sys.cpus().is_empty(), "CPU list must be populated");

        let mut cpu_monitor = CpuMonitor::new();
        let worker = std::thread::spawn(|| {
            let start = std::time::Instant::now();
            let mut acc = 0_u64;
            while start.elapsed() < std::time::Duration::from_millis(250) {
                acc = acc.wrapping_add(1);
                std::hint::black_box(acc);
            }
        });
        let _ = worker.join();

        let usage = cpu_monitor.sample(&mut sys);
        assert!(
            usage > 0.0 && usage <= 100.0,
            "expected positive CPU usage, got {usage}"
        );
    }
}
