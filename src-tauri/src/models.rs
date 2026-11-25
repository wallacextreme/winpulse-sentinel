use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_str_lossy(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            _ => Self::Medium,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolatedMetric {
    Cpu,
    Ram,
    DiskActive,
    DiskLatency,
    Network,
}

impl ViolatedMetric {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Ram => "ram",
            Self::DiskActive => "disk_active",
            Self::DiskLatency => "disk_latency",
            Self::Network => "network",
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value.trim() {
            "cpu" => Self::Cpu,
            "ram" => Self::Ram,
            "disk_active" => Self::DiskActive,
            "disk_latency" => Self::DiskLatency,
            "network" => Self::Network,
            _ => Self::Cpu,
        }
    }

    pub fn label_pt(self) -> &'static str {
        match self {
            Self::Cpu => "CPU",
            Self::Ram => "Memória RAM",
            Self::DiskActive => "Uso de Disco",
            Self::DiskLatency => "Latência de Disco",
            Self::Network => "Rede",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Stable,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimelineItemType {
    Event,
    Snapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetrySample {
    pub timestamp_utc: String,
    pub timestamp_ms: i64,
    pub cpu_percent: f32,
    pub ram_percent: f32,
    pub ram_used_gb: f32,
    pub ram_free_gb: f32,
    pub ram_total_gb: f32,
    pub disk_active_percent: f32,
    pub disk_latency_ms: f32,
    pub net_rx_kbps: f32,
    pub net_tx_kbps: f32,
    pub net_latency_ms: Option<f32>,
    pub net_loss_percent: Option<f32>,
    pub health_status: HealthStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OffendingProcess {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub cpu_percent: f32,
    pub memory_mb: f32,
    pub memory_percent: f32,
    pub disk_read_kbps: f32,
    pub disk_write_kbps: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BottleneckSnapshot {
    pub id: i64,
    pub timestamp_utc: String,
    pub timestamp_ms: i64,
    pub violated_metric: ViolatedMetric,
    pub peak_value: f32,
    pub threshold_value: f32,
    pub duration_secs: u32,
    pub cpu_percent: f32,
    pub ram_percent: f32,
    pub ram_free_gb: f32,
    pub disk_active_percent: f32,
    pub disk_latency_ms: f32,
    pub net_rx_kbps: f32,
    pub net_tx_kbps: f32,
    pub net_latency_ms: Option<f32>,
    pub net_loss_percent: Option<f32>,
    pub top_processes: Vec<OffendingProcess>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewBottleneckSnapshot {
    pub timestamp_utc: String,
    pub timestamp_ms: i64,
    pub violated_metric: ViolatedMetric,
    pub peak_value: f32,
    pub threshold_value: f32,
    pub duration_secs: u32,
    pub cpu_percent: f32,
    pub ram_percent: f32,
    pub ram_free_gb: f32,
    pub disk_active_percent: f32,
    pub disk_latency_ms: f32,
    pub net_rx_kbps: f32,
    pub net_tx_kbps: f32,
    pub net_latency_ms: Option<f32>,
    pub net_loss_percent: Option<f32>,
    pub top_processes: Vec<OffendingProcess>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsEventRecord {
    pub id: i64,
    pub record_id: Option<i64>,
    pub channel: String,
    pub provider_name: String,
    pub event_id: u32,
    pub level: u8,
    pub timestamp_utc: String,
    pub timestamp_ms: i64,
    pub kb_id: Option<String>,
    pub category: String,
    pub severity: Severity,
    pub friendly_title: String,
    pub what_happened: String,
    pub probable_causes: Vec<String>,
    pub solutions: Vec<String>,
    pub raw_xml: String,
    pub correlation_snapshot_id: Option<i64>,
    pub diagnostic_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewWindowsEvent {
    pub record_id: Option<i64>,
    pub channel: String,
    pub provider_name: String,
    pub event_id: u32,
    pub level: u8,
    pub timestamp_utc: String,
    pub timestamp_ms: i64,
    pub kb_id: Option<String>,
    pub category: String,
    pub severity: Severity,
    pub friendly_title: String,
    pub what_happened: String,
    pub probable_causes: Vec<String>,
    pub solutions: Vec<String>,
    pub raw_xml: String,
    pub correlation_snapshot_id: Option<i64>,
    pub diagnostic_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineItem {
    pub uid: String,
    pub item_type: TimelineItemType,
    pub source_id: i64,
    pub timestamp_utc: String,
    pub timestamp_ms: i64,
    pub category: String,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    pub event_id: Option<u32>,
    pub provider_name: Option<String>,
    pub violated_metric: Option<ViolatedMetric>,
    pub peak_value: Option<f32>,
    pub has_correlation: bool,
    pub diagnostic_note: Option<String>,
    pub details_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportHistoryResult {
    pub scanned: usize,
    pub imported: usize,
    pub skipped_duplicates: usize,
    pub days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeBaseEntry {
    pub id: String,
    pub category: String,
    pub log_name: String,
    pub sources: Vec<String>,
    pub event_id: u32,
    pub severity: Severity,
    pub friendly_title: String,
    pub what_happened: String,
    pub probable_causes: Vec<String>,
    pub solutions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentDetail {
    pub item_type: TimelineItemType,
    pub event: Option<WindowsEventRecord>,
    pub snapshot: Option<BottleneckSnapshot>,
    pub correlated_snapshots: Vec<BottleneckSnapshot>,
    pub correlated_events: Vec<WindowsEventRecord>,
    pub diagnostic_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorStatus {
    pub paused: bool,
    pub uptime_secs: u64,
    pub ring_buffer_len: usize,
    pub event_watcher_active: bool,
    pub is_elevated: bool,
    pub health_status: HealthStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteServerStatus {
    pub enabled: bool,
    pub port: u16,
    pub lan_urls: Vec<String>,
    pub pin: Option<String>,
    pub active_clients: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum WsEnvelope {
    Telemetry(TelemetrySample),
    Snapshot(BottleneckSnapshot),
    WindowsEvent(WindowsEventRecord),
    Status(CollectorStatus),
}
