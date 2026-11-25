use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::SentinelError;
use crate::eventlog::xpath::extract_event_data_summary;
use crate::models::{
    BottleneckSnapshot, IncidentDetail, NewBottleneckSnapshot, NewWindowsEvent, OffendingProcess,
    Severity, TimelineItem, TimelineItemType, ViolatedMetric, WindowsEventRecord,
};

pub const INITIAL_MIGRATION_SQL: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../migrations/001_init.sql"));

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self, SentinelError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        Self::init_connection(conn)
    }

    pub fn open_in_memory() -> Result<Self, SentinelError> {
        let conn = Connection::open_in_memory()?;
        Self::init_connection(conn)
    }

    fn init_connection(conn: Connection) -> Result<Self, SentinelError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        conn.execute_batch(INITIAL_MIGRATION_SQL)?;
        let now_ms = Utc::now().timestamp_millis();
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, name, applied_at_ms) VALUES (?1, ?2, ?3)",
            params![1_i64, "001_init", now_ms],
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock_conn(&self) -> Result<MutexGuard<'_, Connection>, SentinelError> {
        self.conn
            .lock()
            .map_err(|_| SentinelError::Internal("database mutex poisoned".to_string()))
    }

    pub fn journal_mode(&self) -> Result<String, SentinelError> {
        let conn = self.lock_conn()?;
        let mode: String = conn.query_row("PRAGMA journal_mode;", [], |row| row.get(0))?;
        Ok(mode)
    }

    pub fn insert_snapshot(
        &self,
        snap: &NewBottleneckSnapshot,
    ) -> Result<BottleneckSnapshot, SentinelError> {
        let conn = self.lock_conn()?;
        let top_processes_json = serde_json::to_string(&snap.top_processes)?;
        let now_ms = Utc::now().timestamp_millis();

        conn.execute(
            "INSERT INTO bottleneck_snapshots (
                timestamp_utc, timestamp_ms, violated_metric, peak_value, threshold_value,
                duration_secs, cpu_percent, ram_percent, ram_free_gb, disk_active_percent,
                disk_latency_ms, net_rx_kbps, net_tx_kbps, net_latency_ms, net_loss_percent,
                top_processes_json, severity, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                snap.timestamp_utc,
                snap.timestamp_ms,
                snap.violated_metric.as_str(),
                snap.peak_value,
                snap.threshold_value,
                snap.duration_secs,
                snap.cpu_percent,
                snap.ram_percent,
                snap.ram_free_gb,
                snap.disk_active_percent,
                snap.disk_latency_ms,
                snap.net_rx_kbps,
                snap.net_tx_kbps,
                snap.net_latency_ms,
                snap.net_loss_percent,
                top_processes_json,
                snap.severity.as_str(),
                now_ms,
            ],
        )?;

        let id = conn.last_insert_rowid();
        Ok(BottleneckSnapshot {
            id,
            timestamp_utc: snap.timestamp_utc.clone(),
            timestamp_ms: snap.timestamp_ms,
            violated_metric: snap.violated_metric,
            peak_value: snap.peak_value,
            threshold_value: snap.threshold_value,
            duration_secs: snap.duration_secs,
            cpu_percent: snap.cpu_percent,
            ram_percent: snap.ram_percent,
            ram_free_gb: snap.ram_free_gb,
            disk_active_percent: snap.disk_active_percent,
            disk_latency_ms: snap.disk_latency_ms,
            net_rx_kbps: snap.net_rx_kbps,
            net_tx_kbps: snap.net_tx_kbps,
            net_latency_ms: snap.net_latency_ms,
            net_loss_percent: snap.net_loss_percent,
            top_processes: snap.top_processes.clone(),
            severity: snap.severity,
        })
    }

    pub fn get_snapshot(&self, id: i64) -> Result<Option<BottleneckSnapshot>, SentinelError> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp_utc, timestamp_ms, violated_metric, peak_value, threshold_value,
                    duration_secs, cpu_percent, ram_percent, ram_free_gb, disk_active_percent,
                    disk_latency_ms, net_rx_kbps, net_tx_kbps, net_latency_ms, net_loss_percent,
                    top_processes_json, severity
             FROM bottleneck_snapshots WHERE id = ?1",
        )?;
        stmt.query_row(params![id], Self::row_to_snapshot)
            .optional()
            .map_err(SentinelError::from)
    }

    pub fn find_snapshots_in_window(
        &self,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<Vec<BottleneckSnapshot>, SentinelError> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp_utc, timestamp_ms, violated_metric, peak_value, threshold_value,
                    duration_secs, cpu_percent, ram_percent, ram_free_gb, disk_active_percent,
                    disk_latency_ms, net_rx_kbps, net_tx_kbps, net_latency_ms, net_loss_percent,
                    top_processes_json, severity
             FROM bottleneck_snapshots
             WHERE timestamp_ms BETWEEN ?1 AND ?2
             ORDER BY timestamp_ms DESC",
        )?;
        let rows = stmt.query_map(params![start_ms, end_ms], Self::row_to_snapshot)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn insert_windows_event(
        &self,
        ev: &NewWindowsEvent,
    ) -> Result<Option<WindowsEventRecord>, SentinelError> {
        let conn = self.lock_conn()?;
        let causes_json = serde_json::to_string(&ev.probable_causes)?;
        let solutions_json = serde_json::to_string(&ev.solutions)?;
        let now_ms = Utc::now().timestamp_millis();

        let changed = conn.execute(
            "INSERT OR IGNORE INTO windows_events (
                record_id, channel, provider_name, event_id, level, timestamp_utc, timestamp_ms,
                kb_id, category, severity, friendly_title, what_happened, probable_causes_json,
                solutions_json, raw_xml, correlation_snapshot_id, diagnostic_note, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                ev.record_id,
                ev.channel,
                ev.provider_name,
                ev.event_id,
                ev.level,
                ev.timestamp_utc,
                ev.timestamp_ms,
                ev.kb_id,
                ev.category,
                ev.severity.as_str(),
                ev.friendly_title,
                ev.what_happened,
                causes_json,
                solutions_json,
                ev.raw_xml,
                ev.correlation_snapshot_id,
                ev.diagnostic_note,
                now_ms,
            ],
        )?;

        if changed == 0 {
            return Ok(None);
        }

        let id = conn.last_insert_rowid();
        Ok(Some(WindowsEventRecord {
            id,
            record_id: ev.record_id,
            channel: ev.channel.clone(),
            provider_name: ev.provider_name.clone(),
            event_id: ev.event_id,
            level: ev.level,
            timestamp_utc: ev.timestamp_utc.clone(),
            timestamp_ms: ev.timestamp_ms,
            kb_id: ev.kb_id.clone(),
            category: ev.category.clone(),
            severity: ev.severity,
            friendly_title: ev.friendly_title.clone(),
            what_happened: ev.what_happened.clone(),
            probable_causes: ev.probable_causes.clone(),
            solutions: ev.solutions.clone(),
            raw_xml: ev.raw_xml.clone(),
            correlation_snapshot_id: ev.correlation_snapshot_id,
            diagnostic_note: ev.diagnostic_note.clone(),
        }))
    }

    pub fn get_windows_event(&self, id: i64) -> Result<Option<WindowsEventRecord>, SentinelError> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, record_id, channel, provider_name, event_id, level, timestamp_utc, timestamp_ms,
                    kb_id, category, severity, friendly_title, what_happened, probable_causes_json,
                    solutions_json, raw_xml, correlation_snapshot_id, diagnostic_note
             FROM windows_events WHERE id = ?1",
        )?;
        stmt.query_row(params![id], Self::row_to_event)
            .optional()
            .map_err(SentinelError::from)
    }

    pub fn find_uncorrelated_events_in_window(
        &self,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<Vec<WindowsEventRecord>, SentinelError> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, record_id, channel, provider_name, event_id, level, timestamp_utc, timestamp_ms,
                    kb_id, category, severity, friendly_title, what_happened, probable_causes_json,
                    solutions_json, raw_xml, correlation_snapshot_id, diagnostic_note
             FROM windows_events
             WHERE timestamp_ms BETWEEN ?1 AND ?2
               AND correlation_snapshot_id IS NULL
             ORDER BY timestamp_ms DESC",
        )?;
        let rows = stmt.query_map(params![start_ms, end_ms], Self::row_to_event)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn save_correlation(
        &self,
        event_id: i64,
        snapshot_id: i64,
        delta_ms: i64,
        offending_process: Option<&str>,
        metric_summary: &str,
        diagnostic_note: &str,
    ) -> Result<(), SentinelError> {
        let conn = self.lock_conn()?;
        let now_ms = Utc::now().timestamp_millis();

        conn.execute(
            "INSERT OR IGNORE INTO correlations (
                event_id, snapshot_id, delta_ms, offending_process, metric_summary, diagnostic_note, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event_id,
                snapshot_id,
                delta_ms,
                offending_process,
                metric_summary,
                diagnostic_note,
                now_ms,
            ],
        )?;

        conn.execute(
            "UPDATE windows_events
             SET correlation_snapshot_id = COALESCE(correlation_snapshot_id, ?1),
                 diagnostic_note = COALESCE(diagnostic_note, ?2)
             WHERE id = ?3",
            params![snapshot_id, diagnostic_note, event_id],
        )?;

        Ok(())
    }

    pub fn set_event_diagnostic_note(
        &self,
        event_id: i64,
        diagnostic_note: &str,
    ) -> Result<(), SentinelError> {
        let conn = self.lock_conn()?;
        conn.execute(
            "UPDATE windows_events
             SET diagnostic_note = COALESCE(diagnostic_note, ?1)
             WHERE id = ?2",
            params![diagnostic_note, event_id],
        )?;
        Ok(())
    }

    pub fn get_timeline(
        &self,
        limit: u32,
        offset: u32,
        category: Option<&str>,
        severity: Option<&str>,
    ) -> Result<Vec<TimelineItem>, SentinelError> {
        let conn = self.lock_conn()?;
        let fetch_limit = (limit.saturating_add(offset)).min(1000) as i64;
        let cat_filter = category.map(str::trim).filter(|s| !s.is_empty());
        let sev_filter = severity.map(str::trim).filter(|s| !s.is_empty());

        let mut items = Vec::new();

        // Fetch Windows Events
        let mut ev_stmt = conn.prepare(
            "SELECT id, timestamp_utc, timestamp_ms, category, severity, friendly_title, what_happened,
                    event_id, provider_name, correlation_snapshot_id, diagnostic_note, raw_xml
             FROM windows_events
             WHERE (?1 IS NULL OR category = ?1)
               AND (?2 IS NULL OR severity = ?2)
             ORDER BY timestamp_ms DESC
             LIMIT ?3",
        )?;
        let ev_rows = ev_stmt.query_map(params![cat_filter, sev_filter, fetch_limit], |row| {
            let id: i64 = row.get(0)?;
            let timestamp_utc: String = row.get(1)?;
            let timestamp_ms: i64 = row.get(2)?;
            let category: String = row.get(3)?;
            let sev_str: String = row.get(4)?;
            let base_title: String = row.get(5)?;
            let base_summary: String = row.get(6)?;
            let event_id: u32 = row.get(7)?;
            let provider_name: String = row.get(8)?;
            let corr_id: Option<i64> = row.get(9)?;
            let diagnostic_note: Option<String> = row.get(10)?;
            let raw_xml: String = row.get(11)?;

            let xml_details = extract_event_data_summary(&raw_xml);
            let title = match &xml_details.app_name {
                Some(app) => format!("{base_title} — {app}"),
                None => base_title,
            };
            let summary = match (&xml_details.module_name, &xml_details.exception_code) {
                (Some(module), Some(code)) => format!("Módulo: {module} · Código: {code} — {base_summary}"),
                (Some(module), None) => format!("Módulo: {module} — {base_summary}"),
                (None, Some(code)) => format!("Código: {code} — {base_summary}"),
                (None, None) => base_summary,
            };

            Ok(TimelineItem {
                uid: format!("event-{id}"),
                item_type: TimelineItemType::Event,
                source_id: id,
                timestamp_utc,
                timestamp_ms,
                category,
                severity: Severity::from_str_lossy(&sev_str),
                title,
                summary,
                event_id: Some(event_id),
                provider_name: Some(provider_name),
                violated_metric: None,
                peak_value: None,
                has_correlation: corr_id.is_some() || diagnostic_note.is_some(),
                diagnostic_note,
                details_text: xml_details.searchable_text,
            })
        })?;
        for row in ev_rows {
            items.push(row?);
        }

        // Fetch Bottleneck Snapshots
        let mut snap_stmt = conn.prepare(
            "SELECT s.id, s.timestamp_utc, s.timestamp_ms, s.violated_metric, s.peak_value,
                    s.duration_secs, s.top_processes_json, s.severity,
                    EXISTS(SELECT 1 FROM correlations c WHERE c.snapshot_id = s.id) AS has_corr
             FROM bottleneck_snapshots s
             WHERE (?1 IS NULL OR s.severity = ?1)
             ORDER BY s.timestamp_ms DESC
             LIMIT ?2",
        )?;
        let snap_rows = snap_stmt.query_map(params![sev_filter, fetch_limit], |row| {
            let id: i64 = row.get(0)?;
            let timestamp_utc: String = row.get(1)?;
            let timestamp_ms: i64 = row.get(2)?;
            let metric_str: String = row.get(3)?;
            let peak_value: f32 = row.get(4)?;
            let duration_secs: u32 = row.get(5)?;
            let top_json: String = row.get(6)?;
            let sev_str: String = row.get(7)?;
            let has_corr: bool = row.get(8)?;

            let metric = ViolatedMetric::from_db_str(&metric_str);
            let category_name = snapshot_category(metric).to_string();
            let top_procs: Vec<OffendingProcess> =
                serde_json::from_str(&top_json).unwrap_or_default();
            let top_name = top_procs
                .first()
                .map(|p| p.name.as_str())
                .unwrap_or("Sistema");

            let unit = if metric == ViolatedMetric::DiskLatency {
                "ms"
            } else {
                "%"
            };
            let title = format!(
                "Pico de {} ({:.1}{}) por {}s",
                metric.label_pt(),
                peak_value,
                unit,
                duration_secs
            );
            let summary = format!(
                "Gargalo sustentado detectado pela Caixa-Preta. Principal ofensor: {top_name}."
            );

            Ok(TimelineItem {
                uid: format!("snapshot-{id}"),
                item_type: TimelineItemType::Snapshot,
                source_id: id,
                timestamp_utc,
                timestamp_ms,
                category: category_name,
                severity: Severity::from_str_lossy(&sev_str),
                title,
                summary,
                event_id: None,
                provider_name: Some(top_name.to_string()),
                violated_metric: Some(metric),
                peak_value: Some(peak_value),
                has_correlation: has_corr,
                diagnostic_note: None,
                details_text: Some(
                    top_procs
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
            })
        })?;
        for row in snap_rows {
            let item = row?;
            if let Some(filter_cat) = cat_filter {
                if item.category != filter_cat {
                    continue;
                }
            }
            items.push(item);
        }

        items.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        let start = (offset as usize).min(items.len());
        let end = start.saturating_add(limit as usize).min(items.len());
        Ok(items[start..end].to_vec())
    }

    pub fn get_incident_detail(
        &self,
        item_type: TimelineItemType,
        id: i64,
    ) -> Result<Option<IncidentDetail>, SentinelError> {
        match item_type {
            TimelineItemType::Event => {
                let Some(event) = self.get_windows_event(id)? else {
                    return Ok(None);
                };
                let conn = self.lock_conn()?;
                let mut stmt = conn.prepare(
                    "SELECT s.id, s.timestamp_utc, s.timestamp_ms, s.violated_metric, s.peak_value,
                            s.threshold_value, s.duration_secs, s.cpu_percent, s.ram_percent,
                            s.ram_free_gb, s.disk_active_percent, s.disk_latency_ms, s.net_rx_kbps,
                            s.net_tx_kbps, s.net_latency_ms, s.net_loss_percent,
                            s.top_processes_json, s.severity
                     FROM bottleneck_snapshots s
                     INNER JOIN correlations c ON c.snapshot_id = s.id
                     WHERE c.event_id = ?1
                     ORDER BY ABS(c.delta_ms) ASC",
                )?;
                let rows = stmt.query_map(params![id], Self::row_to_snapshot)?;
                let mut snapshots = Vec::new();
                for row in rows {
                    snapshots.push(row?);
                }
                let diagnostic_note = event.diagnostic_note.clone();
                Ok(Some(IncidentDetail {
                    item_type,
                    event: Some(event),
                    snapshot: snapshots.first().cloned(),
                    correlated_snapshots: snapshots,
                    correlated_events: Vec::new(),
                    diagnostic_note,
                }))
            }
            TimelineItemType::Snapshot => {
                let Some(snapshot) = self.get_snapshot(id)? else {
                    return Ok(None);
                };
                let conn = self.lock_conn()?;
                let mut stmt = conn.prepare(
                    "SELECT e.id, e.record_id, e.channel, e.provider_name, e.event_id, e.level,
                            e.timestamp_utc, e.timestamp_ms, e.kb_id, e.category, e.severity,
                            e.friendly_title, e.what_happened, e.probable_causes_json,
                            e.solutions_json, e.raw_xml, e.correlation_snapshot_id,
                            e.diagnostic_note
                     FROM windows_events e
                     INNER JOIN correlations c ON c.event_id = e.id
                     WHERE c.snapshot_id = ?1
                     ORDER BY ABS(c.delta_ms) ASC",
                )?;
                let rows = stmt.query_map(params![id], Self::row_to_event)?;
                let mut events = Vec::new();
                for row in rows {
                    events.push(row?);
                }
                let diagnostic_note = events.first().and_then(|e| e.diagnostic_note.clone());
                Ok(Some(IncidentDetail {
                    item_type,
                    event: events.first().cloned(),
                    snapshot: Some(snapshot),
                    correlated_snapshots: Vec::new(),
                    correlated_events: events,
                    diagnostic_note,
                }))
            }
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), SentinelError> {
        let conn = self.lock_conn()?;
        let now_ms = Utc::now().timestamp_millis();
        conn.execute(
            "INSERT INTO app_settings (key, value, updated_at_ms)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at_ms = excluded.updated_at_ms",
            params![key, value, now_ms],
        )?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>, SentinelError> {
        let conn = self.lock_conn()?;
        conn.query_row(
            "SELECT value FROM app_settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(SentinelError::from)
    }

    pub fn has_recent_critical_event(&self, since_ms: i64) -> Result<bool, SentinelError> {
        let conn = self.lock_conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM windows_events WHERE severity = 'critical' AND timestamp_ms >= ?1",
            params![since_ms],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn has_any_events(&self) -> Result<bool, SentinelError> {
        let conn = self.lock_conn()?;
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM windows_events", [], |row| row.get(0))?;
        Ok(count > 0)
    }

    fn row_to_snapshot(row: &rusqlite::Row<'_>) -> rusqlite::Result<BottleneckSnapshot> {
        let metric_str: String = row.get(3)?;
        let top_json: String = row.get(16)?;
        let sev_str: String = row.get(17)?;
        let top_processes: Vec<OffendingProcess> =
            serde_json::from_str(&top_json).unwrap_or_default();

        Ok(BottleneckSnapshot {
            id: row.get(0)?,
            timestamp_utc: row.get(1)?,
            timestamp_ms: row.get(2)?,
            violated_metric: ViolatedMetric::from_db_str(&metric_str),
            peak_value: row.get(4)?,
            threshold_value: row.get(5)?,
            duration_secs: row.get(6)?,
            cpu_percent: row.get(7)?,
            ram_percent: row.get(8)?,
            ram_free_gb: row.get(9)?,
            disk_active_percent: row.get(10)?,
            disk_latency_ms: row.get(11)?,
            net_rx_kbps: row.get(12)?,
            net_tx_kbps: row.get(13)?,
            net_latency_ms: row.get(14)?,
            net_loss_percent: row.get(15)?,
            top_processes,
            severity: Severity::from_str_lossy(&sev_str),
        })
    }

    fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<WindowsEventRecord> {
        let sev_str: String = row.get(10)?;
        let causes_json: String = row.get(13)?;
        let solutions_json: String = row.get(14)?;

        let probable_causes: Vec<String> = serde_json::from_str(&causes_json).unwrap_or_default();
        let solutions: Vec<String> = serde_json::from_str(&solutions_json).unwrap_or_default();

        Ok(WindowsEventRecord {
            id: row.get(0)?,
            record_id: row.get(1)?,
            channel: row.get(2)?,
            provider_name: row.get(3)?,
            event_id: row.get(4)?,
            level: row.get(5)?,
            timestamp_utc: row.get(6)?,
            timestamp_ms: row.get(7)?,
            kb_id: row.get(8)?,
            category: row.get(9)?,
            severity: Severity::from_str_lossy(&sev_str),
            friendly_title: row.get(11)?,
            what_happened: row.get(12)?,
            probable_causes,
            solutions,
            raw_xml: row.get(15)?,
            correlation_snapshot_id: row.get(16)?,
            diagnostic_note: row.get(17)?,
        })
    }
}

pub fn snapshot_category(metric: ViolatedMetric) -> &'static str {
    match metric {
        ViolatedMetric::Cpu => "Processador (CPU)",
        ViolatedMetric::Ram => "Memória RAM",
        ViolatedMetric::DiskActive | ViolatedMetric::DiskLatency => "Disco (HD / SSD)",
        ViolatedMetric::Network => "Rede e Internet",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_new_snapshot(ts_ms: i64, metric: ViolatedMetric, peak: f32) -> NewBottleneckSnapshot {
        NewBottleneckSnapshot {
            timestamp_utc: "2026-11-25T13:00:00Z".to_string(),
            timestamp_ms: ts_ms,
            violated_metric: metric,
            peak_value: peak,
            threshold_value: 90.0,
            duration_secs: 5,
            cpu_percent: if metric == ViolatedMetric::Cpu { peak } else { 22.0 },
            ram_percent: if metric == ViolatedMetric::Ram { peak } else { 54.0 },
            ram_free_gb: 2.1,
            disk_active_percent: 15.0,
            disk_latency_ms: 4.5,
            net_rx_kbps: 120.0,
            net_tx_kbps: 45.0,
            net_latency_ms: Some(12.0),
            net_loss_percent: Some(0.0),
            top_processes: vec![OffendingProcess {
                pid: 4242,
                name: "chrome.exe".to_string(),
                exe_path: Some("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".to_string()),
                cpu_percent: 18.0,
                memory_mb: 6144.0,
                memory_percent: peak,
                disk_read_kbps: 0.0,
                disk_write_kbps: 0.0,
            }],
            severity: Severity::High,
        }
    }

    fn sample_new_event(ts_ms: i64, record_id: Option<i64>) -> NewWindowsEvent {
        NewWindowsEvent {
            record_id,
            channel: "Application".to_string(),
            provider_name: "Application Hang".to_string(),
            event_id: 1002,
            level: 2,
            timestamp_utc: "2026-11-25T13:00:03Z".to_string(),
            timestamp_ms: ts_ms,
            kb_id: Some("APP_1002".to_string()),
            category: "Aplicativos".to_string(),
            severity: Severity::Medium,
            friendly_title: "Um programa congelou e parou de responder".to_string(),
            what_happened: "Travou".to_string(),
            probable_causes: vec!["Falta de memória RAM".to_string()],
            solutions: vec!["Verifique linha do tempo".to_string()],
            raw_xml: "<Event/>".to_string(),
            correlation_snapshot_id: None,
            diagnostic_note: None,
        }
    }

    #[test]
    fn opens_file_database_in_wal_mode() {
        let dir = std::env::temp_dir().join(format!("winpulse_db_test_{}", uuid::Uuid::new_v4()));
        let db_path = dir.join("sentinel.db");
        let db = Database::open(&db_path).expect("open file db");
        let mode = db.journal_mode().expect("journal mode");
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deduplicates_windows_events_by_channel_and_record_id() {
        let db = Database::open_in_memory().expect("in-memory db");
        let first = db
            .insert_windows_event(&sample_new_event(1_000_000, Some(99)))
            .expect("insert 1");
        assert!(first.is_some());

        let duplicate = db
            .insert_windows_event(&sample_new_event(1_000_000, Some(99)))
            .expect("insert duplicate");
        assert!(duplicate.is_none());
    }

    #[test]
    fn timeline_and_incident_detail_return_correlated_records() {
        let db = Database::open_in_memory().expect("in-memory db");
        let snap = db
            .insert_snapshot(&sample_new_snapshot(100_000, ViolatedMetric::Ram, 94.0))
            .expect("snapshot");
        let ev = db
            .insert_windows_event(&sample_new_event(103_000, Some(10)))
            .expect("event")
            .expect("inserted");

        db.save_correlation(
            ev.id,
            snap.id,
            3_000,
            Some("chrome.exe"),
            "Memória RAM 94%",
            "3 segundos antes deste travamento (ID 1002), o processo chrome.exe consumiu 94% da Memória RAM.",
        )
        .expect("save correlation");

        let timeline = db.get_timeline(20, 0, None, None).expect("timeline");
        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[0].item_type, TimelineItemType::Event);
        assert!(timeline[0].has_correlation);

        let detail = db
            .get_incident_detail(TimelineItemType::Event, ev.id)
            .expect("detail")
            .expect("present");
        assert_eq!(detail.correlated_snapshots.len(), 1);
        assert_eq!(detail.correlated_snapshots[0].id, snap.id);
        assert!(detail.diagnostic_note.is_some());
    }
}
