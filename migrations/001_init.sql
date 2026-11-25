-- WinPulse Sentinel — Initial SQLite Schema (WAL Mode configured at connection open)

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_ms INTEGER NOT NULL
);

-- Module A: Bottleneck Flight Recorder Snapshots
CREATE TABLE IF NOT EXISTS bottleneck_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    violated_metric TEXT NOT NULL CHECK (violated_metric IN ('cpu', 'ram', 'disk_active', 'disk_latency', 'network')),
    peak_value REAL NOT NULL,
    threshold_value REAL NOT NULL,
    duration_secs INTEGER NOT NULL,
    cpu_percent REAL NOT NULL,
    ram_percent REAL NOT NULL,
    ram_free_gb REAL NOT NULL,
    disk_active_percent REAL NOT NULL,
    disk_latency_ms REAL NOT NULL,
    net_rx_kbps REAL NOT NULL,
    net_tx_kbps REAL NOT NULL,
    net_latency_ms REAL,
    net_loss_percent REAL,
    top_processes_json TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high' CHECK (severity IN ('medium', 'high', 'critical')),
    created_at_ms INTEGER NOT NULL
);

-- Module B & C: Windows Event Log Entries + Knowledge Base Enrichment + Module D Correlation Link
CREATE TABLE IF NOT EXISTS windows_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id INTEGER,
    channel TEXT NOT NULL CHECK (channel IN ('System', 'Application')),
    provider_name TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    level INTEGER NOT NULL DEFAULT 2,
    timestamp_utc TEXT NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    kb_id TEXT,
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('medium', 'high', 'critical')),
    friendly_title TEXT NOT NULL,
    what_happened TEXT NOT NULL,
    probable_causes_json TEXT NOT NULL,
    solutions_json TEXT NOT NULL,
    raw_xml TEXT NOT NULL,
    correlation_snapshot_id INTEGER REFERENCES bottleneck_snapshots(id) ON DELETE SET NULL,
    diagnostic_note TEXT,
    created_at_ms INTEGER NOT NULL,
    UNIQUE(channel, record_id)
);

-- Module D: Explicit Event <-> Snapshot Correlation Records ([T - 15s, T + 5s])
CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES windows_events(id) ON DELETE CASCADE,
    snapshot_id INTEGER NOT NULL REFERENCES bottleneck_snapshots(id) ON DELETE CASCADE,
    delta_ms INTEGER NOT NULL,
    offending_process TEXT,
    metric_summary TEXT NOT NULL,
    diagnostic_note TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    UNIQUE(event_id, snapshot_id)
);

-- Runtime key-value settings (non-secret operational preferences)
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

-- Timestamp & query-path indexes
CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp_ms
    ON bottleneck_snapshots (timestamp_ms DESC);

CREATE INDEX IF NOT EXISTS idx_snapshots_metric_timestamp_ms
    ON bottleneck_snapshots (violated_metric, timestamp_ms DESC);

CREATE INDEX IF NOT EXISTS idx_events_timestamp_ms
    ON windows_events (timestamp_ms DESC);

CREATE INDEX IF NOT EXISTS idx_events_severity_timestamp_ms
    ON windows_events (severity, timestamp_ms DESC);

CREATE INDEX IF NOT EXISTS idx_events_category_timestamp_ms
    ON windows_events (category, timestamp_ms DESC);

CREATE INDEX IF NOT EXISTS idx_events_event_id_timestamp_ms
    ON windows_events (event_id, timestamp_ms DESC);

CREATE INDEX IF NOT EXISTS idx_correlations_event_id
    ON correlations (event_id);

CREATE INDEX IF NOT EXISTS idx_correlations_snapshot_id
    ON correlations (snapshot_id);
