-- WinPulse Sentinel — AI Diagnoses Cache & Human-in-the-Loop Command Audit Log

CREATE TABLE IF NOT EXISTS ai_diagnoses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_uid TEXT NOT NULL,
    provider_kind TEXT NOT NULL CHECK (provider_kind IN ('cloud_proxy', 'gemini_byok', 'ollama_local')),
    model_name TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_diagnoses_target_uid
    ON ai_diagnoses (target_uid, created_at_ms DESC);

CREATE TABLE IF NOT EXISTS command_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL CHECK (source IN ('ai', 'catalog', 'mcp')),
    shell TEXT NOT NULL CHECK (shell IN ('powershell', 'cmd')),
    command_text TEXT NOT NULL,
    rationale TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('read_only', 'moderate')),
    requires_admin INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'rejected', 'cancelled', 'timed_out')),
    exit_code INTEGER,
    stdout_text TEXT NOT NULL DEFAULT '',
    stderr_text TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER,
    created_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_command_audit_created_at
    ON command_audit_log (created_at_ms DESC);
