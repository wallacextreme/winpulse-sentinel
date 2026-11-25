use std::path::Path;

use serde::Deserialize;

use crate::error::SentinelError;
use crate::models::{KnowledgeBaseEntry, Severity};

pub const EMBEDDED_KNOWLEDGE_BASE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../knowledge_base.json"));

#[derive(Debug, Clone, Deserialize)]
pub struct KnowledgeBaseFile {
    pub version: String,
    pub last_updated: String,
    pub fallback_event: FallbackEventSpec,
    pub events: Vec<KnowledgeBaseEventSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FallbackEventSpec {
    pub category: String,
    pub severity: String,
    pub friendly_title: String,
    pub what_happened: String,
    pub probable_causes: Vec<String>,
    pub solutions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KnowledgeBaseEventSpec {
    pub id: String,
    pub category: String,
    pub log_name: String,
    pub sources: Vec<String>,
    pub event_id: u32,
    pub severity: String,
    pub friendly_title: String,
    pub what_happened: String,
    pub probable_causes: Vec<String>,
    pub solutions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TranslatedEvent {
    pub kb_id: Option<String>,
    pub category: String,
    pub severity: Severity,
    pub friendly_title: String,
    pub what_happened: String,
    pub probable_causes: Vec<String>,
    pub solutions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct KnowledgeBase {
    data: KnowledgeBaseFile,
}

const MAX_KB_OVERRIDE_BYTES: u64 = 2 * 1024 * 1024;

impl KnowledgeBase {
    pub fn from_embedded() -> Result<Self, SentinelError> {
        let data: KnowledgeBaseFile = serde_json::from_str(EMBEDDED_KNOWLEDGE_BASE)?;
        Ok(Self { data })
    }

    pub fn load_with_override(override_path: Option<&Path>) -> Result<Self, SentinelError> {
        if let Some(path) = override_path {
            if path.is_file() {
                match std::fs::metadata(path) {
                    Ok(meta) if meta.len() > MAX_KB_OVERRIDE_BYTES => {
                        tracing::warn!(
                            path = %path.display(),
                            size = meta.len(),
                            "External knowledge_base.json exceeds 2 MiB limit; falling back to embedded KB"
                        );
                        return Self::from_embedded();
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %err,
                            "Unable to stat external knowledge_base.json override; falling back to embedded KB"
                        );
                        return Self::from_embedded();
                    }
                }
                match std::fs::read_to_string(path) {
                    Ok(raw) => match serde_json::from_str::<KnowledgeBaseFile>(&raw) {
                        Ok(data) => {
                            tracing::info!(
                                path = %path.display(),
                                version = %data.version,
                                "Loaded external knowledge_base.json override"
                            );
                            return Ok(Self { data });
                        }
                        Err(err) => {
                            tracing::warn!(
                                path = %path.display(),
                                error = %err,
                                "Invalid external knowledge_base.json override; falling back to embedded KB"
                            );
                        }
                    },
                    Err(err) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %err,
                            "Unable to read external knowledge_base.json override; falling back to embedded KB"
                        );
                    }
                }
            }
        }
        Self::from_embedded()
    }

    pub fn version(&self) -> &str {
        &self.data.version
    }

    pub fn entry_count(&self) -> usize {
        self.data.events.len()
    }

    pub fn catalog(&self) -> Vec<KnowledgeBaseEntry> {
        self.data
            .events
            .iter()
            .map(|e| KnowledgeBaseEntry {
                id: e.id.clone(),
                category: e.category.clone(),
                log_name: e.log_name.clone(),
                sources: e.sources.clone(),
                event_id: e.event_id,
                severity: Severity::from_str_lossy(&e.severity),
                friendly_title: e.friendly_title.clone(),
                what_happened: e.what_happened.clone(),
                probable_causes: e.probable_causes.clone(),
                solutions: e.solutions.clone(),
            })
            .collect()
    }

    pub fn translate(&self, channel: &str, provider_name: &str, event_id: u32) -> TranslatedEvent {
        let provider_trimmed = provider_name.trim();
        let channel_trimmed = channel.trim();

        // Application-channel Windows Error Reporting (Event ID 1001: MoBEX / APPCRASH / Store apps)
        if event_id == 1001
            && provider_trimmed.eq_ignore_ascii_case("Windows Error Reporting")
            && (channel_trimmed.is_empty() || channel_trimmed.eq_ignore_ascii_case("Application"))
        {
            if let Some(entry) = self.data.events.iter().find(|e| e.id == "APP_1000") {
                return TranslatedEvent {
                    kb_id: Some("APP_1000".to_string()),
                    category: entry.category.clone(),
                    severity: Severity::High,
                    friendly_title: "Relatório de falha de aplicativo (Windows Error Reporting)"
                        .to_string(),
                    what_happened: entry.what_happened.clone(),
                    probable_causes: entry.probable_causes.clone(),
                    solutions: entry.solutions.clone(),
                };
            }
        }

        // Disk ID 51 (paging/IO warning) shares DISK_7_51 taxonomy in knowledge_base.json
        if event_id == 51 && provider_trimmed.eq_ignore_ascii_case("disk") {
            if let Some(entry) = self.data.events.iter().find(|e| e.id == "DISK_7_51") {
                return TranslatedEvent {
                    kb_id: Some("DISK_7_51".to_string()),
                    category: entry.category.clone(),
                    severity: Severity::High,
                    friendly_title: "Erro de paginação ou leitura detectado no disco (ID 51)"
                        .to_string(),
                    what_happened: entry.what_happened.clone(),
                    probable_causes: entry.probable_causes.clone(),
                    solutions: entry.solutions.clone(),
                };
            }
        }

        // Exact match: event_id + provider + channel
        if let Some(entry) = self.data.events.iter().find(|e| {
            e.event_id == event_id
                && (channel_trimmed.is_empty()
                    || e.log_name.eq_ignore_ascii_case(channel_trimmed))
                && e.sources
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(provider_trimmed))
        }) {
            return Self::from_entry(entry);
        }

        // Secondary match: event_id + provider (ignoring channel variation)
        if let Some(entry) = self.data.events.iter().find(|e| {
            e.event_id == event_id
                && e.sources
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(provider_trimmed))
        }) {
            return Self::from_entry(entry);
        }

        // Fallback for uncataloged events
        let fb = &self.data.fallback_event;
        TranslatedEvent {
            kb_id: None,
            category: fb.category.clone(),
            severity: Severity::from_str_lossy(&fb.severity),
            friendly_title: fb.friendly_title.clone(),
            what_happened: fb.what_happened.clone(),
            probable_causes: fb.probable_causes.clone(),
            solutions: fb.solutions.clone(),
        }
    }

    fn from_entry(entry: &KnowledgeBaseEventSpec) -> TranslatedEvent {
        TranslatedEvent {
            kb_id: Some(entry.id.clone()),
            category: entry.category.clone(),
            severity: Severity::from_str_lossy(&entry.severity),
            friendly_title: entry.friendly_title.clone(),
            what_happened: entry.what_happened.clone(),
            probable_causes: entry.probable_causes.clone(),
            solutions: entry.solutions.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_kb_loads_all_14_entries() {
        let kb = KnowledgeBase::from_embedded().expect("embedded kb");
        assert_eq!(kb.version(), "1.0.0");
        assert_eq!(kb.entry_count(), 14);
    }

    #[test]
    fn translates_known_events_case_insensitively() {
        let kb = KnowledgeBase::from_embedded().expect("embedded kb");

        let hang = kb.translate("Application", "application hang", 1002);
        assert_eq!(hang.kb_id.as_deref(), Some("APP_1002"));
        assert_eq!(hang.severity, Severity::Medium);

        let kp = kb.translate("System", "Microsoft-Windows-Kernel-Power", 41);
        assert_eq!(kp.kb_id.as_deref(), Some("SYS_41"));
        assert_eq!(kp.severity, Severity::Critical);

        let disk_51 = kb.translate("System", "disk", 51);
        assert_eq!(disk_51.kb_id.as_deref(), Some("DISK_7_51"));
        assert_eq!(disk_51.severity, Severity::High);

        let gpu = kb.translate("System", "Display", 4101);
        assert_eq!(gpu.kb_id.as_deref(), Some("GPU_4101"));
    }

    #[test]
    fn returns_fallback_for_unknown_event_and_invalid_override() {
        let dir = std::env::temp_dir().join(format!("winpulse_kb_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let bad_file = dir.join("knowledge_base.json");
        std::fs::write(&bad_file, "{ invalid json").expect("write bad file");

        let kb = KnowledgeBase::load_with_override(Some(&bad_file)).expect("fallback to embedded");
        assert_eq!(kb.entry_count(), 14);

        let unknown = kb.translate("System", "UnknownProvider", 99999);
        assert!(unknown.kb_id.is_none());
        assert_eq!(unknown.category, "Geral");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn uses_valid_external_override_when_present() {
        let dir = std::env::temp_dir().join(format!("winpulse_kb_ovr_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let ovr_file = dir.join("knowledge_base.json");
        let custom = EMBEDDED_KNOWLEDGE_BASE.replace("\"1.0.0\"", "\"9.9.9\"");
        std::fs::write(&ovr_file, custom).expect("write override");

        let kb = KnowledgeBase::load_with_override(Some(&ovr_file)).expect("load override");
        assert_eq!(kb.version(), "9.9.9");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
