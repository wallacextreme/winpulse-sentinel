use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchableIncident {
    pub uid: String,
    pub item_type: String,
    pub source_id: f64,
    pub timestamp_ms: f64,
    pub category: String,
    pub severity: String,
    pub title: String,
    pub summary: String,
    pub event_id: Option<u32>,
    pub provider_name: Option<String>,
    pub violated_metric: Option<String>,
    pub peak_value: Option<f32>,
    pub has_correlation: bool,
    pub diagnostic_note: Option<String>,
    #[serde(default)]
    pub details_text: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IncidentFilterQuery {
    pub query: String,
    pub categories: Vec<String>,
    pub severities: Vec<String>,
    pub item_types: Vec<String>,
    pub only_correlated: bool,
    pub from_timestamp_ms: Option<f64>,
    pub to_timestamp_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientCorrelationMatch {
    pub event_uid: String,
    pub snapshot_uid: String,
    pub delta_ms: f64,
    pub diagnostic_note: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentFacetCounts {
    pub total: usize,
    pub by_category: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
}

pub fn fold_portuguese(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let folded = match ch {
            'á' | 'à' | 'â' | 'ã' | 'ä' | 'Á' | 'À' | 'Â' | 'Ã' | 'Ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' | 'Ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' | 'Í' | 'Ì' | 'Î' | 'Ï' => 'i',
            'ó' | 'ò' | 'ô' | 'õ' | 'ö' | 'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ö' => 'o',
            'ú' | 'ù' | 'û' | 'ü' | 'Ú' | 'Ù' | 'Û' | 'Ü' => 'u',
            'ç' | 'Ç' => 'c',
            'ñ' | 'Ñ' => 'n',
            other => other.to_ascii_lowercase(),
        };
        out.push(folded);
    }
    out
}

#[derive(Debug, Clone)]
struct IndexedIncident {
    item: SearchableIncident,
    folded_blob: String,
    folded_category: String,
    folded_severity: String,
    folded_item_type: String,
}

impl IndexedIncident {
    fn from_item(item: SearchableIncident) -> Self {
        let mut blob_parts = Vec::with_capacity(7);
        blob_parts.push(item.title.as_str());
        blob_parts.push(item.summary.as_str());
        blob_parts.push(item.category.as_str());
        if let Some(ref p) = item.provider_name {
            blob_parts.push(p.as_str());
        }
        if let Some(ref m) = item.violated_metric {
            blob_parts.push(m.as_str());
        }
        if let Some(ref note) = item.diagnostic_note {
            blob_parts.push(note.as_str());
        }
        if let Some(ref details) = item.details_text {
            blob_parts.push(details.as_str());
        }
        let eid_str = item.event_id.map(|id| id.to_string()).unwrap_or_default();
        if !eid_str.is_empty() {
            blob_parts.push(eid_str.as_str());
        }

        let folded_blob = fold_portuguese(&blob_parts.join(" "));
        let folded_category = fold_portuguese(&item.category);
        let folded_severity = fold_portuguese(&item.severity);
        let folded_item_type = fold_portuguese(&item.item_type);

        Self {
            item,
            folded_blob,
            folded_category,
            folded_severity,
            folded_item_type,
        }
    }
}

#[derive(Debug, Default)]
pub struct IncidentEngine {
    entries: Vec<IndexedIncident>,
}

impl IncidentEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn load(&mut self, incidents: Vec<SearchableIncident>) -> usize {
        self.entries.clear();
        let mut seen = HashMap::<String, usize>::with_capacity(incidents.len());
        for item in incidents {
            if let Some(&idx) = seen.get(&item.uid) {
                self.entries[idx] = IndexedIncident::from_item(item);
            } else {
                let idx = self.entries.len();
                seen.insert(item.uid.clone(), idx);
                self.entries.push(IndexedIncident::from_item(item));
            }
        }
        self.sort_descending();
        self.entries.len()
    }

    pub fn upsert(&mut self, incident: SearchableIncident) -> usize {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.item.uid == incident.uid) {
            *existing = IndexedIncident::from_item(incident);
        } else {
            self.entries.push(IndexedIncident::from_item(incident));
        }
        self.sort_descending();
        self.entries.len()
    }

    fn sort_descending(&mut self) {
        self.entries.sort_by(|a, b| {
            b.item
                .timestamp_ms
                .total_cmp(&a.item.timestamp_ms)
                .then_with(|| a.item.uid.cmp(&b.item.uid))
        });
    }

    pub fn search_uids(&self, filter: &IncidentFilterQuery) -> Vec<String> {
        let folded_query = fold_portuguese(&filter.query);
        let tokens: Vec<&str> = folded_query.split_whitespace().collect();
        let cats: Vec<String> = filter.categories.iter().map(|c| fold_portuguese(c)).collect();
        let sevs: Vec<String> = filter.severities.iter().map(|s| fold_portuguese(s)).collect();
        let types: Vec<String> = filter.item_types.iter().map(|t| fold_portuguese(t)).collect();

        let mut matched = Vec::new();
        for entry in &self.entries {
            if filter.only_correlated && !entry.item.has_correlation {
                continue;
            }
            if let Some(from_ts) = filter.from_timestamp_ms {
                if entry.item.timestamp_ms < from_ts {
                    continue;
                }
            }
            if let Some(to_ts) = filter.to_timestamp_ms {
                if entry.item.timestamp_ms > to_ts {
                    continue;
                }
            }
            if !cats.is_empty() && !cats.iter().any(|c| c == &entry.folded_category) {
                continue;
            }
            if !sevs.is_empty() && !sevs.iter().any(|s| s == &entry.folded_severity) {
                continue;
            }
            if !types.is_empty() && !types.iter().any(|t| t == &entry.folded_item_type) {
                continue;
            }
            if !tokens.is_empty()
                && !tokens
                    .iter()
                    .all(|tok| entry.folded_blob.contains(tok))
            {
                continue;
            }
            matched.push(entry.item.uid.clone());
        }
        matched
    }

    pub fn facet_counts(&self) -> IncidentFacetCounts {
        let mut by_category = HashMap::new();
        let mut by_severity = HashMap::new();
        for entry in &self.entries {
            *by_category.entry(entry.item.category.clone()).or_insert(0) += 1;
            *by_severity.entry(entry.item.severity.clone()).or_insert(0) += 1;
        }
        IncidentFacetCounts {
            total: self.entries.len(),
            by_category,
            by_severity,
        }
    }

    pub fn correlate_offline(
        &self,
        lookback_ms: f64,
        lookahead_ms: f64,
    ) -> Vec<ClientCorrelationMatch> {
        let lookback = lookback_ms.max(0.0);
        let lookahead = lookahead_ms.max(0.0);

        let mut snapshots: Vec<&SearchableIncident> = self
            .entries
            .iter()
            .filter(|e| e.item.item_type.eq_ignore_ascii_case("snapshot"))
            .map(|e| &e.item)
            .collect();

        if snapshots.is_empty() {
            return Vec::new();
        }

        snapshots.sort_by(|a, b| a.timestamp_ms.total_cmp(&b.timestamp_ms));

        let mut matches = Vec::new();
        for entry in &self.entries {
            if !entry.item.item_type.eq_ignore_ascii_case("event") {
                continue;
            }
            let event_ts = entry.item.timestamp_ms;
            let min_ts = event_ts - lookback;
            let max_ts = event_ts + lookahead;

            let start_idx = snapshots.partition_point(|s| s.timestamp_ms < min_ts);
            let mut best: Option<(&SearchableIncident, f64)> = None;

            for snap in &snapshots[start_idx..] {
                if snap.timestamp_ms > max_ts {
                    break;
                }
                let delta = event_ts - snap.timestamp_ms;
                let replace = match best {
                    None => true,
                    Some((_, best_delta)) => {
                        let abs_new = delta.abs();
                        let abs_best = best_delta.abs();
                        abs_new < abs_best || (abs_new == abs_best && delta >= 0.0 && best_delta < 0.0)
                    }
                };
                if replace {
                    best = Some((snap, delta));
                }
            }

            if let Some((snap, delta_ms)) = best {
                let diagnostic_note = format_offline_note(delta_ms, &entry.item, snap);
                matches.push(ClientCorrelationMatch {
                    event_uid: entry.item.uid.clone(),
                    snapshot_uid: snap.uid.clone(),
                    delta_ms,
                    diagnostic_note,
                });
            }
        }

        matches
    }
}

fn metric_label_pt(metric: Option<&str>) -> &'static str {
    match metric {
        Some("cpu") => "CPU",
        Some("ram") => "Memória RAM",
        Some("disk_active") => "Uso de Disco",
        Some("disk_latency") => "Latência de Disco",
        Some("network") => "Rede",
        _ => "Sistema",
    }
}

fn format_offline_note(
    delta_ms: f64,
    event: &SearchableIncident,
    snap: &SearchableIncident,
) -> String {
    let abs_secs = (delta_ms.abs() / 1000.0).round() as i64;
    let id_part = event
        .event_id
        .map(|id| format!(" (ID {id})"))
        .unwrap_or_default();
    let timing = if abs_secs == 0 {
        format!("No mesmo instante deste evento{id_part}")
    } else if delta_ms >= 0.0 {
        let unit = if abs_secs == 1 { "segundo" } else { "segundos" };
        format!("{abs_secs} {unit} antes deste evento{id_part}")
    } else {
        let unit = if abs_secs == 1 { "segundo" } else { "segundos" };
        format!("{abs_secs} {unit} após este evento{id_part}")
    };

    let metric_name = metric_label_pt(snap.violated_metric.as_deref());
    let peak = snap.peak_value.unwrap_or(0.0);
    let metric_desc = if snap.violated_metric.as_deref() == Some("disk_latency") {
        format!("{peak:.0} ms de {metric_name}")
    } else {
        format!("{peak:.0}% de {metric_name}")
    };

    match snap.provider_name.as_deref() {
        Some(proc_name) if !proc_name.trim().is_empty() => {
            format!("{timing}, o processo `{proc_name}` registrou pico de {metric_desc}.")
        }
        _ => format!("{timing}, o sistema registrou pico de {metric_desc}."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(uid: &str, ts_ms: f64, event_id: u32, title: &str, cat: &str, sev: &str, corr: bool) -> SearchableIncident {
        SearchableIncident {
            uid: uid.to_string(),
            item_type: "event".to_string(),
            source_id: event_id as f64,
            timestamp_ms: ts_ms,
            category: cat.to_string(),
            severity: sev.to_string(),
            title: title.to_string(),
            summary: "Resumo do evento".to_string(),
            event_id: Some(event_id),
            provider_name: Some("Application Hang".to_string()),
            violated_metric: None,
            peak_value: None,
            has_correlation: corr,
            diagnostic_note: None,
            details_text: Some("mspaint.exe · ucrtbase.dll · 0xc0000409 · MoBEX".to_string()),
        }
    }

    fn make_snapshot(uid: &str, ts_ms: f64, metric: &str, peak: f32, proc_name: &str) -> SearchableIncident {
        SearchableIncident {
            uid: uid.to_string(),
            item_type: "snapshot".to_string(),
            source_id: ts_ms,
            timestamp_ms: ts_ms,
            category: "Memória RAM".to_string(),
            severity: "high".to_string(),
            title: format!("Pico de {metric}"),
            summary: format!("Ofensor principal: {proc_name}"),
            event_id: None,
            provider_name: Some(proc_name.to_string()),
            violated_metric: Some(metric.to_string()),
            peak_value: Some(peak),
            has_correlation: false,
            diagnostic_note: None,
            details_text: None,
        }
    }

    #[test]
    fn searches_with_portuguese_diacritics_and_multi_token_filters() {
        let mut engine = IncidentEngine::new();
        engine.load(vec![
            make_event("ev-1", 103_000.0, 1002, "Programa congelou sem memória", "Aplicativos", "medium", true),
            make_event("ev-2", 105_000.0, 129, "Latência extrema no SSD", "Disco (HD / SSD)", "critical", false),
            make_snapshot("sn-1", 100_000.0, "ram", 94.0, "chrome.exe"),
        ]);

        // Diacritic-insensitive search (descending chronological order: ev-1 @ 103s, sn-1 @ 100s)
        let mem_hits = engine.search_uids(&IncidentFilterQuery {
            query: "memoria".to_string(),
            ..Default::default()
        });
        assert_eq!(mem_hits, vec!["ev-1", "sn-1"]);

        // Multi-token AND search
        let lat_hits = engine.search_uids(&IncidentFilterQuery {
            query: "latencia 129".to_string(),
            ..Default::default()
        });
        assert_eq!(lat_hits, vec!["ev-2"]);

        // Category + severity + correlated filter
        let filtered = engine.search_uids(&IncidentFilterQuery {
            categories: vec!["Aplicativos".to_string()],
            severities: vec!["medium".to_string()],
            only_correlated: true,
            ..Default::default()
        });
        assert_eq!(filtered, vec!["ev-1"]);
    }

    #[test]
    fn upserts_and_computes_facet_counts_and_offline_correlations() {
        let mut engine = IncidentEngine::new();
        engine.load(vec![
            make_snapshot("sn-1", 100_000.0, "ram", 94.0, "chrome.exe"),
            make_event("ev-1", 103_000.0, 1002, "Programa congelou", "Aplicativos", "medium", false),
            make_event("ev-far", 130_000.0, 41, "Desligamento", "Sistema e Energia", "critical", false),
        ]);

        // Upsert updates existing item
        let count = engine.upsert(make_event(
            "ev-1",
            103_000.0,
            1002,
            "Programa congelou atualizado",
            "Aplicativos",
            "high",
            false,
        ));
        assert_eq!(count, 3);

        let facets = engine.facet_counts();
        assert_eq!(facets.total, 3);
        assert_eq!(facets.by_severity.get("high"), Some(&2));
        assert_eq!(facets.by_severity.get("critical"), Some(&1));

        let matches = engine.correlate_offline(15_000.0, 5_000.0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].event_uid, "ev-1");
        assert_eq!(matches[0].snapshot_uid, "sn-1");
        assert_eq!(matches[0].delta_ms, 3_000.0);
        assert!(matches[0].diagnostic_note.contains("chrome.exe"));
        assert!(matches[0].diagnostic_note.contains("3 segundos antes"));
    }
}
