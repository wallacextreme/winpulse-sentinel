pub mod incidents;
pub mod lttb;

use serde::Serialize;
use wasm_bindgen::prelude::*;

use incidents::{IncidentEngine, IncidentFilterQuery, SearchableIncident};

fn to_js_json_compatible<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsValue::from_str(&format!("failed to serialize to JS value: {e}")))
}

#[wasm_bindgen]
pub fn wasm_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[wasm_bindgen]
pub fn lttb_downsample_indices(xs: &[f64], ys: &[f64], threshold: usize) -> Vec<u32> {
    lttb::downsample_indices(xs, ys, threshold)
}

#[wasm_bindgen]
pub fn lttb_downsample_xy(xs: &[f64], ys: &[f64], threshold: usize) -> Vec<f64> {
    lttb::downsample_xy(xs, ys, threshold)
}

#[wasm_bindgen]
pub fn filter_incidents_stateless(
    incidents_js: JsValue,
    filter_js: JsValue,
) -> Result<JsValue, JsValue> {
    let incidents: Vec<SearchableIncident> = serde_wasm_bindgen::from_value(incidents_js)
        .map_err(|e| JsValue::from_str(&format!("invalid incidents payload: {e}")))?;
    let filter: IncidentFilterQuery = serde_wasm_bindgen::from_value(filter_js)
        .map_err(|e| JsValue::from_str(&format!("invalid filter payload: {e}")))?;

    let mut engine = IncidentEngine::new();
    engine.load(incidents);
    let uids = engine.search_uids(&filter);
    to_js_json_compatible(&uids)
}

#[wasm_bindgen]
pub struct IncidentIndex {
    engine: IncidentEngine,
}

#[wasm_bindgen]
impl IncidentIndex {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            engine: IncidentEngine::new(),
        }
    }

    pub fn load_incidents(&mut self, incidents_js: JsValue) -> Result<usize, JsValue> {
        let incidents: Vec<SearchableIncident> = serde_wasm_bindgen::from_value(incidents_js)
            .map_err(|e| JsValue::from_str(&format!("invalid incidents payload: {e}")))?;
        Ok(self.engine.load(incidents))
    }

    pub fn upsert_incident(&mut self, incident_js: JsValue) -> Result<usize, JsValue> {
        let incident: SearchableIncident = serde_wasm_bindgen::from_value(incident_js)
            .map_err(|e| JsValue::from_str(&format!("invalid incident payload: {e}")))?;
        Ok(self.engine.upsert(incident))
    }

    pub fn len(&self) -> usize {
        self.engine.len()
    }

    pub fn is_empty(&self) -> bool {
        self.engine.is_empty()
    }

    pub fn clear(&mut self) {
        self.engine.clear();
    }

    pub fn search_uids(&self, filter_js: JsValue) -> Result<JsValue, JsValue> {
        let filter: IncidentFilterQuery = serde_wasm_bindgen::from_value(filter_js)
            .map_err(|e| JsValue::from_str(&format!("invalid filter payload: {e}")))?;
        let uids = self.engine.search_uids(&filter);
        to_js_json_compatible(&uids)
    }

    pub fn facet_counts(&self) -> Result<JsValue, JsValue> {
        let counts = self.engine.facet_counts();
        to_js_json_compatible(&counts)
    }

    pub fn correlate_offline(
        &self,
        lookback_ms: f64,
        lookahead_ms: f64,
    ) -> Result<JsValue, JsValue> {
        let matches = self.engine.correlate_offline(lookback_ms, lookahead_ms);
        to_js_json_compatible(&matches)
    }
}

impl Default for IncidentIndex {
    fn default() -> Self {
        Self::new()
    }
}
