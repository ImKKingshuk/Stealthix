use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub(crate) type BridgeCallback = Box<dyn FnMut(&str, Value) -> std::result::Result<Value, String>>;

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct LogEntry {
    #[serde(default)]
    pub(crate) level: String,
    #[serde(default)]
    pub(crate) message: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct BridgeResponse {
    #[serde(default)]
    pub(crate) ok: bool,
    pub(crate) message: Option<String>,
    pub(crate) data_json: Option<String>,
    pub(crate) job_json: Option<String>,
    pub(crate) logs: Option<Vec<LogEntry>>,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct InitPayload {
    #[serde(default)]
    pub(crate) dbms: Vec<String>,
    #[serde(default)]
    pub(crate) methods: Vec<String>,
    #[serde(default)]
    pub(crate) profiles: Vec<String>,
    #[serde(default)]
    pub(crate) report_formats: Vec<String>,
    #[serde(default)]
    pub(crate) payload_families: Vec<String>,
    #[serde(default)]
    pub(crate) default_payloads: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub(crate) initial_config: Option<Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct FindingData {
    #[serde(default)]
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) target: String,
    #[serde(default)]
    pub(crate) details: Value,
    pub(crate) parameter: Option<String>,
    pub(crate) location: Option<String>,
    #[serde(default)]
    pub(crate) cvss: f64,
    #[serde(default)]
    pub(crate) severity: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct ScanResultData {
    #[serde(default)]
    pub(crate) target: String,
    #[serde(default)]
    pub(crate) findings: Vec<FindingData>,
    #[serde(default)]
    pub(crate) metadata: Value,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct PollPayload {
    #[serde(default)]
    pub(crate) job_id: String,
    #[serde(default)]
    pub(crate) status: String,
    pub(crate) message: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) started_at: Option<String>,
    pub(crate) finished_at: Option<String>,
    pub(crate) result: Option<ScanResultData>,
    pub(crate) session: Option<Value>,
    pub(crate) finding_count: Option<usize>,
    #[serde(default)]
    pub(crate) phase: String,
    pub(crate) progress_percent: Option<usize>,
    pub(crate) request_count: Option<usize>,
    pub(crate) estimated_total_requests: Option<usize>,
    pub(crate) eta_seconds: Option<usize>,
    pub(crate) active_elapsed_seconds: Option<f64>,
    pub(crate) paused: Option<bool>,
    #[serde(default)]
    pub(crate) tested_params_summary: String,
}
