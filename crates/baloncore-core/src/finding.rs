use serde::{Deserialize, Serialize};

use crate::evidence::EvidenceRecord;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub affected_asset: String,
    pub security_property: String,
    pub impact: String,
    pub evidence: Vec<EvidenceRecord>,
    pub recommended_fix: String,
    pub regression_test: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}
