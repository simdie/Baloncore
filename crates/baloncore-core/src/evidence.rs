use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub id: String,
    pub target: String,
    pub kind: EvidenceKind,
    pub summary: String,
    pub artifact_path: Option<String>,
    #[serde(default)]
    pub sensitivity: Vec<EvidenceSensitivity>,
    #[serde(default)]
    pub redaction_status: RedactionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceKind {
    HttpExchange,
    Screenshot,
    ToolOutput,
    SourceLocation,
    RuntimeObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceSensitivity {
    SessionSecret,
    AuthorizationHeader,
    CsrfToken,
    OtherUserPii,
    ApiKey,
    Password,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum RedactionStatus {
    #[default]
    NotReviewed,
    RedactionRequired,
    Redacted,
    SafeToShare,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionRule {
    pub name: String,
    pub sensitivity: EvidenceSensitivity,
    pub replacement: String,
}

pub fn default_redaction_rules() -> Vec<RedactionRule> {
    vec![
        RedactionRule {
            name: "authorization-header".to_string(),
            sensitivity: EvidenceSensitivity::AuthorizationHeader,
            replacement: "<REDACTED_AUTHORIZATION>".to_string(),
        },
        RedactionRule {
            name: "session-secret".to_string(),
            sensitivity: EvidenceSensitivity::SessionSecret,
            replacement: "<REDACTED_SESSION>".to_string(),
        },
        RedactionRule {
            name: "other-user-pii".to_string(),
            sensitivity: EvidenceSensitivity::OtherUserPii,
            replacement: "<REDACTED_PII>".to_string(),
        },
    ]
}
