use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPackage {
    pub package_id: String,
    pub finding_id: String,
    pub target_endpoint: String,
    pub vulnerability_class: String,
    pub reproduction: ReproductionCommand,
    pub request: HttpRequestProof,
    pub response: HttpResponseProof,
    pub attachments: Vec<ProofAttachment>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceBundleManifest {
    pub version: u32,
    pub bundle_id: String,
    pub sealed_at_unix_seconds: u64,
    pub algorithm: String,
    pub files: Vec<EvidenceFileDigest>,
    pub bundle_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceBundleSignature {
    pub version: u32,
    pub bundle_id: String,
    pub bundle_hash: String,
    pub signed_at_unix_seconds: u64,
    pub algorithm: String,
    pub signer: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceFileDigest {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceBundleVerification {
    pub bundle_id: String,
    pub valid: bool,
    pub expected_bundle_hash: String,
    pub actual_bundle_hash: String,
    pub files: Vec<EvidenceFileVerification>,
    pub signature: Option<EvidenceSignatureVerification>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRunVerification {
    pub run_dir: String,
    pub valid: bool,
    pub total_bundles: usize,
    pub valid_bundles: usize,
    pub invalid_bundles: usize,
    pub unsigned_bundles: usize,
    pub untrusted_bundles: usize,
    pub bundles: Vec<EvidenceBundleVerificationSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceBundleVerificationSummary {
    pub manifest: String,
    pub bundle_id: String,
    pub valid: bool,
    pub signature_present: bool,
    pub signature_valid: bool,
    pub signature_trusted: Option<bool>,
    pub failure_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceFileVerification {
    pub path: String,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub expected_size_bytes: u64,
    pub actual_size_bytes: Option<u64>,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSignatureVerification {
    pub signer: String,
    pub public_key: String,
    pub signature_present: bool,
    pub valid: bool,
    pub trusted: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReproductionCommand {
    pub tool: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpRequestProof {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpResponseProof {
    pub status: u16,
    pub evidence_markers: Vec<String>,
    pub body_excerpt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofAttachment {
    pub kind: ProofAttachmentKind,
    pub path: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofAttachmentKind {
    Screenshot,
    Video,
    OobCallbackLog,
    TimingChart,
    ToolOutput,
}

impl ProofPackage {
    pub fn has_reproducible_evidence(&self) -> bool {
        !self.reproduction.command.trim().is_empty()
            && self.response.status > 0
            && (!self.response.evidence_markers.is_empty() || !self.attachments.is_empty())
    }
}
