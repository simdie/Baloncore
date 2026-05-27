use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::lifecycle::{FindingRecord, FindingState};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyConfig {
    #[serde(default)]
    pub fail_on_critical: bool,
    #[serde(default = "default_true")]
    pub fail_on_high: bool,
    #[serde(default)]
    pub fail_on_medium: bool,
    #[serde(default)]
    pub fail_on_low: bool,
    #[serde(default)]
    pub fail_on_unsigned_evidence: bool,
    #[serde(default)]
    pub fail_on_untrusted_signer: bool,
    #[serde(default)]
    pub fail_on_anonymous_exposure: bool,
    #[serde(default)]
    pub fail_on_regression_failure: bool,
    #[serde(default)]
    pub trusted_signers: Vec<String>,
    #[serde(default)]
    pub baseline_path: Option<String>,
    #[serde(default)]
    pub sarif_output: Option<String>,
    #[serde(default)]
    pub markdown_output: Option<String>,
    #[serde(default)]
    pub json_output: Option<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            fail_on_critical: true,
            fail_on_high: true,
            fail_on_medium: false,
            fail_on_low: false,
            fail_on_unsigned_evidence: true,
            fail_on_untrusted_signer: false,
            fail_on_anonymous_exposure: true,
            fail_on_regression_failure: true,
            trusted_signers: vec![],
            baseline_path: None,
            sarif_output: None,
            markdown_output: None,
            json_output: None,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CIGateResult {
    pub passed: bool,
    pub total_findings: usize,
    pub new_findings: usize,
    pub baseline_findings: usize,
    pub suppressed_findings: usize,
    pub blocking_findings: Vec<BlockingFinding>,
    pub exit_code: i32,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockingFinding {
    pub finding_id: String,
    pub classification: String,
    pub severity: String,
    pub endpoint: String,
    pub reason: String,
    pub state: String,
}

pub fn evaluate_ci_gate(
    findings: &[FindingRecord],
    baseline: &BaselineFile,
    policy: &PolicyConfig,
) -> CIGateResult {
    let mut blocking: Vec<BlockingFinding> = vec![];
    let baseline_ids: Vec<String> = baseline
        .findings
        .iter()
        .map(|b| b.finding_id.clone())
        .collect();

    for f in findings {
        if f.state != FindingState::Reported && f.state != FindingState::Verified {
            continue;
        }

        if baseline_ids.contains(&f.finding_id) {
            continue;
        }

        let is_suppressed = baseline.suppressions.iter().any(|s| {
            let classification_match = s
                .classification
                .as_ref()
                .map_or(true, |c| c == &f.classification);
            let endpoint_match = s.endpoint.as_ref().map_or(true, |e| f.endpoint.contains(e));
            let profile_match = s.profile.as_ref().map_or(true, |p| p == &f.tested_profile);
            let role_match = s.role.as_ref().map_or(true, |r| r == &f.owner_profile);
            classification_match && endpoint_match && profile_match && role_match
        });

        if is_suppressed {
            continue;
        }

        let should_block = match f.severity.to_lowercase().as_str() {
            "critical" => policy.fail_on_critical,
            "high" => policy.fail_on_high,
            "medium" => policy.fail_on_medium,
            "low" => policy.fail_on_low,
            "info" => false,
            _ => policy.fail_on_high,
        };

        if should_block {
            blocking.push(BlockingFinding {
                finding_id: f.finding_id.clone(),
                classification: f.classification.clone(),
                severity: f.severity.clone(),
                endpoint: f.endpoint.clone(),
                reason: format!(
                    "{} severity finding in {} state",
                    f.severity,
                    f.state.as_str()
                ),
                state: f.state.as_str().to_string(),
            });
        }
    }

    let passed = blocking.is_empty();
    let new_findings = findings
        .iter()
        .filter(|f| {
            (f.state == FindingState::Reported || f.state == FindingState::Verified)
                && !baseline_ids.contains(&f.finding_id)
        })
        .count();
    let suppressed = findings
        .iter()
        .filter(|f| {
            baseline.suppressions.iter().any(|s| {
                s.classification
                    .as_ref()
                    .map_or(true, |c| c == &f.classification)
                    && s.endpoint.as_ref().map_or(true, |e| f.endpoint.contains(e))
            })
        })
        .count();

    let summary = if passed {
        format!(
            "CI PASSED: {} total findings, {} new, {} suppressed, {} baseline. No blocking issues.",
            findings.len(),
            new_findings,
            suppressed,
            baseline.findings.len()
        )
    } else {
        format!(
            "CI FAILED: {} blocking findings out of {} total ({} new, {} suppressed, {} baseline).",
            blocking.len(),
            findings.len(),
            new_findings,
            suppressed,
            baseline.findings.len()
        )
    };

    CIGateResult {
        passed,
        total_findings: findings.len(),
        new_findings,
        baseline_findings: baseline.findings.len(),
        suppressed_findings: suppressed,
        blocking_findings: blocking,
        exit_code: if passed { 0 } else { 1 },
        summary,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineFile {
    pub version: u32,
    pub project: String,
    pub generated_at: u64,
    pub findings: Vec<BaselineFinding>,
    #[serde(default)]
    pub suppressions: Vec<crate::config::SuppressionRule>,
}

impl BaselineFile {
    pub fn new(project: &str) -> Self {
        Self {
            version: 1,
            project: project.to_string(),
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            findings: vec![],
            suppressions: vec![],
        }
    }

    pub fn from_findings(
        project: &str,
        findings: &[FindingRecord],
        suppressions: Vec<crate::config::SuppressionRule>,
    ) -> Self {
        Self {
            version: 1,
            project: project.to_string(),
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            findings: findings.iter().map(BaselineFinding::from).collect(),
            suppressions,
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("failed to read baseline: {e}"))?;
        serde_json::from_str(&raw).map_err(|e| format!("failed to parse baseline: {e}"))
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize baseline: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("failed to write baseline: {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineFinding {
    pub finding_id: String,
    pub classification: String,
    pub severity: String,
    pub endpoint: String,
    pub state: String,
}

impl From<&FindingRecord> for BaselineFinding {
    fn from(f: &FindingRecord) -> Self {
        Self {
            finding_id: f.finding_id.clone(),
            classification: f.classification.clone(),
            severity: f.severity.clone(),
            endpoint: f.endpoint.clone(),
            state: f.state.as_str().to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub added_endpoints: Vec<DiffEndpoint>,
    pub removed_endpoints: Vec<DiffEndpoint>,
    pub changed_endpoints: Vec<DiffEndpoint>,
    pub new_candidates: Vec<DiffEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEndpoint {
    pub method: String,
    pub path: String,
    pub source: String,
    pub change_type: String,
}

pub fn diff_openapi_specs(current: &serde_json::Value, previous: &serde_json::Value) -> DiffResult {
    let current_endpoints = extract_endpoints(current);
    let previous_endpoints = extract_endpoints(previous);

    let current_keys: std::collections::HashSet<String> =
        current_endpoints.keys().cloned().collect();
    let previous_keys: std::collections::HashSet<String> =
        previous_endpoints.keys().cloned().collect();

    let mut added = vec![];
    let mut removed = vec![];
    let mut changed = vec![];

    for key in &current_keys {
        if !previous_endpoints.contains_key(key) {
            if let Some(ep) = current_endpoints.get(key) {
                added.push(DiffEndpoint {
                    method: ep.method.clone(),
                    path: ep.path.clone(),
                    source: ep.source.clone(),
                    change_type: "added".to_string(),
                });
            }
        } else {
            let cur_ep = current_endpoints.get(key).unwrap();
            let prev_ep = previous_endpoints.get(key).unwrap();
            if cur_ep.schema != prev_ep.schema || cur_ep.requires_auth != prev_ep.requires_auth {
                changed.push(DiffEndpoint {
                    method: cur_ep.method.clone(),
                    path: cur_ep.path.clone(),
                    source: cur_ep.source.clone(),
                    change_type: "changed".to_string(),
                });
            }
        }
    }

    for key in &previous_keys {
        if !current_endpoints.contains_key(key) {
            if let Some(ep) = previous_endpoints.get(key) {
                removed.push(DiffEndpoint {
                    method: ep.method.clone(),
                    path: ep.path.clone(),
                    source: ep.source.clone(),
                    change_type: "removed".to_string(),
                });
            }
        }
    }

    let auth_relevant_methods = ["POST", "PUT", "PATCH", "DELETE"];
    let auth_relevant_paths = [
        "/api/",
        "/v1/",
        "/v2/",
        "/admin",
        "/user",
        "/account",
        "/auth",
        "/login",
        "/token",
        "/password",
        "/permission",
        "/role",
        "/grant",
    ];
    let new_candidates: Vec<DiffEndpoint> = added
        .iter()
        .chain(changed.iter())
        .filter(|ep| {
            auth_relevant_methods.contains(&ep.method.as_str())
                || auth_relevant_paths.iter().any(|p| ep.path.contains(p))
        })
        .cloned()
        .map(|mut ep| {
            ep.change_type = "candidate".to_string();
            ep
        })
        .collect();

    DiffResult {
        added_endpoints: added,
        removed_endpoints: removed,
        changed_endpoints: changed,
        new_candidates,
    }
}

struct EndpointKey {
    method: String,
    path: String,
    source: String,
    requires_auth: Option<bool>,
    schema: Option<String>,
}

fn extract_endpoints(spec: &serde_json::Value) -> std::collections::HashMap<String, EndpointKey> {
    let mut map = std::collections::HashMap::new();
    if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
        for (path, methods) in paths {
            if let Some(methods_obj) = methods.as_object() {
                for (method, operation) in methods_obj {
                    if method == "parameters" || method == "summary" || method == "description" {
                        continue;
                    }
                    let key = format!("{} {}", method.to_uppercase(), path);
                    let requires_auth = operation
                        .get("security")
                        .and_then(|s| {
                            if s.as_array().map_or(false, |a| a.is_empty()) {
                                Some(false)
                            } else {
                                Some(true)
                            }
                        })
                        .or_else(|| operation.get("security").is_some().then_some(true));
                    let schema = operation
                        .get("responses")
                        .and_then(|r| r.get("200"))
                        .and_then(|r| r.get("content"))
                        .and_then(|c| c.get("application/json"))
                        .and_then(|j| j.get("schema"))
                        .map(|s| s.to_string());
                    map.insert(
                        key,
                        EndpointKey {
                            method: method.to_uppercase(),
                            path: path.clone(),
                            source: "openapi".to_string(),
                            requires_auth,
                            schema,
                        },
                    );
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{FindingRecord, FindingState, FindingTransition};

    fn test_finding(
        id: &str,
        classification: &str,
        severity: &str,
        state: FindingState,
    ) -> FindingRecord {
        FindingRecord {
            finding_id: id.to_string(),
            scan_id: "test-scan".to_string(),
            fingerprint: format!("fp-{}", id),
            classification: classification.to_string(),
            vulnerability_class: classification.to_string(),
            endpoint: "GET /api/invoices/{id}".to_string(),
            object_id: "inv_123".to_string(),
            owner_profile: "user_b".to_string(),
            tested_profile: "user_a".to_string(),
            severity: severity.to_string(),
            score: 80,
            state: state.clone(),
            first_seen_run: "run-1".to_string(),
            last_seen_run: "run-1".to_string(),
            first_seen_at: 1000,
            last_seen_at: 1000,
            seen_count: 1,
            latest_artifacts: "artifacts".to_string(),
            latest_evidence_dir: ".baloncore/runs/test".to_string(),
            transitions: vec![FindingTransition {
                from_state: "Hypothesis".to_string(),
                to_state: state.as_str().to_string(),
                reason: "test".to_string(),
                at: 1000,
                actor: "test".to_string(),
            }],
            defense_classifications: vec![],
        }
    }

    #[test]
    fn ci_gate_passes_with_no_blocking_findings() {
        let findings = vec![test_finding("f1", "BOLA", "low", FindingState::Verified)];
        let baseline = BaselineFile::new("test");
        let policy = PolicyConfig::default();
        let result = evaluate_ci_gate(&findings, &baseline, &policy);
        assert!(result.passed);
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.blocking_findings.len(), 0);
    }

    #[test]
    fn ci_gate_fails_on_critical_verified_finding() {
        let findings = vec![test_finding(
            "f1",
            "BOLA",
            "critical",
            FindingState::Reported,
        )];
        let baseline = BaselineFile::new("test");
        let policy = PolicyConfig::default();
        let result = evaluate_ci_gate(&findings, &baseline, &policy);
        assert!(!result.passed);
        assert_eq!(result.exit_code, 1);
        assert_eq!(result.blocking_findings.len(), 1);
        assert_eq!(result.blocking_findings[0].severity, "critical");
    }

    #[test]
    fn ci_gate_passes_when_finding_in_baseline() {
        let findings = vec![test_finding(
            "f1",
            "BOLA",
            "critical",
            FindingState::Reported,
        )];
        let mut baseline = BaselineFile::new("test");
        baseline.findings.push(BaselineFinding {
            finding_id: "f1".to_string(),
            classification: "BOLA".to_string(),
            severity: "critical".to_string(),
            endpoint: "GET /api/invoices/{id}".to_string(),
            state: "reported".to_string(),
        });
        let policy = PolicyConfig::default();
        let result = evaluate_ci_gate(&findings, &baseline, &policy);
        assert!(result.passed);
        assert_eq!(result.new_findings, 0);
    }

    #[test]
    fn ci_gate_passes_with_suppressed_classification() {
        let findings = vec![test_finding(
            "f1",
            "BOLA",
            "critical",
            FindingState::Reported,
        )];
        let mut baseline = BaselineFile::new("test");
        baseline.suppressions.push(crate::config::SuppressionRule {
            id: "s1".to_string(),
            reason: "acceptable risk".to_string(),
            classification: Some("BOLA".to_string()),
            endpoint: None,
            profile: None,
            role: None,
            object_id: None,
            expires: None,
        });
        let policy = PolicyConfig::default();
        let result = evaluate_ci_gate(&findings, &baseline, &policy);
        assert!(result.passed);
        assert_eq!(result.suppressed_findings, 1);
    }

    #[test]
    fn ci_gate_ignores_rejected_findings() {
        let findings = vec![test_finding(
            "f1",
            "BOLA",
            "critical",
            FindingState::Rejected,
        )];
        let baseline = BaselineFile::new("test");
        let policy = PolicyConfig::default();
        let result = evaluate_ci_gate(&findings, &baseline, &policy);
        assert!(result.passed);
        assert_eq!(result.total_findings, 1);
    }

    #[test]
    fn baseline_file_roundtrip() {
        let mut baseline = BaselineFile::new("test-project");
        baseline.findings.push(BaselineFinding {
            finding_id: "f-123".to_string(),
            classification: "BOLA".to_string(),
            severity: "high".to_string(),
            endpoint: "/api/invoices/{id}".to_string(),
            state: "reported".to_string(),
        });
        let json = serde_json::to_string_pretty(&baseline).unwrap();
        let parsed: BaselineFile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].finding_id, "f-123");
    }

    #[test]
    fn diff_openapi_detects_new_endpoints() {
        let previous = serde_json::json!({
            "paths": { "/api/users": { "get": {} } }
        });
        let current = serde_json::json!({
            "paths": { "/api/users": { "get": {} }, "/api/admin": { "post": {} } }
        });
        let result = diff_openapi_specs(&current, &previous);
        assert_eq!(result.added_endpoints.len(), 1);
        assert_eq!(result.removed_endpoints.len(), 0);
        assert_eq!(result.added_endpoints[0].method, "POST");
    }

    #[test]
    fn diff_openapi_detects_removed_endpoints() {
        let previous = serde_json::json!({
            "paths": { "/api/users": { "get": {} }, "/api/admin": { "post": {} } }
        });
        let current = serde_json::json!({
            "paths": { "/api/users": { "get": {} } }
        });
        let result = diff_openapi_specs(&current, &previous);
        assert_eq!(result.added_endpoints.len(), 0);
        assert_eq!(result.removed_endpoints.len(), 1);
    }

    #[test]
    fn diff_openapi_detects_changed_endpoints() {
        let previous = serde_json::json!({
            "paths": { "/api/users": { "get": { "responses": { "200": { "content": { "application/json": { "schema": { "type": "object" } } } } } } } }
        });
        let current = serde_json::json!({
            "paths": { "/api/users": { "get": { "responses": { "200": { "content": { "application/json": { "schema": { "type": "array" } } } } } } } }
        });
        let result = diff_openapi_specs(&current, &previous);
        assert_eq!(result.changed_endpoints.len(), 1);
        assert_eq!(result.changed_endpoints[0].method, "GET");
        assert_eq!(result.changed_endpoints[0].change_type, "changed");
    }

    #[test]
    fn diff_openapi_detects_auth_candidates() {
        let previous = serde_json::json!({
            "paths": { "/api/users": { "get": {} } }
        });
        let current = serde_json::json!({
            "paths": {
                "/api/users": { "get": {} },
                "/api/admin": { "post": {} },
                "/api/auth/login": { "post": {} },
                "/health": { "get": {} }
            }
        });
        let result = diff_openapi_specs(&current, &previous);
        assert_eq!(result.added_endpoints.len(), 3);
        assert!(
            result.new_candidates.iter().any(|c| c.path == "/api/admin"),
            "admin endpoint should be a candidate"
        );
        assert!(
            result
                .new_candidates
                .iter()
                .any(|c| c.path == "/api/auth/login"),
            "auth endpoint should be a candidate"
        );
        assert!(
            !result.new_candidates.iter().any(|c| c.path == "/health"),
            "health endpoint should not be a candidate"
        );
    }

    #[test]
    fn policy_config_default_flags_critical_and_high() {
        let policy = PolicyConfig::default();
        assert!(policy.fail_on_critical);
        assert!(policy.fail_on_high);
        assert!(!policy.fail_on_medium);
        assert!(!policy.fail_on_low);
        assert!(policy.fail_on_unsigned_evidence);
        assert!(policy.fail_on_regression_failure);
    }
}
