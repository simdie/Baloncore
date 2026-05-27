//! T1.b — real benchmark scorer for the in-tree `labs/vulnerable-saas` target.
//!
//! Consumes a `matrix_summary.json` produced by `scan-openapi-bola` against
//! the lab and emits a `BenchmarkRun` whose `prediction` field reflects what
//! the deterministic classifier said about each ground-truth probe.
//!
//! There is no synthetic-fallback path: if the matrix_summary has no entry
//! that matches a ground-truth probe by `(endpoint, attacker_profile,
//! object_id)`, the probe is scored as `FalseNegative` (the scan FAILED to
//! produce evidence about it). The scorer NEVER fabricates a `TruePositive`
//! from `expected_label`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::evaluation::{
    BenchmarkCase, BenchmarkConfig, BenchmarkDifficulty, BenchmarkDomain, BenchmarkResult,
    BenchmarkRun, BenchmarkSuite, GroundTruthLabel,
};

/// One probe in the hand-labelled ground-truth file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaasProbe {
    pub id: String,
    pub class: String,
    pub endpoint: String,
    pub object_id: String,
    pub owner_profile: String,
    pub attacker_profile: String,
    pub expected_label: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub expected_evidence_substrings: Vec<String>,
}

/// The full ground-truth document for the SaaS lab.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaasGroundTruth {
    pub case_id: String,
    pub description: String,
    pub ground_truth_version: u32,
    pub lab_source: String,
    #[serde(default)]
    pub vulnerabilities: Vec<SaasProbe>,
    #[serde(default)]
    pub decoys: Vec<SaasProbe>,
}

impl SaasGroundTruth {
    /// All probes, vulns + decoys, in declaration order.
    pub fn all_probes(&self) -> Vec<&SaasProbe> {
        self.vulnerabilities.iter().chain(self.decoys.iter()).collect()
    }

    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("read {}: {e}", path.as_ref().display()))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("parse {}: {e}", path.as_ref().display()))
    }
}

/// Build the BenchmarkSuite that pairs 1:1 with a `SaasGroundTruth`. The
/// suite's `case_id`s match probe `id`s exactly.
pub fn saas_cross_tenant_suite(gt: &SaasGroundTruth) -> BenchmarkSuite {
    let mut cases = Vec::new();
    for probe in gt.all_probes() {
        let ground_truth = match probe.expected_label.as_str() {
            "TruePositive" => GroundTruthLabel::TruePositive,
            "TrueNegative" => GroundTruthLabel::TrueNegative,
            "FalsePositive" => GroundTruthLabel::FalsePositive,
            "FalseNegative" => GroundTruthLabel::FalseNegative,
            _ => GroundTruthLabel::Inconclusive,
        };
        let mut tags = vec!["saas".to_string(), probe.class.to_lowercase()];
        if gt.decoys.iter().any(|d| d.id == probe.id) {
            tags.push("decoy".to_string());
        }
        cases.push(BenchmarkCase {
            case_id: probe.id.clone(),
            domain: BenchmarkDomain::WebApi,
            name: probe.id.clone(),
            description: probe.rationale.clone(),
            target: probe.endpoint.clone(),
            ground_truth,
            expected_classification: Some(probe.class.clone()),
            expected_severity: None,
            expected_evidence_keys: probe.expected_evidence_substrings.clone(),
            difficulty: BenchmarkDifficulty::Moderate,
            tags,
            fixture_path: None,
            metadata: BTreeMap::new(),
        });
    }
    BenchmarkSuite {
        suite_id: "baloncore-saas-cross-tenant-v1".to_string(),
        name: "Vulnerable SaaS cross-tenant lab".to_string(),
        version: "1.0.0".to_string(),
        domain: BenchmarkDomain::WebApi,
        description:
            "Hand-labelled ground truth for labs/vulnerable-saas: one planted cross-tenant BOLA + one decoy."
                .to_string(),
        cases,
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("source".to_string(), gt.lab_source.clone());
            m
        },
    }
}

/// Pull every `(endpoint, attacker_profile, object_id, classification_label)`
/// from a matrix_summary.json document. The classification label is the
/// stringified `AuthorizationClass` (e.g. "BrokenObjectLevelAuthorization",
/// "TenantIsolationViolation", "BlockedAsExpected", "IntendedOwnerAccess").
fn extract_observations(matrix: &serde_json::Value) -> Vec<MatrixObservation> {
    let entries = match matrix.get("validations").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return Vec::new(),
    };
    entries
        .iter()
        .filter_map(|entry| {
            let endpoint = entry.get("endpoint")?.as_str()?.to_string();
            let profile = entry.get("profile")?.as_str()?.to_string();
            let object_id = entry
                .get("object_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // The `classification` field is serialized as an enum variant name.
            let classification = entry
                .get("classification")
                .and_then(|v| {
                    if let Some(s) = v.as_str() {
                        Some(s.to_string())
                    } else if let Some(obj) = v.as_object() {
                        obj.keys().next().cloned()
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "Unknown".to_string());
            let body_excerpt = entry
                .pointer("/decision/Verified/evidence_markers")
                .and_then(|v| serde_json::to_string(v).ok())
                .unwrap_or_default();
            Some(MatrixObservation {
                endpoint,
                attacker_profile: profile,
                object_id,
                classification,
                evidence_substring_corpus: body_excerpt,
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
struct MatrixObservation {
    endpoint: String,
    attacker_profile: String,
    object_id: String,
    classification: String,
    /// Concatenated text that can be substring-searched against
    /// `expected_evidence_substrings`. Currently the serialized
    /// `decision.Verified.evidence_markers` array if the validator verified
    /// the case; otherwise empty.
    evidence_substring_corpus: String,
}

/// Map a classification label + ground-truth expected_label to a per-case
/// prediction.
///
/// Rules (intentionally strict):
/// - The ground-truth label is what the scorer is checking the system AGAINST.
///   It is NEVER used to manufacture a prediction.
/// - If no matrix entry exists for the probe, the prediction is `FalseNegative`
///   (we wanted a verdict and didn't get one).
/// - "Finding" classifications: `BrokenObjectLevelAuthorization`,
///   `BrokenFunctionLevelAuthorization`, `MissingAuthentication`,
///   `TenantIsolationViolation`. Anything else means "no finding".
fn classify_prediction(
    matched: Option<&MatrixObservation>,
    expected: GroundTruthLabel,
) -> GroundTruthLabel {
    let matched = match matched {
        Some(m) => m,
        None => return GroundTruthLabel::FalseNegative,
    };
    let is_finding = matches!(
        matched.classification.as_str(),
        "BrokenObjectLevelAuthorization"
            | "BrokenFunctionLevelAuthorization"
            | "MissingAuthentication"
            | "TenantIsolationViolation"
    );
    match (expected, is_finding) {
        (GroundTruthLabel::TruePositive, true) => GroundTruthLabel::TruePositive,
        (GroundTruthLabel::TruePositive, false) => GroundTruthLabel::FalseNegative,
        (GroundTruthLabel::TrueNegative, true) => GroundTruthLabel::FalsePositive,
        (GroundTruthLabel::TrueNegative, false) => GroundTruthLabel::TrueNegative,
        (GroundTruthLabel::FalsePositive, true) => GroundTruthLabel::FalsePositive,
        (GroundTruthLabel::FalsePositive, false) => GroundTruthLabel::TrueNegative,
        (GroundTruthLabel::FalseNegative, true) => GroundTruthLabel::TruePositive,
        (GroundTruthLabel::FalseNegative, false) => GroundTruthLabel::FalseNegative,
        (GroundTruthLabel::Inconclusive, _) => GroundTruthLabel::Inconclusive,
    }
}

fn endpoints_equivalent(a: &str, b: &str) -> bool {
    let normalize = |s: &str| {
        s.trim()
            .trim_start_matches("GET ")
            .trim_start_matches("get ")
            .replace("{orgId}", "{}")
            .replace("{projectId}", "{}")
            .replace("{id}", "{}")
            .to_ascii_lowercase()
    };
    normalize(a) == normalize(b)
}

/// Build a `BenchmarkRun` from a matrix_summary.json document and a
/// hand-labelled SaaS ground-truth. Each probe in the ground-truth produces
/// exactly one `BenchmarkResult` whose `prediction` reflects the matrix
/// classification. The function is pure and deterministic; it does not start
/// the lab, run a scan, or touch the network.
pub fn score_saas_matrix_summary(
    matrix: &serde_json::Value,
    gt: &SaasGroundTruth,
    suite: &BenchmarkSuite,
) -> BenchmarkRun {
    let observations = extract_observations(matrix);
    let mut results = Vec::new();
    for probe in gt.all_probes() {
        let matched = observations.iter().find(|obs| {
            obs.attacker_profile == probe.attacker_profile
                && obs.object_id == probe.object_id
                && endpoints_equivalent(&obs.endpoint, &probe.endpoint)
        });
        let expected = match probe.expected_label.as_str() {
            "TruePositive" => GroundTruthLabel::TruePositive,
            "TrueNegative" => GroundTruthLabel::TrueNegative,
            "FalsePositive" => GroundTruthLabel::FalsePositive,
            "FalseNegative" => GroundTruthLabel::FalseNegative,
            _ => GroundTruthLabel::Inconclusive,
        };
        let prediction = classify_prediction(matched, expected);
        let mut evidence_found = Vec::new();
        if let Some(m) = matched {
            for needle in &probe.expected_evidence_substrings {
                if m.evidence_substring_corpus.contains(needle.as_str()) {
                    evidence_found.push(needle.clone());
                }
            }
        }
        let confidence = if matches!(
            prediction,
            GroundTruthLabel::TruePositive | GroundTruthLabel::TrueNegative
        ) {
            1.0
        } else {
            0.0
        };
        results.push(BenchmarkResult {
            result_id: format!("result_{}", probe.id),
            suite_id: suite.suite_id.clone(),
            case_id: probe.id.clone(),
            domain: BenchmarkDomain::WebApi,
            actual_classification: matched.map(|m| m.classification.clone()),
            actual_severity: None,
            actual_state: Some(if matched.is_some() { "scanned" } else { "missing" }.to_string()),
            prediction,
            confidence,
            evidence_found,
            time_to_result_ms: 0,
            error: matched.is_none().then(|| {
                format!(
                    "no matrix_summary entry matched (endpoint={}, profile={}, object_id={})",
                    probe.endpoint, probe.attacker_profile, probe.object_id
                )
            }),
        });
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    BenchmarkRun {
        run_id: format!("bench-saas-{}", now),
        suite_id: suite.suite_id.clone(),
        suite_version: suite.version.clone(),
        domain: suite.domain.clone(),
        started_at: now,
        completed_at: now,
        config_snapshot: BenchmarkConfig {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            validator_config: "scan-openapi-bola+BolaValidator".to_string(),
            noise_mode: "moderate".to_string(),
            max_active_requests: 500,
            domain_filter: None,
            difficulty_filter: None,
            tag_filter: None,
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("source".to_string(), gt.lab_source.clone());
                m.insert("benchmark_path".to_string(), "real-scan".to_string());
                m
            },
            provider: "fixture".to_string(),
            model: "n/a (deterministic validator)".to_string(),
            prompt_version: "n/a".to_string(),
            git_commit: env!("CARGO_PKG_VERSION").to_string(),
            corpus_hash: format!("saas-cross-tenant-v{}", gt.ground_truth_version),
        },
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gt_fixture() -> SaasGroundTruth {
        SaasGroundTruth {
            case_id: "saas-cross-tenant-bola".to_string(),
            description: "fixture".to_string(),
            ground_truth_version: 1,
            lab_source: "labs/vulnerable-saas/server.js".to_string(),
            vulnerabilities: vec![SaasProbe {
                id: "vuln-cross-tenant-bola-proj-b-001".to_string(),
                class: "TenantIsolationViolation".to_string(),
                endpoint: "GET /api/orgs/{orgId}/projects/{projectId}".to_string(),
                object_id: "proj-b-001".to_string(),
                owner_profile: "org_b_member".to_string(),
                attacker_profile: "org_a_member".to_string(),
                expected_label: "TruePositive".to_string(),
                rationale: "planted cross-tenant BOLA".to_string(),
                expected_evidence_substrings: vec!["proj-b-001".to_string()],
            }],
            decoys: vec![SaasProbe {
                id: "decoy-proj-b-secret".to_string(),
                class: "BlockedAsExpected".to_string(),
                endpoint: "GET /api/orgs/{orgId}/projects/{projectId}".to_string(),
                object_id: "proj-b-secret".to_string(),
                owner_profile: "org_b_member".to_string(),
                attacker_profile: "org_a_member".to_string(),
                expected_label: "TrueNegative".to_string(),
                rationale: "correctly 403'd".to_string(),
                expected_evidence_substrings: vec![],
            }],
        }
    }

    fn matrix(planted_class: &str, decoy_class: &str) -> serde_json::Value {
        json!({
            "validations": [
                {
                    "candidate": 1,
                    "seed": 1,
                    "profile": "org_a_member",
                    "role": "member",
                    "endpoint": "GET /api/orgs/{orgId}/projects/{projectId}",
                    "object_id": "proj-b-001",
                    "classification": planted_class,
                    "decision": { "Verified": { "evidence_markers": ["proj-b-001"] } }
                },
                {
                    "candidate": 2,
                    "seed": 1,
                    "profile": "org_a_member",
                    "role": "member",
                    "endpoint": "GET /api/orgs/{orgId}/projects/{projectId}",
                    "object_id": "proj-b-secret",
                    "classification": decoy_class
                }
            ]
        })
    }

    #[test]
    fn happy_path_planted_tp_decoy_tn() {
        let gt = gt_fixture();
        let suite = saas_cross_tenant_suite(&gt);
        let m = matrix("TenantIsolationViolation", "BlockedAsExpected");
        let run = score_saas_matrix_summary(&m, &gt, &suite);
        assert_eq!(run.results.len(), 2);
        let planted = &run.results[0];
        let decoy = &run.results[1];
        assert_eq!(planted.prediction, GroundTruthLabel::TruePositive);
        assert_eq!(planted.evidence_found, vec!["proj-b-001".to_string()]);
        assert_eq!(decoy.prediction, GroundTruthLabel::TrueNegative);
    }

    #[test]
    fn false_negative_when_planted_bug_missed() {
        let gt = gt_fixture();
        let suite = saas_cross_tenant_suite(&gt);
        let m = matrix("BlockedAsExpected", "BlockedAsExpected");
        let run = score_saas_matrix_summary(&m, &gt, &suite);
        assert_eq!(run.results[0].prediction, GroundTruthLabel::FalseNegative);
        assert_eq!(run.results[1].prediction, GroundTruthLabel::TrueNegative);
    }

    #[test]
    fn decoy_hit_is_false_positive() {
        // Mutation-style scenario: a broken validator that flags the decoy
        // as a BOLA must produce FalsePositive in the run.
        let gt = gt_fixture();
        let suite = saas_cross_tenant_suite(&gt);
        let m = matrix(
            "TenantIsolationViolation",
            "BrokenObjectLevelAuthorization",
        );
        let run = score_saas_matrix_summary(&m, &gt, &suite);
        assert_eq!(run.results[0].prediction, GroundTruthLabel::TruePositive);
        assert_eq!(
            run.results[1].prediction,
            GroundTruthLabel::FalsePositive,
            "the decoy must be scored as FP when a validator flags it"
        );
    }

    #[test]
    fn missing_observation_is_false_negative_not_silent_pass() {
        let gt = gt_fixture();
        let suite = saas_cross_tenant_suite(&gt);
        // Empty matrix: scan ran but found nothing.
        let m = json!({"validations": []});
        let run = score_saas_matrix_summary(&m, &gt, &suite);
        // Planted vuln missing => FN.
        assert_eq!(run.results[0].prediction, GroundTruthLabel::FalseNegative);
        assert!(run.results[0].error.is_some());
        // Decoy missing => still FN (we wanted a verdict on it; not getting one
        // is a scan failure, not a silent pass). This intentionally penalises
        // the scanner for skipping the decoy probe entirely.
        assert_eq!(run.results[1].prediction, GroundTruthLabel::FalseNegative);
    }

    #[test]
    fn ci_gate_fails_when_decoy_flagged_as_bola() {
        // T1.b mutation-style test: a deliberately-broken validator that flags
        // the decoy proj-b-secret as BOLA produces a BenchmarkRun where the
        // decoy probe's prediction is TruePositive. The CI eval gate's
        // max_decoy_fp=0 guard MUST fail this — and the failure must come
        // from the decoy guard specifically, not from a coincidental precision
        // drop. We isolate by setting min_precision = 0.0 so only the decoy
        // guard can flip the result.
        let gt = gt_fixture();
        let suite = saas_cross_tenant_suite(&gt);
        let m = matrix(
            "TenantIsolationViolation",          // planted: detected (good)
            "BrokenObjectLevelAuthorization",    // decoy: WRONGLY flagged
        );
        let run = score_saas_matrix_summary(&m, &gt, &suite);
        let gate = crate::evaluation::eval_gate(
            &run, &suite, /*min_precision*/ 0.0, /*max_decoy_fp*/ 0,
            /*max_recall_drop*/ 1.0, None, None,
        );
        assert!(
            !gate.passed,
            "ci gate (decoy guard only) must FAIL when a decoy is flagged; \
             passed={} summary={}",
            gate.passed, gate.summary
        );
        assert!(
            gate.summary.to_lowercase().contains("decoy"),
            "failure must cite the decoy guard, got: {}",
            gate.summary
        );
    }

    #[test]
    fn ci_gate_passes_when_planted_tp_decoy_tn() {
        // Counterpart: the same gate must PASS on a correctly-scored run.
        // Without this, the negative test above could pass trivially (gate
        // could refuse everything).
        let gt = gt_fixture();
        let suite = saas_cross_tenant_suite(&gt);
        let m = matrix("TenantIsolationViolation", "BlockedAsExpected");
        let run = score_saas_matrix_summary(&m, &gt, &suite);
        let gate = crate::evaluation::eval_gate(
            &run, &suite, 0.70, 0, 0.10, None, None,
        );
        assert!(
            gate.passed,
            "ci gate must PASS on a clean run; summary={}",
            gate.summary
        );
    }

    #[test]
    fn score_function_never_uses_expected_label_to_manufacture_prediction() {
        // Pin: even with a deeply mis-labelled matrix (every entry says
        // BlockedAsExpected), the scorer must NOT report the planted vuln as
        // TP just because the ground truth claims it should be.
        let gt = gt_fixture();
        let suite = saas_cross_tenant_suite(&gt);
        let m = matrix("BlockedAsExpected", "BlockedAsExpected");
        let run = score_saas_matrix_summary(&m, &gt, &suite);
        let planted = &run.results[0];
        assert_ne!(
            planted.prediction,
            GroundTruthLabel::TruePositive,
            "the scorer must reflect what the matrix said, not what the ground truth wants"
        );
    }
}
