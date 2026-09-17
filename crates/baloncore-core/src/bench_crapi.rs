//! P2.S3 external corpus — real benchmark scorer for the `OWASP/crAPI` target.
//!
//! crAPI is a multi-service Docker Compose app. The `bench-crapi` runner brings
//! the stack up, drives each ground-truth probe through the real `BolaValidator`
//! (owner / attacker / anonymous exchanges against the live API), records one
//! `validations[]` entry per probe, and tears the whole stack down. This scorer
//! consumes that matrix and emits a `BenchmarkRun`.
//!
//! A probe matches an observation on `(endpoint, attacker_profile, object_id)`.
//! The scorer NEVER uses `expected_label` to manufacture a prediction — it
//! reflects what the validator concluded and compares it to the hand label. A
//! probe with no matching observation scores `FalseNegative`, never a silent
//! pass.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::bench_saas::classify_prediction_from_label;
use crate::evaluation::{
    BenchmarkCase, BenchmarkConfig, BenchmarkDifficulty, BenchmarkDomain, BenchmarkResult,
    BenchmarkRun, BenchmarkSuite, GroundTruthLabel,
};

/// One probe in the hand-labelled crAPI ground-truth file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrapiProbe {
    pub id: String,
    pub class: String,
    pub endpoint: String,
    pub object_id: String,
    pub owner_profile: String,
    pub attacker_profile: String,
    pub expected_label: String,
    #[serde(default)]
    pub owner_markers: Vec<String>,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub expected_evidence_substrings: Vec<String>,
}

/// The full crAPI ground-truth document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrapiGroundTruth {
    pub case_id: String,
    pub description: String,
    pub ground_truth_version: u32,
    pub source: String,
    #[serde(default)]
    pub source_commit: String,
    #[serde(default)]
    pub image_version: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub vulnerabilities: Vec<CrapiProbe>,
    #[serde(default)]
    pub decoys: Vec<CrapiProbe>,
}

impl CrapiGroundTruth {
    pub fn all_probes(&self) -> Vec<&CrapiProbe> {
        self.vulnerabilities
            .iter()
            .chain(self.decoys.iter())
            .collect()
    }

    pub fn is_decoy(&self, id: &str) -> bool {
        self.decoys.iter().any(|d| d.id == id)
    }

    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("read {}: {e}", path.as_ref().display()))?;
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.as_ref().display()))
    }
}

/// Build the `BenchmarkSuite` that pairs 1:1 with a `CrapiGroundTruth`.
pub fn crapi_bola_suite(gt: &CrapiGroundTruth) -> BenchmarkSuite {
    let mut cases = Vec::new();
    for probe in gt.all_probes() {
        let ground_truth = label_from_str(&probe.expected_label);
        let mut tags = vec!["crapi".to_string(), probe.class.to_lowercase()];
        if gt.is_decoy(&probe.id) {
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
        suite_id: "baloncore-crapi-bola-v1".to_string(),
        name: "OWASP crAPI BOLA (vehicle location)".to_string(),
        version: "1.0.0".to_string(),
        domain: BenchmarkDomain::WebApi,
        description:
            "Hand-labelled ground truth for OWASP/crAPI: one planted BOLA (read another user's vehicle location by GUID) plus an owner-scoped-404 decoy and a public-JWKS decoy."
                .to_string(),
        cases,
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("source".to_string(), gt.source.clone());
            m.insert("source_commit".to_string(), gt.source_commit.clone());
            m.insert("image_version".to_string(), gt.image_version.clone());
            m.insert("license".to_string(), gt.license.clone());
            m
        },
    }
}

fn label_from_str(s: &str) -> GroundTruthLabel {
    match s {
        "TruePositive" => GroundTruthLabel::TruePositive,
        "TrueNegative" => GroundTruthLabel::TrueNegative,
        "FalsePositive" => GroundTruthLabel::FalsePositive,
        "FalseNegative" => GroundTruthLabel::FalseNegative,
        _ => GroundTruthLabel::Inconclusive,
    }
}

#[derive(Debug, Clone)]
struct CrapiObservation {
    endpoint: String,
    attacker_profile: String,
    object_id: String,
    classification: String,
    evidence_substring_corpus: String,
}

/// Pull every probe observation from a crAPI matrix_summary.json. Each
/// `validations[]` entry must carry `endpoint`, `profile` (attacker), and
/// `object_id`. The `classification` is the runner's mapping of the
/// `BolaValidator` decision to a label string
/// ("BrokenObjectLevelAuthorization" for Verified, "BlockedAsExpected" for
/// Rejected); an entry missing any key is dropped.
fn extract_observations(matrix: &serde_json::Value) -> Vec<CrapiObservation> {
    let entries = match matrix.get("validations").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return Vec::new(),
    };
    entries
        .iter()
        .filter_map(|entry| {
            let endpoint = entry.get("endpoint")?.as_str()?.to_string();
            let attacker_profile = entry.get("profile")?.as_str()?.to_string();
            let object_id = entry.get("object_id")?.as_str()?.to_string();
            let classification = entry
                .get("classification")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            let evidence_substring_corpus = entry
                .pointer("/decision/Verified/evidence_markers")
                .and_then(|v| serde_json::to_string(v).ok())
                .unwrap_or_default();
            Some(CrapiObservation {
                endpoint,
                attacker_profile,
                object_id,
                classification,
                evidence_substring_corpus,
            })
        })
        .collect()
}

/// Build a `BenchmarkRun` from a crAPI matrix_summary.json and the hand-labelled
/// ground truth. Pure and deterministic; does not start the stack, scan, or
/// touch the network.
pub fn score_crapi_matrix_summary(
    matrix: &serde_json::Value,
    gt: &CrapiGroundTruth,
    suite: &BenchmarkSuite,
) -> BenchmarkRun {
    let observations = extract_observations(matrix);
    let mut results = Vec::new();
    for probe in gt.all_probes() {
        let matched = observations.iter().find(|obs| {
            obs.endpoint == probe.endpoint
                && obs.attacker_profile == probe.attacker_profile
                && obs.object_id == probe.object_id
        });
        let expected = label_from_str(&probe.expected_label);
        let prediction =
            classify_prediction_from_label(matched.map(|m| m.classification.as_str()), expected);
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
            actual_state: Some(
                if matched.is_some() {
                    "scanned"
                } else {
                    "missing"
                }
                .to_string(),
            ),
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
        run_id: format!("bench-crapi-{}", now),
        suite_id: suite.suite_id.clone(),
        suite_version: suite.version.clone(),
        domain: suite.domain.clone(),
        started_at: now,
        completed_at: now,
        config_snapshot: BenchmarkConfig {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            validator_config: "bench-crapi+BolaValidator".to_string(),
            noise_mode: "moderate".to_string(),
            max_active_requests: 500,
            domain_filter: None,
            difficulty_filter: None,
            tag_filter: None,
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("source".to_string(), gt.source.clone());
                m.insert("source_commit".to_string(), gt.source_commit.clone());
                m.insert("image_version".to_string(), gt.image_version.clone());
                m.insert("license".to_string(), gt.license.clone());
                m.insert("benchmark_path".to_string(), "real-scan".to_string());
                m
            },
            provider: "fixture".to_string(),
            model: "n/a (deterministic validator)".to_string(),
            prompt_version: "n/a".to_string(),
            git_commit: env!("CARGO_PKG_VERSION").to_string(),
            corpus_hash: format!("crapi-bola-v{}", gt.ground_truth_version),
        },
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VEHICLE_EP: &str = "GET /identity/api/v2/vehicle/{object_id}/location";
    const VIDEO_EP: &str = "GET /identity/api/v2/user/videos/{object_id}";
    const JWKS_EP: &str = "GET /identity/api/auth/jwks.json";

    fn gt_fixture() -> CrapiGroundTruth {
        CrapiGroundTruth {
            case_id: "crapi-bola-vehicle".to_string(),
            description: "fixture".to_string(),
            ground_truth_version: 1,
            source: "https://github.com/OWASP/crAPI".to_string(),
            source_commit: "d1cbf263".to_string(),
            image_version: "1.1.6-rc8".to_string(),
            license: "Apache-2.0".to_string(),
            vulnerabilities: vec![CrapiProbe {
                id: "vuln-bola-vehicle-location".to_string(),
                class: "BrokenObjectLevelAuthorization".to_string(),
                endpoint: VEHICLE_EP.to_string(),
                object_id: "f89b5f21-7829-45cb-a650-299a61090378".to_string(),
                owner_profile: "adam007@example.com".to_string(),
                attacker_profile: "pogba006@example.com".to_string(),
                owner_markers: vec!["32.778889".to_string()],
                expected_label: "TruePositive".to_string(),
                rationale: "vehicle location BOLA".to_string(),
                expected_evidence_substrings: vec!["32.778889".to_string()],
            }],
            decoys: vec![
                CrapiProbe {
                    id: "decoy-user-video-owner-scoped".to_string(),
                    class: "BlockedAsExpected".to_string(),
                    endpoint: VIDEO_EP.to_string(),
                    object_id: "1".to_string(),
                    owner_profile: "adam007@example.com".to_string(),
                    attacker_profile: "pogba006@example.com".to_string(),
                    owner_markers: vec!["Adam_video".to_string()],
                    expected_label: "TrueNegative".to_string(),
                    rationale: "owner-scoped 404".to_string(),
                    expected_evidence_substrings: vec![],
                },
                CrapiProbe {
                    id: "decoy-public-jwks".to_string(),
                    class: "BlockedAsExpected".to_string(),
                    endpoint: JWKS_EP.to_string(),
                    object_id: "jwks".to_string(),
                    owner_profile: "adam007@example.com".to_string(),
                    attacker_profile: "pogba006@example.com".to_string(),
                    owner_markers: vec!["RSA".to_string()],
                    expected_label: "TrueNegative".to_string(),
                    rationale: "public jwks".to_string(),
                    expected_evidence_substrings: vec![],
                },
            ],
        }
    }

    /// Build a matrix from `(endpoint, object_id, profile, classification)`.
    fn matrix(entries: &[(&str, &str, &str, &str)]) -> serde_json::Value {
        let validations: Vec<_> = entries
            .iter()
            .map(|(ep, obj, profile, class)| {
                json!({
                    "endpoint": ep,
                    "object_id": obj,
                    "profile": profile,
                    "classification": class,
                    "decision": { "Verified": { "evidence_markers": ["32.778889"] } }
                })
            })
            .collect();
        json!({ "validations": validations })
    }

    fn result<'a>(run: &'a BenchmarkRun, id: &str) -> &'a BenchmarkResult {
        run.results
            .iter()
            .find(|r| r.case_id == id)
            .unwrap_or_else(|| panic!("missing result {id}"))
    }

    fn pogba() -> &'static str {
        "pogba006@example.com"
    }

    #[test]
    fn happy_path_vuln_tp_two_decoys_tn() {
        let gt = gt_fixture();
        let suite = crapi_bola_suite(&gt);
        let m = matrix(&[
            (
                VEHICLE_EP,
                "f89b5f21-7829-45cb-a650-299a61090378",
                pogba(),
                "BrokenObjectLevelAuthorization",
            ),
            (VIDEO_EP, "1", pogba(), "BlockedAsExpected"),
            (JWKS_EP, "jwks", pogba(), "BlockedAsExpected"),
        ]);
        let run = score_crapi_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "vuln-bola-vehicle-location").prediction,
            GroundTruthLabel::TruePositive
        );
        assert_eq!(
            result(&run, "vuln-bola-vehicle-location").evidence_found,
            vec!["32.778889".to_string()]
        );
        assert_eq!(
            result(&run, "decoy-user-video-owner-scoped").prediction,
            GroundTruthLabel::TrueNegative
        );
        assert_eq!(
            result(&run, "decoy-public-jwks").prediction,
            GroundTruthLabel::TrueNegative
        );
    }

    #[test]
    fn false_negative_when_bola_missed() {
        let gt = gt_fixture();
        let suite = crapi_bola_suite(&gt);
        let m = matrix(&[
            (
                VEHICLE_EP,
                "f89b5f21-7829-45cb-a650-299a61090378",
                pogba(),
                "BlockedAsExpected",
            ),
            (VIDEO_EP, "1", pogba(), "BlockedAsExpected"),
            (JWKS_EP, "jwks", pogba(), "BlockedAsExpected"),
        ]);
        let run = score_crapi_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "vuln-bola-vehicle-location").prediction,
            GroundTruthLabel::FalseNegative
        );
    }

    #[test]
    fn owner_scoped_decoy_flagged_is_false_positive() {
        let gt = gt_fixture();
        let suite = crapi_bola_suite(&gt);
        let m = matrix(&[
            (
                VEHICLE_EP,
                "f89b5f21-7829-45cb-a650-299a61090378",
                pogba(),
                "BrokenObjectLevelAuthorization",
            ),
            (VIDEO_EP, "1", pogba(), "BrokenObjectLevelAuthorization"), // FP
            (JWKS_EP, "jwks", pogba(), "BlockedAsExpected"),
        ]);
        let run = score_crapi_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "decoy-user-video-owner-scoped").prediction,
            GroundTruthLabel::FalsePositive
        );
    }

    #[test]
    fn public_jwks_decoy_flagged_is_false_positive() {
        let gt = gt_fixture();
        let suite = crapi_bola_suite(&gt);
        let m = matrix(&[
            (
                VEHICLE_EP,
                "f89b5f21-7829-45cb-a650-299a61090378",
                pogba(),
                "BrokenObjectLevelAuthorization",
            ),
            (VIDEO_EP, "1", pogba(), "BlockedAsExpected"),
            (JWKS_EP, "jwks", pogba(), "BrokenObjectLevelAuthorization"), // FP
        ]);
        let run = score_crapi_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "decoy-public-jwks").prediction,
            GroundTruthLabel::FalsePositive
        );
    }

    #[test]
    fn match_key_includes_endpoint_and_object() {
        // Only the VULN observation is present. The decoys share the attacker
        // profile but differ in endpoint/object, so they must NOT match the
        // vuln observation — they score FalseNegative (no verdict), not
        // TrueNegative-by-accident.
        let gt = gt_fixture();
        let suite = crapi_bola_suite(&gt);
        let m = matrix(&[(
            VEHICLE_EP,
            "f89b5f21-7829-45cb-a650-299a61090378",
            pogba(),
            "BrokenObjectLevelAuthorization",
        )]);
        let run = score_crapi_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "vuln-bola-vehicle-location").prediction,
            GroundTruthLabel::TruePositive
        );
        let video = result(&run, "decoy-user-video-owner-scoped");
        assert_eq!(video.prediction, GroundTruthLabel::FalseNegative);
        assert!(video.error.is_some());
    }

    #[test]
    fn missing_observation_is_false_negative_not_silent_pass() {
        let gt = gt_fixture();
        let suite = crapi_bola_suite(&gt);
        let m = json!({ "validations": [] });
        let run = score_crapi_matrix_summary(&m, &gt, &suite);
        for r in &run.results {
            assert_eq!(r.prediction, GroundTruthLabel::FalseNegative);
            assert!(r.error.is_some());
        }
    }

    #[test]
    fn score_function_never_uses_expected_label_to_manufacture_prediction() {
        let gt = gt_fixture();
        let suite = crapi_bola_suite(&gt);
        let m = matrix(&[
            (
                VEHICLE_EP,
                "f89b5f21-7829-45cb-a650-299a61090378",
                pogba(),
                "BlockedAsExpected",
            ),
            (VIDEO_EP, "1", pogba(), "BlockedAsExpected"),
            (JWKS_EP, "jwks", pogba(), "BlockedAsExpected"),
        ]);
        let run = score_crapi_matrix_summary(&m, &gt, &suite);
        assert_ne!(
            result(&run, "vuln-bola-vehicle-location").prediction,
            GroundTruthLabel::TruePositive
        );
    }

    #[test]
    fn ci_gate_fails_when_a_decoy_is_flagged() {
        let gt = gt_fixture();
        let suite = crapi_bola_suite(&gt);
        let m = matrix(&[
            (
                VEHICLE_EP,
                "f89b5f21-7829-45cb-a650-299a61090378",
                pogba(),
                "BrokenObjectLevelAuthorization",
            ),
            (VIDEO_EP, "1", pogba(), "BlockedAsExpected"),
            (JWKS_EP, "jwks", pogba(), "BrokenObjectLevelAuthorization"), // decoy hit
        ]);
        let run = score_crapi_matrix_summary(&m, &gt, &suite);
        let gate = crate::evaluation::eval_gate(&run, &suite, 0.0, 0, 1.0, None, None);
        assert!(
            !gate.passed,
            "gate must fail on a decoy hit; {}",
            gate.summary
        );
        assert!(gate.summary.to_lowercase().contains("decoy"));
    }

    #[test]
    fn ci_gate_passes_on_clean_run() {
        let gt = gt_fixture();
        let suite = crapi_bola_suite(&gt);
        let m = matrix(&[
            (
                VEHICLE_EP,
                "f89b5f21-7829-45cb-a650-299a61090378",
                pogba(),
                "BrokenObjectLevelAuthorization",
            ),
            (VIDEO_EP, "1", pogba(), "BlockedAsExpected"),
            (JWKS_EP, "jwks", pogba(), "BlockedAsExpected"),
        ]);
        let run = score_crapi_matrix_summary(&m, &gt, &suite);
        let gate = crate::evaluation::eval_gate(&run, &suite, 0.70, 0, 0.10, None, None);
        assert!(gate.passed, "clean run must pass; {}", gate.summary);
    }
}
