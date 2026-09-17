//! P2.S3 external corpus — real benchmark scorer for the `dolevf/DVGA` target.
//!
//! DVGA exposes a JWT-identity authorization bypass on its GraphQL API. The
//! `bench-dvga` runner drives each ground-truth probe through the real
//! `GraphQlBolaValidator` and records one `validations[]` entry per probe,
//! tagged with the operation, object id, and the attacker profile. This scorer
//! consumes that matrix and emits a `BenchmarkRun`.
//!
//! A probe matches an observation on `(operation, object_id, attacker_profile)`.
//! As with the SaaS and VAmPI scorers, the scorer NEVER uses `expected_label` to
//! manufacture a prediction — it reflects what the validator concluded for each
//! probe and compares it to the hand label. A probe with no matching
//! observation scores `FalseNegative`, never a silent pass.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::bench_saas::classify_prediction_from_label;
use crate::evaluation::{
    BenchmarkCase, BenchmarkConfig, BenchmarkDifficulty, BenchmarkDomain, BenchmarkResult,
    BenchmarkRun, BenchmarkSuite, GroundTruthLabel,
};

/// One probe in the hand-labelled DVGA ground-truth file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DvgaProbe {
    pub id: String,
    pub class: String,
    /// GraphQL operation the runner drives: "me" (token-identity based) or
    /// "paste" (id-based public read).
    pub operation: String,
    /// The object under test: a username for `me`, a paste id for `paste`.
    pub object_id: String,
    pub owner_profile: String,
    pub attacker_profile: String,
    pub expected_label: String,
    // --- runner-only fields (ignored by the scorer) ---
    #[serde(default)]
    pub owner_identity: Option<String>,
    #[serde(default)]
    pub owner_login_password: Option<String>,
    #[serde(default)]
    pub attacker_forged_identity: Option<String>,
    #[serde(default)]
    pub owner_markers: Vec<String>,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub expected_evidence_substrings: Vec<String>,
}

/// The full DVGA ground-truth document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DvgaGroundTruth {
    pub case_id: String,
    pub description: String,
    pub ground_truth_version: u32,
    pub source: String,
    #[serde(default)]
    pub source_commit: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub vulnerabilities: Vec<DvgaProbe>,
    #[serde(default)]
    pub decoys: Vec<DvgaProbe>,
}

impl DvgaGroundTruth {
    pub fn all_probes(&self) -> Vec<&DvgaProbe> {
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

/// Build the `BenchmarkSuite` that pairs 1:1 with a `DvgaGroundTruth`.
pub fn dvga_graphql_bola_suite(gt: &DvgaGroundTruth) -> BenchmarkSuite {
    let mut cases = Vec::new();
    for probe in gt.all_probes() {
        let ground_truth = label_from_str(&probe.expected_label);
        let mut tags = vec![
            "dvga".to_string(),
            "graphql".to_string(),
            probe.class.to_lowercase(),
            format!("op:{}", probe.operation),
        ];
        if gt.is_decoy(&probe.id) {
            tags.push("decoy".to_string());
        }
        cases.push(BenchmarkCase {
            case_id: probe.id.clone(),
            domain: BenchmarkDomain::WebApi,
            name: probe.id.clone(),
            description: probe.rationale.clone(),
            target: format!("{}({})", probe.operation, probe.object_id),
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
        suite_id: "baloncore-dvga-graphql-bola-v1".to_string(),
        name: "DVGA GraphQL JWT-identity authorization bypass".to_string(),
        version: "1.0.0".to_string(),
        domain: BenchmarkDomain::WebApi,
        description:
            "Hand-labelled ground truth for dolevf/DVGA: one planted GraphQL BOLA (forged admin identity leaks a password) plus a masked-non-admin decoy and a public-paste decoy."
                .to_string(),
        cases,
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("source".to_string(), gt.source.clone());
            m.insert("source_commit".to_string(), gt.source_commit.clone());
            m.insert("image".to_string(), gt.image.clone());
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
struct DvgaObservation {
    operation: String,
    object_id: String,
    attacker_profile: String,
    classification: String,
    evidence_substring_corpus: String,
}

/// Pull every probe observation from a DVGA matrix_summary.json. Each
/// `validations[]` entry must carry `operation`, `object_id`, and `profile`
/// (the attacker profile). The `classification` is the runner's mapping of the
/// `GraphQlBolaValidator` decision to a label string
/// ("BrokenObjectLevelAuthorization" for Verified, "BlockedAsExpected" for
/// Rejected); an entry missing any key is dropped.
fn extract_observations(matrix: &serde_json::Value) -> Vec<DvgaObservation> {
    let entries = match matrix.get("validations").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return Vec::new(),
    };
    entries
        .iter()
        .filter_map(|entry| {
            let operation = entry.get("operation")?.as_str()?.to_string();
            let object_id = entry.get("object_id")?.as_str()?.to_string();
            let attacker_profile = entry.get("profile")?.as_str()?.to_string();
            let classification = entry
                .get("classification")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            let evidence_substring_corpus = entry
                .pointer("/decision/Verified/evidence_markers")
                .and_then(|v| serde_json::to_string(v).ok())
                .unwrap_or_default();
            Some(DvgaObservation {
                operation,
                object_id,
                attacker_profile,
                classification,
                evidence_substring_corpus,
            })
        })
        .collect()
}

/// Build a `BenchmarkRun` from a DVGA matrix_summary.json and the hand-labelled
/// ground truth. Pure and deterministic; does not start the target, scan, or
/// touch the network.
pub fn score_dvga_matrix_summary(
    matrix: &serde_json::Value,
    gt: &DvgaGroundTruth,
    suite: &BenchmarkSuite,
) -> BenchmarkRun {
    let observations = extract_observations(matrix);
    let mut results = Vec::new();
    for probe in gt.all_probes() {
        let matched = observations.iter().find(|obs| {
            obs.operation == probe.operation
                && obs.object_id == probe.object_id
                && obs.attacker_profile == probe.attacker_profile
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
                    "no matrix_summary entry matched (operation={}, object_id={}, profile={})",
                    probe.operation, probe.object_id, probe.attacker_profile
                )
            }),
        });
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    BenchmarkRun {
        run_id: format!("bench-dvga-{}", now),
        suite_id: suite.suite_id.clone(),
        suite_version: suite.version.clone(),
        domain: suite.domain.clone(),
        started_at: now,
        completed_at: now,
        config_snapshot: BenchmarkConfig {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            validator_config: "bench-dvga+GraphQlBolaValidator".to_string(),
            noise_mode: "moderate".to_string(),
            max_active_requests: 500,
            domain_filter: None,
            difficulty_filter: None,
            tag_filter: None,
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("source".to_string(), gt.source.clone());
                m.insert("source_commit".to_string(), gt.source_commit.clone());
                m.insert("image".to_string(), gt.image.clone());
                m.insert("license".to_string(), gt.license.clone());
                m.insert("benchmark_path".to_string(), "real-scan".to_string());
                m
            },
            provider: "fixture".to_string(),
            model: "n/a (deterministic validator)".to_string(),
            prompt_version: "n/a".to_string(),
            git_commit: env!("CARGO_PKG_VERSION").to_string(),
            corpus_hash: format!("dvga-graphql-bola-v{}", gt.ground_truth_version),
        },
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gt_fixture() -> DvgaGroundTruth {
        DvgaGroundTruth {
            case_id: "dvga-graphql-bola".to_string(),
            description: "fixture".to_string(),
            ground_truth_version: 1,
            source: "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application".to_string(),
            source_commit: "a961308c02d1fb462b192681c336b0739e432da7".to_string(),
            image: "dolevf/dvga@sha256:040aa33c".to_string(),
            license: "MIT".to_string(),
            vulnerabilities: vec![DvgaProbe {
                id: "vuln-jwt-forge-admin-password".to_string(),
                class: "BrokenObjectLevelAuthorization".to_string(),
                operation: "me".to_string(),
                object_id: "admin".to_string(),
                owner_profile: "admin-legit".to_string(),
                attacker_profile: "operator-forging-admin".to_string(),
                expected_label: "TruePositive".to_string(),
                owner_identity: Some("admin".to_string()),
                owner_login_password: Some("changeme".to_string()),
                attacker_forged_identity: Some("admin".to_string()),
                owner_markers: vec!["changeme".to_string()],
                rationale: "forged admin identity leaks password".to_string(),
                expected_evidence_substrings: vec!["changeme".to_string()],
            }],
            decoys: vec![
                DvgaProbe {
                    id: "decoy-nonadmin-identity-masked".to_string(),
                    class: "BlockedAsExpected".to_string(),
                    operation: "me".to_string(),
                    object_id: "admin".to_string(),
                    owner_profile: "admin-legit".to_string(),
                    attacker_profile: "operator-forging-operator".to_string(),
                    expected_label: "TrueNegative".to_string(),
                    owner_identity: Some("admin".to_string()),
                    owner_login_password: Some("changeme".to_string()),
                    attacker_forged_identity: Some("operator".to_string()),
                    owner_markers: vec!["changeme".to_string()],
                    rationale: "non-admin identity is masked".to_string(),
                    expected_evidence_substrings: vec![],
                },
                DvgaProbe {
                    id: "decoy-public-paste".to_string(),
                    class: "BlockedAsExpected".to_string(),
                    operation: "paste".to_string(),
                    object_id: "12".to_string(),
                    owner_profile: "anonymous".to_string(),
                    attacker_profile: "operator".to_string(),
                    expected_label: "TrueNegative".to_string(),
                    owner_identity: None,
                    owner_login_password: None,
                    attacker_forged_identity: Some("operator".to_string()),
                    owner_markers: vec!["Mind your own business".to_string()],
                    rationale: "public paste".to_string(),
                    expected_evidence_substrings: vec![],
                },
            ],
        }
    }

    /// Build a matrix from `(operation, object_id, profile, classification)`
    /// tuples. `evidence_markers` defaults to the leaked password for Verified
    /// rows so the positive's evidence_found is exercised.
    fn matrix(entries: &[(&str, &str, &str, &str)]) -> serde_json::Value {
        let validations: Vec<_> = entries
            .iter()
            .map(|(op, obj, profile, class)| {
                json!({
                    "operation": op,
                    "object_id": obj,
                    "profile": profile,
                    "classification": class,
                    "decision": { "Verified": { "evidence_markers": ["owner_marker:changeme"] } }
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

    #[test]
    fn happy_path_vuln_tp_two_decoys_tn() {
        let gt = gt_fixture();
        let suite = dvga_graphql_bola_suite(&gt);
        let m = matrix(&[
            (
                "me",
                "admin",
                "operator-forging-admin",
                "BrokenObjectLevelAuthorization",
            ),
            (
                "me",
                "admin",
                "operator-forging-operator",
                "BlockedAsExpected",
            ),
            ("paste", "12", "operator", "BlockedAsExpected"),
        ]);
        let run = score_dvga_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "vuln-jwt-forge-admin-password").prediction,
            GroundTruthLabel::TruePositive
        );
        assert_eq!(
            result(&run, "vuln-jwt-forge-admin-password").evidence_found,
            vec!["changeme".to_string()]
        );
        assert_eq!(
            result(&run, "decoy-nonadmin-identity-masked").prediction,
            GroundTruthLabel::TrueNegative
        );
        assert_eq!(
            result(&run, "decoy-public-paste").prediction,
            GroundTruthLabel::TrueNegative
        );
    }

    #[test]
    fn false_negative_when_bypass_missed() {
        let gt = gt_fixture();
        let suite = dvga_graphql_bola_suite(&gt);
        let m = matrix(&[
            ("me", "admin", "operator-forging-admin", "BlockedAsExpected"),
            (
                "me",
                "admin",
                "operator-forging-operator",
                "BlockedAsExpected",
            ),
            ("paste", "12", "operator", "BlockedAsExpected"),
        ]);
        let run = score_dvga_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "vuln-jwt-forge-admin-password").prediction,
            GroundTruthLabel::FalseNegative
        );
    }

    #[test]
    fn masked_decoy_flagged_is_false_positive() {
        // If the validator wrongly Verified the masked-non-admin probe, that is
        // a false positive and must be scored as one.
        let gt = gt_fixture();
        let suite = dvga_graphql_bola_suite(&gt);
        let m = matrix(&[
            (
                "me",
                "admin",
                "operator-forging-admin",
                "BrokenObjectLevelAuthorization",
            ),
            (
                "me",
                "admin",
                "operator-forging-operator",
                "BrokenObjectLevelAuthorization",
            ),
            ("paste", "12", "operator", "BlockedAsExpected"),
        ]);
        let run = score_dvga_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "decoy-nonadmin-identity-masked").prediction,
            GroundTruthLabel::FalsePositive
        );
    }

    #[test]
    fn public_paste_decoy_flagged_is_false_positive() {
        let gt = gt_fixture();
        let suite = dvga_graphql_bola_suite(&gt);
        let m = matrix(&[
            (
                "me",
                "admin",
                "operator-forging-admin",
                "BrokenObjectLevelAuthorization",
            ),
            (
                "me",
                "admin",
                "operator-forging-operator",
                "BlockedAsExpected",
            ),
            ("paste", "12", "operator", "BrokenObjectLevelAuthorization"),
        ]);
        let run = score_dvga_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "decoy-public-paste").prediction,
            GroundTruthLabel::FalsePositive
        );
    }

    #[test]
    fn match_key_includes_attacker_profile() {
        // Only the VULN observation (operator-forging-admin) is present. The
        // masked decoy shares operation+object_id but a different attacker
        // profile, so it must NOT match the vuln observation — it scores
        // FalseNegative (no verdict), not TrueNegative-by-accident. If the
        // attacker profile were dropped from the key this goes wrong.
        let gt = gt_fixture();
        let suite = dvga_graphql_bola_suite(&gt);
        let m = matrix(&[(
            "me",
            "admin",
            "operator-forging-admin",
            "BrokenObjectLevelAuthorization",
        )]);
        let run = score_dvga_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "vuln-jwt-forge-admin-password").prediction,
            GroundTruthLabel::TruePositive
        );
        let masked = result(&run, "decoy-nonadmin-identity-masked");
        assert_eq!(masked.prediction, GroundTruthLabel::FalseNegative);
        assert!(masked.error.is_some());
    }

    #[test]
    fn missing_observation_is_false_negative_not_silent_pass() {
        let gt = gt_fixture();
        let suite = dvga_graphql_bola_suite(&gt);
        let m = json!({ "validations": [] });
        let run = score_dvga_matrix_summary(&m, &gt, &suite);
        for r in &run.results {
            assert_eq!(
                r.prediction,
                GroundTruthLabel::FalseNegative,
                "{} should be FN with no observation",
                r.case_id
            );
            assert!(r.error.is_some());
        }
    }

    #[test]
    fn score_function_never_uses_expected_label_to_manufacture_prediction() {
        let gt = gt_fixture();
        let suite = dvga_graphql_bola_suite(&gt);
        let m = matrix(&[
            ("me", "admin", "operator-forging-admin", "BlockedAsExpected"),
            (
                "me",
                "admin",
                "operator-forging-operator",
                "BlockedAsExpected",
            ),
            ("paste", "12", "operator", "BlockedAsExpected"),
        ]);
        let run = score_dvga_matrix_summary(&m, &gt, &suite);
        assert_ne!(
            result(&run, "vuln-jwt-forge-admin-password").prediction,
            GroundTruthLabel::TruePositive
        );
    }

    #[test]
    fn ci_gate_fails_when_a_decoy_is_flagged() {
        let gt = gt_fixture();
        let suite = dvga_graphql_bola_suite(&gt);
        let m = matrix(&[
            (
                "me",
                "admin",
                "operator-forging-admin",
                "BrokenObjectLevelAuthorization",
            ),
            (
                "me",
                "admin",
                "operator-forging-operator",
                "BlockedAsExpected",
            ),
            ("paste", "12", "operator", "BrokenObjectLevelAuthorization"), // decoy hit
        ]);
        let run = score_dvga_matrix_summary(&m, &gt, &suite);
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
        let suite = dvga_graphql_bola_suite(&gt);
        let m = matrix(&[
            (
                "me",
                "admin",
                "operator-forging-admin",
                "BrokenObjectLevelAuthorization",
            ),
            (
                "me",
                "admin",
                "operator-forging-operator",
                "BlockedAsExpected",
            ),
            ("paste", "12", "operator", "BlockedAsExpected"),
        ]);
        let run = score_dvga_matrix_summary(&m, &gt, &suite);
        let gate = crate::evaluation::eval_gate(&run, &suite, 0.70, 0, 0.10, None, None);
        assert!(gate.passed, "clean run must pass; {}", gate.summary);
    }
}
