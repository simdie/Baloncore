//! P2.S3 external corpus — real benchmark scorer for the `erev0s/VAmPI` target.
//!
//! VAmPI has a global `vulnerable=1/0` switch. The `bench-vampi` runner boots
//! BOTH a vulnerable and a secure instance of the SAME target and drives the
//! identical BOLA probe at each through the real `BolaValidator`, recording one
//! `validations[]` entry per probe (tagged with the `mode` it ran against).
//! This scorer consumes that matrix and emits a `BenchmarkRun`.
//!
//! The whole point of VAmPI is the false-positive measurement: the secure-build
//! probe is the decoy. The same bug, toggled off, MUST produce zero findings.
//! So matching is keyed on `(mode, endpoint, attacker_profile, object_id)` — a
//! vulnerable-mode observation must never satisfy a secure-mode probe, or the
//! decoy could be silently "credited" with the vulnerable build's finding.
//!
//! There is no synthetic-fallback path: a probe with no matching matrix entry
//! is scored `FalseNegative`, never a silent pass. The scorer NEVER uses
//! `expected_label` to manufacture a prediction — it only reports what the
//! classifier said for each probe and compares it to the hand label.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::bench_saas::{classify_prediction_from_label, endpoints_equivalent};
use crate::evaluation::{
    BenchmarkCase, BenchmarkConfig, BenchmarkDifficulty, BenchmarkDomain, BenchmarkResult,
    BenchmarkRun, BenchmarkSuite, GroundTruthLabel,
};

/// One probe in the hand-labelled VAmPI ground-truth file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VampiProbe {
    pub id: String,
    pub class: String,
    /// Which build of the SAME target this probe runs against: "vulnerable"
    /// (vulnerable=1) or "secure" (vulnerable=0). This is the discriminator
    /// that keeps the secure-build decoy distinct from the vulnerable-build
    /// true positive on otherwise-identical endpoint/profile/object tuples.
    pub mode: String,
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

/// The full VAmPI ground-truth document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VampiGroundTruth {
    pub case_id: String,
    pub description: String,
    pub ground_truth_version: u32,
    pub source: String,
    #[serde(default)]
    pub source_commit: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub vulnerabilities: Vec<VampiProbe>,
    #[serde(default)]
    pub decoys: Vec<VampiProbe>,
}

impl VampiGroundTruth {
    /// All probes, vulns + decoys, in declaration order.
    pub fn all_probes(&self) -> Vec<&VampiProbe> {
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

/// Build the `BenchmarkSuite` that pairs 1:1 with a `VampiGroundTruth`. Suite
/// `case_id`s match probe `id`s exactly.
pub fn vampi_bola_suite(gt: &VampiGroundTruth) -> BenchmarkSuite {
    let mut cases = Vec::new();
    for probe in gt.all_probes() {
        let ground_truth = label_from_str(&probe.expected_label);
        let mut tags = vec![
            "vampi".to_string(),
            probe.class.to_lowercase(),
            format!("mode:{}", probe.mode),
        ];
        if gt.is_decoy(&probe.id) {
            tags.push("decoy".to_string());
        }
        cases.push(BenchmarkCase {
            case_id: probe.id.clone(),
            domain: BenchmarkDomain::WebApi,
            name: probe.id.clone(),
            description: probe.rationale.clone(),
            target: format!("[{}] {}", probe.mode, probe.endpoint),
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
        suite_id: "baloncore-vampi-bola-v1".to_string(),
        name: "VAmPI BOLA-on-books (vulnerable vs secure toggle)".to_string(),
        version: "1.0.0".to_string(),
        domain: BenchmarkDomain::WebApi,
        description:
            "Hand-labelled ground truth for erev0s/VAmPI: one planted BOLA on the vulnerable build, plus secure-build and owner-self decoys."
                .to_string(),
        cases,
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("source".to_string(), gt.source.clone());
            m.insert("source_commit".to_string(), gt.source_commit.clone());
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
struct VampiObservation {
    mode: String,
    endpoint: String,
    attacker_profile: String,
    object_id: String,
    classification: String,
    /// Concatenated text searchable against `expected_evidence_substrings`.
    evidence_substring_corpus: String,
}

/// Pull every probe observation from a VAmPI matrix_summary.json document. Each
/// `validations[]` entry must carry a `mode` field; an entry without one is
/// dropped (it cannot be matched unambiguously to a mode-specific probe).
fn extract_observations(matrix: &serde_json::Value) -> Vec<VampiObservation> {
    let entries = match matrix.get("validations").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return Vec::new(),
    };
    entries
        .iter()
        .filter_map(|entry| {
            let mode = entry.get("mode")?.as_str()?.to_string();
            let endpoint = entry.get("endpoint")?.as_str()?.to_string();
            let profile = entry.get("profile")?.as_str()?.to_string();
            let object_id = entry
                .get("object_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
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
            Some(VampiObservation {
                mode,
                endpoint,
                attacker_profile: profile,
                object_id,
                classification,
                evidence_substring_corpus: body_excerpt,
            })
        })
        .collect()
}

/// Build a `BenchmarkRun` from a VAmPI matrix_summary.json and the hand-labelled
/// ground truth. Pure and deterministic; does not start the target, scan, or
/// touch the network.
pub fn score_vampi_matrix_summary(
    matrix: &serde_json::Value,
    gt: &VampiGroundTruth,
    suite: &BenchmarkSuite,
) -> BenchmarkRun {
    let observations = extract_observations(matrix);
    let mut results = Vec::new();
    for probe in gt.all_probes() {
        let matched = observations.iter().find(|obs| {
            obs.mode == probe.mode
                && obs.attacker_profile == probe.attacker_profile
                && obs.object_id == probe.object_id
                && endpoints_equivalent(&obs.endpoint, &probe.endpoint)
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
            actual_state: Some(if matched.is_some() { "scanned" } else { "missing" }.to_string()),
            prediction,
            confidence,
            evidence_found,
            time_to_result_ms: 0,
            error: matched.is_none().then(|| {
                format!(
                    "no matrix_summary entry matched (mode={}, endpoint={}, profile={}, object_id={})",
                    probe.mode, probe.endpoint, probe.attacker_profile, probe.object_id
                )
            }),
        });
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    BenchmarkRun {
        run_id: format!("bench-vampi-{}", now),
        suite_id: suite.suite_id.clone(),
        suite_version: suite.version.clone(),
        domain: suite.domain.clone(),
        started_at: now,
        completed_at: now,
        config_snapshot: BenchmarkConfig {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            validator_config: "bench-vampi+BolaValidator".to_string(),
            noise_mode: "moderate".to_string(),
            max_active_requests: 500,
            domain_filter: None,
            difficulty_filter: None,
            tag_filter: None,
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("source".to_string(), gt.source.clone());
                m.insert("source_commit".to_string(), gt.source_commit.clone());
                m.insert("license".to_string(), gt.license.clone());
                m.insert("benchmark_path".to_string(), "real-scan".to_string());
                m
            },
            provider: "fixture".to_string(),
            model: "n/a (deterministic validator)".to_string(),
            prompt_version: "n/a".to_string(),
            git_commit: env!("CARGO_PKG_VERSION").to_string(),
            corpus_hash: format!("vampi-bola-v{}", gt.ground_truth_version),
        },
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gt_fixture() -> VampiGroundTruth {
        VampiGroundTruth {
            case_id: "vampi-bola-books".to_string(),
            description: "fixture".to_string(),
            ground_truth_version: 1,
            source: "https://github.com/erev0s/VAmPI".to_string(),
            source_commit: "f16052dce83f05847133ec98f01c5193a41de7d8".to_string(),
            license: "MIT".to_string(),
            vulnerabilities: vec![VampiProbe {
                id: "vuln-bola-books-vulnerable".to_string(),
                class: "BrokenObjectLevelAuthorization".to_string(),
                mode: "vulnerable".to_string(),
                endpoint: "GET /books/v1/{book}".to_string(),
                object_id: "baloncore-bola-probe".to_string(),
                owner_profile: "name1".to_string(),
                attacker_profile: "name2".to_string(),
                expected_label: "TruePositive".to_string(),
                rationale: "planted BOLA".to_string(),
                expected_evidence_substrings: vec!["BALONCORE_PLANTED_SECRET".to_string()],
            }],
            decoys: vec![
                VampiProbe {
                    id: "decoy-bola-books-secure".to_string(),
                    class: "BlockedAsExpected".to_string(),
                    mode: "secure".to_string(),
                    endpoint: "GET /books/v1/{book}".to_string(),
                    object_id: "baloncore-bola-probe".to_string(),
                    owner_profile: "name1".to_string(),
                    attacker_profile: "name2".to_string(),
                    expected_label: "TrueNegative".to_string(),
                    rationale: "secure mode 404".to_string(),
                    expected_evidence_substrings: vec![],
                },
                VampiProbe {
                    id: "decoy-owner-self-access".to_string(),
                    class: "IntendedOwnerAccess".to_string(),
                    mode: "vulnerable".to_string(),
                    endpoint: "GET /books/v1/{book}".to_string(),
                    object_id: "baloncore-bola-probe".to_string(),
                    owner_profile: "name1".to_string(),
                    attacker_profile: "name1".to_string(),
                    expected_label: "TrueNegative".to_string(),
                    rationale: "owner reads own book".to_string(),
                    expected_evidence_substrings: vec![],
                },
            ],
        }
    }

    /// Build a matrix with explicit per-probe classifications. Each tuple is
    /// `(mode, attacker_profile, classification)`; object/endpoint are fixed.
    fn matrix(entries: &[(&str, &str, &str)]) -> serde_json::Value {
        let validations: Vec<_> = entries
            .iter()
            .map(|(mode, profile, class)| {
                json!({
                    "mode": mode,
                    "profile": profile,
                    "endpoint": "GET /books/v1/{book}",
                    "object_id": "baloncore-bola-probe",
                    "classification": class,
                    "decision": { "Verified": { "evidence_markers": ["BALONCORE_PLANTED_SECRET"] } }
                })
            })
            .collect();
        json!({ "validations": validations })
    }

    fn result<'a>(run: &'a BenchmarkRun, case_id: &str) -> &'a BenchmarkResult {
        run.results
            .iter()
            .find(|r| r.case_id == case_id)
            .unwrap_or_else(|| panic!("missing result for {case_id}"))
    }

    #[test]
    fn happy_path_vuln_tp_secure_tn_owner_tn() {
        let gt = gt_fixture();
        let suite = vampi_bola_suite(&gt);
        let m = matrix(&[
            ("vulnerable", "name2", "BrokenObjectLevelAuthorization"),
            ("secure", "name2", "BlockedAsExpected"),
            ("vulnerable", "name1", "IntendedOwnerAccess"),
        ]);
        let run = score_vampi_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "vuln-bola-books-vulnerable").prediction,
            GroundTruthLabel::TruePositive
        );
        assert_eq!(
            result(&run, "vuln-bola-books-vulnerable").evidence_found,
            vec!["BALONCORE_PLANTED_SECRET".to_string()]
        );
        assert_eq!(
            result(&run, "decoy-bola-books-secure").prediction,
            GroundTruthLabel::TrueNegative
        );
        assert_eq!(
            result(&run, "decoy-owner-self-access").prediction,
            GroundTruthLabel::TrueNegative
        );
    }

    #[test]
    fn false_negative_when_vulnerable_bug_missed() {
        // The vulnerable build was scanned but the validator stayed silent.
        let gt = gt_fixture();
        let suite = vampi_bola_suite(&gt);
        let m = matrix(&[
            ("vulnerable", "name2", "BlockedAsExpected"),
            ("secure", "name2", "BlockedAsExpected"),
            ("vulnerable", "name1", "IntendedOwnerAccess"),
        ]);
        let run = score_vampi_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "vuln-bola-books-vulnerable").prediction,
            GroundTruthLabel::FalseNegative
        );
    }

    #[test]
    fn secure_decoy_flagged_is_false_positive() {
        // The whole reason VAmPI exists: a validator that fires on the secure
        // build (bug toggled off) is producing a false positive and MUST be
        // scored as one.
        let gt = gt_fixture();
        let suite = vampi_bola_suite(&gt);
        let m = matrix(&[
            ("vulnerable", "name2", "BrokenObjectLevelAuthorization"),
            ("secure", "name2", "BrokenObjectLevelAuthorization"), // FP!
            ("vulnerable", "name1", "IntendedOwnerAccess"),
        ]);
        let run = score_vampi_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "decoy-bola-books-secure").prediction,
            GroundTruthLabel::FalsePositive,
            "a finding on the secure build is a false positive"
        );
    }

    #[test]
    fn owner_self_access_flagged_is_false_positive() {
        // Owner reading their own object is legitimate; flagging it is an FP.
        let gt = gt_fixture();
        let suite = vampi_bola_suite(&gt);
        let m = matrix(&[
            ("vulnerable", "name2", "BrokenObjectLevelAuthorization"),
            ("secure", "name2", "BlockedAsExpected"),
            ("vulnerable", "name1", "BrokenObjectLevelAuthorization"), // FP!
        ]);
        let run = score_vampi_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "decoy-owner-self-access").prediction,
            GroundTruthLabel::FalsePositive
        );
    }

    #[test]
    fn mode_is_part_of_the_match_key() {
        // Only the VULNERABLE-build observation is present. The secure-build
        // decoy must NOT be credited with it — it must score FalseNegative
        // (no verdict for the secure mode), not TrueNegative-by-accident.
        // If `mode` were dropped from the match key, the secure probe would
        // wrongly match the vulnerable observation and this goes wrong.
        let gt = gt_fixture();
        let suite = vampi_bola_suite(&gt);
        let m = matrix(&[("vulnerable", "name2", "BrokenObjectLevelAuthorization")]);
        let run = score_vampi_matrix_summary(&m, &gt, &suite);
        assert_eq!(
            result(&run, "vuln-bola-books-vulnerable").prediction,
            GroundTruthLabel::TruePositive
        );
        let secure = result(&run, "decoy-bola-books-secure");
        assert_eq!(
            secure.prediction,
            GroundTruthLabel::FalseNegative,
            "secure-mode probe must not match a vulnerable-mode observation"
        );
        assert!(secure.error.is_some());
    }

    #[test]
    fn missing_observation_is_false_negative_not_silent_pass() {
        let gt = gt_fixture();
        let suite = vampi_bola_suite(&gt);
        let m = json!({ "validations": [] });
        let run = score_vampi_matrix_summary(&m, &gt, &suite);
        for r in &run.results {
            assert_eq!(
                r.prediction,
                GroundTruthLabel::FalseNegative,
                "{} should be FN when no observation exists",
                r.case_id
            );
            assert!(r.error.is_some(), "{} should carry an error", r.case_id);
        }
    }

    #[test]
    fn score_function_never_uses_expected_label_to_manufacture_prediction() {
        // Even when every observation says BlockedAsExpected, the planted vuln
        // must be FalseNegative — the scorer reports what the classifier said,
        // not what the ground truth wants.
        let gt = gt_fixture();
        let suite = vampi_bola_suite(&gt);
        let m = matrix(&[
            ("vulnerable", "name2", "BlockedAsExpected"),
            ("secure", "name2", "BlockedAsExpected"),
            ("vulnerable", "name1", "BlockedAsExpected"),
        ]);
        let run = score_vampi_matrix_summary(&m, &gt, &suite);
        assert_ne!(
            result(&run, "vuln-bola-books-vulnerable").prediction,
            GroundTruthLabel::TruePositive
        );
    }

    #[test]
    fn ci_gate_fails_when_secure_decoy_flagged() {
        // Reuse the production eval gate: a decoy hit on the secure build must
        // fail the gate via the decoy guard specifically. min_precision=0.0 so
        // only the decoy guard can flip the result.
        let gt = gt_fixture();
        let suite = vampi_bola_suite(&gt);
        let m = matrix(&[
            ("vulnerable", "name2", "BrokenObjectLevelAuthorization"),
            ("secure", "name2", "BrokenObjectLevelAuthorization"), // decoy hit
            ("vulnerable", "name1", "IntendedOwnerAccess"),
        ]);
        let run = score_vampi_matrix_summary(&m, &gt, &suite);
        let gate = crate::evaluation::eval_gate(&run, &suite, 0.0, 0, 1.0, None, None);
        assert!(
            !gate.passed,
            "gate must FAIL when a secure-build decoy is flagged; summary={}",
            gate.summary
        );
        assert!(
            gate.summary.to_lowercase().contains("decoy"),
            "failure must cite the decoy guard, got: {}",
            gate.summary
        );
    }

    #[test]
    fn ci_gate_passes_on_clean_run() {
        let gt = gt_fixture();
        let suite = vampi_bola_suite(&gt);
        let m = matrix(&[
            ("vulnerable", "name2", "BrokenObjectLevelAuthorization"),
            ("secure", "name2", "BlockedAsExpected"),
            ("vulnerable", "name1", "IntendedOwnerAccess"),
        ]);
        let run = score_vampi_matrix_summary(&m, &gt, &suite);
        let gate = crate::evaluation::eval_gate(&run, &suite, 0.70, 0, 0.10, None, None);
        assert!(gate.passed, "clean run must pass; summary={}", gate.summary);
    }
}
