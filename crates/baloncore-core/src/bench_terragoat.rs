//! P2.S3 external corpus — real OFFLINE scorer for the `bridgecrewio/TerraGoat`
//! static-IaC target.
//!
//! TerraGoat has no server. `bench-terragoat` parses the vendored `.tf` files
//! into an `IAMGraph` (via `cloud_providers::terraform_hcl`) and runs the real
//! `IAMGraph::analyze()` detection. This scorer consumes the resulting
//! `CloudFinding`s and emits a `BenchmarkRun`.
//!
//! Cloud scoring differs from the HTTP benches: a static analysis examines
//! EVERY resource, so "no finding for a resource" means the analyzer
//! deliberately did not flag it — a `TrueNegative` for a correctly-configured
//! decoy, NOT a "scan miss". (Contrast the HTTP scorers, where a missing
//! observation is a `FalseNegative`.) A probe matches a finding when the
//! finding's `affected_resource` contains the probe's `resource_address`.
//!
//! The scorer NEVER uses `expected_label` to decide whether a resource was
//! flagged — that comes only from the analyzer's findings.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::cloud_iam::CloudFinding;
use crate::evaluation::{
    BenchmarkCase, BenchmarkConfig, BenchmarkDifficulty, BenchmarkDomain, BenchmarkResult,
    BenchmarkRun, BenchmarkSuite, GroundTruthLabel,
};

/// One probe in the hand-labelled TerraGoat ground-truth file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerragoatProbe {
    pub id: String,
    /// Terraform resource address, e.g. `aws_security_group.web-node`.
    pub resource_address: String,
    /// Expected analyzer classification when this is a real vuln.
    pub classification: String,
    pub expected_label: String,
    #[serde(default)]
    pub checkov_rule_id: Option<String>,
    #[serde(default)]
    pub source_file: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub expected_evidence_substrings: Vec<String>,
}

/// The full TerraGoat ground-truth document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerragoatGroundTruth {
    pub case_id: String,
    pub description: String,
    pub ground_truth_version: u32,
    pub source: String,
    #[serde(default)]
    pub source_commit: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub vulnerabilities: Vec<TerragoatProbe>,
    #[serde(default)]
    pub decoys: Vec<TerragoatProbe>,
}

impl TerragoatGroundTruth {
    pub fn all_probes(&self) -> Vec<&TerragoatProbe> {
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

/// Build the `BenchmarkSuite` that pairs 1:1 with a `TerragoatGroundTruth`.
pub fn terragoat_iam_suite(gt: &TerragoatGroundTruth) -> BenchmarkSuite {
    let mut cases = Vec::new();
    for probe in gt.all_probes() {
        let ground_truth = label_from_str(&probe.expected_label);
        let mut tags = vec!["terragoat".to_string(), "cloud".to_string()];
        if let Some(rule) = &probe.checkov_rule_id {
            tags.push(rule.to_lowercase());
        }
        if gt.is_decoy(&probe.id) {
            tags.push("decoy".to_string());
        }
        cases.push(BenchmarkCase {
            case_id: probe.id.clone(),
            domain: BenchmarkDomain::CloudIam,
            name: probe.id.clone(),
            description: probe.rationale.clone(),
            target: probe.resource_address.clone(),
            ground_truth,
            expected_classification: Some(probe.classification.clone()),
            expected_severity: None,
            expected_evidence_keys: probe.expected_evidence_substrings.clone(),
            difficulty: BenchmarkDifficulty::Moderate,
            tags,
            fixture_path: None,
            metadata: BTreeMap::new(),
        });
    }
    BenchmarkSuite {
        suite_id: "baloncore-terragoat-iam-v1".to_string(),
        name: "TerraGoat static IaC (public exposure + over-privileged IAM)".to_string(),
        version: "1.0.0".to_string(),
        domain: BenchmarkDomain::CloudIam,
        description:
            "Hand-labelled ground truth for bridgecrewio/TerraGoat analyzed offline: an open security group + an over-privileged IAM policy (planted vulns) plus an encrypted private bucket and two least-privilege/internal negative controls (decoys)."
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

/// Cloud confusion-matrix mapping. `flagged` = the analyzer produced a finding
/// for the probe's resource. Because a static analysis covers every resource,
/// "not flagged" is a real verdict (clean), never a scan miss.
fn cloud_prediction(expected: GroundTruthLabel, flagged: bool) -> GroundTruthLabel {
    match (expected, flagged) {
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

/// True if a finding pertains to the given Terraform resource address.
fn finding_matches(finding: &CloudFinding, resource_address: &str) -> bool {
    finding.affected_resource.contains(resource_address)
}

/// Count findings that do not correspond to ANY ground-truth probe. Surfaced in
/// run metadata for transparency (so flags outside the curated set are visible,
/// never silently hidden).
pub fn unmatched_findings(findings: &[CloudFinding], gt: &TerragoatGroundTruth) -> Vec<String> {
    findings
        .iter()
        .filter(|f| {
            !gt.all_probes()
                .iter()
                .any(|p| finding_matches(f, &p.resource_address))
        })
        .map(|f| format!("{} [{}]", f.affected_resource, f.classification))
        .collect()
}

/// Build a `BenchmarkRun` from analyzer findings + the hand-labelled ground
/// truth. Pure and deterministic; does not parse files or run the analyzer.
pub fn score_terragoat_findings(
    findings: &[CloudFinding],
    gt: &TerragoatGroundTruth,
    suite: &BenchmarkSuite,
) -> BenchmarkRun {
    let mut results = Vec::new();
    for probe in gt.all_probes() {
        let matched = findings
            .iter()
            .find(|f| finding_matches(f, &probe.resource_address));
        let expected = label_from_str(&probe.expected_label);
        let prediction = cloud_prediction(expected, matched.is_some());
        let evidence_found = if let Some(f) = matched {
            let corpus = format!(
                "{} {} {}",
                f.affected_resource, f.classification, f.description
            );
            probe
                .expected_evidence_substrings
                .iter()
                .filter(|needle| corpus.contains(needle.as_str()))
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
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
            domain: BenchmarkDomain::CloudIam,
            actual_classification: matched.map(|f| f.classification.clone()),
            actual_severity: matched.map(|f| f.severity.as_str().to_string()),
            actual_state: Some(
                if matched.is_some() {
                    "flagged"
                } else {
                    "clean"
                }
                .to_string(),
            ),
            prediction,
            confidence,
            evidence_found,
            time_to_result_ms: 0,
            error: None,
        });
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let unmatched = unmatched_findings(findings, gt);
    BenchmarkRun {
        run_id: format!("bench-terragoat-{}", now),
        suite_id: suite.suite_id.clone(),
        suite_version: suite.version.clone(),
        domain: suite.domain.clone(),
        started_at: now,
        completed_at: now,
        config_snapshot: BenchmarkConfig {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            validator_config: "bench-terragoat+analyze-cloud-iam(hcl)".to_string(),
            noise_mode: "moderate".to_string(),
            max_active_requests: 0,
            domain_filter: None,
            difficulty_filter: None,
            tag_filter: None,
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("source".to_string(), gt.source.clone());
                m.insert("source_commit".to_string(), gt.source_commit.clone());
                m.insert("license".to_string(), gt.license.clone());
                m.insert("benchmark_path".to_string(), "offline-iac".to_string());
                m.insert("total_findings".to_string(), findings.len().to_string());
                m.insert(
                    "unmatched_findings".to_string(),
                    if unmatched.is_empty() {
                        "0".to_string()
                    } else {
                        unmatched.join("; ")
                    },
                );
                m
            },
            provider: "fixture".to_string(),
            model: "n/a (deterministic analyzer)".to_string(),
            prompt_version: "n/a".to_string(),
            git_commit: env!("CARGO_PKG_VERSION").to_string(),
            corpus_hash: format!("terragoat-iam-v{}", gt.ground_truth_version),
        },
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud_iam::{CloudFinding, CloudProvider, CloudSeverity, PrivilegeLevel};

    fn gt_fixture() -> TerragoatGroundTruth {
        let mk = |id: &str, addr: &str, class: &str, label: &str| TerragoatProbe {
            id: id.to_string(),
            resource_address: addr.to_string(),
            classification: class.to_string(),
            expected_label: label.to_string(),
            checkov_rule_id: None,
            source_file: String::new(),
            rationale: String::new(),
            expected_evidence_substrings: vec![],
        };
        TerragoatGroundTruth {
            case_id: "terragoat-iam".to_string(),
            description: "fixture".to_string(),
            ground_truth_version: 1,
            source: "https://github.com/bridgecrewio/terragoat".to_string(),
            source_commit: "729f8da".to_string(),
            license: "Apache-2.0".to_string(),
            vulnerabilities: vec![
                mk(
                    "vuln-open-security-group-web-node",
                    "aws_security_group.web-node",
                    "PublicResourceExposure",
                    "TruePositive",
                ),
                mk(
                    "vuln-overprivileged-user-policy",
                    "aws_iam_user_policy.userpolicy",
                    "OverPrivilegedPolicy",
                    "TruePositive",
                ),
            ],
            decoys: vec![
                mk(
                    "decoy-encrypted-private-logs-bucket",
                    "aws_s3_bucket.logs",
                    "BlockedAsExpected",
                    "TrueNegative",
                ),
                mk(
                    "decoy-least-privilege-policy",
                    "aws_iam_user_policy.scoped",
                    "BlockedAsExpected",
                    "TrueNegative",
                ),
                mk(
                    "decoy-internal-security-group",
                    "aws_security_group.internal",
                    "BlockedAsExpected",
                    "TrueNegative",
                ),
            ],
        }
    }

    fn finding(classification: &str, affected: &str) -> CloudFinding {
        CloudFinding {
            id: format!("f-{affected}"),
            classification: classification.to_string(),
            severity: CloudSeverity::High,
            provider: CloudProvider::AWS,
            affected_resource: affected.to_string(),
            affected_resource_arn: None,
            description: String::new(),
            identity_chain: vec![],
            remediation: String::new(),
            evidence: vec![],
            is_reachable: true,
            is_theoretical: false,
            privilege_level: PrivilegeLevel::Admin,
        }
    }

    fn result<'a>(run: &'a BenchmarkRun, id: &str) -> &'a BenchmarkResult {
        run.results
            .iter()
            .find(|r| r.case_id == id)
            .unwrap_or_else(|| panic!("missing result {id}"))
    }

    /// The realistic clean run: both planted vulns flagged, no decoy flagged.
    fn clean_findings() -> Vec<CloudFinding> {
        vec![
            finding("PublicResourceExposure", "aws_security_group.web-node"),
            finding(
                "OverPrivilegedPolicy",
                "aws_iam_user.user -> aws_iam_user_policy.userpolicy",
            ),
        ]
    }

    #[test]
    fn happy_path_two_vulns_tp_three_decoys_tn() {
        let gt = gt_fixture();
        let suite = terragoat_iam_suite(&gt);
        let run = score_terragoat_findings(&clean_findings(), &gt, &suite);
        assert_eq!(
            result(&run, "vuln-open-security-group-web-node").prediction,
            GroundTruthLabel::TruePositive
        );
        assert_eq!(
            result(&run, "vuln-overprivileged-user-policy").prediction,
            GroundTruthLabel::TruePositive
        );
        for d in [
            "decoy-encrypted-private-logs-bucket",
            "decoy-least-privilege-policy",
            "decoy-internal-security-group",
        ] {
            assert_eq!(
                result(&run, d).prediction,
                GroundTruthLabel::TrueNegative,
                "{d} must be a true negative"
            );
        }
    }

    #[test]
    fn false_negative_when_vuln_not_flagged() {
        let gt = gt_fixture();
        let suite = terragoat_iam_suite(&gt);
        // Only the SG is flagged; the over-privileged policy is missed.
        let findings = vec![finding(
            "PublicResourceExposure",
            "aws_security_group.web-node",
        )];
        let run = score_terragoat_findings(&findings, &gt, &suite);
        assert_eq!(
            result(&run, "vuln-overprivileged-user-policy").prediction,
            GroundTruthLabel::FalseNegative
        );
    }

    #[test]
    fn scoped_policy_decoy_flagged_is_false_positive() {
        // The credibility-critical cloud FP: flagging a least-privilege policy.
        let gt = gt_fixture();
        let suite = terragoat_iam_suite(&gt);
        let mut findings = clean_findings();
        findings.push(finding(
            "OverPrivilegedPolicy",
            "aws_iam_user.app -> aws_iam_user_policy.scoped",
        ));
        let run = score_terragoat_findings(&findings, &gt, &suite);
        assert_eq!(
            result(&run, "decoy-least-privilege-policy").prediction,
            GroundTruthLabel::FalsePositive
        );
    }

    #[test]
    fn private_bucket_decoy_flagged_is_false_positive() {
        let gt = gt_fixture();
        let suite = terragoat_iam_suite(&gt);
        let mut findings = clean_findings();
        findings.push(finding("PublicResourceExposure", "aws_s3_bucket.logs"));
        let run = score_terragoat_findings(&findings, &gt, &suite);
        assert_eq!(
            result(&run, "decoy-encrypted-private-logs-bucket").prediction,
            GroundTruthLabel::FalsePositive
        );
    }

    #[test]
    fn not_flagged_decoy_is_true_negative_not_false_negative() {
        // Cloud-specific: a resource with no finding is a deliberate clean
        // verdict (TrueNegative for a decoy), NOT a "scan miss" FalseNegative.
        let gt = gt_fixture();
        let suite = terragoat_iam_suite(&gt);
        let run = score_terragoat_findings(&clean_findings(), &gt, &suite);
        let decoy = result(&run, "decoy-internal-security-group");
        assert_eq!(decoy.prediction, GroundTruthLabel::TrueNegative);
        assert!(decoy.error.is_none());
    }

    #[test]
    fn score_never_uses_expected_label_to_manufacture_flag() {
        // With NO findings, the planted vulns must score FalseNegative (the
        // analyzer found nothing), never TruePositive because the label says so.
        let gt = gt_fixture();
        let suite = terragoat_iam_suite(&gt);
        let run = score_terragoat_findings(&[], &gt, &suite);
        assert_eq!(
            result(&run, "vuln-open-security-group-web-node").prediction,
            GroundTruthLabel::FalseNegative
        );
        assert_eq!(
            result(&run, "vuln-overprivileged-user-policy").prediction,
            GroundTruthLabel::FalseNegative
        );
    }

    #[test]
    fn unmatched_findings_are_surfaced() {
        let gt = gt_fixture();
        let mut findings = clean_findings();
        findings.push(finding("PublicResourceExposure", "aws_s3_bucket.someother"));
        let unmatched = unmatched_findings(&findings, &gt);
        assert_eq!(unmatched.len(), 1);
        assert!(unmatched[0].contains("someother"));
    }

    #[test]
    fn ci_gate_fails_when_a_decoy_is_flagged() {
        let gt = gt_fixture();
        let suite = terragoat_iam_suite(&gt);
        let mut findings = clean_findings();
        findings.push(finding(
            "OverPrivilegedPolicy",
            "aws_iam_user.app -> aws_iam_user_policy.scoped",
        ));
        let run = score_terragoat_findings(&findings, &gt, &suite);
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
        let suite = terragoat_iam_suite(&gt);
        let run = score_terragoat_findings(&clean_findings(), &gt, &suite);
        let gate = crate::evaluation::eval_gate(&run, &suite, 0.70, 0, 0.10, None, None);
        assert!(gate.passed, "clean run must pass; {}", gate.summary);
    }
}
