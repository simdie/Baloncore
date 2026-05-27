use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::github::RevalidationTarget;

use crate::github::RevalidationPlan;
use crate::lifecycle::FindingRecord;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RevalidationReport {
    pub pr_number: u64,
    pub started_at: u64,
    pub finished_at: u64,
    pub total_targets: usize,
    pub fixed_count: usize,
    pub still_failing_count: usize,
    pub skipped_count: usize,
    pub error_count: usize,
    pub results: Vec<RevalidationResult>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RevalidationResult {
    pub finding_id: String,
    pub endpoint: String,
    pub classification: String,
    pub status: RevalidationStatus,
    pub reason: String,
    pub remediation_path: Option<String>,
    pub regression_verdict: Option<String>,
    pub checks_passed: Option<usize>,
    pub checks_total: Option<usize>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevalidationStatus {
    Fixed,
    StillFailing,
    SkippedNoRemediation,
    SkippedAlreadyFixed,
    Error,
}

impl RevalidationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::StillFailing => "still-failing",
            Self::SkippedNoRemediation => "skipped-no-remediation",
            Self::SkippedAlreadyFixed => "skipped-already-fixed",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevalidationRunner {
    pub plan: RevalidationPlan,
    pub findings: Vec<FindingRecord>,
    pub evidence_store_path: String,
    pub target_url: String,
    pub owner_profile: String,
    pub attacker_profile: String,
}

impl RevalidationRunner {
    pub fn new(
        plan: RevalidationPlan,
        findings: Vec<FindingRecord>,
        evidence_store_path: &str,
    ) -> Self {
        Self {
            plan,
            findings,
            evidence_store_path: evidence_store_path.to_string(),
            target_url: String::new(),
            owner_profile: String::new(),
            attacker_profile: String::new(),
        }
    }

    pub fn with_credentials(
        mut self,
        target_url: &str,
        owner_profile: &str,
        attacker_profile: &str,
    ) -> Self {
        self.target_url = target_url.to_string();
        self.owner_profile = owner_profile.to_string();
        self.attacker_profile = attacker_profile.to_string();
        self
    }

    pub fn run(&self) -> RevalidationReport {
        let started_at = unix_seconds();
        let mut results = Vec::new();
        let mut fixed_count = 0usize;
        let mut still_failing_count = 0usize;
        let mut skipped_count = 0usize;
        let mut error_count = 0usize;

        for target in &self.plan.affected_findings {
            let start = std::time::Instant::now();
            let finding = self
                .findings
                .iter()
                .find(|f| f.finding_id == target.finding_id);

            let result = match finding {
                None => {
                    error_count += 1;
                    RevalidationResult {
                        finding_id: target.finding_id.clone(),
                        endpoint: target.endpoint.clone(),
                        classification: target.classification.clone(),
                        status: RevalidationStatus::SkippedNoRemediation,
                        reason: "finding not found in evidence store".to_string(),
                        remediation_path: None,
                        regression_verdict: None,
                        checks_passed: None,
                        checks_total: None,
                        duration_ms: start.elapsed().as_millis() as u64,
                    }
                }
                Some(f) => {
                    let remediation_path = self
                        .evidence_store_path
                        .trim_end_matches("/index.json")
                        .to_string();
                    let remediation_file = format!(
                        "{}/runs/{}/{}/remediation.json",
                        remediation_path, f.scan_id, f.finding_id
                    );
                    let plan_path = std::path::Path::new(&remediation_file);

                    if matches!(
                        f.state,
                        crate::lifecycle::FindingState::Fixed
                            | crate::lifecycle::FindingState::Closed
                    ) {
                        skipped_count += 1;
                        RevalidationResult {
                            finding_id: f.finding_id.clone(),
                            endpoint: f.endpoint.clone(),
                            classification: f.classification.clone(),
                            status: RevalidationStatus::SkippedAlreadyFixed,
                            reason: format!("finding already in `{}` state", f.state.as_str()),
                            remediation_path: Some(plan_path.display().to_string()),
                            regression_verdict: None,
                            checks_passed: None,
                            checks_total: None,
                            duration_ms: start.elapsed().as_millis() as u64,
                        }
                    } else if !plan_path.exists() {
                        skipped_count += 1;
                        RevalidationResult {
                            finding_id: f.finding_id.clone(),
                            endpoint: f.endpoint.clone(),
                            classification: f.classification.clone(),
                            status: RevalidationStatus::SkippedNoRemediation,
                            reason: "no remediation.json found for this finding".to_string(),
                            remediation_path: None,
                            regression_verdict: None,
                            checks_passed: None,
                            checks_total: None,
                            duration_ms: start.elapsed().as_millis() as u64,
                        }
                    } else {
                        match try_run_regression(plan_path, &self.target_url) {
                            Ok(verdict) => {
                                if verdict.passed() {
                                    fixed_count += 1;
                                    RevalidationResult {
                                        finding_id: f.finding_id.clone(),
                                        endpoint: f.endpoint.clone(),
                                        classification: f.classification.clone(),
                                        status: RevalidationStatus::Fixed,
                                        reason: format!(
                                            "{} regression checks passed",
                                            verdict.passed_checks
                                        ),
                                        remediation_path: Some(plan_path.display().to_string()),
                                        regression_verdict: Some(verdict.verdict_str().to_string()),
                                        checks_passed: Some(verdict.passed_checks),
                                        checks_total: Some(verdict.total_checks),
                                        duration_ms: start.elapsed().as_millis() as u64,
                                    }
                                } else {
                                    still_failing_count += 1;
                                    RevalidationResult {
                                        finding_id: f.finding_id.clone(),
                                        endpoint: f.endpoint.clone(),
                                        classification: f.classification.clone(),
                                        status: RevalidationStatus::StillFailing,
                                        reason: format!(
                                            "{}/{} checks failed",
                                            verdict.failed_checks, verdict.total_checks
                                        ),
                                        remediation_path: Some(plan_path.display().to_string()),
                                        regression_verdict: Some(verdict.verdict_str().to_string()),
                                        checks_passed: Some(verdict.passed_checks),
                                        checks_total: Some(verdict.total_checks),
                                        duration_ms: start.elapsed().as_millis() as u64,
                                    }
                                }
                            }
                            Err(e) => {
                                error_count += 1;
                                RevalidationResult {
                                    finding_id: f.finding_id.clone(),
                                    endpoint: f.endpoint.clone(),
                                    classification: f.classification.clone(),
                                    status: RevalidationStatus::Error,
                                    reason: format!("regression execution failed: {e}"),
                                    remediation_path: Some(plan_path.display().to_string()),
                                    regression_verdict: None,
                                    checks_passed: None,
                                    checks_total: None,
                                    duration_ms: start.elapsed().as_millis() as u64,
                                }
                            }
                        }
                    }
                }
            };

            results.push(result);
        }

        let summary = format!(
            "Revalidation complete: {} fixed, {} still failing, {} skipped, {} errors ({} targets)",
            fixed_count,
            still_failing_count,
            skipped_count,
            error_count,
            self.plan.affected_findings.len()
        );

        RevalidationReport {
            pr_number: self.plan.pr_number,
            started_at,
            finished_at: unix_seconds(),
            total_targets: self.plan.affected_findings.len(),
            fixed_count,
            still_failing_count,
            skipped_count,
            error_count,
            results,
            summary,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegressionVerdictSummary {
    pub passed_checks: usize,
    pub failed_checks: usize,
    pub total_checks: usize,
}

impl RegressionVerdictSummary {
    pub fn passed(&self) -> bool {
        self.failed_checks == 0 && self.total_checks > 0
    }

    pub fn verdict_str(&self) -> &'static str {
        if self.passed() {
            "Fixed"
        } else {
            "StillFailing"
        }
    }
}

fn try_run_regression(
    remediation_path: &std::path::Path,
    _target_url: &str,
) -> Result<RegressionVerdictSummary, String> {
    let raw = std::fs::read_to_string(remediation_path)
        .map_err(|e| format!("failed to read {}: {e}", remediation_path.display()))?;
    let plan: crate::web_api::RemediationPlan =
        serde_json::from_str(&raw).map_err(|e| format!("failed to parse remediation plan: {e}"))?;

    if plan.regression_checks.is_empty() {
        return Ok(RegressionVerdictSummary {
            passed_checks: 0,
            failed_checks: 0,
            total_checks: 0,
        });
    }

    let runner = crate::web_api::HttpRequestRunner::new()
        .map_err(|e| format!("failed to initialize HTTP runner: {e}"))?;
    let mut passed = 0usize;
    let mut failed = 0usize;

    for check in &plan.regression_checks {
        let result = runner
            .send(&crate::web_api::HttpRequestSpec {
                id: format!("revalidation-{}", check.name),
                profile: check.profile.clone(),
                method: check.method.clone(),
                url: check.url.clone(),
                bearer_token: check
                    .auth_header
                    .as_deref()
                    .and_then(bearer_token_from_auth),
                cookies: vec![],
                headers: vec![],
                csrf_token_header: None,
                csrf_token: None,
            })
            .map_err(|e| format!("HTTP request failed for {}: {e}", check.name))?;
        if check.expected_statuses.contains(&result.status) {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    Ok(RegressionVerdictSummary {
        passed_checks: passed,
        failed_checks: failed,
        total_checks: passed + failed,
    })
}

fn bearer_token_from_auth(auth_header: &str) -> Option<String> {
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        Some(token.to_string())
    } else if let Some(token) = auth_header.strip_prefix("bearer ") {
        Some(token.to_string())
    } else {
        None
    }
}

pub fn render_revalidation_report(report: &RevalidationReport) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Revalidation Report\n\n");
    md.push_str(&format!("**PR:** #{}\n\n", report.pr_number));
    md.push_str(&format!("**Summary:** {}\n\n", report.summary));
    md.push_str("| Status | Count |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!("| Fixed | {} |\n", report.fixed_count));
    md.push_str(&format!(
        "| Still Failing | {} |\n",
        report.still_failing_count
    ));
    md.push_str(&format!("| Skipped | {} |\n", report.skipped_count));
    md.push_str(&format!("| Errors | {} |\n\n", report.error_count));

    if !report.results.is_empty() {
        md.push_str("## Per-Finding Results\n\n");
        md.push_str("| Finding | Endpoint | Status | Details |\n");
        md.push_str("|---------|----------|--------|----------|\n");
        for result in &report.results {
            let status_icon = match result.status {
                RevalidationStatus::Fixed => "+",
                RevalidationStatus::StillFailing => "x",
                RevalidationStatus::SkippedNoRemediation => "~",
                RevalidationStatus::SkippedAlreadyFixed => "v",
                RevalidationStatus::Error => "!",
            };
            md.push_str(&format!(
                "| {} | `{}` | `{}` | {} |\n",
                result.finding_id, result.endpoint, status_icon, result.reason
            ));
        }
        md.push('\n');
    }

    md
}

pub fn generate_fix_lifecycle_transitions(report: &RevalidationReport) -> Vec<FixTransition> {
    report
        .results
        .iter()
        .filter(|r| r.status == RevalidationStatus::Fixed)
        .map(|r| FixTransition {
            finding_id: r.finding_id.clone(),
            from_state: "Verified".to_string(),
            to_state: "Fixed".to_string(),
            reason: r.reason.clone(),
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FixTransition {
    pub finding_id: String,
    pub from_state: String,
    pub to_state: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CIPreset {
    pub id: String,
    pub name: String,
    pub description: String,
    pub stages: Vec<crate::ci_pipeline::CIPipelineStage>,
    pub policy: crate::ci::PolicyConfig,
    pub scan_command: String,
    pub schedule_cron: String,
}

impl CIPreset {
    pub fn rest_api() -> Self {
        Self {
            id: "rest-api".to_string(),
            name: "REST API Security Scan".to_string(),
            description: "OpenAPI-driven BOLA/BFLA scan with CI gate, SARIF, and notifications."
                .to_string(),
            stages: vec![
                crate::ci_pipeline::CIPipelineStage::Gate,
                crate::ci_pipeline::CIPipelineStage::Sarif,
                crate::ci_pipeline::CIPipelineStage::Notify,
                crate::ci_pipeline::CIPipelineStage::Summary,
                crate::ci_pipeline::CIPipelineStage::Upload,
            ],
            policy: {
                let mut p = crate::ci::PolicyConfig::default();
                p.fail_on_high = true;
                p
            },
            scan_command: "baloncore scan-openapi-bola --base-url $BALONCORE_BASE_URL --openapi-url $BALONCORE_OPENAPI_URL --owner-profile $BALONCORE_OWNER --ci-anonymous-exposure"
                .to_string(),
            schedule_cron: "0 6 * * 1-5".to_string(),
        }
    }

    pub fn graphql_api() -> Self {
        Self {
            id: "graphql-api".to_string(),
            name: "GraphQL API Security Scan".to_string(),
            description: "GraphQL introspection-based scan with CI gate, SARIF, and PR review."
                .to_string(),
            stages: vec![
                crate::ci_pipeline::CIPipelineStage::Gate,
                crate::ci_pipeline::CIPipelineStage::Sarif,
                crate::ci_pipeline::CIPipelineStage::Notify,
                crate::ci_pipeline::CIPipelineStage::Revalidate,
            ],
            policy: {
                let mut p = crate::ci::PolicyConfig::default();
                p.fail_on_critical = true;
                p.fail_on_high = true;
                p.fail_on_medium = true;
                p
            },
            scan_command:
                "baloncore ci-pipeline-run --config .baloncore/ci/pipeline_config.json --ci"
                    .to_string(),
            schedule_cron: "0 6 * * 1-5".to_string(),
        }
    }

    pub fn security_audit() -> Self {
        Self {
            id: "security-audit".to_string(),
            name: "Full Security Audit".to_string(),
            description:
                "Comprehensive scan with evidence verification, redaction checks, and full notification suite."
                    .to_string(),
            stages: vec![
                crate::ci_pipeline::CIPipelineStage::Gate,
                crate::ci_pipeline::CIPipelineStage::Sarif,
                crate::ci_pipeline::CIPipelineStage::Notify,
                crate::ci_pipeline::CIPipelineStage::Summary,
                crate::ci_pipeline::CIPipelineStage::Revalidate,
                crate::ci_pipeline::CIPipelineStage::Upload,
            ],
            policy: {
                let mut p = crate::ci::PolicyConfig::default();
                p.fail_on_unsigned_evidence = true;
                p.fail_on_untrusted_signer = true;
                p.fail_on_anonymous_exposure = true;
                p.fail_on_regression_failure = true;
                p
            },
            scan_command:
                "baloncore ci-pipeline-run --config .baloncore/ci/pipeline_config.json --ci --generate-workflow"
                    .to_string(),
            schedule_cron: "0 2 * * 0".to_string(),
        }
    }

    pub fn all_presets() -> Vec<Self> {
        vec![
            Self::rest_api(),
            Self::graphql_api(),
            Self::security_audit(),
        ]
    }

    pub fn by_id(id: &str) -> Option<Self> {
        Self::all_presets().into_iter().find(|p| p.id == id)
    }

    pub fn to_pipeline_config(&self, project: &str) -> crate::ci_pipeline::CIPipelineConfig {
        crate::ci_pipeline::CIPipelineConfig {
            version: 1,
            project: project.to_string(),
            stages: self.stages.clone(),
            policy: self.policy.clone(),
            notifications: vec![],
            github_actions: None,
        }
    }
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_finding(
        id: &str,
        endpoint: &str,
        state: crate::lifecycle::FindingState,
    ) -> FindingRecord {
        FindingRecord {
            finding_id: id.to_string(),
            scan_id: format!("scan-{id}"),
            fingerprint: format!("fp-{id}"),
            classification: "BOLA".to_string(),
            vulnerability_class: "bola".to_string(),
            endpoint: endpoint.to_string(),
            object_id: format!("obj-{id}"),
            owner_profile: "user_b".to_string(),
            tested_profile: "user_a".to_string(),
            severity: "high".to_string(),
            score: 80,
            state,
            first_seen_run: "run-1".to_string(),
            last_seen_run: "run-1".to_string(),
            first_seen_at: 1000,
            last_seen_at: 1000,
            seen_count: 1,
            latest_artifacts: String::new(),
            latest_evidence_dir: String::new(),
            transitions: vec![],
            defense_classifications: vec![],
        }
    }

    #[test]
    fn revalidation_status_names() {
        assert_eq!(RevalidationStatus::Fixed.as_str(), "fixed");
        assert_eq!(RevalidationStatus::StillFailing.as_str(), "still-failing");
        assert_eq!(
            RevalidationStatus::SkippedNoRemediation.as_str(),
            "skipped-no-remediation"
        );
        assert_eq!(
            RevalidationStatus::SkippedAlreadyFixed.as_str(),
            "skipped-already-fixed"
        );
        assert_eq!(RevalidationStatus::Error.as_str(), "error");
    }

    #[test]
    fn regression_verdict_summary_passed() {
        let passed = RegressionVerdictSummary {
            passed_checks: 3,
            failed_checks: 0,
            total_checks: 3,
        };
        assert!(passed.passed());
        assert_eq!(passed.verdict_str(), "Fixed");

        let failed = RegressionVerdictSummary {
            passed_checks: 1,
            failed_checks: 2,
            total_checks: 3,
        };
        assert!(!failed.passed());
        assert_eq!(failed.verdict_str(), "StillFailing");
    }

    #[test]
    fn runner_skips_already_fixed_findings() {
        let plan = RevalidationPlan {
            pr_number: 42,
            affected_endpoints: vec!["/api/invoices/{id}".to_string()],
            affected_findings: vec![RevalidationTarget {
                finding_id: "f-123".to_string(),
                endpoint: "GET /api/invoices/{id}".to_string(),
                classification: "BOLA".to_string(),
                reason: "endpoint changed".to_string(),
            }],
            retest_commands: vec![],
            summary: String::new(),
        };
        let findings = vec![make_test_finding(
            "f-123",
            "GET /api/invoices/{id}",
            crate::lifecycle::FindingState::Fixed,
        )];
        let runner = RevalidationRunner::new(plan, findings, ".baloncore/evidence/index.json");
        let report = runner.run();
        assert_eq!(report.total_targets, 1);
        assert_eq!(report.skipped_count, 1);
        assert_eq!(report.fixed_count, 0);
        assert_eq!(
            report.results[0].status,
            RevalidationStatus::SkippedAlreadyFixed
        );
    }

    #[test]
    fn runner_skips_missing_finding() {
        let plan = RevalidationPlan {
            pr_number: 1,
            affected_endpoints: vec![],
            affected_findings: vec![RevalidationTarget {
                finding_id: "f-gone".to_string(),
                endpoint: "GET /api/gone".to_string(),
                classification: "BOLA".to_string(),
                reason: "removed endpoint".to_string(),
            }],
            retest_commands: vec![],
            summary: String::new(),
        };
        let runner = RevalidationRunner::new(plan, vec![], ".baloncore/evidence/index.json");
        let report = runner.run();
        assert_eq!(report.error_count, 1);
        assert_eq!(
            report.results[0].status,
            RevalidationStatus::SkippedNoRemediation
        );
    }

    #[test]
    fn runner_skips_when_no_remediation_file() {
        let plan = RevalidationPlan {
            pr_number: 1,
            affected_endpoints: vec![],
            affected_findings: vec![RevalidationTarget {
                finding_id: "f-1".to_string(),
                endpoint: "GET /api/test".to_string(),
                classification: "BOLA".to_string(),
                reason: "endpoint changed".to_string(),
            }],
            retest_commands: vec![],
            summary: String::new(),
        };
        let find = make_test_finding(
            "f-1",
            "GET /api/test",
            crate::lifecycle::FindingState::Verified,
        );
        let runner = RevalidationRunner::new(plan, vec![find], ".baloncore/evidence/index.json");
        let report = runner.run();
        assert_eq!(report.skipped_count, 1);
        assert_eq!(
            report.results[0].status,
            RevalidationStatus::SkippedNoRemediation
        );
    }

    #[test]
    fn generate_fix_lifecycle_transitions_only_fixed() {
        let report = RevalidationReport {
            pr_number: 1,
            started_at: 1000,
            finished_at: 1001,
            total_targets: 3,
            fixed_count: 1,
            still_failing_count: 1,
            skipped_count: 1,
            error_count: 0,
            results: vec![
                RevalidationResult {
                    finding_id: "f-fixed".to_string(),
                    endpoint: "GET /api/a".to_string(),
                    classification: "BOLA".to_string(),
                    status: RevalidationStatus::Fixed,
                    reason: "2/2 passed".to_string(),
                    remediation_path: None,
                    regression_verdict: Some("Fixed".to_string()),
                    checks_passed: Some(2),
                    checks_total: Some(2),
                    duration_ms: 42,
                },
                RevalidationResult {
                    finding_id: "f-failing".to_string(),
                    endpoint: "GET /api/b".to_string(),
                    classification: "BOLA".to_string(),
                    status: RevalidationStatus::StillFailing,
                    reason: "1/2 passed".to_string(),
                    remediation_path: None,
                    regression_verdict: Some("StillFailing".to_string()),
                    checks_passed: Some(1),
                    checks_total: Some(2),
                    duration_ms: 55,
                },
                RevalidationResult {
                    finding_id: "f-skipped".to_string(),
                    endpoint: "GET /api/c".to_string(),
                    classification: "BOLA".to_string(),
                    status: RevalidationStatus::SkippedNoRemediation,
                    reason: "no remediation".to_string(),
                    remediation_path: None,
                    regression_verdict: None,
                    checks_passed: None,
                    checks_total: None,
                    duration_ms: 10,
                },
            ],
            summary: String::new(),
        };
        let transitions = generate_fix_lifecycle_transitions(&report);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].finding_id, "f-fixed");
        assert_eq!(transitions[0].to_state, "Fixed");
    }

    #[test]
    fn render_revalidation_report_includes_summary() {
        let report = RevalidationReport {
            pr_number: 99,
            started_at: 1000,
            finished_at: 1001,
            total_targets: 2,
            fixed_count: 1,
            still_failing_count: 1,
            skipped_count: 0,
            error_count: 0,
            results: vec![
                RevalidationResult {
                    finding_id: "f1".to_string(),
                    endpoint: "GET /api/a".to_string(),
                    classification: "BOLA".to_string(),
                    status: RevalidationStatus::Fixed,
                    reason: "ok".to_string(),
                    remediation_path: None,
                    regression_verdict: None,
                    checks_passed: None,
                    checks_total: None,
                    duration_ms: 10,
                },
                RevalidationResult {
                    finding_id: "f2".to_string(),
                    endpoint: "GET /api/b".to_string(),
                    classification: "BOLA".to_string(),
                    status: RevalidationStatus::StillFailing,
                    reason: "failed".to_string(),
                    remediation_path: None,
                    regression_verdict: None,
                    checks_passed: None,
                    checks_total: None,
                    duration_ms: 20,
                },
            ],
            summary: "Revalidation complete".to_string(),
        };
        let md = render_revalidation_report(&report);
        assert!(md.contains("**PR:** #99"));
        assert!(md.contains("Revalidation complete"));
        assert!(md.contains("Revalidation complete"));
        assert!(md.contains("| Fixed | 1 |"));
        assert!(md.contains("| Still Failing | 1 |"));
        assert!(md.contains("f1"));
        assert!(md.contains("f2"));
    }

    #[test]
    fn ci_preset_rest_api_has_correct_stages() {
        let preset = CIPreset::rest_api();
        assert_eq!(preset.id, "rest-api");
        assert_eq!(preset.stages.len(), 5);
        assert!(preset
            .stages
            .contains(&crate::ci_pipeline::CIPipelineStage::Gate));
        assert!(preset
            .stages
            .contains(&crate::ci_pipeline::CIPipelineStage::Sarif));
        assert!(preset
            .stages
            .contains(&crate::ci_pipeline::CIPipelineStage::Upload));
    }

    #[test]
    fn ci_preset_graphql_has_revalidate() {
        let preset = CIPreset::graphql_api();
        assert_eq!(preset.id, "graphql-api");
        assert!(preset
            .stages
            .contains(&crate::ci_pipeline::CIPipelineStage::Revalidate));
    }

    #[test]
    fn ci_preset_security_audit_is_most_comprehensive() {
        let preset = CIPreset::security_audit();
        assert_eq!(preset.stages.len(), 6);
        assert!(preset.policy.fail_on_unsigned_evidence);
        assert!(preset.policy.fail_on_anonymous_exposure);
    }

    #[test]
    fn ci_preset_lookup_by_id() {
        assert!(CIPreset::by_id("rest-api").is_some());
        assert!(CIPreset::by_id("graphql-api").is_some());
        assert!(CIPreset::by_id("security-audit").is_some());
        assert!(CIPreset::by_id("nonexistent").is_none());
    }

    #[test]
    fn ci_preset_to_pipeline_config() {
        let config = CIPreset::rest_api().to_pipeline_config("test-project");
        assert_eq!(config.project, "test-project");
        assert_eq!(config.stages.len(), 5);
        assert!(config.policy.fail_on_high);
    }

    #[test]
    fn unix_seconds_is_reasonable() {
        let ts = unix_seconds();
        assert!(ts > 1_700_000_000, "unix timestamp should be >= ~2024");
    }

    #[test]
    fn regression_verdict_summary_empty_passes() {
        let empty = RegressionVerdictSummary {
            passed_checks: 0,
            failed_checks: 0,
            total_checks: 0,
        };
        assert!(!empty.passed(), "empty (0 checks) should not pass");
        assert_eq!(empty.verdict_str(), "StillFailing");
    }

    #[test]
    fn fix_transition_serialization() {
        let transition = FixTransition {
            finding_id: "f-1".to_string(),
            from_state: "Verified".to_string(),
            to_state: "Fixed".to_string(),
            reason: "passed revalidation".to_string(),
        };
        let json = serde_json::to_string_pretty(&transition).unwrap();
        assert!(json.contains("f-1"));
        assert!(json.contains("Fixed"));
    }
}
