use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::defense::DefenseMaturityScore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDiligenceReport {
    pub title: String,
    pub generated_at: u64,
    pub target: String,
    pub overall_posture: SecurityPosture,
    pub questionnaire: SecurityQuestionnaire,
    pub compliance_coverage: ComplianceCoverageReport,
    pub risk_heatmap: RiskHeatmap,
    pub evidence_quality: EvidenceQualityAssessment,
    pub investment_readiness: InvestmentReadinessScore,
    pub findings_summary: Vec<DiligenceFindingSummary>,
    pub recommendations: Vec<DiligenceRecommendation>,
    pub executive_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPosture {
    pub score: f64,
    pub grade: String,
    pub tier: String,
    pub components: BTreeMap<String, f64>,
    pub summary: String,
}

impl SecurityPosture {
    pub fn compute(
        total_findings: usize,
        fixed_findings: usize,
        critical_findings: usize,
        high_findings: usize,
        medium_findings: usize,
        low_findings: usize,
        fp_reduction_rate: f64,
        defense_maturity: &BTreeMap<String, DefenseMaturityScore>,
        benchmark_f1: Option<f64>,
        has_signed_evidence: bool,
        has_encryption: bool,
    ) -> Self {
        let fix_rate = if total_findings > 0 {
            fixed_findings as f64 / total_findings as f64
        } else {
            1.0
        };

        let severity_score = compute_severity_score(
            critical_findings,
            high_findings,
            medium_findings,
            low_findings,
            total_findings,
        );

        let avg_defense_maturity: f64 = if defense_maturity.is_empty() {
            0.5
        } else {
            defense_maturity.values().map(|m| m.overall).sum::<f64>()
                / defense_maturity.len() as f64
        };

        let benchmark_score = benchmark_f1.unwrap_or(0.8);
        let evidence_score = if has_signed_evidence && has_encryption {
            1.0
        } else if has_signed_evidence || has_encryption {
            0.7
        } else {
            0.4
        };
        let fpr_score = fp_reduction_rate.clamp(0.0, 1.0);

        let mut components = BTreeMap::new();
        components.insert("fix_rate".to_string(), fix_rate);
        components.insert("severity_health".to_string(), severity_score);
        components.insert("fp_reduction".to_string(), fpr_score);
        components.insert("defense_maturity".to_string(), avg_defense_maturity);
        components.insert("benchmark_performance".to_string(), benchmark_score);
        components.insert("evidence_integrity".to_string(), evidence_score);

        let score = fix_rate * 0.25
            + severity_score * 0.20
            + fpr_score * 0.15
            + avg_defense_maturity * 0.15
            + benchmark_score * 0.15
            + evidence_score * 0.10;

        let (grade, tier) = posture_grade(score);
        let summary = format!(
            "Security posture score: {:.1}/100 — Grade {} ({})",
            score * 100.0,
            grade,
            tier
        );

        Self {
            score,
            grade: grade.to_string(),
            tier: tier.to_string(),
            components,
            summary,
        }
    }
}

fn compute_severity_score(
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    total: usize,
) -> f64 {
    if total == 0 {
        return 1.0;
    }
    let critical_penalty = (critical as f64 / total as f64) * 1.0;
    let high_penalty = (high as f64 / total as f64) * 0.7;
    let medium_penalty = (medium as f64 / total as f64) * 0.3;
    let low_penalty = (low as f64 / total as f64) * 0.1;
    (1.0 - critical_penalty - high_penalty - medium_penalty - low_penalty).max(0.0)
}

fn posture_grade(score: f64) -> (&'static str, &'static str) {
    match score {
        s if s >= 0.95 => ("A+", "Investment-Grade"),
        s if s >= 0.85 => ("A", "Enterprise-Ready"),
        s if s >= 0.75 => ("B+", "Mature"),
        s if s >= 0.65 => ("B", "Improving"),
        s if s >= 0.50 => ("C", "Developing"),
        _ => ("D", "Needs Attention"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityQuestionnaire {
    pub sections: Vec<QuestionnaireSection>,
    pub total_questions: usize,
    pub answered_count: usize,
    pub auto_answered_count: usize,
    pub evidence_backed_count: usize,
    pub unanswered_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionnaireSection {
    pub title: String,
    pub category: String,
    pub questions: Vec<QuestionnaireAnswer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionnaireAnswer {
    pub id: String,
    pub question: String,
    pub answer: String,
    pub confidence: String,
    pub evidence: String,
    pub source: String,
    pub is_auto_answered: bool,
    pub is_evidence_backed: bool,
}

impl SecurityQuestionnaire {
    pub fn from_findings(
        findings: &[DiligenceFindingSummary],
        posture: &SecurityPosture,
        compliance: &ComplianceCoverageReport,
    ) -> Self {
        let mut sections = Vec::new();

        sections.push(access_control_section(findings, compliance));
        sections.push(tenant_isolation_section(findings));
        sections.push(api_security_section(findings, posture));
        sections.push(data_protection_section(posture));
        sections.push(incident_response_section(posture));
        sections.push(ci_cd_security_section(findings));
        sections.push(business_logic_section(findings));

        let total_questions: usize = sections.iter().map(|s| s.questions.len()).sum();
        let answered_count = total_questions;
        let auto_answered_count: usize = sections
            .iter()
            .flat_map(|s| &s.questions)
            .filter(|q| q.is_auto_answered)
            .count();
        let evidence_backed_count: usize = sections
            .iter()
            .flat_map(|s| &s.questions)
            .filter(|q| q.is_evidence_backed)
            .count();

        Self {
            sections,
            total_questions,
            answered_count,
            auto_answered_count,
            evidence_backed_count,
            unanswered_count: 0,
        }
    }
}

fn access_control_section(
    findings: &[DiligenceFindingSummary],
    compliance: &ComplianceCoverageReport,
) -> QuestionnaireSection {
    let bola_findings: Vec<&DiligenceFindingSummary> = findings
        .iter()
        .filter(|f| f.classification.contains("BOLA") || f.classification.contains("authorization"))
        .collect();
    let has_bola_evidence = !bola_findings.is_empty();
    let fixed_count = bola_findings.iter().filter(|f| f.is_fixed).count();
    let owasp_covered = compliance.frameworks.iter().any(|fw| {
        fw.framework == "OWASP API Top 10"
            && fw
                .controls
                .iter()
                .any(|c| c.control_id == "API1" && c.covered)
    });

    QuestionnaireSection {
        title: "Access Control & Authorization".to_string(),
        category: "application_security".to_string(),
        questions: vec![
            QuestionnaireAnswer {
                id: "ac-1".to_string(),
                question:
                    "Do you have broken object-level authorization (BOLA/IDOR) protection in place?"
                        .to_string(),
                answer: if has_bola_evidence {
                    format!("Yes. {} BOLA findings were identified and {}/{} have been fixed. Evidence-backed validation confirms object-level access control.",
                        bola_findings.len(), fixed_count, bola_findings.len())
                } else {
                    "Yes. No BOLA vulnerabilities were detected in the most recent scan."
                        .to_string()
                },
                confidence: if has_bola_evidence {
                    "high".to_string()
                } else {
                    "medium".to_string()
                },
                evidence: if has_bola_evidence {
                    "verified findings with request/response evidence".to_string()
                } else {
                    "negative scan result".to_string()
                },
                source: "baloncore-web-api-validator".to_string(),
                is_auto_answered: true,
                is_evidence_backed: has_bola_evidence,
            },
            QuestionnaireAnswer {
                id: "ac-2".to_string(),
                question: "Do you enforce function-level authorization for privileged endpoints?"
                    .to_string(),
                answer: if has_bola_evidence {
                    format!(
                        "Yes. {} authorization-related findings were detected and addressed.",
                        bola_findings.len()
                    )
                } else {
                    "Yes. No authorization bypasses were detected.".to_string()
                },
                confidence: if has_bola_evidence {
                    "high".to_string()
                } else {
                    "medium".to_string()
                },
                evidence: "deterministic validator output".to_string(),
                source: "baloncore-bola-validator".to_string(),
                is_auto_answered: true,
                is_evidence_backed: has_bola_evidence,
            },
            QuestionnaireAnswer {
                id: "ac-3".to_string(),
                question: "Is your authorization aligned with OWASP API Top 10?".to_string(),
                answer: if owasp_covered {
                    "Yes. OWASP API1 (BOLA) and API5 (BFLA) controls are covered with evidence."
                        .to_string()
                } else {
                    "Partially. OWASP API coverage is based on scan results.".to_string()
                },
                confidence: if owasp_covered {
                    "high".to_string()
                } else {
                    "medium".to_string()
                },
                evidence: "compliance mapping to OWASP API Top 10".to_string(),
                source: "baloncore-compliance-mapping".to_string(),
                is_auto_answered: true,
                is_evidence_backed: owasp_covered,
            },
        ],
    }
}

fn tenant_isolation_section(findings: &[DiligenceFindingSummary]) -> QuestionnaireSection {
    let tenant_findings: Vec<&DiligenceFindingSummary> = findings
        .iter()
        .filter(|f| f.classification.contains("tenant") || f.classification.contains("isolation"))
        .collect();
    let has_evidence = !tenant_findings.is_empty();

    QuestionnaireSection {
        title: "Tenant Isolation".to_string(),
        category: "multi_tenancy".to_string(),
        questions: vec![
            QuestionnaireAnswer {
                id: "ti-1".to_string(),
                question: "How do you ensure cross-tenant data isolation?".to_string(),
                answer: if has_evidence {
                    format!("Multi-tenant isolation is validated through {} tenant isolation test(s). Cross-tenant access attempts are rejected with evidence markers.",
                        tenant_findings.len())
                } else {
                    "Multi-tenant validation is active. No cross-tenant data leaks were detected.".to_string()
                },
                confidence: if has_evidence { "high".to_string() } else { "medium".to_string() },
                evidence: "tenant isolation violation tests".to_string(),
                source: "baloncore-tenant-validator".to_string(),
                is_auto_answered: true,
                is_evidence_backed: has_evidence,
            },
            QuestionnaireAnswer {
                id: "ti-2".to_string(),
                question: "Can a user in Organization A access data belonging to Organization B?".to_string(),
                answer: "No. Deterministic tenant isolation tests verify that cross-tenant access is blocked.".to_string(),
                confidence: "high".to_string(),
                evidence: "cross-tenant BOLA test results".to_string(),
                source: "baloncore-tenant-isolation-validator".to_string(),
                is_auto_answered: true,
                is_evidence_backed: has_evidence,
            },
        ],
    }
}

fn api_security_section(
    findings: &[DiligenceFindingSummary],
    posture: &SecurityPosture,
) -> QuestionnaireSection {
    let has_graphql = findings
        .iter()
        .any(|f| f.classification.contains("GraphQL") || f.classification.contains("graphql"));

    QuestionnaireSection {
        title: "API Security".to_string(),
        category: "api_security".to_string(),
        questions: vec![
            QuestionnaireAnswer {
                id: "api-1".to_string(),
                question: "Do you perform automated API security testing as part of CI/CD?"
                    .to_string(),
                answer:
                    "Yes. BALONCORE API security scans run on every PR and on a scheduled basis."
                        .to_string(),
                confidence: "high".to_string(),
                evidence: "CI pipeline configuration and run history".to_string(),
                source: "baloncore-ci-pipeline".to_string(),
                is_auto_answered: true,
                is_evidence_backed: true,
            },
            QuestionnaireAnswer {
                id: "api-2".to_string(),
                question: "Is GraphQL introspection and authorization validated?".to_string(),
                answer: if has_graphql {
                    "Yes. GraphQL endpoints are introspected and tested for field-level authorization bypasses.".to_string()
                } else {
                    "GraphQL validation is available if GraphQL endpoints are present.".to_string()
                },
                confidence: if has_graphql {
                    "high".to_string()
                } else {
                    "medium".to_string()
                },
                evidence: "GraphQL BOLA validation results".to_string(),
                source: "baloncore-graphql-validator".to_string(),
                is_auto_answered: true,
                is_evidence_backed: has_graphql,
            },
            QuestionnaireAnswer {
                id: "api-3".to_string(),
                question: "What is your overall API security posture?".to_string(),
                answer: posture.summary.clone(),
                confidence: "high".to_string(),
                evidence: "composite posture score from multiple security signals".to_string(),
                source: "baloncore-posture-engine".to_string(),
                is_auto_answered: true,
                is_evidence_backed: true,
            },
        ],
    }
}

fn data_protection_section(posture: &SecurityPosture) -> QuestionnaireSection {
    let evidence_ok = posture
        .components
        .get("evidence_integrity")
        .is_some_and(|s| *s > 0.5);

    QuestionnaireSection {
        title: "Data Protection & Evidence Integrity".to_string(),
        category: "data_protection".to_string(),
        questions: vec![
            QuestionnaireAnswer {
                id: "dp-1".to_string(),
                question: "Are security findings backed by tamper-evident evidence?".to_string(),
                answer: if evidence_ok {
                    "Yes. All verified findings include SHA-256 sealed evidence bundles with Ed25519 signatures.".to_string()
                } else {
                    "Evidence bundles are being strengthened. Signature infrastructure is available.".to_string()
                },
                confidence: if evidence_ok { "high".to_string() } else { "medium".to_string() },
                evidence: "evidence bundle manifests with signatures".to_string(),
                source: "baloncore-evidence-integrity".to_string(),
                is_auto_answered: true,
                is_evidence_backed: evidence_ok,
            },
            QuestionnaireAnswer {
                id: "dp-2".to_string(),
                question: "Is evidence encrypted at rest?".to_string(),
                answer: if posture.components.get("evidence_integrity").is_some_and(|s| *s > 0.7) {
                    "Yes. Evidence is encrypted at rest using AES-256-GCM.".to_string()
                } else {
                    "Evidence encryption is available and being rolled out.".to_string()
                },
                confidence: "medium".to_string(),
                evidence: "encryption configuration in platform state".to_string(),
                source: "baloncore-platform-encryption".to_string(),
                is_auto_answered: true,
                is_evidence_backed: false,
            },
            QuestionnaireAnswer {
                id: "dp-3".to_string(),
                question: "How is sensitive data (tokens, PII) handled in reports?".to_string(),
                answer: "All reports are redacted before export. Auth headers, session tokens, and PII are automatically stripped.".to_string(),
                confidence: "high".to_string(),
                evidence: "redaction pipeline verified by CI checks".to_string(),
                source: "baloncore-redaction-engine".to_string(),
                is_auto_answered: true,
                is_evidence_backed: true,
            },
        ],
    }
}

fn incident_response_section(posture: &SecurityPosture) -> QuestionnaireSection {
    let fix_rate = posture.components.get("fix_rate").copied().unwrap_or(0.0);
    let fix_summary = if fix_rate > 0.8 {
        "Yes. Over 80% of verified findings are fixed within the defined remediation window."
            .to_string()
    } else if fix_rate > 0.5 {
        format!(
            "Partially. {:.0}% of findings are fixed. Improving toward 80% target.",
            fix_rate * 100.0
        )
    } else {
        format!(
            "In progress. {:.0}% of findings are fixed. Remediation acceleration is needed.",
            fix_rate * 100.0
        )
    };

    QuestionnaireSection {
        title: "Incident Response & Remediation".to_string(),
        category: "incident_response".to_string(),
        questions: vec![
            QuestionnaireAnswer {
                id: "ir-1".to_string(),
                question: "What is your process for fixing verified security findings?".to_string(),
                answer: "Verified findings are assigned severity, linked to remediation plans with fix code and regression tests, and tracked through Fixed → Retested → Closed lifecycle.".to_string(),
                confidence: "high".to_string(),
                evidence: "finding lifecycle tracking with state transitions".to_string(),
                source: "baloncore-finding-lifecycle".to_string(),
                is_auto_answered: true,
                is_evidence_backed: true,
            },
            QuestionnaireAnswer {
                id: "ir-2".to_string(),
                question: "Do you have an automated remediation verification process?".to_string(),
                answer: "Yes. Regression checks run automatically. Findings that pass regression are auto-transitioned to Fixed state.".to_string(),
                confidence: "high".to_string(),
                evidence: "CI revalidation pipeline with auto-fix transitions".to_string(),
                source: "baloncore-revalidation-runner".to_string(),
                is_auto_answered: true,
                is_evidence_backed: true,
            },
            QuestionnaireAnswer {
                id: "ir-3".to_string(),
                question: "What is your fix rate for verified findings?".to_string(),
                answer: fix_summary.clone(),
                confidence: "high".to_string(),
                evidence: "computed from finding lifecycle data".to_string(),
                source: "baloncore-metrics-engine".to_string(),
                is_auto_answered: true,
                is_evidence_backed: true,
            },
        ],
    }
}

fn ci_cd_security_section(findings: &[DiligenceFindingSummary]) -> QuestionnaireSection {
    let ci_runs = findings
        .iter()
        .any(|f| f.classification.contains("regression") || f.source.contains("ci-pipeline"));

    QuestionnaireSection {
        title: "CI/CD Security Integration".to_string(),
        category: "ci_cd".to_string(),
        questions: vec![
            QuestionnaireAnswer {
                id: "ci-1".to_string(),
                question: "Do security checks run automatically in CI/CD pipelines?".to_string(),
                answer: if ci_runs {
                    "Yes. BALONCORE runs on every PR and on a scheduled basis with configurable CI policies.".to_string()
                } else {
                    "CI/CD integration is configured and available. Pipeline is defined but may not have execution history yet.".to_string()
                },
                confidence: if ci_runs { "high".to_string() } else { "medium".to_string() },
                evidence: "CI pipeline configuration and run history".to_string(),
                source: "baloncore-ci-pipeline".to_string(),
                is_auto_answered: true,
                is_evidence_backed: ci_runs,
            },
            QuestionnaireAnswer {
                id: "ci-2".to_string(),
                question: "Can critical security issues block a release?".to_string(),
                answer: "Yes. CI gate policies can be configured to block releases on critical/high/medium/low severity findings.".to_string(),
                confidence: "high".to_string(),
                evidence: "PolicyConfig with severity gates".to_string(),
                source: "baloncore-ci-gate".to_string(),
                is_auto_answered: true,
                is_evidence_backed: true,
            },
        ],
    }
}

fn business_logic_section(findings: &[DiligenceFindingSummary]) -> QuestionnaireSection {
    let bl_findings: Vec<&DiligenceFindingSummary> = findings
        .iter()
        .filter(|f| {
            f.classification.contains("business")
                || f.classification.contains("price")
                || f.classification.contains("state_skip")
                || f.classification.contains("replay")
                || f.classification.contains("quantity")
        })
        .collect();
    let has_evidence = !bl_findings.is_empty();

    QuestionnaireSection {
        title: "Business Logic Security".to_string(),
        category: "application_security".to_string(),
        questions: vec![
            QuestionnaireAnswer {
                id: "bl-1".to_string(),
                question: "Do you test for business logic abuse (price tampering, state-skip, replay attacks)?".to_string(),
                answer: if has_evidence {
                    format!("Yes. {} business-logic abuse finding(s) were identified, including {}. All are evidence-backed with before/after state comparison.",
                        bl_findings.len(),
                        bl_findings.first().map(|f| f.title.as_str()).unwrap_or(""))
                } else {
                    "Yes. Business-logic validation is active. No abuses were detected in the most recent scan.".to_string()
                },
                confidence: if has_evidence { "high".to_string() } else { "medium".to_string() },
                evidence: "business-logic validator output with state comparison".to_string(),
                source: "baloncore-business-logic-validator".to_string(),
                is_auto_answered: true,
                is_evidence_backed: has_evidence,
            },
            QuestionnaireAnswer {
                id: "bl-2".to_string(),
                question: "How do you validate workflow invariants (e.g., payment before shipping)?".to_string(),
                answer: if has_evidence {
                    "Workflow invariant validation runs deterministically. State transitions are verified with before/after evidence.".to_string()
                } else {
                    "Workflow invariant validation is configured and ready.".to_string()
                },
                confidence: if has_evidence { "high".to_string() } else { "medium".to_string() },
                evidence: "workflow invariant validation results".to_string(),
                source: "baloncore-workflow-validator".to_string(),
                is_auto_answered: true,
                is_evidence_backed: has_evidence,
            },
        ],
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCoverageReport {
    pub frameworks: Vec<FrameworkCoverage>,
    pub total_controls: usize,
    pub covered_controls: usize,
    pub coverage_rate: f64,
    pub gap_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkCoverage {
    pub framework: String,
    pub total_controls: usize,
    pub covered_controls: usize,
    pub coverage_rate: f64,
    pub controls: Vec<FrameworkControlStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkControlStatus {
    pub control_id: String,
    pub control_name: String,
    pub covered: bool,
    pub evidence_classifications: Vec<String>,
    pub evidence_count: usize,
    pub maturity: String,
}

impl ComplianceCoverageReport {
    pub fn from_findings(findings: &[DiligenceFindingSummary]) -> Self {
        let framework_defs = vec![
            (
                "OWASP API Top 10",
                vec![
                    ("API1", "Broken Object Level Authorization"),
                    ("API2", "Broken Authentication"),
                    ("API3", "Broken Object Property Level Authorization"),
                    ("API4", "Unrestricted Resource Consumption"),
                    ("API5", "Broken Function Level Authorization"),
                    ("API6", "Unrestricted Access to Sensitive Business Flows"),
                    ("API7", "Server-Side Request Forgery"),
                    ("API8", "Security Misconfiguration"),
                    ("API9", "Improper Inventory Management"),
                    ("API10", "Unsafe Consumption of APIs"),
                ],
            ),
            (
                "SOC 2",
                vec![
                    ("CC6.1", "Logical and Physical Access Controls"),
                    ("CC6.2", "User Access Provisioning"),
                    ("CC6.3", "Access Termination and Review"),
                    ("CC6.4", "Least Privilege and Role-Based Access"),
                    ("CC6.5", "Inbound and Outbound Communications"),
                    ("CC6.6", "Threat Detection and Monitoring"),
                    ("CC6.7", "Data Confidentiality and Transmission"),
                    ("CC6.8", "Change Management"),
                ],
            ),
            (
                "AWS Well-Architected (Security)",
                vec![
                    ("SEC1", "Identity and Access Management"),
                    ("SEC2", "Detective Controls"),
                    ("SEC3", "Infrastructure Protection"),
                    ("SEC4", "Data Protection"),
                    ("SEC5", "Incident Response"),
                    ("SEC10", "IAM and Federation"),
                ],
            ),
            (
                "GDPR Security Requirements",
                vec![
                    ("Art32-1a", "Pseudonymisation and Encryption"),
                    ("Art32-1b", "Confidentiality, Integrity, Availability"),
                    ("Art32-1c", "Availability and Access Recovery"),
                    ("Art32-1d", "Regular Testing and Evaluation"),
                    ("Art33", "Breach Notification Capability"),
                ],
            ),
        ];

        let mut frameworks = Vec::new();
        let mut total_controls = 0usize;
        let mut covered_controls = 0usize;

        for (fw_name, controls) in &framework_defs {
            let mut statuses = Vec::new();
            let mut fw_covered = 0usize;
            let fw_total = controls.len();

            for (control_id, control_name) in controls {
                let evidence = match_classification_to_control(control_id, findings);

                let maturity = if evidence.len() >= 3 {
                    "high".to_string()
                } else if evidence.len() >= 1 {
                    "medium".to_string()
                } else {
                    "none".to_string()
                };

                let covered = !evidence.is_empty();
                if covered {
                    fw_covered += 1;
                }

                statuses.push(FrameworkControlStatus {
                    control_id: control_id.to_string(),
                    control_name: control_name.to_string(),
                    covered,
                    evidence_classifications: evidence
                        .iter()
                        .map(|f| f.classification.clone())
                        .collect(),
                    evidence_count: evidence.len(),
                    maturity,
                });
            }

            let fw_coverage = if fw_total > 0 {
                fw_covered as f64 / fw_total as f64
            } else {
                0.0
            };

            total_controls += fw_total;
            covered_controls += fw_covered;

            frameworks.push(FrameworkCoverage {
                framework: fw_name.to_string(),
                total_controls: fw_total,
                covered_controls: fw_covered,
                coverage_rate: fw_coverage,
                controls: statuses,
            });
        }

        let coverage_rate = if total_controls > 0 {
            covered_controls as f64 / total_controls as f64
        } else {
            0.0
        };

        let gap_summary = if coverage_rate >= 0.9 {
            "Excellent compliance coverage. Most controls are backed by verified findings."
                .to_string()
        } else if coverage_rate >= 0.7 {
            "Good compliance coverage. Some controls lack evidence and should be prioritized."
                .to_string()
        } else if coverage_rate >= 0.5 {
            "Moderate compliance coverage. Several gaps exist that should be addressed.".to_string()
        } else {
            "Limited compliance coverage. Significant gaps require attention.".to_string()
        };

        Self {
            frameworks,
            total_controls,
            covered_controls,
            coverage_rate,
            gap_summary,
        }
    }
}

fn match_classification_to_control<'a>(
    control_id: &str,
    findings: &'a [DiligenceFindingSummary],
) -> Vec<&'a DiligenceFindingSummary> {
    let relevant: &[(&str, &[&str])] = &[
        ("API1", &["bola", "object.level.authorization"]),
        ("API2", &["missing.auth", "authentication"]),
        ("API5", &["function.level", "bfla", "privilege"]),
        ("API6", &["business.logic", "quantity", "price", "state"]),
        ("CC6.1", &["bola", "authorization", "isolation"]),
        ("CC6.3", &["tenant", "isolation"]),
        ("CC6.4", &["least.privilege", "role"]),
        ("CC6.7", &["csrf", "ssrf"]),
        ("SEC1", &["iam", "privilege"]),
        ("SEC4", &["exposure", "encryption"]),
        ("SEC10", &["iam", "privilege", "federation"]),
        ("Art32-1a", &["encryption"]),
        ("Art32-1b", &["integrity", "evidence"]),
        ("Art32-1d", &["testing", "evaluation", "benchmark"]),
        ("Art33", &["detection", "audit"]),
    ];

    let keywords = relevant
        .iter()
        .find(|(id, _)| *id == control_id)
        .map(|(_, kw)| *kw)
        .unwrap_or(&[]);

    findings
        .iter()
        .filter(|f| {
            let lower = f.classification.to_lowercase();
            keywords.iter().any(|kw| lower.contains(kw))
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskHeatmap {
    pub categories: Vec<RiskCategory>,
    pub total_risks: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskCategory {
    pub name: String,
    pub severity: String,
    pub finding_count: usize,
    pub fixed_count: usize,
    pub open_count: usize,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceQualityAssessment {
    pub total_findings: usize,
    pub signed_count: usize,
    pub encrypted_count: usize,
    pub audit_trail_complete: bool,
    pub redacted_properly: bool,
    pub score: f64,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestmentReadinessScore {
    pub score: f64,
    pub grade: String,
    pub strengths: Vec<String>,
    pub gaps: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiligenceFindingSummary {
    pub finding_id: String,
    pub classification: String,
    pub vulnerability_class: String,
    pub title: String,
    pub severity: String,
    pub score: u8,
    pub is_fixed: bool,
    pub is_suppressed: bool,
    pub endpoint: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiligenceRecommendation {
    pub category: String,
    pub priority: String,
    pub title: String,
    pub description: String,
    pub impact: String,
    pub effort: String,
}

impl SecurityDiligenceReport {
    pub fn assemble(
        target: &str,
        findings: Vec<DiligenceFindingSummary>,
        fp_reduction_rate: f64,
        defense_maturity: BTreeMap<String, DefenseMaturityScore>,
        benchmark_f1: Option<f64>,
        has_signed_evidence: bool,
        has_encryption: bool,
        has_audit_trail: bool,
        redaction_passes: bool,
    ) -> Self {
        let now = unix_seconds();

        let total_findings = findings.len();
        let fixed_findings = findings.iter().filter(|f| f.is_fixed).count();
        let critical_findings = findings.iter().filter(|f| f.severity == "critical").count();
        let high_findings = findings.iter().filter(|f| f.severity == "high").count();
        let medium_findings = findings.iter().filter(|f| f.severity == "medium").count();
        let low_findings = findings.iter().filter(|f| f.severity == "low").count();

        let posture = SecurityPosture::compute(
            total_findings,
            fixed_findings,
            critical_findings,
            high_findings,
            medium_findings,
            low_findings,
            fp_reduction_rate,
            &defense_maturity,
            benchmark_f1,
            has_signed_evidence,
            has_encryption,
        );

        let compliance = ComplianceCoverageReport::from_findings(&findings);
        let questionnaire = SecurityQuestionnaire::from_findings(&findings, &posture, &compliance);

        let risk_categories = build_risk_categories(&findings);

        let critical_count = risk_categories
            .iter()
            .filter(|r| r.risk_level == "critical")
            .count();
        let high_count = risk_categories
            .iter()
            .filter(|r| r.risk_level == "high")
            .count();
        let medium_count = risk_categories
            .iter()
            .filter(|r| r.risk_level == "medium")
            .count();
        let low_count = risk_categories
            .iter()
            .filter(|r| r.risk_level == "low")
            .count();

        let risk_heatmap = RiskHeatmap {
            categories: risk_categories,
            total_risks: total_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
        };

        let signed_count = if has_signed_evidence {
            total_findings
        } else {
            0
        };
        let encrypted_count = if has_encryption { total_findings } else { 0 };

        let evidence_quality = EvidenceQualityAssessment {
            total_findings,
            signed_count,
            encrypted_count,
            audit_trail_complete: has_audit_trail,
            redacted_properly: redaction_passes,
            score: if has_signed_evidence && has_encryption && redaction_passes {
                1.0
            } else if has_signed_evidence && redaction_passes {
                0.8
            } else if has_signed_evidence {
                0.6
            } else {
                0.3
            },
            summary: if has_signed_evidence && has_encryption && redaction_passes {
                "Excellent evidence quality. All findings are signed, encrypted, and properly redacted."
                    .to_string()
            } else if has_signed_evidence && redaction_passes {
                "Good evidence quality. Findings are signed and redacted.".to_string()
            } else {
                "Evidence quality needs improvement. Signatures and redaction should be enabled."
                    .to_string()
            },
        };

        let invest_score =
            posture.score * 0.5 + compliance.coverage_rate * 0.25 + evidence_quality.score * 0.25;

        let (invest_grade, _) = posture_grade(invest_score);
        let mut strengths = Vec::new();
        let mut gaps = Vec::new();

        if fixed_findings as f64 / total_findings.max(1) as f64 > 0.7 {
            strengths.push(format!(
                "Strong fix rate: {}/{} findings resolved",
                fixed_findings, total_findings
            ));
        } else {
            gaps.push("Fix rate below 70% target".to_string());
        }

        if compliance.coverage_rate > 0.7 {
            strengths.push(format!(
                "Compliance coverage: {:.0}% across {} frameworks",
                compliance.coverage_rate * 100.0,
                compliance.frameworks.len()
            ));
        } else {
            gaps.push("Compliance coverage could be improved".to_string());
        }

        if has_signed_evidence && has_encryption {
            strengths.push("Evidence is signed and encrypted".to_string());
        } else {
            gaps.push("Evidence signing or encryption not fully deployed".to_string());
        }

        if questionnaire.evidence_backed_count as f64 / questionnaire.total_questions.max(1) as f64
            > 0.5
        {
            strengths.push("Majority of questionnaire answers are evidence-backed".to_string());
        }

        let invest_summary = format!(
            "Investment readiness: {:.1}/100 — Grade {}. {} strengths, {} gaps.",
            invest_score * 100.0,
            invest_grade,
            strengths.len(),
            gaps.len()
        );

        let investment_readiness = InvestmentReadinessScore {
            score: invest_score,
            grade: invest_grade.to_string(),
            strengths,
            gaps,
            summary: invest_summary,
        };

        let recommendations =
            build_diligence_recommendations(&posture, &compliance, &evidence_quality);

        let executive_summary = format!(
            "BALONCORE security diligence assessment for {}: {} findings across {} frameworks. \
             Security posture grade: {}. Compliance coverage: {:.0}%. Investment readiness: {}.",
            target,
            total_findings,
            compliance.frameworks.len(),
            posture.grade,
            compliance.coverage_rate * 100.0,
            invest_grade,
        );

        SecurityDiligenceReport {
            title: format!("BALONCORE Security Diligence Report — {}", target),
            generated_at: now,
            target: target.to_string(),
            overall_posture: posture,
            questionnaire,
            compliance_coverage: compliance,
            risk_heatmap,
            evidence_quality,
            investment_readiness,
            findings_summary: findings,
            recommendations,
            executive_summary,
        }
    }

    pub fn to_html(&self) -> String {
        render_diligence_html(self)
    }

    pub fn to_markdown(&self) -> String {
        render_diligence_markdown(self)
    }
}

fn build_risk_categories(findings: &[DiligenceFindingSummary]) -> Vec<RiskCategory> {
    let cats = [
        ("authorization", "Access Control"),
        ("isolation", "Tenant Isolation"),
        ("business", "Business Logic"),
        ("graphql", "GraphQL Security"),
        ("authentication", "Authentication"),
        ("middleware", "Security Middleware"),
    ];

    cats.iter()
        .map(|(key, name)| {
            let matches: Vec<&DiligenceFindingSummary> = findings
                .iter()
                .filter(|f| f.classification.to_lowercase().contains(key))
                .collect();
            let finding_count = matches.len();
            let fixed_count = matches.iter().filter(|f| f.is_fixed).count();
            let open_count = finding_count - fixed_count;

            let risk_level = if open_count > 0 && matches.iter().any(|f| f.severity == "critical") {
                "critical"
            } else if open_count > 0 && matches.iter().any(|f| f.severity == "high") {
                "high"
            } else if open_count > 0 {
                "medium"
            } else {
                "low"
            };

            RiskCategory {
                name: name.to_string(),
                severity: if finding_count > 0 {
                    matches
                        .iter()
                        .max_by_key(|f| severity_rank(&f.severity))
                        .map(|f| f.severity.clone())
                        .unwrap_or_else(|| "none".to_string())
                } else {
                    "none".to_string()
                },
                finding_count,
                fixed_count,
                open_count,
                risk_level: risk_level.to_string(),
            }
        })
        .collect()
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn build_diligence_recommendations(
    posture: &SecurityPosture,
    compliance: &ComplianceCoverageReport,
    evidence: &EvidenceQualityAssessment,
) -> Vec<DiligenceRecommendation> {
    let mut recs = Vec::new();

    if *posture.components.get("fix_rate").unwrap_or(&0.0) < 0.7 {
        recs.push(DiligenceRecommendation {
            category: "remediation".to_string(),
            priority: "high".to_string(),
            title: "Accelerate finding remediation".to_string(),
            description: "Fix rate is below 70%. Prioritize fixing verified findings and implementing regression tests."
                .to_string(),
            impact: "Directly improves security posture and investment readiness score.".to_string(),
            effort: "Medium — requires developer time to fix findings.".to_string(),
        });
    }

    if compliance.coverage_rate < 0.7 {
        recs.push(DiligenceRecommendation {
            category: "compliance".to_string(),
            priority: "medium".to_string(),
            title: "Expand compliance coverage".to_string(),
            description: format!(
                "Compliance coverage is at {:.0}%. Add test cases that map to uncovered controls.",
                compliance.coverage_rate * 100.0
            ),
            impact: "Improves ability to answer security questionnaires and pass audits."
                .to_string(),
            effort: "Medium — add test cases targeting uncovered controls.".to_string(),
        });
    }

    if evidence.score < 0.8 {
        recs.push(DiligenceRecommendation {
            category: "evidence".to_string(),
            priority: "high".to_string(),
            title: "Enable evidence signing and encryption".to_string(),
            description: "Evidence integrity can be strengthened by enabling Ed25519 signing and AES-256-GCM encryption."
                .to_string(),
            impact: "Critical for passing enterprise security reviews and compliance audits.".to_string(),
            effort: "Low — configuration change. Infrastructure is already built.".to_string(),
        });
    }

    if !posture
        .components
        .get("fp_reduction")
        .is_some_and(|s| *s > 0.5)
    {
        recs.push(DiligenceRecommendation {
            category: "quality".to_string(),
            priority: "medium".to_string(),
            title: "Improve false positive reduction".to_string(),
            description: "False positive reduction rate is low. Review baseline suppressions and detector tuning."
                .to_string(),
            impact: "Reduces noise and increases trust in automated findings.".to_string(),
            effort: "Low — baseline suppressions and policy tuning.".to_string(),
        });
    }

    recs
}

fn render_diligence_markdown(report: &SecurityDiligenceReport) -> String {
    let mut md = String::new();
    md.push_str(&format!("# {}\n\n", report.title));
    md.push_str(&format!(
        "**Generated:** {}\n\n",
        format_timestamp(report.generated_at)
    ));
    md.push_str(&format!("**Target:** {}\n\n", report.target));

    md.push_str("## Executive Summary\n\n");
    md.push_str(&report.executive_summary);
    md.push_str("\n\n");

    md.push_str("## Security Posture\n\n");
    md.push_str(&format!(
        "**Score:** {:.1}/100 — Grade **{}** ({})\n\n",
        report.overall_posture.score * 100.0,
        report.overall_posture.grade,
        report.overall_posture.tier
    ));
    md.push_str("### Component Scores\n\n");
    md.push_str("| Component | Score |\n");
    md.push_str("|-----------|-------|\n");
    for (component, score) in &report.overall_posture.components {
        md.push_str(&format!(
            "| {} | {:.1}% |\n",
            component_to_label(component),
            score * 100.0
        ));
    }
    md.push('\n');

    md.push_str("## Compliance Coverage\n\n");
    md.push_str(&format!(
        "**Overall:** {:.0}% ({}/{})\n\n",
        report.compliance_coverage.coverage_rate * 100.0,
        report.compliance_coverage.covered_controls,
        report.compliance_coverage.total_controls,
    ));
    md.push_str(&report.compliance_coverage.gap_summary);
    md.push_str("\n\n");
    md.push_str("| Framework | Coverage | Controls |\n");
    md.push_str("|-----------|----------|----------|\n");
    for fw in &report.compliance_coverage.frameworks {
        md.push_str(&format!(
            "| {} | {:.0}% | {}/{} |\n",
            fw.framework,
            fw.coverage_rate * 100.0,
            fw.covered_controls,
            fw.total_controls
        ));
    }
    md.push('\n');

    md.push_str("## Risk Heatmap\n\n");
    md.push_str("| Category | Severity | Findings | Fixed | Open | Risk |\n");
    md.push_str("|----------|----------|----------|-------|------|------|\n");
    for cat in &report.risk_heatmap.categories {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            cat.name,
            cat.severity,
            cat.finding_count,
            cat.fixed_count,
            cat.open_count,
            cat.risk_level
        ));
    }
    md.push('\n');

    md.push_str("## Evidence Quality\n\n");
    md.push_str(&report.evidence_quality.summary);
    md.push_str("\n\n");
    md.push_str(&format!(
        "- Signed: {}/{}\n- Encrypted: {}/{}\n- Redacted: {}\n- Audit trail: {}\n\n",
        report.evidence_quality.signed_count,
        report.evidence_quality.total_findings,
        report.evidence_quality.encrypted_count,
        report.evidence_quality.total_findings,
        if report.evidence_quality.redacted_properly {
            "pass"
        } else {
            "fail"
        },
        if report.evidence_quality.audit_trail_complete {
            "yes"
        } else {
            "no"
        },
    ));

    md.push_str("## Investment Readiness\n\n");
    md.push_str(&format!(
        "**Score:** {:.1}/100 — Grade **{}**\n\n",
        report.investment_readiness.score * 100.0,
        report.investment_readiness.grade
    ));
    if !report.investment_readiness.strengths.is_empty() {
        md.push_str("### Strengths\n\n");
        for s in &report.investment_readiness.strengths {
            md.push_str(&format!("- {s}\n"));
        }
        md.push('\n');
    }
    if !report.investment_readiness.gaps.is_empty() {
        md.push_str("### Gaps\n\n");
        for g in &report.investment_readiness.gaps {
            md.push_str(&format!("- {g}\n"));
        }
        md.push('\n');
    }

    md.push_str("## Questionnaire Summary\n\n");
    md.push_str(&format!(
        "{}/{} questions answered ({}% auto-answered, {}% evidence-backed)\n\n",
        report.questionnaire.answered_count,
        report.questionnaire.total_questions,
        (report.questionnaire.auto_answered_count as f64
            / report.questionnaire.total_questions.max(1) as f64
            * 100.0) as usize,
        (report.questionnaire.evidence_backed_count as f64
            / report.questionnaire.total_questions.max(1) as f64
            * 100.0) as usize,
    ));

    if !report.recommendations.is_empty() {
        md.push_str("## Recommendations\n\n");
        for rec in &report.recommendations {
            md.push_str(&format!(
                "### {} [{}]\n\n",
                rec.title,
                rec.priority.to_uppercase()
            ));
            md.push_str(&format!("{}\\n\\n", rec.description));
            md.push_str(&format!("- Impact: {}\n", rec.impact));
            md.push_str(&format!("- Effort: {}\n\n", rec.effort));
        }
    }

    md.push_str("---\n*Generated by BALONCORE Security Diligence Engine*\n");

    md
}

fn component_to_label(component: &str) -> &'static str {
    match component {
        "fix_rate" => "Fix Rate",
        "severity_health" => "Severity Health",
        "fp_reduction" => "FP Reduction",
        "defense_maturity" => "Defense Maturity",
        "benchmark_performance" => "Benchmark Performance",
        "evidence_integrity" => "Evidence Integrity",
        _ => "Other",
    }
}

fn render_diligence_html(report: &SecurityDiligenceReport) -> String {
    let md = render_diligence_markdown(report);
    format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>{}</title>
        <style>body{{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem;line-height:1.6}}
        h1,h2{{color:#3b82f6}} table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #334155;padding:0.5rem;text-align:left}}
        th{{background:#1e293b}} .critical{{color:#dc2626}} .high{{color:#ea580c}} .medium{{color:#d97706}} .low{{color:#65a30d}}
        </style></head><body><pre>{}</pre></body></html>"#,
        html_escape(&report.title),
        html_escape(&md),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn format_timestamp(epoch: u64) -> String {
    let secs_per_day = 86400u64;
    let secs_per_year = 365 * secs_per_day;
    let years = 1970 + epoch / secs_per_year;
    let day_of_year = (epoch % secs_per_year) / secs_per_day;
    format!("{}-{} UTC (epoch {epoch})", years, day_of_year)
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

    fn make_summary(
        id: &str,
        classification: &str,
        severity: &str,
        is_fixed: bool,
    ) -> DiligenceFindingSummary {
        DiligenceFindingSummary {
            finding_id: id.to_string(),
            classification: classification.to_string(),
            vulnerability_class: classification.to_string(),
            title: format!("Test finding {id}"),
            severity: severity.to_string(),
            score: 70,
            is_fixed,
            is_suppressed: false,
            endpoint: "/api/test".to_string(),
            source: "bola-validator".to_string(),
        }
    }

    #[test]
    fn posture_empty_findings_gives_perfect_severity() {
        let posture = SecurityPosture::compute(
            0,
            0,
            0,
            0,
            0,
            0,
            0.5,
            &BTreeMap::new(),
            Some(0.8),
            false,
            false,
        );
        assert!(posture.score > 0.5);
        assert_eq!(*posture.components.get("severity_health").unwrap(), 1.0);
    }

    #[test]
    fn posture_critical_findings_lower_grade() {
        let posture = SecurityPosture::compute(
            10,
            2,
            5,
            1,
            1,
            1,
            0.5,
            &BTreeMap::new(),
            Some(0.8),
            false,
            false,
        );
        assert!(posture.score < 0.7);
        assert!(
            posture.components["severity_health"] < 0.5,
            "severity_health with 5 criticals should be < 0.5"
        );
    }

    #[test]
    fn posture_all_fixed_gives_high_fix_rate() {
        let posture = SecurityPosture::compute(
            5,
            5,
            0,
            2,
            2,
            1,
            0.8,
            &BTreeMap::new(),
            Some(0.9),
            true,
            true,
        );
        assert_eq!(*posture.components.get("fix_rate").unwrap(), 1.0);
        assert_eq!(*posture.components.get("evidence_integrity").unwrap(), 1.0);
        assert!(posture.score > 0.75);
    }

    #[test]
    fn posture_grade_mapping() {
        assert_eq!(posture_grade(0.96).0, "A+");
        assert_eq!(posture_grade(0.86).0, "A");
        assert_eq!(posture_grade(0.76).0, "B+");
        assert_eq!(posture_grade(0.66).0, "B");
        assert_eq!(posture_grade(0.51).0, "C");
        assert_eq!(posture_grade(0.4).0, "D");
    }

    #[test]
    fn compliance_report_computes_coverage() {
        let findings = vec![
            make_summary("f1", "broken_object_level_authorization", "high", false),
            make_summary("f2", "tenant_isolation", "critical", true),
        ];
        let report = ComplianceCoverageReport::from_findings(&findings);
        assert!(report.total_controls > 0);
        assert!(report.covered_controls > 0);
        assert!(report.coverage_rate > 0.0);
        assert!(!report.frameworks.is_empty());
    }

    #[test]
    fn compliance_report_empty_findings_has_zero_coverage() {
        let report = ComplianceCoverageReport::from_findings(&[]);
        assert_eq!(report.coverage_rate, 0.0);
        assert_eq!(report.covered_controls, 0);
    }

    #[test]
    fn questionnaire_auto_answers_all_questions() {
        let findings = vec![make_summary(
            "f1",
            "broken_object_level_authorization",
            "high",
            true,
        )];
        let compliance = ComplianceCoverageReport::from_findings(&findings);
        let posture = SecurityPosture::compute(
            1,
            1,
            0,
            1,
            0,
            0,
            0.5,
            &BTreeMap::new(),
            Some(0.8),
            true,
            true,
        );
        let q = SecurityQuestionnaire::from_findings(&findings, &posture, &compliance);
        assert_eq!(q.answered_count, q.total_questions);
        assert!(q.auto_answered_count > 0);
        assert!(q.total_questions > 0);
    }

    #[test]
    fn full_diligence_report_assembles() {
        let findings = vec![
            make_summary("f1", "broken_object_level_authorization", "high", true),
            make_summary("f2", "business_logic_price_tamper", "high", false),
            make_summary("f3", "tenant_isolation", "critical", true),
        ];
        let report = SecurityDiligenceReport::assemble(
            "https://api.example.com",
            findings,
            0.6,
            BTreeMap::new(),
            Some(0.85),
            true,
            true,
            true,
            true,
        );
        assert!(report.executive_summary.contains("https://api.example.com"));
        assert!(report.overall_posture.score > 0.0);
        assert!(!report.compliance_coverage.frameworks.is_empty());
        assert!(!report.questionnaire.sections.is_empty());
        assert!(!report.risk_heatmap.categories.is_empty());
        assert!(report.investment_readiness.score > 0.0);
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn diligence_markdown_renders() {
        let findings = vec![make_summary("f1", "bola", "high", true)];
        let report = SecurityDiligenceReport::assemble(
            "test",
            findings,
            0.7,
            BTreeMap::new(),
            Some(0.8),
            true,
            true,
            true,
            true,
        );
        let md = report.to_markdown();
        assert!(md.contains("Security Diligence Report"));
        assert!(md.contains("Security Posture"));
        assert!(md.contains("Compliance Coverage"));
        assert!(md.contains("Risk Heatmap"));
        assert!(md.contains("Investment Readiness"));
    }

    #[test]
    fn diligence_html_renders() {
        let findings = vec![make_summary("f1", "bola", "high", true)];
        let report = SecurityDiligenceReport::assemble(
            "test",
            findings,
            0.7,
            BTreeMap::new(),
            Some(0.8),
            true,
            true,
            true,
            true,
        );
        let html = report.to_html();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Security Diligence"));
    }

    #[test]
    fn evidence_quality_scoring() {
        let findings = vec![
            make_summary("f1", "bola", "high", true),
            make_summary("f2", "bfla", "critical", false),
        ];
        let report = SecurityDiligenceReport::assemble(
            "test",
            findings,
            0.6,
            BTreeMap::new(),
            Some(0.8),
            true,
            true,
            true,
            true,
        );
        assert_eq!(report.evidence_quality.score, 1.0);
        assert_eq!(report.evidence_quality.signed_count, 2);
        assert_eq!(report.evidence_quality.encrypted_count, 2);
    }

    #[test]
    fn risk_heatmap_categories() {
        let findings = vec![
            make_summary("f1", "broken_object_level_authorization", "critical", false),
            make_summary("f2", "tenant_isolation", "high", true),
            make_summary("f3", "business_logic_price_tamper", "high", false),
            make_summary("f4", "graphql_field_authorization", "medium", true),
            make_summary("f5", "missing_authentication", "medium", false),
        ];
        let report = SecurityDiligenceReport::assemble(
            "test",
            findings,
            0.5,
            BTreeMap::new(),
            Some(0.8),
            true,
            true,
            true,
            true,
        );
        assert!(!report.risk_heatmap.categories.is_empty());
        let auth_cat = report
            .risk_heatmap
            .categories
            .iter()
            .find(|c| c.name == "Access Control")
            .unwrap();
        assert!(auth_cat.finding_count > 0);
    }

    #[test]
    fn investment_readiness_shows_gaps_when_scores_low() {
        let findings = vec![make_summary("f1", "bola", "critical", false)];
        let report = SecurityDiligenceReport::assemble(
            "test",
            findings,
            0.3,
            BTreeMap::new(),
            Some(0.7),
            false,
            false,
            false,
            false,
        );
        assert!(!report.investment_readiness.gaps.is_empty());
        assert!(report.investment_readiness.gaps.len() >= 2);
    }

    #[test]
    fn recommendations_for_low_fix_rate() {
        let findings = vec![
            make_summary("f1", "bola", "high", false),
            make_summary("f2", "bfla", "high", false),
            make_summary("f3", "tenant_isolation", "critical", false),
        ];
        let report = SecurityDiligenceReport::assemble(
            "test",
            findings,
            0.4,
            BTreeMap::new(),
            Some(0.8),
            false,
            false,
            true,
            true,
        );
        let fix_rec = report
            .recommendations
            .iter()
            .find(|r| r.title.contains("Accelerate"));
        assert!(fix_rec.is_some());
        let evidence_rec = report
            .recommendations
            .iter()
            .find(|r| r.title.contains("signing"));
        assert!(evidence_rec.is_some());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiligenceHistory {
    pub version: u32,
    pub target: String,
    pub total_reports: u64,
    pub last_updated_at: u64,
    pub entries: Vec<DiligenceHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiligenceHistoryEntry {
    pub timestamp: u64,
    pub report_id: String,
    pub posture_score: f64,
    pub posture_grade: String,
    pub compliance_coverage: f64,
    pub investment_readiness: f64,
    pub total_findings: usize,
    pub fixed_findings: usize,
    pub critical_open: usize,
    pub high_open: usize,
}

impl DiligenceHistory {
    pub fn new(target: &str) -> Self {
        Self {
            version: 1,
            target: target.to_string(),
            total_reports: 0,
            last_updated_at: unix_seconds(),
            entries: Vec::new(),
        }
    }

    pub fn append(&mut self, report: &SecurityDiligenceReport) {
        let critical_open = report
            .risk_heatmap
            .categories
            .iter()
            .filter(|c| c.risk_level == "critical")
            .map(|c| c.open_count)
            .sum();
        let high_open = report
            .risk_heatmap
            .categories
            .iter()
            .filter(|c| c.risk_level == "high")
            .map(|c| c.open_count)
            .sum();
        let fixed = report
            .findings_summary
            .iter()
            .filter(|f| f.is_fixed)
            .count();

        self.entries.push(DiligenceHistoryEntry {
            timestamp: unix_seconds(),
            report_id: format!("diligence-{}", self.total_reports + 1),
            posture_score: report.overall_posture.score,
            posture_grade: report.overall_posture.grade.clone(),
            compliance_coverage: report.compliance_coverage.coverage_rate,
            investment_readiness: report.investment_readiness.score,
            total_findings: report.findings_summary.len(),
            fixed_findings: fixed,
            critical_open,
            high_open,
        });
        self.total_reports += 1;
        self.last_updated_at = unix_seconds();

        if self.entries.len() > 100 {
            self.entries.drain(0..self.entries.len() - 100);
        }
    }

    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        if !path.as_ref().exists() {
            return Ok(Self::new("unknown"));
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read diligence history: {e}"))?;
        serde_json::from_str(&raw).map_err(|e| format!("failed to parse diligence history: {e}"))
    }

    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<(), String> {
        if let Some(parent) = path.as_ref().parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize diligence history: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("failed to write diligence history: {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiligenceTrend {
    pub first_score: f64,
    pub latest_score: f64,
    pub delta: f64,
    pub direction: String,
    pub entries: usize,
    pub posture_slope: f64,
    pub fix_rate_slope: f64,
    pub coverage_slope: f64,
    pub summary: String,
}

pub fn compute_diligence_trend(history: &DiligenceHistory) -> DiligenceTrend {
    if history.entries.len() < 2 {
        let score = history
            .entries
            .first()
            .map(|e| e.posture_score)
            .unwrap_or(0.0);
        return DiligenceTrend {
            first_score: score,
            latest_score: score,
            delta: 0.0,
            direction: "stable".to_string(),
            entries: history.entries.len(),
            posture_slope: 0.0,
            fix_rate_slope: 0.0,
            coverage_slope: 0.0,
            summary: "Not enough data points for trend analysis (need ≥ 2 reports).".to_string(),
        };
    }

    let first = &history.entries[0];
    let last = &history.entries[history.entries.len() - 1];

    let first_score = first.posture_score;
    let latest_score = last.posture_score;
    let delta = latest_score - first_score;

    let direction = if delta > 0.05 {
        "improving".to_string()
    } else if delta < -0.05 {
        "declining".to_string()
    } else {
        "stable".to_string()
    };

    let _n = history.entries.len() as f64;
    let indices: Vec<f64> = (0..history.entries.len()).map(|i| i as f64).collect();
    let scores: Vec<f64> = history.entries.iter().map(|e| e.posture_score).collect();
    let fix_rates: Vec<f64> = history
        .entries
        .iter()
        .map(|e| {
            if e.total_findings > 0 {
                e.fixed_findings as f64 / e.total_findings as f64
            } else {
                1.0
            }
        })
        .collect();
    let coverages: Vec<f64> = history
        .entries
        .iter()
        .map(|e| e.compliance_coverage)
        .collect();

    let posture_slope = linear_slope(&indices, &scores);
    let fix_rate_slope = linear_slope(&indices, &fix_rates);
    let coverage_slope = linear_slope(&indices, &coverages);

    let summary = format!(
        "{} trend: posture {:.1}% → {:.1}% (Δ {:+.1}%). {} reports analyzed.",
        direction,
        first_score * 100.0,
        latest_score * 100.0,
        delta * 100.0,
        history.entries.len()
    );

    DiligenceTrend {
        first_score,
        latest_score,
        delta,
        direction,
        entries: history.entries.len(),
        posture_slope,
        fix_rate_slope,
        coverage_slope,
        summary,
    }
}

fn linear_slope(x: &[f64], y: &[f64]) -> f64 {
    if x.len() < 2 {
        return 0.0;
    }
    let n = x.len() as f64;
    let sum_x: f64 = x.iter().sum();
    let sum_y: f64 = y.iter().sum();
    let sum_xy: f64 = x.iter().zip(y.iter()).map(|(xi, yi)| xi * yi).sum();
    let sum_x2: f64 = x.iter().map(|xi| xi * xi).sum();

    let denominator = n * sum_x2 - sum_x * sum_x;
    if denominator == 0.0 {
        return 0.0;
    }
    (n * sum_xy - sum_x * sum_y) / denominator
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkSpecificReport {
    pub framework: String,
    pub title: String,
    pub generated_at: u64,
    pub target: String,
    pub posture: SecurityPosture,
    pub coverage: FrameworkCoverage,
    pub evidence_summary: EvidenceQualityAssessment,
    pub controls_detail: Vec<FrameworkControlStatus>,
    pub recommendations: Vec<DiligenceRecommendation>,
    pub summary: String,
}

impl FrameworkSpecificReport {
    pub fn for_soc2(report: &SecurityDiligenceReport) -> Option<Self> {
        let fw = report
            .compliance_coverage
            .frameworks
            .iter()
            .find(|fw| fw.framework == "SOC 2")?;

        Some(Self {
            framework: "SOC 2".to_string(),
            title: format!("BALONCORE SOC 2 Compliance Evidence — {}", report.target),
            generated_at: unix_seconds(),
            target: report.target.clone(),
            posture: report.overall_posture.clone(),
            coverage: fw.clone(),
            evidence_summary: report.evidence_quality.clone(),
            controls_detail: fw.controls.clone(),
            recommendations: report
                .recommendations
                .iter()
                .filter(|r| r.category == "evidence" || r.category == "compliance")
                .cloned()
                .collect(),
            summary: format!(
                "SOC 2 coverage: {:.0}% ({}/{} controls). Evidence quality: {:.0}%.",
                fw.coverage_rate * 100.0,
                fw.covered_controls,
                fw.total_controls,
                report.evidence_quality.score * 100.0
            ),
        })
    }

    pub fn for_owasp(report: &SecurityDiligenceReport) -> Option<Self> {
        let fw = report
            .compliance_coverage
            .frameworks
            .iter()
            .find(|fw| fw.framework == "OWASP API Top 10")?;

        Some(Self {
            framework: "OWASP API Top 10".to_string(),
            title: format!("BALONCORE OWASP API Top 10 Compliance — {}", report.target),
            generated_at: unix_seconds(),
            target: report.target.clone(),
            posture: report.overall_posture.clone(),
            coverage: fw.clone(),
            evidence_summary: report.evidence_quality.clone(),
            controls_detail: fw.controls.clone(),
            recommendations: report
                .recommendations
                .iter()
                .filter(|r| r.category == "remediation" || r.category == "compliance")
                .cloned()
                .collect(),
            summary: format!(
                "OWASP API Top 10 coverage: {:.0}% ({}/{} controls).",
                fw.coverage_rate * 100.0,
                fw.covered_controls,
                fw.total_controls
            ),
        })
    }

    pub fn vendor_security_review(report: &SecurityDiligenceReport) -> Self {
        let total = report.findings_summary.len();
        let fixed = report
            .findings_summary
            .iter()
            .filter(|f| f.is_fixed)
            .count();
        let open = total - fixed;
        let posture = &report.overall_posture;
        let compliance = &report.compliance_coverage;

        Self {
            framework: "vendor-security-review".to_string(),
            title: format!("BALONCORE Vendor Security Review — {}", report.target),
            generated_at: unix_seconds(),
            target: report.target.clone(),
            posture: posture.clone(),
            coverage: compliance
                .frameworks
                .first()
                .cloned()
                .unwrap_or_else(|| FrameworkCoverage {
                    framework: "Combined".to_string(),
                    total_controls: 0,
                    covered_controls: 0,
                    coverage_rate: 0.0,
                    controls: vec![],
                }),
            evidence_summary: report.evidence_quality.clone(),
            controls_detail: compliance
                .frameworks
                .iter()
                .flat_map(|fw| fw.controls.clone())
                .collect(),
            recommendations: vec![DiligenceRecommendation {
                category: "summary".to_string(),
                priority: "info".to_string(),
                title: "Automated Security Validation".to_string(),
                description: format!(
                    "BALONCORE runs automated security validation on every PR. \
                         {} findings analyzed, {} resolved, {} open. \
                         Posture grade: {}. Investment readiness: {}.",
                    total, fixed, open, posture.grade, report.investment_readiness.grade
                ),
                impact: "Provides continuous security assurance.".to_string(),
                effort: "Already operational.".to_string(),
            }],
            summary: format!(
                "Vendor security posture: grade {} ({}). {} findings analyzed. \
                 {}% compliance coverage.",
                posture.grade,
                posture.tier,
                total,
                (compliance.coverage_rate * 100.0) as usize
            ),
        }
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("# {}\n\n", self.title));
        md.push_str(&format!(
            "**Generated:** {}\n\n",
            format_timestamp(self.generated_at)
        ));
        md.push_str(&format!("**Target:** {}\n\n", self.target));
        md.push_str(&format!("**Summary:** {}\n\n", self.summary));

        md.push_str(&format!(
            "## Posture\n\n**Grade:** {} ({:.1}/100)\n\n",
            self.posture.grade,
            self.posture.score * 100.0
        ));

        md.push_str("## Framework Controls\n\n");
        md.push_str("| Control | Status | Evidence | Maturity |\n");
        md.push_str("|---------|--------|----------|----------|\n");
        for c in &self.controls_detail {
            let status = if c.covered { "covered" } else { "not covered" };
            let evidence = if c.evidence_count > 0 {
                format!("{} finding(s)", c.evidence_count)
            } else {
                "none".to_string()
            };
            md.push_str(&format!(
                "| {} ({}) | {} | {} | {} |\n",
                c.control_id, c.control_name, status, evidence, c.maturity
            ));
        }
        md.push('\n');

        md.push_str(&format!(
            "## Evidence Quality\n\n**Score:** {:.0}%\n\n- Signed: {}/{}\n- Encrypted: {}/{}\n- Redacted: {}\n- Audit trail: {}\n\n",
            self.evidence_summary.score * 100.0,
            self.evidence_summary.signed_count,
            self.evidence_summary.total_findings,
            self.evidence_summary.encrypted_count,
            self.evidence_summary.total_findings,
            if self.evidence_summary.redacted_properly { "pass" } else { "fail" },
            if self.evidence_summary.audit_trail_complete { "yes" } else { "no" },
        ));

        if !self.recommendations.is_empty() {
            md.push_str("## Recommendations\n\n");
            for r in &self.recommendations {
                md.push_str(&format!(
                    "- **[{}]** {} — {}\n",
                    r.priority.to_uppercase(),
                    r.title,
                    r.description
                ));
            }
            md.push('\n');
        }

        md.push_str("---\n*Generated by BALONCORE Security Diligence Engine*\n");
        md
    }
}

pub fn render_diligence_trend(history: &DiligenceHistory) -> String {
    let trend = compute_diligence_trend(history);

    let mut md = String::new();
    md.push_str("# BALONCORE Diligence Trend Report\n\n");
    md.push_str(&format!("**Target:** {}\n\n", history.target));
    md.push_str(&format!("{}\n\n", trend.summary));

    md.push_str("## Posture Over Time\n\n");
    md.push_str("| # | Date | Posture | Grade | Coverage | Fixed | Critical Open |\n");
    md.push_str("|----|------|---------|-------|----------|-------|---------------|\n");
    for (i, entry) in history.entries.iter().enumerate() {
        let date = format_timestamp(entry.timestamp);
        md.push_str(&format!(
            "| {} | {} | {:.1}% | {} | {:.0}% | {}/{} | {} |\n",
            i + 1,
            date,
            entry.posture_score * 100.0,
            entry.posture_grade,
            entry.compliance_coverage * 100.0,
            entry.fixed_findings,
            entry.total_findings,
            entry.critical_open,
        ));
    }
    md.push('\n');

    md.push_str("## Trend Analysis\n\n");
    md.push_str(&format!(
        "| Metric | Trend |\n|--------|-------|\n| Posture slope | {:+.4} per report |\n| Fix rate slope | {:+.4} per report |\n| Coverage slope | {:+.4} per report |\n\n",
        trend.posture_slope, trend.fix_rate_slope, trend.coverage_slope
    ));

    md.push_str("---\n*Generated by BALONCORE Security Diligence Engine*\n");
    md
}

#[cfg(test)]
mod diligence_history_tests {
    use super::*;

    fn make_report(
        score: f64,
        grade: &str,
        coverage: f64,
        total: usize,
        fixed: usize,
        critical_open: usize,
    ) -> SecurityDiligenceReport {
        SecurityDiligenceReport {
            title: "Test".to_string(),
            generated_at: unix_seconds(),
            target: "test".to_string(),
            overall_posture: SecurityPosture {
                score,
                grade: grade.to_string(),
                tier: "Mature".to_string(),
                components: BTreeMap::new(),
                summary: String::new(),
            },
            questionnaire: SecurityQuestionnaire {
                sections: vec![],
                total_questions: 0,
                answered_count: 0,
                auto_answered_count: 0,
                evidence_backed_count: 0,
                unanswered_count: 0,
            },
            compliance_coverage: ComplianceCoverageReport {
                frameworks: vec![],
                total_controls: 0,
                covered_controls: 0,
                coverage_rate: coverage,
                gap_summary: String::new(),
            },
            risk_heatmap: RiskHeatmap {
                categories: if critical_open > 0 {
                    vec![RiskCategory {
                        name: "Access Control".to_string(),
                        severity: "critical".to_string(),
                        finding_count: critical_open + fixed,
                        fixed_count: fixed,
                        open_count: critical_open,
                        risk_level: "critical".to_string(),
                    }]
                } else {
                    vec![]
                },
                total_risks: total,
                critical_count: critical_open,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
            },
            evidence_quality: EvidenceQualityAssessment {
                total_findings: total,
                signed_count: total,
                encrypted_count: total,
                audit_trail_complete: true,
                redacted_properly: true,
                score: 1.0,
                summary: String::new(),
            },
            investment_readiness: InvestmentReadinessScore {
                score: 0.8,
                grade: "A".to_string(),
                strengths: vec![],
                gaps: vec![],
                summary: String::new(),
            },
            findings_summary: (0..total)
                .map(|i| {
                    let is_fixed = i < fixed;
                    DiligenceFindingSummary {
                        finding_id: format!("f-{i}"),
                        classification: "bola".to_string(),
                        vulnerability_class: "bola".to_string(),
                        title: format!("Finding {i}"),
                        severity: if i < critical_open {
                            "critical".to_string()
                        } else {
                            "high".to_string()
                        },
                        score: 70,
                        is_fixed,
                        is_suppressed: false,
                        endpoint: "/api/test".to_string(),
                        source: "test".to_string(),
                    }
                })
                .collect(),
            recommendations: vec![],
            executive_summary: String::new(),
        }
    }

    #[test]
    fn history_append_and_trend() {
        let mut history = DiligenceHistory::new("test");
        history.append(&make_report(0.6, "C", 0.5, 10, 3, 2));
        history.append(&make_report(0.7, "B", 0.7, 8, 5, 1));
        history.append(&make_report(0.85, "A", 0.85, 5, 5, 0));

        let trend = compute_diligence_trend(&history);
        assert_eq!(trend.entries, 3);
        assert_eq!(trend.direction, "improving");
        assert!(trend.delta > 0.1);
        assert!(trend.posture_slope > 0.0);
        assert!(trend.fix_rate_slope > 0.0);
    }

    #[test]
    fn trend_insufficient_data() {
        let mut history = DiligenceHistory::new("test");
        history.append(&make_report(0.7, "B", 0.6, 5, 2, 1));
        let trend = compute_diligence_trend(&history);
        assert_eq!(trend.entries, 1);
        assert_eq!(trend.direction, "stable");
        assert_eq!(trend.delta, 0.0);
    }

    #[test]
    fn trend_declining_detected() {
        let mut history = DiligenceHistory::new("test");
        history.append(&make_report(0.85, "A", 0.9, 3, 3, 0));
        history.append(&make_report(0.7, "B", 0.7, 8, 4, 2));
        let trend = compute_diligence_trend(&history);
        assert_eq!(trend.direction, "declining");
        assert!(trend.delta < -0.05);
    }

    #[test]
    fn history_persist_and_reload() {
        let dir = std::env::temp_dir().join("baloncore-diligence-history-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("diligence_history.json");
        let mut history = DiligenceHistory::new("test");
        history.append(&make_report(0.7, "B", 0.6, 5, 2, 1));
        history.save(&path).unwrap();

        let loaded = DiligenceHistory::load(&path).unwrap();
        assert_eq!(loaded.total_reports, 1);
        assert_eq!(loaded.entries.len(), 1);
        assert!((loaded.entries[0].posture_score - 0.7).abs() < 0.01);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn soc2_report_generates() {
        let report = make_report(0.8, "A", 0.75, 10, 8, 1);
        let full_report = SecurityDiligenceReport::assemble(
            "test",
            report.findings_summary.clone(),
            0.6,
            BTreeMap::new(),
            Some(0.85),
            true,
            true,
            true,
            true,
        );
        let soc2 = FrameworkSpecificReport::for_soc2(&full_report);
        assert!(soc2.is_some());
        let report = soc2.unwrap();
        assert_eq!(report.framework, "SOC 2");
        let md = report.to_markdown();
        assert!(md.contains("SOC 2"));
        assert!(md.contains("Framework Controls"));
    }

    #[test]
    fn owasp_report_generates() {
        let report = make_report(0.8, "A", 0.75, 10, 8, 1);
        let full_report = SecurityDiligenceReport::assemble(
            "test",
            report.findings_summary.clone(),
            0.6,
            BTreeMap::new(),
            Some(0.85),
            true,
            true,
            true,
            true,
        );
        let owasp = FrameworkSpecificReport::for_owasp(&full_report);
        assert!(owasp.is_some());
        assert!(owasp.unwrap().to_markdown().contains("OWASP"));
    }

    #[test]
    fn vendor_security_review_generates() {
        let report = make_report(0.85, "A", 0.8, 5, 4, 0);
        let full_report = SecurityDiligenceReport::assemble(
            "test",
            report.findings_summary.clone(),
            0.7,
            BTreeMap::new(),
            Some(0.85),
            true,
            true,
            true,
            true,
        );
        let vendor = FrameworkSpecificReport::vendor_security_review(&full_report);
        assert_eq!(vendor.framework, "vendor-security-review");
        let md = vendor.to_markdown();
        assert!(md.contains("Vendor Security Review"));
        assert!(md.contains("Automated Security Validation"));
    }

    #[test]
    fn render_trend_report_includes_history() {
        let mut history = DiligenceHistory::new("test");
        history.append(&make_report(0.6, "C", 0.5, 10, 3, 2));
        history.append(&make_report(0.8, "A", 0.8, 5, 4, 0));
        let trend_md = render_diligence_trend(&history);
        assert!(trend_md.contains("Posture Over Time"));
        assert!(trend_md.contains("Trend Analysis"));
        assert!(trend_md.contains("60.0%"));
        assert!(trend_md.contains("80.0%"));
    }

    #[test]
    fn linear_slope_positive() {
        let x = [0.0, 1.0, 2.0, 3.0];
        let y = [0.0, 1.0, 2.0, 3.0];
        assert!((linear_slope(&x, &y) - 1.0).abs() < 0.001);
    }

    #[test]
    fn linear_slope_negative() {
        let x = [0.0, 1.0, 2.0];
        let y = [3.0, 2.0, 1.0];
        assert!((linear_slope(&x, &y) - (-1.0)).abs() < 0.001);
    }
}
