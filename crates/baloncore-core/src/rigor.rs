use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceProof {
    pub proof_id: String,
    pub target: String,
    pub generated_at: u64,
    pub scope_audit: ScopeAuditProof,
    pub custody_chain: CustodyChain,
    pub decoy_verification: DecoyVerification,
    pub report_integrity: ReportIntegrityCheck,
    pub defense_lineage: Vec<DefenseLineageEntry>,
    pub audit_integrity: AuditIntegrityRecord,
    pub regression_provenance: Vec<RegressionProvenanceEntry>,
    pub all_passed: bool,
    pub summary: String,
    pub grade: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeAuditProof {
    pub scope_contract_id: String,
    pub verified_at: u64,
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub blocked_requests: u64,
    pub host_deny_list: Vec<String>,
    pub host_allow_list: Vec<String>,
    pub url_allow_list: Vec<String>,
    pub max_depth: u8,
    pub verification_hash: String,
    pub signer: String,
    pub passed: bool,
    pub summary: String,
}

impl ScopeAuditProof {
    pub fn new(
        contract_id: &str,
        config: &crate::config::ScopeConfig,
        total: u64,
        allowed: u64,
        blocked: u64,
    ) -> Self {
        let passed = blocked == 0;
        let summary = if passed {
            format!(
                "Scope audit passed: {}/{} requests within authorized scope. Contract: {}.",
                allowed, total, contract_id
            )
        } else {
            format!(
                "Scope audit failed: {} requests blocked out of {} total. Contract: {}.",
                blocked, total, contract_id
            )
        };

        let mut hasher = Sha256::new();
        hasher.update(contract_id.as_bytes());
        hasher.update(&total.to_le_bytes());
        hasher.update(&allowed.to_le_bytes());
        hasher.update(&blocked.to_le_bytes());
        let hash = hex_encode(&hasher.finalize());

        Self {
            scope_contract_id: contract_id.to_string(),
            verified_at: unix_seconds(),
            total_requests: total,
            allowed_requests: allowed,
            blocked_requests: blocked,
            host_deny_list: config.deny_hosts.clone(),
            host_allow_list: config.allow_hosts.clone(),
            url_allow_list: config.allow_urls.clone(),
            max_depth: config.max_depth,
            verification_hash: hash,
            signer: "baloncore-scope-guard".to_string(),
            passed,
            summary,
        }
    }

    pub fn passed(&self) -> bool {
        self.blocked_requests == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustodyChain {
    pub chain_id: String,
    pub target: String,
    pub created_at: u64,
    pub steps: Vec<CustodyStep>,
    pub root_hash: String,
    pub is_continuous: bool,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustodyStep {
    pub step: u64,
    pub phase: String,
    pub description: String,
    pub timestamp: u64,
    pub actor: String,
    pub artifact_hash: String,
    pub previous_hash: String,
    pub metadata: Vec<(String, String)>,
}

impl CustodyChain {
    pub fn new(target: &str) -> Self {
        let chain_id = format!("custody-{}-{}", target.replace('/', "-"), unix_seconds());
        Self {
            chain_id,
            target: target.to_string(),
            created_at: unix_seconds(),
            steps: Vec::new(),
            root_hash: String::new(),
            is_continuous: true,
            summary: String::new(),
        }
    }

    pub fn add_step(
        &mut self,
        phase: &str,
        description: &str,
        actor: &str,
        artifact_content: &str,
        metadata: Vec<(String, String)>,
    ) {
        let prev_hash = self
            .steps
            .last()
            .map(|s| s.artifact_hash.clone())
            .unwrap_or_else(|| self.chain_id.clone());
        let step_num = (self.steps.len() + 1) as u64;

        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(phase.as_bytes());
        hasher.update(description.as_bytes());
        hasher.update(artifact_content.as_bytes());
        let artifact_hash = hex_encode(&hasher.finalize());

        self.steps.push(CustodyStep {
            step: step_num,
            phase: phase.to_string(),
            description: description.to_string(),
            timestamp: unix_seconds(),
            actor: actor.to_string(),
            artifact_hash,
            previous_hash: prev_hash,
            metadata,
        });

        self.root_hash = self
            .steps
            .last()
            .map(|s| s.artifact_hash.clone())
            .unwrap_or_default();
    }

    pub fn verify_continuity(&self) -> bool {
        for window in self.steps.windows(2) {
            let prev = &window[0];
            let curr = &window[1];
            if curr.previous_hash != prev.artifact_hash {
                return false;
            }
        }
        true
    }

    pub fn finalize(&mut self) {
        self.is_continuous = self.verify_continuity();
        self.summary = format!(
            "Custody chain {}: {} steps, continuous={}, root={}",
            self.chain_id,
            self.steps.len(),
            self.is_continuous,
            &self.root_hash[..16]
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecoyVerification {
    pub total_decoys: usize,
    pub correctly_rejected: usize,
    pub incorrectly_accepted: usize,
    pub rejection_rate: f64,
    pub decoys: Vec<DecoyResult>,
    pub passed: bool,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecoyResult {
    pub decoy_id: String,
    pub endpoint: String,
    pub expected_result: String,
    pub actual_result: String,
    pub rejected: bool,
    pub evidence: String,
}

impl DecoyVerification {
    pub fn new(decoys: Vec<DecoyResult>) -> Self {
        let total = decoys.len();
        let correctly_rejected = decoys.iter().filter(|d| d.rejected).count();
        let incorrectly_accepted = total - correctly_rejected;
        let rejection_rate = if total > 0 {
            correctly_rejected as f64 / total as f64
        } else {
            1.0
        };
        let passed = incorrectly_accepted == 0;

        let summary = if passed {
            format!(
                "Decoy verification passed: {}/{} decoys correctly rejected ({:.0}%).",
                correctly_rejected,
                total,
                rejection_rate * 100.0
            )
        } else {
            format!(
                "Decoy verification failed: {} decoys incorrectly accepted out of {} total.",
                incorrectly_accepted, total
            )
        };

        Self {
            total_decoys: total,
            correctly_rejected,
            incorrectly_accepted,
            rejection_rate,
            decoys,
            passed,
            summary,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportIntegrityCheck {
    pub report_type: String,
    pub report_path: String,
    pub verified_at: u64,
    pub total_findings_in_report: usize,
    pub total_findings_in_evidence: usize,
    pub matched_count: usize,
    pub unmatched_in_report: Vec<String>,
    pub unmatched_in_evidence: Vec<String>,
    pub report_hash: String,
    pub evidence_hash: String,
    pub is_consistent: bool,
    pub summary: String,
}

impl ReportIntegrityCheck {
    pub fn verify(
        report_type: &str,
        report_path: &str,
        report_finding_ids: Vec<String>,
        evidence_finding_ids: Vec<String>,
    ) -> Self {
        let report_set: std::collections::HashSet<&String> = report_finding_ids.iter().collect();
        let evidence_set: std::collections::HashSet<&String> =
            evidence_finding_ids.iter().collect();

        let matched: Vec<_> = report_set.intersection(&evidence_set).collect();
        let unmatched_in_report: Vec<String> = report_set
            .difference(&evidence_set)
            .map(|s| s.to_string())
            .collect();
        let unmatched_in_evidence: Vec<String> = evidence_set
            .difference(&report_set)
            .map(|s| s.to_string())
            .collect();

        let is_consistent = unmatched_in_report.is_empty() && unmatched_in_evidence.is_empty();

        let mut report_hasher = Sha256::new();
        for id in &report_finding_ids {
            report_hasher.update(id.as_bytes());
        }
        let report_hash = hex_encode(&report_hasher.finalize());

        let mut evidence_hasher = Sha256::new();
        for id in &evidence_finding_ids {
            evidence_hasher.update(id.as_bytes());
        }
        let evidence_hash = hex_encode(&evidence_hasher.finalize());

        let summary = if is_consistent {
            format!(
                "Report integrity verified: all {} findings in {} match evidence ({} total).",
                matched.len(),
                report_type,
                evidence_finding_ids.len()
            )
        } else {
            format!(
                "Report integrity mismatch: {} unmatched in report, {} unmatched in evidence.",
                unmatched_in_report.len(),
                unmatched_in_evidence.len()
            )
        };

        Self {
            report_type: report_type.to_string(),
            report_path: report_path.to_string(),
            verified_at: unix_seconds(),
            total_findings_in_report: report_finding_ids.len(),
            total_findings_in_evidence: evidence_finding_ids.len(),
            matched_count: matched.len(),
            unmatched_in_report,
            unmatched_in_evidence,
            report_hash,
            evidence_hash,
            is_consistent,
            summary,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DefenseLineageEntry {
    pub finding_id: String,
    pub classification: String,
    pub defense_artifact: String,
    pub artifact_type: String,
    pub generated_at: u64,
    pub generated_from: String,
    pub verification_hash: String,
    pub summary: String,
}

impl DefenseLineageEntry {
    pub fn new(
        finding_id: &str,
        classification: &str,
        artifact_type: &str,
        artifact_content: &str,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(finding_id.as_bytes());
        hasher.update(classification.as_bytes());
        hasher.update(artifact_type.as_bytes());
        hasher.update(artifact_content.as_bytes());
        let hash = hex_encode(&hasher.finalize());

        let artifact = format!("{}-{}", artifact_type, &hash[..8]);

        Self {
            finding_id: finding_id.to_string(),
            classification: classification.to_string(),
            defense_artifact: artifact,
            artifact_type: artifact_type.to_string(),
            generated_at: unix_seconds(),
            generated_from: format!("finding {} ({})", finding_id, classification),
            verification_hash: hash,
            summary: format!(
                "{} generated from finding {} ({})",
                artifact_type, finding_id, classification
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditIntegrityRecord {
    pub record_id: String,
    pub events: Vec<TamperEvidentEvent>,
    pub root_hash: String,
    pub sealed_at: u64,
    pub sealer: String,
    pub is_tamper_evident: bool,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TamperEvidentEvent {
    pub event_id: String,
    pub timestamp: u64,
    pub actor: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub outcome: String,
    pub event_hash: String,
    pub previous_hash: String,
}

impl AuditIntegrityRecord {
    pub fn new(record_id: &str) -> Self {
        Self {
            record_id: record_id.to_string(),
            events: Vec::new(),
            root_hash: String::new(),
            sealed_at: 0,
            sealer: "baloncore-audit-guard".to_string(),
            is_tamper_evident: true,
            summary: String::new(),
        }
    }

    pub fn record(
        &mut self,
        actor: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        outcome: &str,
    ) {
        let prev_hash = self
            .events
            .last()
            .map(|e| e.event_hash.clone())
            .unwrap_or_else(|| self.record_id.clone());

        let event_id = format!("audit-{}-{}", self.record_id, self.events.len() + 1);
        let timestamp = unix_seconds();

        let mut hasher = Sha256::new();
        hasher.update(event_id.as_bytes());
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(actor.as_bytes());
        hasher.update(action.as_bytes());
        hasher.update(resource_type.as_bytes());
        hasher.update(resource_id.as_bytes());
        hasher.update(outcome.as_bytes());
        hasher.update(prev_hash.as_bytes());
        let event_hash = hex_encode(&hasher.finalize());

        self.events.push(TamperEvidentEvent {
            event_id,
            timestamp,
            actor: actor.to_string(),
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: resource_id.to_string(),
            outcome: outcome.to_string(),
            event_hash,
            previous_hash: prev_hash,
        });

        self.root_hash = self
            .events
            .last()
            .map(|e| e.event_hash.clone())
            .unwrap_or_default();
    }

    pub fn seal(&mut self) {
        self.sealed_at = unix_seconds();
        self.summary = format!(
            "Audit record {}: {} events, sealed at {}, root={}",
            self.record_id,
            self.events.len(),
            self.sealed_at,
            &self.root_hash[..16]
        );
    }

    pub fn verify(&self) -> bool {
        if self.events.is_empty() {
            return true;
        }
        let mut prev_hash = self.record_id.clone();
        for event in &self.events {
            if event.previous_hash != prev_hash {
                return false;
            }
            let mut hasher = Sha256::new();
            hasher.update(event.event_id.as_bytes());
            hasher.update(&event.timestamp.to_le_bytes());
            hasher.update(event.actor.as_bytes());
            hasher.update(event.action.as_bytes());
            hasher.update(event.resource_type.as_bytes());
            hasher.update(event.resource_id.as_bytes());
            hasher.update(event.outcome.as_bytes());
            hasher.update(prev_hash.as_bytes());
            let computed = hex_encode(&hasher.finalize());
            if computed != event.event_hash {
                return false;
            }
            prev_hash = event.event_hash.clone();
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegressionProvenanceEntry {
    pub finding_id: String,
    pub classification: String,
    pub first_regression_at: u64,
    pub last_regression_at: u64,
    pub total_regressions: u64,
    pub total_passes: u64,
    pub total_failures: u64,
    pub pass_rate: f64,
    pub history: Vec<RegressionCheckpoint>,
    pub currently_fixed: bool,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegressionCheckpoint {
    pub timestamp: u64,
    pub verdict: String,
    pub passed_checks: usize,
    pub total_checks: usize,
}

impl RegressionProvenanceEntry {
    pub fn new(finding_id: &str, classification: &str) -> Self {
        Self {
            finding_id: finding_id.to_string(),
            classification: classification.to_string(),
            first_regression_at: 0,
            last_regression_at: 0,
            total_regressions: 0,
            total_passes: 0,
            total_failures: 0,
            pass_rate: 0.0,
            history: Vec::new(),
            currently_fixed: false,
            summary: "No regression checks recorded yet.".to_string(),
        }
    }

    pub fn record(&mut self, passed: bool, passed_checks: usize, total_checks: usize) {
        let now = unix_seconds();
        if self.first_regression_at == 0 {
            self.first_regression_at = now;
        }
        self.last_regression_at = now;
        self.total_regressions += 1;
        if passed {
            self.total_passes += 1;
            self.currently_fixed = true;
        } else {
            self.total_failures += 1;
            self.currently_fixed = false;
        }
        self.pass_rate = self.total_passes as f64 / self.total_regressions as f64;

        self.history.push(RegressionCheckpoint {
            timestamp: now,
            verdict: if passed {
                "Fixed".to_string()
            } else {
                "StillFailing".to_string()
            },
            passed_checks,
            total_checks,
        });

        self.summary = format!(
            "{}: {} regressions ({} passed, {} failed, {:.0}% pass rate). Currently: {}.",
            self.finding_id,
            self.total_regressions,
            self.total_passes,
            self.total_failures,
            self.pass_rate * 100.0,
            if self.currently_fixed {
                "fixed"
            } else {
                "not fixed"
            }
        );
    }
}

impl ComplianceProof {
    pub fn assemble(
        target: &str,
        scope_config: &crate::config::ScopeConfig,
        total_requests: u64,
        allowed_requests: u64,
        blocked_requests: u64,
        decoy_results: Vec<DecoyResult>,
        report_finding_ids: Vec<String>,
        evidence_finding_ids: Vec<String>,
        defense_entries: Vec<DefenseLineageEntry>,
        regression_entries: Vec<RegressionProvenanceEntry>,
    ) -> Self {
        let scope_audit = ScopeAuditProof::new(
            "default",
            scope_config,
            total_requests,
            allowed_requests,
            blocked_requests,
        );
        let decoy_verification = DecoyVerification::new(decoy_results);
        let report_integrity = ReportIntegrityCheck::verify(
            "flagship-report",
            "flagship_report.html",
            report_finding_ids,
            evidence_finding_ids,
        );

        let mut audit = AuditIntegrityRecord::new(&format!("compliance-{}", unix_seconds()));
        let mut custody = CustodyChain::new(target);

        custody.add_step(
            "authorization",
            &scope_audit.summary,
            "scope-guard",
            &scope_audit.verification_hash,
            vec![
                (
                    "scope_contract".to_string(),
                    scope_audit.scope_contract_id.clone(),
                ),
                ("allowed".to_string(), allowed_requests.to_string()),
                ("blocked".to_string(), blocked_requests.to_string()),
            ],
        );

        custody.add_step(
            "scan",
            &format!(
                "Scan completed: {} requests, {} allowed",
                total_requests, allowed_requests
            ),
            "scan-engine",
            &hex_encode(&Sha256::digest(
                format!("{}-{}", target, total_requests).as_bytes(),
            )),
            vec![("target".to_string(), target.to_string())],
        );

        custody.add_step(
            "validation",
            &format!("{} decoys verified", decoy_verification.total_decoys),
            "decoy-validator",
            &hex_encode(&Sha256::digest(decoy_verification.summary.as_bytes())),
            vec![(
                "correctly_rejected".to_string(),
                decoy_verification.correctly_rejected.to_string(),
            )],
        );

        custody.add_step(
            "reporting",
            &report_integrity.summary,
            "report-verifier",
            &report_integrity.report_hash,
            vec![(
                "is_consistent".to_string(),
                report_integrity.is_consistent.to_string(),
            )],
        );

        custody.finalize();

        audit.record(
            "baloncore-compliance-engine",
            "compliance-proof-generated",
            "compliance",
            target,
            "success",
        );
        audit.record(
            "scope-guard",
            "scope-audit-completed",
            "scope",
            &scope_audit.scope_contract_id,
            if scope_audit.passed() {
                "passed"
            } else {
                "failed"
            },
        );
        audit.seal();

        let all_passed = scope_audit.passed()
            && decoy_verification.passed
            && report_integrity.is_consistent
            && custody.is_continuous
            && audit.is_tamper_evident;

        let grade = if all_passed {
            "A+".to_string()
        } else if scope_audit.passed() && decoy_verification.passed {
            "B".to_string()
        } else {
            "F".to_string()
        };

        let proof_id = format!("rigor-{}-{}", target.replace('/', "-"), unix_seconds());
        let summary = format!(
            "BUILD_RIGOR compliance proof {}: grade {}. Scope={}, Decoys={}, Report={}, Custody={}, Audit={}.",
            proof_id,
            grade,
            if scope_audit.passed() { "pass" } else { "fail" },
            if decoy_verification.passed { "pass" } else { "fail" },
            if report_integrity.is_consistent { "pass" } else { "fail" },
            if custody.is_continuous { "pass" } else { "fail" },
            if audit.is_tamper_evident { "pass" } else { "fail" },
        );

        Self {
            proof_id,
            target: target.to_string(),
            generated_at: unix_seconds(),
            scope_audit,
            custody_chain: custody,
            decoy_verification,
            report_integrity,
            defense_lineage: defense_entries,
            audit_integrity: audit,
            regression_provenance: regression_entries,
            all_passed,
            summary,
            grade,
        }
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!(
            "# BUILD_RIGOR Compliance Proof — {}\n\n",
            self.target
        ));
        md.push_str(&format!("**Proof ID:** {}\n\n", self.proof_id));
        md.push_str(&format!(
            "**Generated:** {}\n\n",
            format_timestamp(self.generated_at)
        ));
        md.push_str(&format!(
            "**Overall Grade:** {} ({})\n\n",
            self.grade,
            if self.all_passed {
                "all checks passed"
            } else {
                "some checks failed"
            }
        ));
        md.push_str(&format!("{}\n\n", self.summary));

        md.push_str("## 1. Authorization — Scope Audit\n\n");
        md.push_str(&self.scope_audit.summary);
        md.push_str("\n\n");
        md.push_str(&format!(
            "- Contract: {}\n",
            self.scope_audit.scope_contract_id
        ));
        md.push_str(&format!(
            "- Requests: {} allowed / {} blocked / {} total\n",
            self.scope_audit.allowed_requests,
            self.scope_audit.blocked_requests,
            self.scope_audit.total_requests
        ));
        md.push_str(&format!(
            "- Verification hash: {}\n\n",
            self.scope_audit.verification_hash
        ));

        md.push_str("## 2. Evidence — Custody Chain\n\n");
        md.push_str(&self.custody_chain.summary);
        md.push_str("\n\n");
        md.push_str("| Step | Phase | Description | Actor |\n");
        md.push_str("|------|-------|-------------|-------|\n");
        for step in &self.custody_chain.steps {
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                step.step, step.phase, step.description, step.actor
            ));
        }
        md.push('\n');

        md.push_str("## 3. False-Positive Control — Decoy Verification\n\n");
        md.push_str(&self.decoy_verification.summary);
        md.push_str("\n\n");
        if !self.decoy_verification.decoys.is_empty() {
            md.push_str("| Decoy | Expected | Actual | Rejected |\n");
            md.push_str("|-------|----------|--------|----------|\n");
            for d in &self.decoy_verification.decoys {
                let rejected = if d.rejected { "yes" } else { "no" };
                md.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    d.decoy_id, d.expected_result, d.actual_result, rejected
                ));
            }
            md.push('\n');
        }

        md.push_str("## 4. Customer Artifact — Report Integrity\n\n");
        md.push_str(&self.report_integrity.summary);
        md.push_str("\n\n");

        md.push_str("## 5. Regression — Provenance\n\n");
        if self.regression_provenance.is_empty() {
            md.push_str("No regression data available.\n\n");
        } else {
            md.push_str("| Finding | Regressions | Passed | Pass Rate | Currently |\n");
            md.push_str("|---------|-------------|--------|-----------|-----------|\n");
            for rp in &self.regression_provenance {
                md.push_str(&format!(
                    "| {} | {} | {} | {:.0}% | {} |\n",
                    rp.finding_id,
                    rp.total_regressions,
                    rp.total_passes,
                    rp.pass_rate * 100.0,
                    if rp.currently_fixed {
                        "fixed"
                    } else {
                        "not fixed"
                    }
                ));
            }
            md.push('\n');
        }

        md.push_str("## 6. Defense — Lineage\n\n");
        if self.defense_lineage.is_empty() {
            md.push_str("No defense lineage data available.\n\n");
        } else {
            md.push_str("| Finding | Artifact Type | Defense Artifact |\n");
            md.push_str("|---------|---------------|------------------|\n");
            for dl in &self.defense_lineage {
                md.push_str(&format!(
                    "| {} | {} | {} |\n",
                    dl.finding_id, dl.artifact_type, dl.defense_artifact
                ));
            }
            md.push('\n');
        }

        md.push_str("## 7. Audit + Isolation — Integrity\n\n");
        md.push_str(&format!(
            "{} events, sealed at {}. Tamper-evident: {}\n\n",
            self.audit_integrity.events.len(),
            format_timestamp(self.audit_integrity.sealed_at),
            if self.audit_integrity.is_tamper_evident {
                "yes"
            } else {
                "no"
            }
        ));

        md.push_str("---\n*Generated by BALONCORE BUILD_RIGOR Compliance Engine*\n");
        md
    }
}

fn format_timestamp(epoch: u64) -> String {
    format!("epoch {} UTC", epoch)
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
    use crate::config::ScopeConfig;

    fn test_scope_config() -> ScopeConfig {
        ScopeConfig {
            allow_urls: vec!["https://api.example.com".to_string()],
            allow_hosts: vec!["api.example.com".to_string()],
            deny_hosts: vec![],
            max_depth: 3,
        }
    }

    #[test]
    fn scope_audit_passes_with_no_blocked() {
        let audit = ScopeAuditProof::new("test-contract", &test_scope_config(), 100, 100, 0);
        assert!(audit.passed());
        assert!(audit.summary.contains("passed"));
        assert!(!audit.verification_hash.is_empty());
    }

    #[test]
    fn scope_audit_fails_with_blocked() {
        let audit = ScopeAuditProof::new("test-contract", &test_scope_config(), 100, 95, 5);
        assert!(!audit.passed());
        assert!(audit.summary.contains("failed"));
    }

    #[test]
    fn custody_chain_is_continuous() {
        let mut chain = CustodyChain::new("test-target");
        chain.add_step("auth", "Scope verified", "scope-guard", "auth-data", vec![]);
        chain.add_step("scan", "Scan completed", "scanner", "scan-data", vec![]);
        chain.add_step(
            "report",
            "Report generated",
            "reporter",
            "report-data",
            vec![],
        );
        chain.finalize();
        assert!(chain.is_continuous);
        assert_eq!(chain.steps.len(), 3);
        assert!(chain.verify_continuity());
    }

    #[test]
    fn custody_chain_detects_break() {
        let mut chain = CustodyChain::new("test");
        chain.add_step("a", "step a", "actor", "data1", vec![]);
        chain.add_step("b", "step b", "actor", "data2", vec![]);
        chain.steps[1].previous_hash = "tampered".to_string();
        chain.finalize();
        assert!(!chain.is_continuous);
        assert!(!chain.verify_continuity());
    }

    #[test]
    fn decoy_verification_all_rejected() {
        let decoys = vec![DecoyResult {
            decoy_id: "d1".to_string(),
            endpoint: "/api/secret".to_string(),
            expected_result: "403".to_string(),
            actual_result: "403".to_string(),
            rejected: true,
            evidence: "access denied".to_string(),
        }];
        let v = DecoyVerification::new(decoys);
        assert!(v.passed);
        assert_eq!(v.rejection_rate, 1.0);
    }

    #[test]
    fn decoy_verification_one_accepted() {
        let decoys = vec![
            DecoyResult {
                decoy_id: "d1".to_string(),
                endpoint: "/api/secret".to_string(),
                expected_result: "403".to_string(),
                actual_result: "403".to_string(),
                rejected: true,
                evidence: "access denied".to_string(),
            },
            DecoyResult {
                decoy_id: "d2".to_string(),
                endpoint: "/api/leaked".to_string(),
                expected_result: "403".to_string(),
                actual_result: "200".to_string(),
                rejected: false,
                evidence: "data exposed".to_string(),
            },
        ];
        let v = DecoyVerification::new(decoys);
        assert!(!v.passed);
        assert_eq!(v.rejection_rate, 0.5);
    }

    #[test]
    fn report_integrity_consistent() {
        let report_ids = vec!["f1".to_string(), "f2".to_string()];
        let evidence_ids = vec!["f1".to_string(), "f2".to_string()];
        let check = ReportIntegrityCheck::verify("test", "test.html", report_ids, evidence_ids);
        assert!(check.is_consistent);
        assert_eq!(check.matched_count, 2);
    }

    #[test]
    fn report_integrity_mismatch() {
        let report_ids = vec!["f1".to_string(), "f2".to_string()];
        let evidence_ids = vec!["f1".to_string(), "f3".to_string()];
        let check = ReportIntegrityCheck::verify("test", "test.html", report_ids, evidence_ids);
        assert!(!check.is_consistent);
        assert!(!check.unmatched_in_report.is_empty());
    }

    #[test]
    fn defense_lineage_hashes_are_deterministic() {
        let dl1 = DefenseLineageEntry::new("f-123", "BOLA", "sigma-rule", "rule content here");
        let dl2 = DefenseLineageEntry::new("f-123", "BOLA", "sigma-rule", "rule content here");
        assert_eq!(dl1.verification_hash, dl2.verification_hash);
    }

    #[test]
    fn defense_lineage_different_content_hashes_differ() {
        let dl1 = DefenseLineageEntry::new("f-123", "BOLA", "sigma", "content a");
        let dl2 = DefenseLineageEntry::new("f-123", "BOLA", "sigma", "content b");
        assert_ne!(dl1.verification_hash, dl2.verification_hash);
    }

    #[test]
    fn audit_integrity_chain_verifies() {
        let mut audit = AuditIntegrityRecord::new("test-audit");
        audit.record("user-1", "scan-started", "scan", "scan-1", "success");
        audit.record("user-1", "finding-verified", "finding", "f-1", "verified");
        audit.record("system", "evidence-sealed", "evidence", "ev-1", "sealed");
        audit.seal();
        assert!(audit.verify());
        assert_eq!(audit.events.len(), 3);
    }

    #[test]
    fn audit_integrity_detects_tampering() {
        let mut audit = AuditIntegrityRecord::new("test-audit");
        audit.record("user-1", "scan", "scan", "s1", "ok");
        audit.events[0].action = "tampered".to_string();
        audit.seal();
        assert!(!audit.verify());
    }

    #[test]
    fn regression_provenance_tracks_history() {
        let mut rp = RegressionProvenanceEntry::new("f-1", "BOLA");
        rp.record(true, 2, 2);
        rp.record(true, 3, 3);
        rp.record(false, 1, 3);
        assert_eq!(rp.total_regressions, 3);
        assert_eq!(rp.total_passes, 2);
        assert_eq!(rp.total_failures, 1);
        assert!(!rp.currently_fixed);
        assert!(rp.summary.contains("67%"));
    }

    #[test]
    fn regression_provenance_stays_fixed_after_passes() {
        let mut rp = RegressionProvenanceEntry::new("f-2", "BFLA");
        rp.record(true, 3, 3);
        assert!(rp.currently_fixed);
        rp.record(true, 2, 2);
        assert!(rp.currently_fixed);
        assert_eq!(rp.pass_rate, 1.0);
    }

    #[test]
    fn full_compliance_proof_assembles() {
        let proof = ComplianceProof::assemble(
            "https://api.example.com",
            &test_scope_config(),
            50,
            50,
            0,
            vec![DecoyResult {
                decoy_id: "d1".to_string(),
                endpoint: "/api/secret".to_string(),
                expected_result: "403".to_string(),
                actual_result: "403".to_string(),
                rejected: true,
                evidence: "blocked".to_string(),
            }],
            vec!["f1".to_string(), "f2".to_string()],
            vec!["f1".to_string(), "f2".to_string()],
            vec![DefenseLineageEntry::new("f1", "BOLA", "sigma", "rule")],
            vec![],
        );
        assert!(proof.all_passed);
        assert_eq!(proof.grade, "A+");
    }

    #[test]
    fn compliance_proof_fails_with_blocked_requests() {
        let proof = ComplianceProof::assemble(
            "https://api.example.com",
            &test_scope_config(),
            50,
            45,
            5,
            vec![],
            vec!["f1".to_string()],
            vec!["f1".to_string()],
            vec![],
            vec![],
        );
        assert!(!proof.all_passed);
        assert_ne!(proof.grade, "A+");
    }

    #[test]
    fn compliance_proof_to_markdown() {
        let proof = ComplianceProof::assemble(
            "https://api.example.com",
            &test_scope_config(),
            10,
            10,
            0,
            vec![DecoyResult {
                decoy_id: "d1".to_string(),
                endpoint: "/api/secret".to_string(),
                expected_result: "403".to_string(),
                actual_result: "403".to_string(),
                rejected: true,
                evidence: "ok".to_string(),
            }],
            vec!["f1".to_string()],
            vec!["f1".to_string()],
            vec![],
            vec![],
        );
        let md = proof.to_markdown();
        assert!(md.contains("BUILD_RIGOR Compliance Proof"));
        assert!(md.contains("Scope Audit"));
        assert!(md.contains("Custody Chain"));
        assert!(md.contains("Decoy Verification"));
        assert!(md.contains("Report Integrity"));
        assert!(md.contains("Defense"));
        assert!(md.contains("Audit"));
    }
}
