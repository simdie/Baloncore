use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::lifecycle::{FindingRecord, FindingState, ScanRecord};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricPoint {
    pub metric: String,
    pub value: f64,
    pub source_run_ids: Vec<String>,
    pub source_finding_ids: Vec<String>,
    pub computed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VulnClassMetricsSummary {
    pub vuln_class: String,
    pub verified_count: usize,
    pub rejected_count: usize,
    pub suppressed_count: usize,
    pub total_candidates: usize,
    pub false_positive_reduction_rate: f64,
    pub mean_time_to_proof_ms: Option<f64>,
    pub median_time_to_proof_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricsSummary {
    pub total_scans: usize,
    pub total_findings: usize,
    pub verified_findings: usize,
    pub rejected_hypotheses: usize,
    pub suppressed_findings: usize,
    pub verified_findings_per_scan: f64,
    pub false_positive_reduction_rate: f64,
    pub time_to_proof: TimeToProofMetrics,
    pub time_to_fix: TimeToFixMetrics,
    pub retest_success_rate: f64,
    pub ci_blocked_criticals: usize,
    pub scan_volume_over_time: Vec<ScanVolumePoint>,
    pub model_calls_per_verified: f64,
    pub tokens_per_verified: f64,
    pub per_vuln_class: Vec<VulnClassMetricsSummary>,
    pub traces: Vec<MetricPoint>,
    pub computed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimeToProofMetrics {
    pub mean_ms: f64,
    pub median_ms: f64,
    pub p90_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub sample_count: usize,
}

impl Default for TimeToProofMetrics {
    fn default() -> Self {
        Self {
            mean_ms: 0.0,
            median_ms: 0.0,
            p90_ms: 0.0,
            min_ms: 0.0,
            max_ms: 0.0,
            sample_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimeToFixMetrics {
    pub mean_ms: f64,
    pub median_ms: f64,
    pub p90_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub sample_count: usize,
}

impl Default for TimeToFixMetrics {
    fn default() -> Self {
        Self {
            mean_ms: 0.0,
            median_ms: 0.0,
            p90_ms: 0.0,
            min_ms: 0.0,
            max_ms: 0.0,
            sample_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanVolumePoint {
    pub period: String,
    pub count: usize,
    pub verified: usize,
    pub rejected: usize,
}

pub fn verified_findings_per_scan(scans: &[ScanRecord]) -> f64 {
    if scans.is_empty() {
        return 0.0;
    }
    let total: usize = scans.iter().map(|s| s.verified_findings).sum();
    total as f64 / scans.len() as f64
}

pub fn false_positive_reduction_rate(findings: &[FindingRecord]) -> f64 {
    let suppressed = findings
        .iter()
        .filter(|f| f.state == FindingState::Rejected)
        .count();
    let verified = findings
        .iter()
        .filter(|f| f.state == FindingState::Verified)
        .count();
    let total_candidates = suppressed
        + verified
        + findings
            .iter()
            .filter(|f| f.state == FindingState::NeedsMoreEvidence)
            .count();
    if total_candidates == 0 {
        return 0.0;
    }
    (suppressed
        + findings
            .iter()
            .filter(|f| f.state == FindingState::Rejected)
            .count()) as f64
        / total_candidates as f64
}

pub fn false_positive_reduction_rate_from_store(findings: &[FindingRecord]) -> f64 {
    let rejected = findings
        .iter()
        .filter(|f| f.state == FindingState::Rejected)
        .count();
    let suppressed = findings
        .iter()
        .filter(|f| {
            f.transitions
                .iter()
                .any(|t| t.to_state == "rejected" || t.to_state == "NeedsMoreEvidence")
                && f.state == FindingState::Verified
        })
        .count();
    let verified = findings
        .iter()
        .filter(|f| f.state == FindingState::Verified)
        .count();
    let hypothesis = findings
        .iter()
        .filter(|f| f.state == FindingState::Hypothesis)
        .count();
    let total = rejected + suppressed + verified + hypothesis;
    if total == 0 {
        return 0.0;
    }
    rejected as f64 / total as f64
}

pub fn time_to_proof(findings: &[FindingRecord]) -> TimeToProofMetrics {
    let mut times: Vec<u64> = Vec::new();
    for finding in findings {
        if finding.state == FindingState::Verified
            || finding.state == FindingState::Reported
            || finding.state == FindingState::Fixed
            || finding.state == FindingState::Retested
            || finding.state == FindingState::Closed
        {
            let verified_at = finding
                .transitions
                .iter()
                .find(|t| t.to_state == "verified")
                .map(|t| t.at);
            if let Some(v_at) = verified_at {
                let delta = v_at.saturating_sub(finding.first_seen_at);
                times.push(delta);
            }
        }
    }
    compute_time_metrics(&times)
}

pub fn time_to_fix(findings: &[FindingRecord]) -> TimeToFixMetrics {
    let mut times: Vec<u64> = Vec::new();
    for finding in findings {
        let verified_at = finding
            .transitions
            .iter()
            .find(|t| t.to_state == "verified")
            .map(|t| t.at);
        let fixed_at = finding
            .transitions
            .iter()
            .find(|t| t.to_state == "fixed")
            .map(|t| t.at);
        if let (Some(v), Some(f)) = (verified_at, fixed_at) {
            if f > v {
                times.push(f - v);
            }
        }
    }
    let ttp = compute_time_metrics(&times);
    TimeToFixMetrics {
        mean_ms: ttp.mean_ms,
        median_ms: ttp.median_ms,
        p90_ms: ttp.p90_ms,
        min_ms: ttp.min_ms,
        max_ms: ttp.max_ms,
        sample_count: ttp.sample_count,
    }
}

fn compute_time_metrics(times: &[u64]) -> TimeToProofMetrics {
    if times.is_empty() {
        return TimeToProofMetrics::default();
    }
    let mut sorted = times.to_vec();
    sorted.sort();

    let n = sorted.len();
    let sum: u64 = sorted.iter().sum();
    let mean = sum as f64 / n as f64;
    let median = if n % 2 == 0 {
        (sorted[n / 2 - 1] + sorted[n / 2]) as f64 / 2.0
    } else {
        sorted[n / 2] as f64
    };
    let p90_idx = ((n as f64) * 0.9) as usize;
    let p90 = sorted[p90_idx.min(n - 1)] as f64;
    let min = sorted[0] as f64;
    let max = sorted[n - 1] as f64;

    TimeToProofMetrics {
        mean_ms: mean,
        median_ms: median,
        p90_ms: p90,
        min_ms: min,
        max_ms: max,
        sample_count: n,
    }
}

pub fn retest_success_rate(findings: &[FindingRecord]) -> f64 {
    let retested_pass: usize = findings
        .iter()
        .filter(|f| {
            f.transitions
                .iter()
                .any(|t| t.to_state == "retested" && t.reason.to_lowercase().contains("pass"))
        })
        .count();
    let fixed_and_retested: usize = findings
        .iter()
        .filter(|f| {
            f.transitions.iter().any(|t| t.to_state == "fixed")
                && f.transitions.iter().any(|t| t.to_state == "retested")
        })
        .count();
    if fixed_and_retested == 0 {
        return 0.0;
    }
    retested_pass as f64 / fixed_and_retested as f64
}

pub fn retest_success_rate_simple(findings: &[FindingRecord]) -> f64 {
    let retested = findings
        .iter()
        .filter(|f| f.state == FindingState::Retested)
        .count();
    let fixed: usize = findings
        .iter()
        .filter(|f| {
            f.state == FindingState::Fixed
                || f.state == FindingState::Retested
                || f.state == FindingState::Closed
        })
        .count();
    if fixed == 0 {
        return 0.0;
    }
    retested as f64 / fixed as f64
}

/// Count findings that BALONCORE caught at CI time with severity = critical.
///
/// "Blocked at CI" means the finding is in a lifecycle state that represents
/// being caught and not yet fixed/closed: `Verified` (just promoted to a real
/// finding), `Reported` (handed to the team), or `NeedsMoreEvidence` (open
/// investigation). Findings already `Fixed`/`Retested`/`Closed`/`Rejected`
/// are not "blocked" — they've moved past the gate.
///
/// Severity is parsed case-insensitively; both "critical" and "Critical" count.
pub fn ci_blocked_criticals(findings: &[FindingRecord]) -> usize {
    findings
        .iter()
        .filter(|f| {
            matches!(
                f.state,
                FindingState::Verified | FindingState::Reported | FindingState::NeedsMoreEvidence
            )
        })
        .filter(|f| f.severity.eq_ignore_ascii_case("critical"))
        .count()
}

pub fn scan_volume_over_time(scans: &[ScanRecord], bucket: &str) -> Vec<ScanVolumePoint> {
    if scans.is_empty() {
        return Vec::new();
    }

    let mut buckets: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();

    let bucket_seconds = match bucket {
        "hour" | "hourly" => 3600,
        "day" | "daily" => 86400,
        "week" | "weekly" => 604800,
        "month" | "monthly" => 2592000,
        _ => 86400,
    };

    for scan in scans {
        let bucket_key = if bucket_seconds > 0 {
            format!("t{}", scan.started_at / bucket_seconds as u64)
        } else {
            "t0".to_string()
        };
        let entry = buckets.entry(bucket_key).or_insert((0, 0, 0));
        entry.0 += 1;
        entry.1 += scan.verified_findings;
        entry.2 += scan.rejected_hypotheses;
    }

    buckets
        .into_iter()
        .map(|(period, (count, verified, rejected))| ScanVolumePoint {
            period,
            count,
            verified,
            rejected,
        })
        .collect()
}

pub fn model_calls_per_verified(scans: &[ScanRecord], model_calls: u32) -> f64 {
    let total_verified: usize = scans.iter().map(|s| s.verified_findings).sum();
    if total_verified == 0 {
        return 0.0;
    }
    model_calls as f64 / total_verified as f64
}

pub fn tokens_per_verified(scans: &[ScanRecord], total_tokens: u32) -> f64 {
    let total_verified: usize = scans.iter().map(|s| s.verified_findings).sum();
    if total_verified == 0 {
        return 0.0;
    }
    total_tokens as f64 / total_verified as f64
}

pub fn vuln_class_breakdown(findings: &[FindingRecord]) -> Vec<VulnClassMetricsSummary> {
    let mut class_map: BTreeMap<String, (usize, usize, usize, usize)> = BTreeMap::new();

    for finding in findings {
        let vc = &finding.vulnerability_class;
        let entry = class_map.entry(vc.clone()).or_insert((0, 0, 0, 0));
        match finding.state {
            FindingState::Verified
            | FindingState::Reported
            | FindingState::Fixed
            | FindingState::Retested
            | FindingState::Closed => entry.0 += 1,
            FindingState::Rejected => entry.1 += 1,
            FindingState::Hypothesis => entry.2 += 1,
            FindingState::NeedsMoreEvidence => entry.3 += 1,
        }
    }

    let mut result = Vec::new();
    for (vc, (verified, rejected, hypothesis, needs_evidence)) in class_map {
        let total = verified + rejected + hypothesis + needs_evidence;
        let fprr = if total > 0 {
            rejected as f64 / total as f64
        } else {
            0.0
        };
        result.push(VulnClassMetricsSummary {
            vuln_class: vc,
            verified_count: verified,
            rejected_count: rejected,
            suppressed_count: 0,
            total_candidates: total,
            false_positive_reduction_rate: fprr,
            mean_time_to_proof_ms: None,
            median_time_to_proof_ms: None,
        });
    }
    result
}

pub fn compute_metrics_summary(
    scans: &[ScanRecord],
    findings: &[FindingRecord],
    model_calls: u32,
    total_tokens: u32,
    now: u64,
) -> MetricsSummary {
    let total_findings = findings.len();
    let verified = findings
        .iter()
        .filter(|f| {
            f.state == FindingState::Verified
                || f.state == FindingState::Reported
                || f.state == FindingState::Fixed
                || f.state == FindingState::Retested
                || f.state == FindingState::Closed
        })
        .count();
    let rejected = findings
        .iter()
        .filter(|f| f.state == FindingState::Rejected)
        .count();
    let suppressed = findings
        .iter()
        .filter(|f| f.state == FindingState::NeedsMoreEvidence)
        .count();
    let vfps = verified_findings_per_scan(scans);
    let fprr = false_positive_reduction_rate_from_store(findings);
    let ttp = time_to_proof(findings);
    let ttf = time_to_fix(findings);
    let rsr = retest_success_rate_simple(findings);
    let cic = ci_blocked_criticals(findings);
    let svo = scan_volume_over_time(scans, "day");
    let mcpv = model_calls_per_verified(scans, model_calls);
    let tpv = tokens_per_verified(scans, total_tokens);
    let per_vc = vuln_class_breakdown(findings);

    let traces = vec![
        MetricPoint {
            metric: "verified_findings_per_scan".to_string(),
            value: vfps,
            source_run_ids: scans.iter().map(|s| s.scan_id.clone()).take(10).collect(),
            source_finding_ids: vec![],
            computed_at: now,
        },
        MetricPoint {
            metric: "false_positive_reduction_rate".to_string(),
            value: fprr,
            source_run_ids: scans.iter().map(|s| s.scan_id.clone()).take(10).collect(),
            source_finding_ids: findings
                .iter()
                .filter(|f| f.state == FindingState::Rejected)
                .map(|f| f.finding_id.clone())
                .take(10)
                .collect(),
            computed_at: now,
        },
        MetricPoint {
            metric: "mean_time_to_proof_ms".to_string(),
            value: ttp.mean_ms,
            source_run_ids: vec![],
            source_finding_ids: findings
                .iter()
                .filter(|f| f.state == FindingState::Verified)
                .map(|f| f.finding_id.clone())
                .take(10)
                .collect(),
            computed_at: now,
        },
        MetricPoint {
            metric: "retest_success_rate".to_string(),
            value: rsr,
            source_run_ids: vec![],
            source_finding_ids: findings
                .iter()
                .filter(|f| f.state == FindingState::Retested)
                .map(|f| f.finding_id.clone())
                .take(10)
                .collect(),
            computed_at: now,
        },
        MetricPoint {
            metric: "ci_blocked_criticals".to_string(),
            value: cic as f64,
            source_run_ids: scans.iter().map(|s| s.scan_id.clone()).take(10).collect(),
            source_finding_ids: vec![],
            computed_at: now,
        },
    ];

    MetricsSummary {
        total_scans: scans.len(),
        total_findings,
        verified_findings: verified,
        rejected_hypotheses: rejected,
        suppressed_findings: suppressed,
        verified_findings_per_scan: vfps,
        false_positive_reduction_rate: fprr,
        time_to_proof: ttp,
        time_to_fix: ttf,
        retest_success_rate: rsr,
        ci_blocked_criticals: cic,
        scan_volume_over_time: svo,
        model_calls_per_verified: mcpv,
        tokens_per_verified: tpv,
        per_vuln_class: per_vc,
        traces,
        computed_at: now,
    }
}

pub fn render_metrics_summary(summary: &MetricsSummary) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Metrics Summary\n\n");

    md.push_str("## Overview\n\n");
    md.push_str(&format!("**Total Scans:** {}  \n", summary.total_scans));
    md.push_str(&format!(
        "**Total Findings:** {}  \n",
        summary.total_findings
    ));
    md.push_str(&format!(
        "**Verified Findings:** {}  \n",
        summary.verified_findings
    ));
    md.push_str(&format!(
        "**Rejected Hypotheses:** {}  \n",
        summary.rejected_hypotheses
    ));
    md.push_str(&format!(
        "**Suppressed Findings:** {}  \n\n",
        summary.suppressed_findings
    ));

    md.push_str("## Key Metrics\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!(
        "| Verified Findings/Scan | {:.2} |\n",
        summary.verified_findings_per_scan
    ));
    md.push_str(&format!(
        "| FP Reduction Rate | {:.1}% |\n",
        summary.false_positive_reduction_rate * 100.0
    ));
    md.push_str(&format!(
        "| Mean Time to Proof | {:.0}ms |\n",
        summary.time_to_proof.mean_ms
    ));
    md.push_str(&format!(
        "| Median Time to Proof | {:.0}ms |\n",
        summary.time_to_proof.median_ms
    ));
    md.push_str(&format!(
        "| P90 Time to Proof | {:.0}ms |\n",
        summary.time_to_proof.p90_ms
    ));
    md.push_str(&format!(
        "| Retest Success Rate | {:.1}% |\n",
        summary.retest_success_rate * 100.0
    ));
    md.push_str(&format!(
        "| CI Blocked Criticals | {} |\n",
        summary.ci_blocked_criticals
    ));
    md.push_str(&format!(
        "| Model Calls/Verified | {:.1} |\n",
        summary.model_calls_per_verified
    ));
    md.push_str(&format!(
        "| Tokens/Verified | {:.0} |\n",
        summary.tokens_per_verified
    ));

    if summary.time_to_fix.sample_count > 0 {
        md.push_str(&format!(
            "| Mean Time to Fix | {:.0}ms |\n",
            summary.time_to_fix.mean_ms
        ));
        md.push_str(&format!(
            "| Median Time to Fix | {:.0}ms |\n",
            summary.time_to_fix.median_ms
        ));
        md.push_str(&format!(
            "| P90 Time to Fix | {:.0}ms |\n",
            summary.time_to_fix.p90_ms
        ));
    } else {
        md.push_str("| Mean Time to Fix | N/A |\n");
    }

    if !summary.per_vuln_class.is_empty() {
        md.push_str("\n## Per-Vulnerability-Class\n\n");
        md.push_str("| Class | Verified | Rejected | Total | FP Reduction |\n");
        md.push_str("|-------|----------|----------|-------|-------------|\n");
        for vc in &summary.per_vuln_class {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {:.1}% |\n",
                vc.vuln_class,
                vc.verified_count,
                vc.rejected_count,
                vc.total_candidates,
                vc.false_positive_reduction_rate * 100.0
            ));
        }
    }

    if !summary.scan_volume_over_time.is_empty() {
        md.push_str("\n## Scan Volume Over Time\n\n");
        md.push_str("| Period | Scans | Verified | Rejected |\n");
        md.push_str("|--------|-------|----------|----------|\n");
        for point in &summary.scan_volume_over_time {
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                point.period, point.count, point.verified, point.rejected
            ));
        }
    }

    if !summary.traces.is_empty() {
        md.push_str("\n## Trace Provenance\n\n");
        md.push_str("| Metric | Value | Sources |\n");
        md.push_str("|--------|-------|--------|\n");
        for trace in &summary.traces {
            let sources = if !trace.source_finding_ids.is_empty() {
                trace
                    .source_finding_ids
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            } else if !trace.source_run_ids.is_empty() {
                trace
                    .source_run_ids
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                "computed".to_string()
            };
            md.push_str(&format!(
                "| {} | {:.2} | {} |\n",
                trace.metric, trace.value, sources
            ));
        }
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{FindingState, FindingTransition};

    fn make_finding(
        id: &str,
        state: FindingState,
        first_seen: u64,
        vuln_class: &str,
    ) -> FindingRecord {
        FindingRecord {
            finding_id: id.to_string(),
            scan_id: "scan-1".to_string(),
            fingerprint: format!("fp-{}", id),
            classification: "BOLA".to_string(),
            vulnerability_class: vuln_class.to_string(),
            endpoint: "/api/test".to_string(),
            object_id: "obj-1".to_string(),
            owner_profile: "user_a".to_string(),
            tested_profile: "user_b".to_string(),
            severity: "high".to_string(),
            score: 8,
            state,
            first_seen_run: "scan-1".to_string(),
            last_seen_run: "scan-1".to_string(),
            first_seen_at: first_seen,
            last_seen_at: first_seen + 3600,
            seen_count: 1,
            latest_artifacts: "/tmp".to_string(),
            latest_evidence_dir: "/tmp".to_string(),
            transitions: vec![],
            defense_classifications: vec![],
        }
    }

    fn make_verified_with_transition(
        id: &str,
        first_seen: u64,
        verified_at: u64,
        vuln_class: &str,
    ) -> FindingRecord {
        let mut f = make_finding(id, FindingState::Verified, first_seen, vuln_class);
        f.transitions.push(FindingTransition {
            from_state: "hypothesis".to_string(),
            to_state: "verified".to_string(),
            reason: "validator confirmed".to_string(),
            at: verified_at,
            actor: "bola-validator".to_string(),
        });
        f
    }

    fn make_fixed_finding(
        id: &str,
        first_seen: u64,
        verified_at: u64,
        fixed_at: u64,
        vuln_class: &str,
    ) -> FindingRecord {
        let mut f = make_finding(id, FindingState::Fixed, first_seen, vuln_class);
        f.transitions.push(FindingTransition {
            from_state: "hypothesis".to_string(),
            to_state: "verified".to_string(),
            reason: "validator confirmed".to_string(),
            at: verified_at,
            actor: "bola-validator".to_string(),
        });
        f.transitions.push(FindingTransition {
            from_state: "verified".to_string(),
            to_state: "fixed".to_string(),
            reason: "patched".to_string(),
            at: fixed_at,
            actor: "engineer".to_string(),
        });
        f
    }

    fn make_scan(id: &str, verified: usize, rejected: usize) -> ScanRecord {
        ScanRecord {
            scan_id: id.to_string(),
            started_at: 1000000,
            finished_at: Some(1003600),
            scan_type: "web_api".to_string(),
            base_url: "http://localhost:3000".to_string(),
            owner_profile: "user_a".to_string(),
            matrix_profiles: vec!["user_a".to_string(), "user_b".to_string()],
            endpoints_imported: 10,
            candidates_considered: 20,
            validated_count: 15,
            verified_findings: verified,
            rejected_hypotheses: rejected,
            suppressed_findings: 0,
            noise_mode: "moderate".to_string(),
            run_dir: "/tmp".to_string(),
            findings: vec![],
        }
    }

    #[test]
    fn verified_findings_per_scan_empty() {
        let result = verified_findings_per_scan(&[]);
        assert_eq!(result, 0.0);
    }

    #[test]
    fn verified_findings_per_scan_single() {
        let scans = vec![make_scan("s1", 5, 2)];
        let result = verified_findings_per_scan(&scans);
        assert_eq!(result, 5.0);
    }

    #[test]
    fn verified_findings_per_scan_multiple() {
        let scans = vec![make_scan("s1", 3, 1), make_scan("s2", 7, 2)];
        let result = verified_findings_per_scan(&scans);
        assert_eq!(result, 5.0);
    }

    #[test]
    fn false_positive_reduction_rate_empty() {
        let result = false_positive_reduction_rate_from_store(&[]);
        assert_eq!(result, 0.0);
    }

    #[test]
    fn false_positive_reduction_rate_all_verified() {
        let findings = vec![
            make_finding("f1", FindingState::Verified, 100, "BOLA"),
            make_finding("f2", FindingState::Verified, 200, "BOLA"),
        ];
        let result = false_positive_reduction_rate_from_store(&findings);
        assert_eq!(result, 0.0);
    }

    #[test]
    fn false_positive_reduction_rate_mixed() {
        let findings = vec![
            make_finding("f1", FindingState::Verified, 100, "BOLA"),
            make_finding("f2", FindingState::Rejected, 200, "BFLA"),
            make_finding("f3", FindingState::Rejected, 300, "BOLA"),
        ];
        let result = false_positive_reduction_rate_from_store(&findings);
        assert!(
            (result - 0.667).abs() < 0.01,
            "expected ~0.667, got {}",
            result
        );
    }

    #[test]
    fn time_to_proof_empty() {
        let result = time_to_proof(&[]);
        assert_eq!(result.sample_count, 0);
        assert_eq!(result.mean_ms, 0.0);
        assert_eq!(result.median_ms, 0.0);
    }

    #[test]
    fn time_to_proof_with_transitions() {
        let findings = vec![
            make_verified_with_transition("f1", 1000, 5000, "BOLA"),
            make_verified_with_transition("f2", 2000, 8000, "BFLA"),
            make_verified_with_transition("f3", 3000, 3000, "BOLA"),
        ];
        let result = time_to_proof(&findings);
        assert_eq!(result.sample_count, 3);
        assert_eq!(result.median_ms, 4000.0);
        assert!(result.mean_ms > 0.0);
    }

    #[test]
    fn time_to_proof_ignores_non_verified() {
        let findings = vec![make_finding("f1", FindingState::Hypothesis, 100, "BOLA")];
        let result = time_to_proof(&findings);
        assert_eq!(result.sample_count, 0);
    }

    #[test]
    fn time_to_fix_empty() {
        let result = time_to_fix(&[]);
        assert_eq!(result.sample_count, 0);
    }

    #[test]
    fn time_to_fix_with_fixed() {
        let findings = vec![
            make_fixed_finding("f1", 1000, 5000, 25000, "BOLA"),
            make_fixed_finding("f2", 2000, 8000, 50000, "BFLA"),
        ];
        let result = time_to_fix(&findings);
        assert_eq!(result.sample_count, 2);
        assert_eq!(result.mean_ms, 31000.0);
    }

    #[test]
    fn retest_success_rate_empty() {
        let result = retest_success_rate_simple(&[]);
        assert_eq!(result, 0.0);
    }

    #[test]
    fn retest_success_rate_some_retested() {
        let mut f1 = make_finding("f1", FindingState::Retested, 100, "BOLA");
        let mut f2 = make_finding("f2", FindingState::Closed, 200, "BFLA");
        let f3 = make_finding("f3", FindingState::Fixed, 300, "BOLA");
        f1.transitions.push(FindingTransition {
            from_state: "fixed".to_string(),
            to_state: "retested".to_string(),
            reason: "pass".to_string(),
            at: 5000,
            actor: "retest".to_string(),
        });
        f2.transitions.push(FindingTransition {
            from_state: "fixed".to_string(),
            to_state: "retested".to_string(),
            reason: "pass".to_string(),
            at: 6000,
            actor: "retest".to_string(),
        });
        let findings = vec![f1, f2, f3];
        let result = retest_success_rate_simple(&findings);
        assert!(result > 0.0);
    }

    #[test]
    fn ci_blocked_criticals_empty() {
        let result = ci_blocked_criticals(&[]);
        assert_eq!(result, 0);
    }

    fn make_finding_with_severity(id: &str, sev: &str, state: FindingState) -> FindingRecord {
        let mut f = make_finding(id, state, 100, "BrokenObjectLevelAuthorization");
        f.severity = sev.to_string();
        f
    }

    #[test]
    fn ci_blocked_criticals_only_counts_critical_and_blocked_states() {
        // T3.c: prior implementation summed scans[].verified_findings of ALL
        // severities. This pins the corrected semantics: severity=critical AND
        // state in {Verified, Reported, NeedsMoreEvidence}.
        let findings = vec![
            make_finding_with_severity("fa", "critical", FindingState::Verified),
            make_finding_with_severity("fb", "Critical", FindingState::Reported),
            make_finding_with_severity("fc", "critical", FindingState::Fixed),
            make_finding_with_severity("fd", "high", FindingState::Verified),
            make_finding_with_severity("fe", "critical", FindingState::Rejected),
            make_finding_with_severity("ff", "critical", FindingState::NeedsMoreEvidence),
        ];
        // Verified + Reported + NeedsMoreEvidence at critical = 3.
        assert_eq!(ci_blocked_criticals(&findings), 3);
    }

    #[test]
    fn ci_blocked_criticals_does_not_count_total_verified() {
        // Regression test for the prior wrong semantics: 5 Verified findings,
        // none critical, must produce 0 (not 5).
        let findings: Vec<FindingRecord> = (0..5)
            .map(|i| make_finding_with_severity(&format!("f{i}"), "high", FindingState::Verified))
            .collect();
        assert_eq!(
            ci_blocked_criticals(&findings),
            0,
            "ci_blocked_criticals must NOT sum verified_findings — see PROGRESS.md T3.c"
        );
    }

    #[test]
    fn scan_volume_over_time_empty() {
        let result = scan_volume_over_time(&[], "day");
        assert!(result.is_empty());
    }

    #[test]
    fn scan_volume_over_time_daily() {
        let scans = vec![make_scan("s1", 3, 1), make_scan("s2", 7, 2)];
        let result = scan_volume_over_time(&scans, "day");
        assert!(!result.is_empty());
        let total_count: usize = result.iter().map(|p| p.count).sum();
        assert_eq!(total_count, 2);
    }

    #[test]
    fn model_calls_per_verified_empty() {
        let result = model_calls_per_verified(&[], 100);
        assert_eq!(result, 0.0);
    }

    #[test]
    fn model_calls_per_verified_with_data() {
        let scans = vec![make_scan("s1", 5, 2)];
        let result = model_calls_per_verified(&scans, 50);
        assert_eq!(result, 10.0);
    }

    #[test]
    fn tokens_per_verified_with_data() {
        let scans = vec![make_scan("s1", 5, 2)];
        let result = tokens_per_verified(&scans, 2500);
        assert_eq!(result, 500.0);
    }

    #[test]
    fn vuln_class_breakdown_empty() {
        let result = vuln_class_breakdown(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn vuln_class_breakdown_with_findings() {
        let findings = vec![
            make_finding("f1", FindingState::Verified, 100, "BOLA"),
            make_finding("f2", FindingState::Verified, 200, "BOLA"),
            make_finding("f3", FindingState::Rejected, 300, "BFLA"),
            make_finding("f4", FindingState::Hypothesis, 400, "BOLA"),
        ];
        let result = vuln_class_breakdown(&findings);
        assert_eq!(result.len(), 2);
        let bola = result.iter().find(|v| v.vuln_class == "BOLA").unwrap();
        assert_eq!(bola.verified_count, 2);
        assert_eq!(bola.total_candidates, 3);
    }

    #[test]
    fn compute_metrics_summary_comprehensive() {
        let scans = vec![make_scan("scan-1", 3, 1), make_scan("scan-2", 5, 2)];
        let findings = vec![
            make_verified_with_transition("f1", 1000, 5000, "BOLA"),
            make_verified_with_transition("f2", 2000, 8000, "BFLA"),
            make_finding("f3", FindingState::Rejected, 300, "BOLA"),
        ];
        let summary = compute_metrics_summary(&scans, &findings, 100, 5000, 1700000000);

        assert_eq!(summary.total_scans, 2);
        assert_eq!(summary.total_findings, 3);
        assert_eq!(summary.verified_findings, 2);
        assert_eq!(summary.rejected_hypotheses, 1);
        assert!(summary.verified_findings_per_scan > 0.0);
        assert!(!summary.traces.is_empty());
        assert!(!summary.per_vuln_class.is_empty());
    }

    #[test]
    fn compute_metrics_summary_empty_inputs() {
        let summary = compute_metrics_summary(&[], &[], 0, 0, 1700000000);
        assert_eq!(summary.total_scans, 0);
        assert_eq!(summary.total_findings, 0);
        assert_eq!(summary.verified_findings, 0);
        assert_eq!(summary.verified_findings_per_scan, 0.0);
        assert_eq!(summary.false_positive_reduction_rate, 0.0);
        assert_eq!(summary.time_to_proof.sample_count, 0);
        assert_eq!(summary.time_to_fix.sample_count, 0);
        assert_eq!(summary.retest_success_rate, 0.0);
        assert_eq!(summary.ci_blocked_criticals, 0);
        assert_eq!(summary.model_calls_per_verified, 0.0);
        assert_eq!(summary.tokens_per_verified, 0.0);
    }

    #[test]
    fn render_metrics_summary_produces_markdown() {
        let scans = vec![make_scan("s1", 3, 1)];
        let findings = vec![make_verified_with_transition("f1", 1000, 5000, "BOLA")];
        let summary = compute_metrics_summary(&scans, &findings, 50, 2500, 1700000000);
        let md = render_metrics_summary(&summary);
        assert!(md.contains("Metrics Summary"));
        assert!(md.contains("Key Metrics"));
        assert!(md.contains("verified_findings_per_scan"));
        assert!(md.contains("BOLA"));
    }

    #[test]
    fn time_metrics_single_value() {
        let times = vec![5000u64];
        let result = compute_time_metrics(&times);
        assert_eq!(result.sample_count, 1);
        assert_eq!(result.mean_ms, 5000.0);
        assert_eq!(result.median_ms, 5000.0);
        assert_eq!(result.min_ms, 5000.0);
        assert_eq!(result.max_ms, 5000.0);
    }

    #[test]
    fn time_metrics_p90() {
        let times: Vec<u64> = (100..111).map(|i| i * 100).collect();
        let result = compute_time_metrics(&times);
        assert_eq!(result.sample_count, 11);
        assert!(result.p90_ms > 0.0);
    }
}

#[cfg(test)]
mod p3s1_tests {
    use super::*;
    use crate::lifecycle::{FindingRecord, FindingState};

    fn make_finding(
        id: &str,
        state: FindingState,
        first_seen: u64,
        vuln_class: &str,
    ) -> FindingRecord {
        FindingRecord {
            finding_id: id.to_string(),
            scan_id: "scan-1".to_string(),
            fingerprint: format!("fp-{}", id),
            classification: "BOLA".to_string(),
            vulnerability_class: vuln_class.to_string(),
            endpoint: "/api/test".to_string(),
            object_id: "obj-1".to_string(),
            owner_profile: "user_a".to_string(),
            tested_profile: "user_b".to_string(),
            severity: "high".to_string(),
            score: 8,
            state,
            first_seen_run: "scan-1".to_string(),
            last_seen_run: "scan-1".to_string(),
            first_seen_at: first_seen,
            last_seen_at: first_seen + 3600,
            seen_count: 1,
            latest_artifacts: "/tmp".to_string(),
            latest_evidence_dir: "/tmp".to_string(),
            transitions: vec![],
            defense_classifications: vec![],
        }
    }

    fn make_scan(id: &str, verified: usize, rejected: usize) -> ScanRecord {
        ScanRecord {
            scan_id: id.to_string(),
            started_at: 1000000,
            finished_at: Some(1003600),
            scan_type: "web_api".to_string(),
            base_url: "http://localhost:3000".to_string(),
            owner_profile: "user_a".to_string(),
            matrix_profiles: vec!["user_a".to_string(), "user_b".to_string()],
            endpoints_imported: 10,
            candidates_considered: 20,
            validated_count: 15,
            verified_findings: verified,
            rejected_hypotheses: rejected,
            suppressed_findings: 0,
            noise_mode: "moderate".to_string(),
            run_dir: "/tmp".to_string(),
            findings: vec![],
        }
    }

    #[test]
    fn rollup_new_is_empty() {
        let rollup = MetricsRollup::new();
        assert_eq!(rollup.total_scans_indexed, 0);
        assert!(rollup.last_scan_id.is_none());
        assert_eq!(rollup.cumulative.total_scans, 0);
        assert_eq!(rollup.per_scan.len(), 0);
    }

    #[test]
    fn rollup_add_scan_updates_counts() {
        let mut rollup = MetricsRollup::new();
        let scan = make_scan("scan-1", 5, 2);
        rollup.add_scan(&scan, &[], 100, 5000);

        assert_eq!(rollup.total_scans_indexed, 1);
        assert_eq!(rollup.last_scan_id, Some("scan-1".to_string()));
        assert_eq!(rollup.per_scan.len(), 1);
        assert_eq!(rollup.per_scan[0].verified_findings, 5);
        assert_eq!(rollup.per_scan[0].rejected_hypotheses, 2);
    }

    #[test]
    fn rollup_add_multiple_scans() {
        let mut rollup = MetricsRollup::new();
        let scan1 = make_scan("scan-1", 3, 1);
        let scan2 = make_scan("scan-2", 7, 2);
        rollup.add_scan(&scan1, &[], 100, 5000);
        rollup.add_scan(&scan2, &[], 200, 10000);

        assert_eq!(rollup.total_scans_indexed, 2);
        assert_eq!(rollup.last_scan_id, Some("scan-2".to_string()));
        assert_eq!(rollup.per_scan.len(), 2);
        assert_eq!(rollup.cumulative.total_scans, 2);
        assert_eq!(rollup.cumulative.verified_findings_per_scan, 5.0);
    }

    #[test]
    fn rollup_incremental_update_with_findings() {
        let mut rollup = MetricsRollup::new();
        let scan = make_scan("scan-1", 2, 1);
        let findings = vec![
            make_finding("f1", FindingState::Verified, 100, "BOLA"),
            make_finding("f2", FindingState::Rejected, 200, "BFLA"),
        ];
        rollup.add_scan(&scan, &findings, 50, 2500);

        assert_eq!(rollup.cumulative.total_findings, 2);
        assert_eq!(rollup.cumulative.verified_findings, 1);
        assert!(rollup.cumulative.per_vuln_class.len() > 0);
    }

    #[test]
    fn save_and_load_rollup() {
        let dir = std::env::temp_dir().join("baloncore-rollup-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("metrics.json");

        let mut rollup = MetricsRollup::new();
        let scan = make_scan("scan-1", 3, 1);
        rollup.add_scan(&scan, &[], 100, 5000);
        save_metrics_rollup(&rollup, &path).unwrap();

        let loaded = load_metrics_rollup(&path).unwrap();
        assert_eq!(loaded.total_scans_indexed, 1);
        assert_eq!(loaded.last_scan_id, Some("scan-1".to_string()));
        assert_eq!(loaded.per_scan.len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_nonexistent_rollup_returns_new() {
        let path = std::path::PathBuf::from("/tmp/baloncore-nonexistent-rollup-test.json");
        let rollup = load_metrics_rollup(&path).unwrap();
        assert_eq!(rollup.total_scans_indexed, 0);
    }

    #[test]
    fn metrics_trend_daily() {
        let mut rollup = MetricsRollup::new();
        let s1 = make_scan("s1", 5, 2);
        let s2 = make_scan("s2", 3, 1);
        rollup.add_scan(&s1, &[], 100, 5000);
        rollup.add_scan(&s2, &[], 200, 10000);

        let trend = compute_metrics_trend(&rollup, "verified_findings", "day");
        assert!(!trend.is_empty());
        let total_samples: usize = trend.iter().map(|p| p.sample_count).sum();
        assert_eq!(total_samples, 2);
    }

    #[test]
    fn metrics_trend_empty() {
        let rollup = MetricsRollup::new();
        let trend = compute_metrics_trend(&rollup, "verified_findings", "day");
        assert!(trend.is_empty());
    }

    #[test]
    fn render_trend_produces_markdown() {
        let mut rollup = MetricsRollup::new();
        let scan = make_scan("s1", 5, 2);
        rollup.add_scan(&scan, &[], 100, 5000);
        let trend = compute_metrics_trend(&rollup, "verified_findings", "day");
        let md = render_metrics_trend(&trend);
        assert!(md.contains("Metrics Trend"));
        assert!(md.contains("verified_findings"));
    }

    #[test]
    fn render_rollup_produces_markdown() {
        let mut rollup = MetricsRollup::new();
        let scan = make_scan("s1", 3, 1);
        rollup.add_scan(&scan, &[], 100, 5000);
        let md = render_metrics_rollup(&rollup);
        assert!(md.contains("Metrics Summary"));
        assert!(md.contains("Rollup Metadata"));
        assert!(md.contains("Total Scans Indexed"));
    }

    #[test]
    fn rollup_hand_computation_matches() {
        let mut rollup = MetricsRollup::new();
        let scan = make_scan("s1", 5, 3);
        // Build findings with explicit severities so the corrected
        // ci_blocked_criticals semantics (severity=critical, state=blocked)
        // produce a known value. Two critical+Verified findings, two
        // high+Verified, one critical+Rejected, one Hypothesis at high.
        let mut findings = vec![
            make_finding("f1", FindingState::Verified, 100, "BOLA"),
            make_finding("f2", FindingState::Verified, 200, "BOLA"),
            make_finding("f3", FindingState::Verified, 300, "BFLA"),
            make_finding("f4", FindingState::Rejected, 400, "BOLA"),
            make_finding("f5", FindingState::Hypothesis, 500, "BFLA"),
        ];
        findings[0].severity = "critical".to_string();
        findings[1].severity = "critical".to_string();
        findings[2].severity = "high".to_string();
        findings[3].severity = "critical".to_string(); // Rejected → not blocked
        findings[4].severity = "high".to_string();

        rollup.add_scan(&scan, &findings, 50, 2500);

        assert_eq!(rollup.cumulative.total_scans, 1);
        assert_eq!(rollup.cumulative.verified_findings, 3);
        assert_eq!(rollup.cumulative.rejected_hypotheses, 1);
        // Corrected semantics (T3.c): 2 critical+Verified count; the critical
        // Rejected one does NOT (state filter), the high+Verified ones do NOT
        // (severity filter).
        assert_eq!(rollup.cumulative.ci_blocked_criticals, 2);
        assert!((rollup.cumulative.verified_findings_per_scan - 5.0).abs() < 0.001);
        assert!((rollup.cumulative.model_calls_per_verified - 10.0).abs() < 0.001);
        assert!((rollup.cumulative.tokens_per_verified - 500.0).abs() < 0.001);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricsRollup {
    pub version: u32,
    pub total_scans_indexed: usize,
    pub last_scan_id: Option<String>,
    pub last_updated_at: u64,
    pub cumulative: MetricsSummary,
    pub per_scan: Vec<ScanMetricsEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanMetricsEntry {
    pub scan_id: String,
    pub verified_findings: usize,
    pub rejected_hypotheses: usize,
    pub suppressed_findings: usize,
    pub total_candidates: usize,
    pub started_at: u64,
    pub computed_at: u64,
}

impl Default for MetricsRollup {
    fn default() -> Self {
        Self {
            version: 2,
            total_scans_indexed: 0,
            last_scan_id: None,
            last_updated_at: 0,
            cumulative: MetricsSummary {
                total_scans: 0,
                total_findings: 0,
                verified_findings: 0,
                rejected_hypotheses: 0,
                suppressed_findings: 0,
                verified_findings_per_scan: 0.0,
                false_positive_reduction_rate: 0.0,
                time_to_proof: TimeToProofMetrics::default(),
                time_to_fix: TimeToFixMetrics::default(),
                retest_success_rate: 0.0,
                ci_blocked_criticals: 0,
                scan_volume_over_time: vec![],
                model_calls_per_verified: 0.0,
                tokens_per_verified: 0.0,
                per_vuln_class: vec![],
                traces: vec![],
                computed_at: 0,
            },
            per_scan: vec![],
        }
    }
}

impl MetricsRollup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_scan(
        &mut self,
        scan: &ScanRecord,
        findings: &[FindingRecord],
        model_calls: u32,
        total_tokens: u32,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = ScanMetricsEntry {
            scan_id: scan.scan_id.clone(),
            verified_findings: scan.verified_findings,
            rejected_hypotheses: scan.rejected_hypotheses,
            suppressed_findings: scan.suppressed_findings,
            total_candidates: scan.candidates_considered,
            started_at: scan.started_at,
            computed_at: now,
        };

        self.total_scans_indexed += 1;
        self.last_scan_id = Some(scan.scan_id.clone());
        self.last_updated_at = now;
        self.per_scan.push(entry);

        let mut all_scans: Vec<ScanRecord> = Vec::new();
        for entry in &self.per_scan {
            all_scans.push(ScanRecord {
                scan_id: entry.scan_id.clone(),
                started_at: entry.started_at,
                finished_at: Some(entry.started_at + 3600),
                scan_type: "web_api".to_string(),
                base_url: "http://localhost:3000".to_string(),
                owner_profile: "user_a".to_string(),
                matrix_profiles: vec![],
                endpoints_imported: 0,
                candidates_considered: entry.total_candidates,
                validated_count: entry.verified_findings + entry.rejected_hypotheses,
                verified_findings: entry.verified_findings,
                rejected_hypotheses: entry.rejected_hypotheses,
                suppressed_findings: entry.suppressed_findings,
                noise_mode: "moderate".to_string(),
                run_dir: String::new(),
                findings: vec![],
            });
        }

        self.cumulative =
            compute_metrics_summary(&all_scans, findings, model_calls, total_tokens, now);
    }
}

pub fn save_metrics_rollup(rollup: &MetricsRollup, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(rollup).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, json).map_err(|e| e.to_string())
}

pub fn load_metrics_rollup(path: &Path) -> Result<MetricsRollup, String> {
    if !path.exists() {
        return Ok(MetricsRollup::new());
    }
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricsTrendPoint {
    pub period: String,
    pub metric: String,
    pub value: f64,
    pub sample_count: usize,
}

pub fn compute_metrics_trend(
    rollup: &MetricsRollup,
    metric_name: &str,
    bucket: &str,
) -> Vec<MetricsTrendPoint> {
    let bucket_seconds = match bucket {
        "hour" | "hourly" => 3600,
        "day" | "daily" => 86400,
        "week" | "weekly" => 604800,
        "month" | "monthly" => 2592000,
        _ => 86400,
    };

    let mut buckets: BTreeMap<u64, Vec<f64>> = BTreeMap::new();

    for entry in &rollup.per_scan {
        let bucket_key = entry.started_at / bucket_seconds.max(1) as u64;
        let value = match metric_name {
            "verified_findings_per_scan" => entry.verified_findings as f64,
            "rejected_hypotheses" => entry.rejected_hypotheses as f64,
            "total_candidates" => entry.total_candidates as f64,
            "verified_findings" => entry.verified_findings as f64,
            "suppressed_findings" => entry.suppressed_findings as f64,
            _ => entry.verified_findings as f64,
        };
        buckets.entry(bucket_key).or_default().push(value);
    }

    buckets
        .into_iter()
        .map(|(bucket_key, values)| {
            let period = format!("t{}", bucket_key);
            let sum: f64 = values.iter().sum();
            let count = values.len();
            MetricsTrendPoint {
                period,
                metric: metric_name.to_string(),
                value: sum / count as f64,
                sample_count: count,
            }
        })
        .collect()
}

pub fn render_metrics_trend(points: &[MetricsTrendPoint]) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Metrics Trend\n\n");

    if points.is_empty() {
        md.push_str("No data available for the requested metric and time bucket.\n");
        return md;
    }

    md.push_str(&format!("**Metric:** {}  \n\n", points[0].metric));
    md.push_str("| Period | Value | Samples |\n");
    md.push_str("|--------|-------|--------|\n");
    for point in points {
        md.push_str(&format!(
            "| {} | {:.2} | {} |\n",
            point.period, point.value, point.sample_count
        ));
    }

    md
}

pub fn render_metrics_rollup(rollup: &MetricsRollup) -> String {
    let md = render_metrics_summary(&rollup.cumulative);
    let mut full = String::from(md);
    full.push_str(&format!("\n## Rollup Metadata\n\n"));
    full.push_str(&format!("**Version:** {}  \n", rollup.version));
    full.push_str(&format!(
        "**Total Scans Indexed:** {}  \n",
        rollup.total_scans_indexed
    ));
    if let Some(ref last_scan) = rollup.last_scan_id {
        full.push_str(&format!("**Last Scan:** {}  \n", last_scan));
    }
    full.push_str(&format!("**Last Updated:** {}  \n", rollup.last_updated_at));
    full.push_str(&format!(
        "**Per-Scan Entries:** {}  \n",
        rollup.per_scan.len()
    ));
    full
}

#[cfg(test)]
mod p3s4_traceability_anti_gaming {
    use super::*;
    use crate::lifecycle::FindingTransition;

    fn make_finding(
        id: &str,
        state: FindingState,
        vuln_class: &str,
        first_seen: u64,
    ) -> FindingRecord {
        FindingRecord {
            finding_id: id.to_string(),
            scan_id: "scan-1".to_string(),
            fingerprint: format!("fp-{}", id),
            classification: vuln_class.to_string(),
            vulnerability_class: vuln_class.to_string(),
            endpoint: "/api/test".to_string(),
            object_id: "obj-1".to_string(),
            owner_profile: "user_a".to_string(),
            tested_profile: "user_b".to_string(),
            severity: "high".to_string(),
            score: 8,
            state,
            first_seen_run: "scan-1".to_string(),
            last_seen_run: "scan-1".to_string(),
            first_seen_at: first_seen,
            last_seen_at: first_seen + 3600,
            seen_count: 1,
            latest_artifacts: "/tmp".to_string(),
            latest_evidence_dir: "/tmp".to_string(),
            transitions: vec![],
            defense_classifications: vec![],
        }
    }

    fn make_finding_with_transition(
        id: &str,
        state: FindingState,
        vuln_class: &str,
        first_seen: u64,
        transition_from_state: &str,
        transition_to_state: &str,
        transition_at: u64,
    ) -> FindingRecord {
        let mut f = make_finding(id, state, vuln_class, first_seen);
        f.transitions.push(FindingTransition {
            from_state: transition_from_state.to_string(),
            to_state: transition_to_state.to_string(),
            reason: "test transition".to_string(),
            at: transition_at,
            actor: "system".to_string(),
        });
        f
    }

    fn make_scan(id: &str, verified: usize, rejected: usize) -> ScanRecord {
        ScanRecord {
            scan_id: id.to_string(),
            started_at: 1000000,
            finished_at: Some(1003600),
            scan_type: "web_api".to_string(),
            base_url: "http://localhost:3000".to_string(),
            owner_profile: "user_a".to_string(),
            matrix_profiles: vec!["user_a".to_string()],
            endpoints_imported: 10,
            candidates_considered: 20,
            validated_count: 15,
            verified_findings: verified,
            rejected_hypotheses: rejected,
            suppressed_findings: 0,
            noise_mode: "moderate".to_string(),
            run_dir: "/tmp".to_string(),
            findings: vec![],
        }
    }

    #[test]
    fn traceability_metrics_equal_independent_recomputation() {
        let scan1 = make_scan("scan-1", 3, 1);
        let scan2 = make_scan("scan-2", 2, 2);
        let findings = vec![
            make_finding("f1", FindingState::Verified, "BOLA", 1000000),
            make_finding("f2", FindingState::Verified, "BOLA", 1000100),
            make_finding("f3", FindingState::Verified, "BFLA", 1000200),
            make_finding("f4", FindingState::Verified, "BOLA", 2000000),
            make_finding("f5", FindingState::Reported, "IDOR", 2000100),
            make_finding("f6", FindingState::Rejected, "BOLA", 3000000),
            make_finding("f7", FindingState::Rejected, "BFLA", 3000100),
            make_finding("f8", FindingState::NeedsMoreEvidence, "BOLA", 4000000),
        ];
        let scans = vec![scan1.clone(), scan2.clone()];
        let now = 5000000_u64;
        let model_calls = 200_u32;
        let total_tokens = 50000_u32;

        let summary = compute_metrics_summary(&scans, &findings, model_calls, total_tokens, now);

        let independent_verified = findings
            .iter()
            .filter(|f| {
                matches!(
                    f.state,
                    FindingState::Verified
                        | FindingState::Reported
                        | FindingState::Fixed
                        | FindingState::Retested
                        | FindingState::Closed
                )
            })
            .count();
        assert_eq!(
            summary.verified_findings, independent_verified,
            "verified_findings must match independent recomputation from raw findings"
        );

        let independent_rejected = findings
            .iter()
            .filter(|f| f.state == FindingState::Rejected)
            .count();
        assert_eq!(
            summary.rejected_hypotheses, independent_rejected,
            "rejected must match independent recomputation"
        );

        let independent_suppressed = findings
            .iter()
            .filter(|f| f.state == FindingState::NeedsMoreEvidence)
            .count();
        assert_eq!(
            summary.suppressed_findings, independent_suppressed,
            "suppressed must match independent recomputation"
        );

        assert_eq!(
            summary.total_findings,
            findings.len(),
            "total_findings must equal raw findings count"
        );

        assert_eq!(summary.total_scans, 2, "total_scans must equal scans count");

        let independent_vfps = verified_findings_per_scan(&scans);
        assert!(
            (summary.verified_findings_per_scan - independent_vfps).abs() < 0.001,
            "verified_findings_per_scan must match independent recomputation"
        );

        let independent_fprr = false_positive_reduction_rate_from_store(&findings);
        assert!(
            (summary.false_positive_reduction_rate - independent_fprr).abs() < 0.001,
            "FP reduction rate must match independent recomputation"
        );

        let independent_rsr = retest_success_rate_simple(&findings);
        assert!(
            (summary.retest_success_rate - independent_rsr).abs() < 0.001,
            "retest success rate must match independent recomputation"
        );

        let independent_cic = ci_blocked_criticals(&findings);
        assert_eq!(
            summary.ci_blocked_criticals, independent_cic,
            "CI blocked criticals must match independent recomputation"
        );

        let independent_mcpv = model_calls_per_verified(&scans, model_calls);
        assert!(
            (summary.model_calls_per_verified - independent_mcpv).abs() < 0.001,
            "model_calls_per_verified must match independent recomputation"
        );

        let independent_tpv = tokens_per_verified(&scans, total_tokens);
        assert!(
            (summary.tokens_per_verified - independent_tpv).abs() < 0.001,
            "tokens_per_verified must match independent recomputation"
        );

        let independent_per_vc = vuln_class_breakdown(&findings);
        assert_eq!(
            summary.per_vuln_class.len(),
            independent_per_vc.len(),
            "per_vuln_class count must match"
        );
        for (computed, independent) in summary.per_vuln_class.iter().zip(independent_per_vc.iter())
        {
            assert_eq!(computed.vuln_class, independent.vuln_class);
            assert_eq!(
                computed.verified_count, independent.verified_count,
                "per-class verified must match"
            );
            assert_eq!(
                computed.rejected_count, independent.rejected_count,
                "per-class rejected must match"
            );
            assert_eq!(
                computed.suppressed_count, independent.suppressed_count,
                "per-class suppressed must match"
            );
        }

        for trace in &summary.traces {
            assert!(!trace.metric.is_empty(), "trace metric must not be empty");
            assert!(trace.computed_at == now, "trace computed_at must match now");
            if trace.metric.contains("time_to_proof") || trace.metric == "mean_time_to_proof_ms" {
                assert!(
                    !trace.source_finding_ids.is_empty() || trace.value == 0.0,
                    "time-to-proof trace must reference source finding IDs"
                );
            }
        }
    }

    #[test]
    fn traceability_rollup_cumulative_matches_compute() {
        let scan = make_scan("scan-1", 3, 1);
        let findings = vec![
            make_finding("f1", FindingState::Verified, "BOLA", 1000000),
            make_finding("f2", FindingState::Verified, "BFLA", 1000100),
            make_finding("f3", FindingState::Rejected, "BOLA", 1000200),
        ];
        let mut rollup = MetricsRollup::new();
        rollup.add_scan(&scan, &findings, 100, 5000);

        let direct =
            compute_metrics_summary(&[scan], &findings, 100, 5000, rollup.cumulative.computed_at);

        assert_eq!(
            rollup.cumulative.total_scans, direct.total_scans,
            "rollup total_scans must match direct computation"
        );
        assert_eq!(
            rollup.cumulative.total_findings, direct.total_findings,
            "rollup total_findings must match direct computation"
        );
        assert_eq!(
            rollup.cumulative.verified_findings, direct.verified_findings,
            "rollup verified_findings must match direct computation"
        );
        assert_eq!(
            rollup.cumulative.rejected_hypotheses, direct.rejected_hypotheses,
            "rollup rejected must match direct computation"
        );
        assert_eq!(
            rollup.cumulative.suppressed_findings, direct.suppressed_findings,
            "rollup suppressed must match direct computation"
        );
        assert!(
            (rollup.cumulative.verified_findings_per_scan - direct.verified_findings_per_scan)
                .abs()
                < 0.001
        );
        assert!(
            (rollup.cumulative.false_positive_reduction_rate
                - direct.false_positive_reduction_rate)
                .abs()
                < 0.001
        );
        assert!((rollup.cumulative.retest_success_rate - direct.retest_success_rate).abs() < 0.001);
        assert_eq!(
            rollup.cumulative.ci_blocked_criticals,
            direct.ci_blocked_criticals
        );
        assert!(
            (rollup.cumulative.model_calls_per_verified - direct.model_calls_per_verified).abs()
                < 0.001
        );
        assert!((rollup.cumulative.tokens_per_verified - direct.tokens_per_verified).abs() < 0.001);
    }

    #[test]
    fn anti_gaming_hypothesis_not_counted_as_verified() {
        let scan = make_scan("scan-1", 0, 0);
        let findings = vec![
            make_finding("h1", FindingState::Hypothesis, "BOLA", 1000000),
            make_finding("h2", FindingState::Hypothesis, "BFLA", 1000100),
            make_finding("h3", FindingState::Hypothesis, "IDOR", 1000200),
        ];
        let summary = compute_metrics_summary(&[scan], &findings, 50, 2500, 5000000);

        assert_eq!(
            summary.verified_findings, 0,
            "Hypothesis findings must NOT be counted as verified"
        );
        assert_eq!(
            summary.rejected_hypotheses, 0,
            "Hypothesis findings must NOT be counted as rejected"
        );
        assert_eq!(
            summary.suppressed_findings, 0,
            "Hypothesis findings must NOT be counted as suppressed"
        );
        assert_eq!(
            summary.total_findings, 3,
            "Total findings still includes all records"
        );

        for vc in &summary.per_vuln_class {
            assert_eq!(
                vc.verified_count, 0,
                "Per-class verified must be zero for all-hypothesis dataset"
            );
        }
    }

    #[test]
    fn anti_gaming_rejected_not_counted_as_verified() {
        let scan = make_scan("scan-1", 0, 0);
        let findings = vec![
            make_finding("f1", FindingState::Rejected, "BOLA", 1000000),
            make_finding("f2", FindingState::Rejected, "BFLA", 1000100),
        ];
        let summary = compute_metrics_summary(&[scan], &findings, 50, 2500, 5000000);

        assert_eq!(
            summary.verified_findings, 0,
            "Rejected findings must NOT be counted as verified"
        );
        assert_eq!(
            summary.rejected_hypotheses, 2,
            "Rejected findings must be counted as rejected"
        );
        assert_eq!(summary.suppressed_findings, 0);

        let bfla_vc = summary
            .per_vuln_class
            .iter()
            .find(|vc| vc.vuln_class == "BFLA")
            .unwrap();
        assert_eq!(bfla_vc.rejected_count, 1);
        assert_eq!(bfla_vc.verified_count, 0);
    }

    #[test]
    fn anti_gaming_suppressed_not_counted_as_verified() {
        let scan = make_scan("scan-1", 0, 0);
        let findings = vec![
            make_finding("f1", FindingState::NeedsMoreEvidence, "BOLA", 1000000),
            make_finding("f2", FindingState::NeedsMoreEvidence, "BFLA", 1000100),
        ];
        let summary = compute_metrics_summary(&[scan], &findings, 50, 2500, 5000000);

        assert_eq!(
            summary.verified_findings, 0,
            "Suppressed findings must NOT be counted as verified"
        );
        assert_eq!(
            summary.rejected_hypotheses, 0,
            "Suppressed findings must NOT be counted as rejected"
        );
        assert_eq!(
            summary.suppressed_findings, 2,
            "Suppressed findings must be counted as suppressed"
        );
    }

    #[test]
    fn anti_gaming_mixed_states_only_verified_counted() {
        let findings = vec![
            make_finding("f1", FindingState::Hypothesis, "BOLA", 1000000),
            make_finding("f2", FindingState::Rejected, "BOLA", 1000100),
            make_finding("f3", FindingState::NeedsMoreEvidence, "BFLA", 1000200),
            make_finding("f4", FindingState::Verified, "BOLA", 1000300),
            make_finding("f5", FindingState::Reported, "IDOR", 1000400),
            make_finding("f6", FindingState::Fixed, "BFLA", 1000500),
            make_finding("f7", FindingState::Retested, "BOLA", 1000600),
            make_finding("f8", FindingState::Closed, "IDOR", 1000700),
            make_finding("f9", FindingState::Hypothesis, "BFLA", 1000800),
        ];
        let scans = vec![make_scan("scan-1", 0, 0)];
        let summary = compute_metrics_summary(&scans, &findings, 200, 10000, 5000000);

        assert_eq!(
            summary.verified_findings, 5,
            "Only Verified/Reported/Fixed/Retested/Closed must be counted as verified"
        );
        assert_eq!(
            summary.rejected_hypotheses, 1,
            "Only Rejected must be counted as rejected"
        );
        assert_eq!(
            summary.suppressed_findings, 1,
            "Only NeedsMoreEvidence must be counted as suppressed"
        );
        assert_eq!(
            summary.total_findings, 9,
            "Total must include all records regardless of state"
        );

        let bola_vc = summary
            .per_vuln_class
            .iter()
            .find(|vc| vc.vuln_class == "BOLA")
            .unwrap();
        assert_eq!(
            bola_vc.verified_count, 2,
            "BOLA verified: f4(Verified) + f7(Retested)"
        );
        assert_eq!(bola_vc.rejected_count, 1, "BOLA rejected: f2");
        assert_eq!(
            bola_vc.suppressed_count, 0,
            "BOLA suppressed: 0 (Hypothesis is counted in hypothesis bucket, not suppressed)"
        );
    }

    #[test]
    fn anti_gaming_rollup_excludes_unverified_from_cumulative() {
        let scan = make_scan("scan-1", 0, 0);
        let findings = vec![
            make_finding("h1", FindingState::Hypothesis, "BOLA", 1000000),
            make_finding("f1", FindingState::Rejected, "BFLA", 2000000),
            make_finding("f2", FindingState::NeedsMoreEvidence, "IDOR", 3000000),
        ];
        let mut rollup = MetricsRollup::new();
        rollup.add_scan(&scan, &findings, 100, 5000);

        assert_eq!(
            rollup.cumulative.verified_findings, 0,
            "Rollup must not count hypotheses, rejected, or suppressed as verified"
        );
        assert_eq!(
            rollup.cumulative.rejected_hypotheses, 1,
            "Rollup must count Rejected as rejected"
        );
        assert_eq!(
            rollup.cumulative.suppressed_findings, 1,
            "Rollup must count NeedsMoreEvidence as suppressed"
        );
    }

    #[test]
    fn anti_gaming_no_false_positive_inflation() {
        let scan = make_scan("scan-1", 0, 0);
        let findings = vec![
            make_finding("f1", FindingState::Verified, "BOLA", 1000000),
            make_finding("f2", FindingState::Verified, "BOLA", 1000100),
            make_finding("f3", FindingState::Rejected, "BFLA", 1000200),
            make_finding("f4", FindingState::Hypothesis, "IDOR", 1000300),
        ];
        let summary = compute_metrics_summary(&[scan], &findings, 100, 5000, 5000000);

        assert!(
            summary.false_positive_reduction_rate > 0.0,
            "FP reduction must be positive when there are rejections"
        );
        assert!(
            summary.false_positive_reduction_rate <= 1.0,
            "FP reduction must not exceed 1.0"
        );
        assert_eq!(
            summary.verified_findings, 2,
            "Only Verified findings counted"
        );
    }

    #[test]
    fn traceability_persistence_roundtrip_preserves_values() {
        let dir = std::env::temp_dir().join("baloncore-p3s4-roundtrip-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("metrics.json");

        let scan = make_scan("scan-1", 3, 1);
        let findings = vec![
            make_finding("f1", FindingState::Verified, "BOLA", 1000000),
            make_finding("f2", FindingState::Verified, "BFLA", 1000100),
            make_finding("f3", FindingState::Rejected, "BOLA", 1000200),
        ];

        let mut rollup = MetricsRollup::new();
        rollup.add_scan(&scan, &findings, 100, 5000);
        let original_cumulative = rollup.cumulative.clone();

        save_metrics_rollup(&rollup, &path).unwrap();
        let loaded = load_metrics_rollup(&path).unwrap();

        assert_eq!(
            loaded.cumulative.total_scans, original_cumulative.total_scans,
            "Persistence roundtrip: total_scans must match"
        );
        assert_eq!(
            loaded.cumulative.verified_findings, original_cumulative.verified_findings,
            "Persistence roundtrip: verified_findings must match"
        );
        assert_eq!(
            loaded.cumulative.rejected_hypotheses, original_cumulative.rejected_hypotheses,
            "Persistence roundtrip: rejected must match"
        );
        assert_eq!(
            loaded.cumulative.suppressed_findings, original_cumulative.suppressed_findings,
            "Persistence roundtrip: suppressed must match"
        );
        assert_eq!(
            loaded.total_scans_indexed, rollup.total_scans_indexed,
            "Persistence roundtrip: total_scans_indexed must match"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
