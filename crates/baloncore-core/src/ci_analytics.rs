use serde::{Deserialize, Serialize};

use crate::ci_pipeline::CIPipelineResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CIPipelineHistory {
    pub version: u32,
    pub project: String,
    pub total_runs: u64,
    pub last_updated_at: u64,
    pub runs: Vec<CIPipelineRunRecord>,
}

impl CIPipelineHistory {
    pub fn new(project: &str) -> Self {
        Self {
            version: 1,
            project: project.to_string(),
            total_runs: 0,
            last_updated_at: unix_seconds(),
            runs: Vec::new(),
        }
    }

    pub fn append(&mut self, result: &CIPipelineResult) {
        let mut record = CIPipelineRunRecord::from(result);
        record.project = self.project.clone();
        self.runs.push(record);
        self.total_runs += 1;
        self.last_updated_at = unix_seconds();
        if self.runs.len() > 500 {
            self.runs.drain(0..self.runs.len() - 500);
        }
    }

    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        if !path.as_ref().exists() {
            return Ok(Self::new("baloncore"));
        }
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("failed to read history: {e}"))?;
        serde_json::from_str(&raw).map_err(|e| format!("failed to parse history: {e}"))
    }

    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<(), String> {
        if let Some(parent) = path.as_ref().parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize history: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("failed to write history: {e}"))
    }

    pub fn recent(&self, limit: usize) -> Vec<&CIPipelineRunRecord> {
        let start = if self.runs.len() > limit {
            self.runs.len() - limit
        } else {
            0
        };
        self.runs[start..].iter().collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CIPipelineRunRecord {
    pub timestamp: u64,
    pub project: String,
    pub passed: bool,
    pub total_findings: usize,
    pub new_findings: usize,
    pub blocking_findings: usize,
    pub suppressed_findings: usize,
    pub duration_ms: u64,
    pub stages: Vec<StageRecord>,
    pub notifications_sent: usize,
    pub notifications_failed: usize,
    pub summary_path: Option<String>,
    pub sarif_path: Option<String>,
    pub commit_sha: Option<String>,
    pub branch: Option<String>,
    pub pr_number: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageRecord {
    pub name: String,
    pub passed: bool,
    pub duration_ms: u64,
}

impl From<&CIPipelineResult> for CIPipelineRunRecord {
    fn from(result: &CIPipelineResult) -> Self {
        let total_duration = result.stages.iter().map(|s| s.duration_ms).sum::<u64>();
        let notif_sent = result
            .notification_results
            .iter()
            .filter(|n| n.delivered)
            .count();
        let notif_failed = result
            .notification_results
            .iter()
            .filter(|n| !n.delivered)
            .count();

        Self {
            timestamp: unix_seconds(),
            project: result.project.clone(),
            passed: result.passed,
            total_findings: result.gate.total_findings,
            new_findings: result.gate.new_findings,
            blocking_findings: result.gate.blocking_findings.len(),
            suppressed_findings: result.gate.suppressed_findings,
            duration_ms: total_duration,
            stages: result
                .stages
                .iter()
                .map(|s| StageRecord {
                    name: s.stage.clone(),
                    passed: s.passed,
                    duration_ms: s.duration_ms,
                })
                .collect(),
            notifications_sent: notif_sent,
            notifications_failed: notif_failed,
            summary_path: result.summary_path.clone(),
            sarif_path: result.sarif_path.clone(),
            commit_sha: None,
            branch: None,
            pr_number: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CIAnalytics {
    pub total_runs: u64,
    pub total_passes: u64,
    pub total_failures: u64,
    pub pass_rate: f64,
    pub total_findings_seen: usize,
    pub total_blocking_findings: usize,
    pub avg_findings_per_run: f64,
    pub avg_duration_ms: f64,
    pub notification_delivery_rate: f64,
    pub failure_rate_14d: f64,
    pub failure_rate_30d: f64,
    pub trend: Vec<RunTrendPoint>,
    pub most_common_blocking: Vec<BlockingClassCount>,
    pub stage_pass_rates: Vec<StagePassRate>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunTrendPoint {
    pub period: String,
    pub runs: u64,
    pub passes: u64,
    pub failures: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockingClassCount {
    pub classification: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagePassRate {
    pub stage: String,
    pub rate: f64,
    pub total: u64,
}

pub fn compute_ci_analytics(history: &CIPipelineHistory) -> CIAnalytics {
    let runs = &history.runs;
    if runs.is_empty() {
        return CIAnalytics {
            total_runs: 0,
            total_passes: 0,
            total_failures: 0,
            pass_rate: 0.0,
            total_findings_seen: 0,
            total_blocking_findings: 0,
            avg_findings_per_run: 0.0,
            avg_duration_ms: 0.0,
            notification_delivery_rate: 0.0,
            failure_rate_14d: 0.0,
            failure_rate_30d: 0.0,
            trend: vec![],
            most_common_blocking: vec![],
            stage_pass_rates: vec![],
            summary: "No CI runs recorded yet.".to_string(),
        };
    }

    let total_runs = runs.len() as u64;
    let total_passes = runs.iter().filter(|r| r.passed).count() as u64;
    let total_failures = total_runs - total_passes;
    let pass_rate = total_passes as f64 / total_runs as f64;
    let total_findings_seen: usize = runs.iter().map(|r| r.total_findings).sum();
    let total_blocking_findings: usize = runs.iter().map(|r| r.blocking_findings).sum();
    let avg_findings_per_run = total_findings_seen as f64 / total_runs as f64;
    let avg_duration_ms: f64 =
        runs.iter().map(|r| r.duration_ms as f64).sum::<f64>() / total_runs as f64;

    let total_notif_attempts: usize = runs
        .iter()
        .map(|r| r.notifications_sent + r.notifications_failed)
        .sum();
    let notification_delivery_rate = if total_notif_attempts > 0 {
        runs.iter().map(|r| r.notifications_sent).sum::<usize>() as f64
            / total_notif_attempts as f64
    } else {
        1.0
    };

    let now = unix_seconds();
    let fourteen_days = 14 * 24 * 3600;
    let thirty_days = 30 * 24 * 3600;

    let runs_14d: Vec<&CIPipelineRunRecord> = runs
        .iter()
        .filter(|r| now.saturating_sub(r.timestamp) <= fourteen_days)
        .collect();
    let failure_rate_14d = if !runs_14d.is_empty() {
        runs_14d.iter().filter(|r| !r.passed).count() as f64 / runs_14d.len() as f64
    } else {
        0.0
    };

    let runs_30d: Vec<&CIPipelineRunRecord> = runs
        .iter()
        .filter(|r| now.saturating_sub(r.timestamp) <= thirty_days)
        .collect();
    let failure_rate_30d = if !runs_30d.is_empty() {
        runs_30d.iter().filter(|r| !r.passed).count() as f64 / runs_30d.len() as f64
    } else {
        0.0
    };

    let mut trend = Vec::new();
    let days = [1, 7, 14, 30, 90];
    for d in days {
        let cutoff = now.saturating_sub(d * 24 * 3600);
        let window: Vec<&CIPipelineRunRecord> =
            runs.iter().filter(|r| r.timestamp >= cutoff).collect();
        if !window.is_empty() {
            trend.push(RunTrendPoint {
                period: format!("{d}d"),
                runs: window.len() as u64,
                passes: window.iter().filter(|r| r.passed).count() as u64,
                failures: window.iter().filter(|r| !r.passed).count() as u64,
            });
        }
    }

    let mut class_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for run in runs {
        for stage in &run.stages {
            if !stage.passed {
                class_counts
                    .entry("ci-gate-failed".to_string())
                    .or_insert(0);
                *class_counts.get_mut("ci-gate-failed").unwrap() += 1;
            }
        }
        if !run.passed {
            *class_counts
                .entry("pipeline-failure".to_string())
                .or_insert(0) += 1;
        }
    }
    let mut most_common_blocking: Vec<BlockingClassCount> = class_counts
        .into_iter()
        .map(|(classification, count)| BlockingClassCount {
            classification,
            count,
        })
        .collect();
    most_common_blocking.sort_by(|a, b| b.count.cmp(&a.count));

    let mut stage_stats: std::collections::HashMap<String, (u64, u64)> =
        std::collections::HashMap::new();
    for run in runs {
        for stage in &run.stages {
            let entry = stage_stats.entry(stage.name.clone()).or_insert((0, 0));
            entry.0 += 1;
            if stage.passed {
                entry.1 += 1;
            }
        }
    }
    let mut stage_pass_rates: Vec<StagePassRate> = stage_stats
        .into_iter()
        .map(|(stage, (total, passed))| StagePassRate {
            stage,
            rate: if total > 0 {
                passed as f64 / total as f64
            } else {
                0.0
            },
            total,
        })
        .collect();
    stage_pass_rates.sort_by(|a, b| b.total.cmp(&a.total));

    let summary = format!(
        "{} runs: {:.1}% pass rate. {:.1} avg findings/run. {:.0}ms avg duration. \
         Last 14d failure rate: {:.1}%.",
        total_runs,
        pass_rate * 100.0,
        avg_findings_per_run,
        avg_duration_ms,
        failure_rate_14d * 100.0
    );

    CIAnalytics {
        total_runs,
        total_passes,
        total_failures,
        pass_rate,
        total_findings_seen,
        total_blocking_findings,
        avg_findings_per_run,
        avg_duration_ms,
        notification_delivery_rate,
        failure_rate_14d,
        failure_rate_30d,
        trend,
        most_common_blocking,
        stage_pass_rates,
        summary,
    }
}

pub fn render_ci_dashboard(analytics: &CIAnalytics, history: &CIPipelineHistory) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE CI Dashboard\n\n");

    md.push_str(&analytics.summary);
    md.push_str("\n\n");

    md.push_str("## Key Metrics\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!(
        "| Pass Rate | {:.1}% |\n",
        analytics.pass_rate * 100.0
    ));
    md.push_str(&format!(
        "| Total Runs | {} ({} passed, {} failed) |\n",
        analytics.total_runs, analytics.total_passes, analytics.total_failures
    ));
    md.push_str(&format!(
        "| Avg Findings/Run | {:.1} |\n",
        analytics.avg_findings_per_run
    ));
    md.push_str(&format!(
        "| Avg Duration | {:.0}ms |\n",
        analytics.avg_duration_ms
    ));
    md.push_str(&format!(
        "| Notification Delivery | {:.1}% |\n",
        analytics.notification_delivery_rate * 100.0
    ));
    md.push_str(&format!(
        "| Failure Rate (14d) | {:.1}% |\n",
        analytics.failure_rate_14d * 100.0
    ));
    md.push_str(&format!(
        "| Failure Rate (30d) | {:.1}% |\n\n",
        analytics.failure_rate_30d * 100.0
    ));

    if !analytics.trend.is_empty() {
        md.push_str("## Trend\n\n");
        md.push_str("| Window | Runs | Passes | Failures |\n");
        md.push_str("|--------|------|--------|----------|\n");
        for point in &analytics.trend {
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                point.period, point.runs, point.passes, point.failures
            ));
        }
        md.push('\n');
    }

    if !analytics.stage_pass_rates.is_empty() {
        md.push_str("## Stage Pass Rates\n\n");
        md.push_str("| Stage | Pass Rate | Total |\n");
        md.push_str("|-------|-----------|-------|\n");
        for stage in &analytics.stage_pass_rates {
            md.push_str(&format!(
                "| {} | {:.1}% | {} |\n",
                stage.stage,
                stage.rate * 100.0,
                stage.total
            ));
        }
        md.push('\n');
    }

    let recent = history.recent(10);
    if !recent.is_empty() {
        md.push_str("## Recent Runs\n\n");
        md.push_str("| Time | Status | Findings | Blocking | Duration |\n");
        md.push_str("|------|--------|----------|----------|----------|\n");
        for run in recent.iter().rev() {
            let status = if run.passed { "PASS" } else { "FAIL" };
            let time_str = format_timestamp_short(run.timestamp);
            md.push_str(&format!(
                "| {} | {} | {} | {} | {}ms |\n",
                time_str, status, run.total_findings, run.blocking_findings, run.duration_ms
            ));
        }
        md.push('\n');
    }

    md
}

fn format_timestamp_short(epoch: u64) -> String {
    let now = unix_seconds();
    let delta = now.saturating_sub(epoch);
    if delta < 60 {
        format!("{delta}s ago")
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86400 {
        format!("{}h ago", delta / 3600)
    } else {
        format!("{}d ago", delta / 86400)
    }
}

pub fn render_ci_dashboard_compact(analytics: &CIAnalytics) -> String {
    format!(
        "CI: {:.0}% pass rate | {} runs | {:.1} findings/run | {:.0}ms avg | {:.0}% 14d failure",
        analytics.pass_rate * 100.0,
        analytics.total_runs,
        analytics.avg_findings_per_run,
        analytics.avg_duration_ms,
        analytics.failure_rate_14d * 100.0
    )
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
    use crate::ci::{CIGateResult, PolicyConfig};
    use crate::ci_pipeline::{CIPipelineConfig, CIPipelineResult, NotificationResult, StageResult};

    fn make_pipeline_result(passed: bool, findings: usize, blocking: usize) -> CIPipelineResult {
        CIPipelineResult {
            passed,
            project: "test".to_string(),
            stages: vec![
                StageResult {
                    stage: "gate".to_string(),
                    passed,
                    message: String::new(),
                    duration_ms: 100,
                },
                StageResult {
                    stage: "sarif".to_string(),
                    passed: true,
                    message: String::new(),
                    duration_ms: 50,
                },
            ],
            gate: CIGateResult {
                passed,
                total_findings: findings,
                new_findings: if passed { 0 } else { blocking },
                baseline_findings: findings.saturating_sub(blocking),
                suppressed_findings: 0,
                blocking_findings: if !passed {
                    vec![crate::ci::BlockingFinding {
                        finding_id: "f-1".to_string(),
                        classification: "BOLA".to_string(),
                        severity: "high".to_string(),
                        endpoint: "GET /api/test".to_string(),
                        reason: "test".to_string(),
                        state: "Verified".to_string(),
                    }]
                } else {
                    vec![]
                },
                exit_code: if passed { 0 } else { 1 },
                summary: String::new(),
            },
            notification_results: vec![NotificationResult {
                adapter: "slack".to_string(),
                url: "https://hooks.slack.com/test".to_string(),
                delivered: true,
                status_code: Some(200),
                error: None,
                retries: 0,
            }],
            summary_path: None,
            sarif_path: None,
        }
    }

    #[test]
    fn history_append_and_retrieve() {
        let mut history = CIPipelineHistory::new("test");
        assert_eq!(history.total_runs, 0);

        let result = make_pipeline_result(true, 5, 0);
        history.append(&result);
        assert_eq!(history.total_runs, 1);
        assert_eq!(history.runs.len(), 1);
        assert!(history.runs[0].passed);
        assert_eq!(history.runs[0].total_findings, 5);
    }

    #[test]
    fn history_trims_to_500() {
        let mut history = CIPipelineHistory::new("test");
        for i in 0..600 {
            let result = make_pipeline_result(i % 2 == 0, i, 0);
            history.append(&result);
        }
        assert_eq!(history.total_runs, 600);
        assert!(history.runs.len() <= 500);
    }

    #[test]
    fn history_persist_and_reload() {
        let dir = std::env::temp_dir().join("baloncore-ci-history-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ci_history.json");
        let mut history = CIPipelineHistory::new("test");
        history.append(&make_pipeline_result(true, 3, 0));
        history.append(&make_pipeline_result(false, 10, 2));
        history.save(&path).unwrap();

        let loaded = CIPipelineHistory::load(&path).unwrap();
        assert_eq!(loaded.total_runs, 2);
        assert_eq!(loaded.runs.len(), 2);
        assert!(loaded.runs[0].passed);
        assert!(!loaded.runs[1].passed);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_load_nonexistent_returns_empty() {
        let history = CIPipelineHistory::load("/nonexistent/baloncore/ci_history.json").unwrap();
        assert_eq!(history.total_runs, 0);
    }

    #[test]
    fn analytics_pass_rate() {
        let mut history = CIPipelineHistory::new("test");
        for _ in 0..8 {
            history.append(&make_pipeline_result(true, 5, 0));
        }
        for _ in 0..2 {
            history.append(&make_pipeline_result(false, 10, 3));
        }
        let analytics = compute_ci_analytics(&history);
        assert_eq!(analytics.total_runs, 10);
        assert_eq!(analytics.total_passes, 8);
        assert_eq!(analytics.total_failures, 2);
        assert!((analytics.pass_rate - 0.8).abs() < 0.01);
    }

    #[test]
    fn analytics_empty_history() {
        let history = CIPipelineHistory::new("test");
        let analytics = compute_ci_analytics(&history);
        assert_eq!(analytics.total_runs, 0);
        assert_eq!(analytics.pass_rate, 0.0);
        assert!(analytics.summary.contains("No CI runs"));
    }

    #[test]
    fn analytics_trend_points() {
        let mut history = CIPipelineHistory::new("test");
        history.append(&make_pipeline_result(true, 3, 0));
        let analytics = compute_ci_analytics(&history);
        assert!(!analytics.trend.is_empty());
        assert!(analytics.trend[0].period == "1d" || analytics.trend[0].period == "7d");
    }

    #[test]
    fn format_timestamp_short_relative() {
        let ts = unix_seconds();
        let result = format_timestamp_short(ts);
        assert!(result.contains("s ago"));

        let one_hour_ago = ts - 3601;
        let result = format_timestamp_short(one_hour_ago);
        assert!(result.contains("h ago"));

        let one_day_ago = ts - 86401;
        let result = format_timestamp_short(one_day_ago);
        assert!(result.contains("d ago"));
    }

    #[test]
    fn render_ci_dashboard_includes_metrics() {
        let mut history = CIPipelineHistory::new("test");
        history.append(&make_pipeline_result(true, 5, 0));
        let analytics = compute_ci_analytics(&history);
        let dashboard = render_ci_dashboard(&analytics, &history);
        assert!(dashboard.contains("BALONCORE CI Dashboard"));
        assert!(dashboard.contains("Pass Rate"));
        assert!(dashboard.contains("Recent Runs"));
    }

    #[test]
    fn render_dashboard_compact() {
        let mut history = CIPipelineHistory::new("test");
        history.append(&make_pipeline_result(true, 3, 0));
        let analytics = compute_ci_analytics(&history);
        let compact = render_ci_dashboard_compact(&analytics);
        assert!(compact.contains("CI:"));
        assert!(compact.contains("pass rate"));
    }

    #[test]
    fn recent_returns_limited_runs() {
        let mut history = CIPipelineHistory::new("test");
        for i in 0..50 {
            history.append(&make_pipeline_result(true, i, 0));
        }
        let recent = history.recent(10);
        assert_eq!(recent.len(), 10);
        assert_eq!(recent[9].total_findings, 49);
    }

    #[test]
    fn analytics_stage_pass_rates() {
        let mut history = CIPipelineHistory::new("test");
        history.append(&make_pipeline_result(true, 3, 0));
        let analytics = compute_ci_analytics(&history);
        assert!(!analytics.stage_pass_rates.is_empty());
        let gate_stage = analytics
            .stage_pass_rates
            .iter()
            .find(|s| s.stage == "gate")
            .unwrap();
        assert_eq!(gate_stage.rate, 1.0);
    }
}
