use serde::{Deserialize, Serialize};
use std::fmt;

use crate::ci::{CIGateResult, PolicyConfig};
use crate::lifecycle::FindingRecord;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CIPipelineConfig {
    pub version: u32,
    pub project: String,
    #[serde(default)]
    pub stages: Vec<CIPipelineStage>,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub notifications: Vec<NotificationTarget>,
    #[serde(default)]
    pub github_actions: Option<GitHubActionsConfig>,
}

impl CIPipelineConfig {
    pub fn new(project: &str) -> Self {
        Self {
            version: 1,
            project: project.to_string(),
            stages: vec![
                CIPipelineStage::Gate,
                CIPipelineStage::Sarif,
                CIPipelineStage::Notify,
                CIPipelineStage::Summary,
            ],
            policy: PolicyConfig::default(),
            notifications: vec![],
            github_actions: None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.project.is_empty() {
            return Err("project name must not be empty".to_string());
        }
        for notif in &self.notifications {
            if notif.adapter.is_empty() {
                return Err("notification adapter must not be empty".to_string());
            }
            if notif.url.is_empty() {
                return Err(format!(
                    "notification url for {} must not be empty",
                    notif.adapter
                ));
            }
            if !matches!(notif.adapter.as_str(), "slack" | "linear" | "jira") {
                return Err(format!(
                    "unsupported notification adapter: {}",
                    notif.adapter
                ));
            }
        }
        if let Some(ref gh) = self.github_actions {
            if gh.repository.is_empty() {
                return Err("github_actions repository must not be empty".to_string());
            }
        }
        Ok(())
    }

    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize pipeline config: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("failed to write pipeline config: {e}"))
    }

    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read pipeline config: {e}"))?;
        serde_json::from_str(&raw).map_err(|e| format!("failed to parse pipeline config: {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CIPipelineStage {
    Gate,
    Sarif,
    Notify,
    Summary,
    Revalidate,
    Upload,
}

impl CIPipelineStage {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Gate => "gate",
            Self::Sarif => "sarif",
            Self::Notify => "notify",
            Self::Summary => "summary",
            Self::Revalidate => "revalidate",
            Self::Upload => "upload",
        }
    }
}

impl fmt::Display for CIPipelineStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationTarget {
    pub adapter: String,
    pub url: String,
    #[serde(default)]
    pub secret_env: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_retry_count")]
    pub max_retries: u32,
    #[serde(default = "default_retry_delay_ms")]
    pub retry_delay_ms: u64,
    #[serde(default)]
    pub extra_headers: Vec<(String, String)>,
}

fn default_true() -> bool {
    true
}

fn default_retry_count() -> u32 {
    3
}

fn default_retry_delay_ms() -> u64 {
    1000
}

impl NotificationTarget {
    pub fn slack(webhook_url: &str, secret_env: &str) -> Self {
        Self {
            adapter: "slack".to_string(),
            url: webhook_url.to_string(),
            secret_env: secret_env.to_string(),
            enabled: true,
            max_retries: 3,
            retry_delay_ms: 1000,
            extra_headers: vec![],
        }
    }

    pub fn linear(api_url: &str, secret_env: &str) -> Self {
        Self {
            adapter: "linear".to_string(),
            url: api_url.to_string(),
            secret_env: secret_env.to_string(),
            enabled: true,
            max_retries: 3,
            retry_delay_ms: 1000,
            extra_headers: vec![],
        }
    }

    pub fn jira(api_url: &str, secret_env: &str) -> Self {
        Self {
            adapter: "jira".to_string(),
            url: api_url.to_string(),
            secret_env: secret_env.to_string(),
            enabled: true,
            max_retries: 3,
            retry_delay_ms: 1000,
            extra_headers: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitHubActionsConfig {
    pub repository: String,
    #[serde(default)]
    pub branch: String,
    #[serde(default)]
    pub workflow_name: String,
    #[serde(default = "default_cron_schedule")]
    pub schedule_cron: String,
    #[serde(default = "default_true")]
    pub upload_sarif: bool,
    #[serde(default = "default_true")]
    pub post_pr_comment: bool,
    #[serde(default)]
    pub baloncore_version: String,
    #[serde(default)]
    pub extra_env: Vec<(String, String)>,
}

fn default_cron_schedule() -> String {
    "0 6 * * 1-5".to_string()
}

impl GitHubActionsConfig {
    pub fn new(repository: &str) -> Self {
        Self {
            repository: repository.to_string(),
            branch: "main".to_string(),
            workflow_name: "baloncore-ci".to_string(),
            schedule_cron: default_cron_schedule(),
            upload_sarif: true,
            post_pr_comment: true,
            baloncore_version: env!("CARGO_PKG_VERSION").to_string(),
            extra_env: vec![],
        }
    }

    pub fn to_workflow_yaml(&self, config: &CIPipelineConfig) -> String {
        let mut yaml = String::new();
        yaml.push_str("name: ");
        yaml.push_str(&self.workflow_name);
        yaml.push('\n');
        yaml.push_str("on:\n");
        yaml.push_str("  schedule:\n");
        yaml.push_str("    - cron: '");
        yaml.push_str(&self.schedule_cron);
        yaml.push_str("'\n");
        yaml.push_str("  push:\n");
        yaml.push_str("    branches: ['");
        yaml.push_str(&self.branch);
        yaml.push_str("']\n");
        yaml.push_str("  pull_request:\n");
        yaml.push_str("    branches: ['");
        yaml.push_str(&self.branch);
        yaml.push_str("']\n");
        yaml.push_str("  workflow_dispatch:\n\n");
        yaml.push_str("permissions:\n");
        yaml.push_str("  contents: read\n");
        if self.upload_sarif {
            yaml.push_str("  security-events: write\n");
        }
        if self.post_pr_comment {
            yaml.push_str("  pull-requests: write\n");
        }
        yaml.push_str("\njobs:\n");
        yaml.push_str("  baloncore-ci:\n");
        yaml.push_str("    runs-on: ubuntu-latest\n");
        yaml.push_str("    steps:\n");
        yaml.push_str("      - uses: actions/checkout@v4\n\n");
        yaml.push_str("      - name: Install BALONCORE\n");
        yaml.push_str("        run: |\n");
        yaml.push_str("          curl -sSL https://baloncore.ai/install.sh | sh\n\n");
        yaml.push_str("      - name: Run BALONCORE scan\n");
        yaml.push_str("        run: |\n");
        yaml.push_str("          baloncore scan-openapi-bola \\\n");
        yaml.push_str("            --base-url ${{ vars.BALONCORE_BASE_URL }} \\\n");
        yaml.push_str("            --openapi-url ${{ vars.BALONCORE_OPENAPI_URL }} \\\n");
        yaml.push_str("            --owner-profile ${{ vars.BALONCORE_OWNER }} \\\n");
        yaml.push_str("            --attacker-profile ${{ vars.BALONCORE_ATTACKER }} \\\n");
        yaml.push_str("            --out-dir .baloncore/runs/latest\n\n");

        for stage in &config.stages {
            match stage {
                CIPipelineStage::Gate => {
                    yaml.push_str("      - name: BALONCORE CI gate\n");
                    yaml.push_str("        run: |\n");
                    yaml.push_str("          baloncore ci-run \\\n");
                    yaml.push_str("            --store .baloncore/evidence/index.json \\\n");
                    yaml.push_str("            --markdown-output .baloncore/ci/pr_summary.md \\\n");
                    yaml.push_str("            --ci\n\n");
                }
                CIPipelineStage::Sarif => {
                    yaml.push_str("      - name: Generate SARIF\n");
                    yaml.push_str("        if: always()\n");
                    yaml.push_str("        run: |\n");
                    yaml.push_str("          baloncore export-evidence-sarif \\\n");
                    yaml.push_str("            --store .baloncore/evidence/index.json \\\n");
                    yaml.push_str("            .baloncore/ci/baloncore.sarif\n\n");
                    if self.upload_sarif {
                        yaml.push_str("      - name: Upload SARIF to GitHub\n");
                        yaml.push_str("        if: always()\n");
                        yaml.push_str("        uses: github/codeql-action/upload-sarif@v3\n");
                        yaml.push_str("        with:\n");
                        yaml.push_str("          sarif_file: .baloncore/ci/baloncore.sarif\n\n");
                    }
                }
                CIPipelineStage::Notify => {
                    for notif in &config.notifications {
                        if !notif.enabled {
                            continue;
                        }
                        yaml.push_str("      - name: Notify ");
                        yaml.push_str(&notif.adapter);
                        yaml.push('\n');
                        yaml.push_str("        if: always()\n");
                        yaml.push_str("        run: |\n");
                        yaml.push_str("          baloncore ci-pipeline-run notify \\\n");
                        yaml.push_str("            --adapter ");
                        yaml.push_str(&notif.adapter);
                        yaml.push_str(" \\\n");
                        yaml.push_str("            --url \"${{ secrets.");
                        yaml.push_str(&notif.secret_env);
                        yaml.push_str(" }}\" \\\n");
                        yaml.push_str("            --summary .baloncore/ci/pr_summary.md\n\n");
                    }
                }
                CIPipelineStage::Summary => {
                    if self.post_pr_comment {
                        yaml.push_str("      - name: Post PR summary\n");
                        yaml.push_str("        if: github.event_name == 'pull_request'\n");
                        yaml.push_str("        uses: actions/github-script@v7\n");
                        yaml.push_str("        with:\n");
                        yaml.push_str("          script: |\n");
                        yaml.push_str("            const fs = require('fs');\n");
                        yaml.push_str("            const summary = fs.readFileSync('.baloncore/ci/pr_summary.md', 'utf8');\n");
                        yaml.push_str("            await github.rest.issues.createComment({\n");
                        yaml.push_str("              owner: context.repo.owner,\n");
                        yaml.push_str("              repo: context.repo.repo,\n");
                        yaml.push_str("              issue_number: context.issue.number,\n");
                        yaml.push_str("              body: summary\n");
                        yaml.push_str("            });\n\n");
                    }
                }
                CIPipelineStage::Revalidate => {
                    yaml.push_str("      - name: Revalidate findings\n");
                    yaml.push_str("        if: always()\n");
                    yaml.push_str("        run: |\n");
                    yaml.push_str("          baloncore ci-run \\\n");
                    yaml.push_str("            --store .baloncore/evidence/index.json \\\n");
                    yaml.push_str("            --baseline .baloncore/evidence/baseline.json \\\n");
                    yaml.push_str("            --ci\n\n");
                }
                CIPipelineStage::Upload => {
                    yaml.push_str("      - name: Upload evidence artifacts\n");
                    yaml.push_str("        if: always()\n");
                    yaml.push_str("        uses: actions/upload-artifact@v4\n");
                    yaml.push_str("        with:\n");
                    yaml.push_str("          name: baloncore-evidence\n");
                    yaml.push_str("          path: .baloncore/evidence/\n");
                    yaml.push_str("          retention-days: 30\n\n");
                }
            }
        }

        yaml
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CIPipelineResult {
    pub passed: bool,
    pub project: String,
    pub stages: Vec<StageResult>,
    pub gate: CIGateResult,
    pub notification_results: Vec<NotificationResult>,
    pub summary_path: Option<String>,
    pub sarif_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StageResult {
    pub stage: String,
    pub passed: bool,
    pub message: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotificationResult {
    pub adapter: String,
    pub url: String,
    pub delivered: bool,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub retries: u32,
}

pub struct CIPipelineRunner<'a> {
    pub config: &'a CIPipelineConfig,
    pub findings: Vec<FindingRecord>,
    pub baseline_path: Option<&'a std::path::Path>,
}

impl<'a> CIPipelineRunner<'a> {
    pub fn new(config: &'a CIPipelineConfig, findings: Vec<FindingRecord>) -> Self {
        Self {
            config,
            findings,
            baseline_path: None,
        }
    }

    pub fn with_baseline(mut self, path: &'a std::path::Path) -> Self {
        self.baseline_path = Some(path);
        self
    }

    pub fn run(&self, evidence_store_path: &std::path::Path) -> CIPipelineResult {
        let mut stages = Vec::new();
        let mut gate_result = CIGateResult {
            passed: true,
            total_findings: 0,
            new_findings: 0,
            baseline_findings: 0,
            suppressed_findings: 0,
            blocking_findings: vec![],
            exit_code: 0,
            summary: String::new(),
        };
        let mut notification_results = Vec::new();
        let mut summary_path = None;
        let mut sarif_path = None;
        let pipeline_passed;

        for stage in &self.config.stages {
            match stage {
                CIPipelineStage::Gate => {
                    let start = std::time::Instant::now();
                    let baseline = self
                        .baseline_path
                        .map(|p| {
                            crate::ci::BaselineFile::load(p).unwrap_or_else(|_| {
                                crate::ci::BaselineFile::new(&self.config.project)
                            })
                        })
                        .unwrap_or_else(|| crate::ci::BaselineFile::new(&self.config.project));
                    gate_result =
                        crate::ci::evaluate_ci_gate(&self.findings, &baseline, &self.config.policy);
                    let duration = start.elapsed().as_millis() as u64;
                    stages.push(StageResult {
                        stage: "gate".to_string(),
                        passed: gate_result.passed,
                        message: gate_result.summary.clone(),
                        duration_ms: duration,
                    });
                }
                CIPipelineStage::Sarif => {
                    let start = std::time::Instant::now();
                    let sarif_output = evidence_store_path
                        .parent()
                        .unwrap_or(std::path::Path::new("."))
                        .join("ci")
                        .join("baloncore.sarif");
                    if let Err(e) = crate::sarif::sarif_to_file(&self.findings, &sarif_output) {
                        stages.push(StageResult {
                            stage: "sarif".to_string(),
                            passed: false,
                            message: format!("SARIF generation failed: {e}"),
                            duration_ms: start.elapsed().as_millis() as u64,
                        });
                    } else {
                        sarif_path = Some(sarif_output.display().to_string());
                        stages.push(StageResult {
                            stage: "sarif".to_string(),
                            passed: true,
                            message: format!("SARIF written to {}", sarif_output.display()),
                            duration_ms: start.elapsed().as_millis() as u64,
                        });
                    }
                }
                CIPipelineStage::Notify => {
                    for notif in &self.config.notifications {
                        if !notif.enabled {
                            continue;
                        }
                        let summary = gate_result.summary.clone();
                        let result = deliver_notification(notif, &summary);
                        notification_results.push(result);
                    }
                    stages.push(StageResult {
                        stage: "notify".to_string(),
                        passed: notification_results
                            .iter()
                            .all(|r| r.delivered || !r.delivered && r.error.is_some()),
                        message: format!(
                            "{} notification(s) processed",
                            notification_results.len()
                        ),
                        duration_ms: 0,
                    });
                }
                CIPipelineStage::Summary => {
                    let start = std::time::Instant::now();
                    let md_output = evidence_store_path
                        .parent()
                        .unwrap_or(std::path::Path::new("."))
                        .join("ci")
                        .join("pr_summary.md");
                    if let Some(parent) = md_output.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let markdown = render_ci_pipeline_summary(
                        &gate_result.summary,
                        &gate_result,
                        &notification_results,
                    );
                    let _ = std::fs::write(&md_output, &markdown);
                    summary_path = Some(md_output.display().to_string());
                    stages.push(StageResult {
                        stage: "summary".to_string(),
                        passed: true,
                        message: format!("Summary written to {}", md_output.display()),
                        duration_ms: start.elapsed().as_millis() as u64,
                    });
                }
                CIPipelineStage::Revalidate => {
                    stages.push(StageResult {
                        stage: "revalidate".to_string(),
                        passed: true,
                        message: "revalidation staged for next CI run".to_string(),
                        duration_ms: 0,
                    });
                }
                CIPipelineStage::Upload => {
                    stages.push(StageResult {
                        stage: "upload".to_string(),
                        passed: true,
                        message: "upload configured for CI environment".to_string(),
                        duration_ms: 0,
                    });
                }
            }
        }

        pipeline_passed = gate_result.passed;
        CIPipelineResult {
            passed: pipeline_passed,
            project: self.config.project.clone(),
            stages,
            gate: gate_result,
            notification_results,
            summary_path,
            sarif_path,
        }
    }
}

pub fn render_ci_pipeline_summary(
    summary: &str,
    gate: &CIGateResult,
    notification_results: &[NotificationResult],
) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE CI Pipeline Summary\n\n");
    md.push_str(summary);
    md.push_str("\n\n");

    md.push_str("## Evidence Gate\n\n");
    md.push_str(&format!(
        "- Passed: `{}`\n- Total findings: `{}`\n- New findings: `{}`\n- Baseline findings: `{}`\n- Suppressed findings: `{}`\n- Blocking findings: `{}`\n\n",
        gate.passed,
        gate.total_findings,
        gate.new_findings,
        gate.baseline_findings,
        gate.suppressed_findings,
        gate.blocking_findings.len()
    ));

    if !gate.blocking_findings.is_empty() {
        md.push_str("### Blocking Findings\n\n");
        for finding in &gate.blocking_findings {
            md.push_str(&format!(
                "- `{}` `{}` at `{}`: {}\n",
                finding.severity, finding.classification, finding.endpoint, finding.reason
            ));
        }
        md.push('\n');
    }

    if !notification_results.is_empty() {
        md.push_str("## Notifications\n\n");
        for result in notification_results {
            let status = if result.delivered {
                "delivered"
            } else {
                "failed"
            };
            md.push_str(&format!(
                "- `{}` → {}: {}{}\n",
                result.adapter,
                result.url,
                status,
                result
                    .error
                    .as_ref()
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default()
            ));
        }
        md.push('\n');
    }

    md
}

pub fn deliver_notification(target: &NotificationTarget, summary: &str) -> NotificationResult {
    let payload = build_notification_payload(&target.adapter, summary);
    let secret = std::env::var(&target.secret_env).unwrap_or_default();
    let mut attempts = 0u32;
    let max_attempts = target.max_retries.max(1);

    while attempts < max_attempts {
        attempts += 1;
        let result =
            send_notification_request(&target.url, &payload, &secret, &target.extra_headers);
        match result {
            Ok(status) => {
                return NotificationResult {
                    adapter: target.adapter.clone(),
                    url: target.url.clone(),
                    delivered: status >= 200 && status < 300,
                    status_code: Some(status),
                    error: if status >= 300 {
                        Some(format!("HTTP {}", status))
                    } else {
                        None
                    },
                    retries: attempts - 1,
                };
            }
            Err(e) => {
                if attempts >= max_attempts {
                    return NotificationResult {
                        adapter: target.adapter.clone(),
                        url: target.url.clone(),
                        delivered: false,
                        status_code: None,
                        error: Some(e),
                        retries: attempts - 1,
                    };
                }
                std::thread::sleep(std::time::Duration::from_millis(target.retry_delay_ms));
            }
        }
    }

    NotificationResult {
        adapter: target.adapter.clone(),
        url: target.url.clone(),
        delivered: false,
        status_code: None,
        error: Some("max retries exceeded".to_string()),
        retries: attempts,
    }
}

fn build_notification_payload(adapter: &str, summary: &str) -> serde_json::Value {
    let title = if summary.contains("CI FAILED") {
        "BALONCORE CI failed"
    } else {
        "BALONCORE CI passed"
    };
    match adapter {
        "slack" => serde_json::json!({
            "text": title,
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
                {"type": "context", "elements": [{"type": "mrkdwn", "text": "Sent by BALONCORE CI pipeline."}]}
            ]
        }),
        "linear" => serde_json::json!({
            "title": title,
            "description": summary,
            "labels": ["security", "baloncore", "ci"]
        }),
        "jira" => serde_json::json!({
            "fields": {
                "project": {"key": "SEC"},
                "summary": title,
                "description": summary,
                "issuetype": {"name": "Bug"},
                "labels": ["security", "baloncore", "ci"]
            }
        }),
        _ => serde_json::json!({
            "text": summary,
            "title": title
        }),
    }
}

fn send_notification_request(
    url: &str,
    payload: &serde_json::Value,
    secret: &str,
    extra_headers: &[(String, String)],
) -> Result<u16, String> {
    #[cfg(feature = "live-models")]
    {
        use std::io::Read;
        let body = serde_json::to_string(payload)
            .map_err(|e| format!("failed to serialize payload: {e}"))?;
        let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        if !secret.is_empty() {
            headers.push(("Authorization".to_string(), format!("Bearer {secret}")));
        }
        for (k, v) in extra_headers {
            headers.push((k.clone(), v.clone()));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;
        let mut request = client.post(url);
        for (key, value) in &headers {
            request = request.header(key.as_str(), value.as_str());
        }
        let response = request
            .body(body)
            .send()
            .map_err(|e| format!("HTTP request failed: {e}"))?;
        Ok(response.status().as_u16())
    }
    #[cfg(not(feature = "live-models"))]
    {
        let _ = (url, payload, secret, extra_headers);
        Err("notification delivery requires --features live-models (reqwest)".to_string())
    }
}

pub fn generate_github_actions_workflow(config: &CIPipelineConfig) -> String {
    let gh = config.github_actions.as_ref();
    let gh_config = gh
        .cloned()
        .unwrap_or_else(|| GitHubActionsConfig::new("owner/repo"));
    gh_config.to_workflow_yaml(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_config_roundtrip() {
        let config = CIPipelineConfig::new("test-project");
        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: CIPipelineConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.project, "test-project");
        assert_eq!(parsed.stages.len(), 4);
        assert_eq!(parsed.version, 1);
    }

    #[test]
    fn pipeline_config_validation_rejects_empty_project() {
        let config = CIPipelineConfig {
            version: 1,
            project: String::new(),
            stages: vec![],
            policy: PolicyConfig::default(),
            notifications: vec![],
            github_actions: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn pipeline_config_validation_rejects_bad_adapter() {
        let config = CIPipelineConfig {
            version: 1,
            project: "test".to_string(),
            stages: vec![],
            policy: PolicyConfig::default(),
            notifications: vec![NotificationTarget {
                adapter: "pager".to_string(),
                url: "https://example.com".to_string(),
                secret_env: "PAGER_KEY".to_string(),
                enabled: true,
                max_retries: 3,
                retry_delay_ms: 1000,
                extra_headers: vec![],
            }],
            github_actions: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn pipeline_config_validation_accepts_valid_slack() {
        let config = CIPipelineConfig {
            version: 1,
            project: "test".to_string(),
            stages: vec![],
            policy: PolicyConfig::default(),
            notifications: vec![NotificationTarget::slack(
                "https://hooks.slack.com/services/test",
                "SLACK_WEBHOOK_URL",
            )],
            github_actions: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn pipeline_config_save_and_load() {
        let dir = std::env::temp_dir().join("baloncore-pipeline-config-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("pipeline_config.json");
        let config = CIPipelineConfig::new("test-project");
        config.save(&path).unwrap();
        let loaded = CIPipelineConfig::load(&path).unwrap();
        assert_eq!(loaded.project, "test-project");
        assert_eq!(loaded.stages, config.stages);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn github_actions_workflow_includes_all_stages() {
        let config = CIPipelineConfig {
            version: 1,
            project: "test".to_string(),
            stages: vec![
                CIPipelineStage::Gate,
                CIPipelineStage::Sarif,
                CIPipelineStage::Notify,
                CIPipelineStage::Summary,
                CIPipelineStage::Upload,
            ],
            policy: PolicyConfig::default(),
            notifications: vec![NotificationTarget::slack(
                "https://hooks.slack.com/services/test",
                "SLACK_WEBHOOK_URL",
            )],
            github_actions: Some(GitHubActionsConfig::new("acme/api")),
        };
        let yaml = generate_github_actions_workflow(&config);
        assert!(yaml.contains("name: baloncore-ci"));
        assert!(yaml.contains("BALONCORE CI gate"));
        assert!(yaml.contains("Generate SARIF"));
        assert!(yaml.contains("upload-sarif"));
        assert!(yaml.contains("Notify slack"));
        assert!(yaml.contains("Post PR summary"));
        assert!(yaml.contains("upload-artifact"));
    }

    #[test]
    fn stage_name_matches() {
        assert_eq!(CIPipelineStage::Gate.name(), "gate");
        assert_eq!(CIPipelineStage::Sarif.name(), "sarif");
        assert_eq!(CIPipelineStage::Notify.name(), "notify");
        assert_eq!(CIPipelineStage::Summary.name(), "summary");
        assert_eq!(CIPipelineStage::Revalidate.name(), "revalidate");
        assert_eq!(CIPipelineStage::Upload.name(), "upload");
    }

    #[test]
    fn notification_target_constructors() {
        let slack = NotificationTarget::slack("https://hooks.slack.com/test", "SLACK_KEY");
        assert_eq!(slack.adapter, "slack");
        assert_eq!(slack.url, "https://hooks.slack.com/test");
        assert!(slack.enabled);
        assert_eq!(slack.max_retries, 3);

        let linear = NotificationTarget::linear("https://api.linear.app", "LINEAR_KEY");
        assert_eq!(linear.adapter, "linear");
        assert_eq!(linear.url, "https://api.linear.app");

        let jira = NotificationTarget::jira("https://acme.atlassian.net", "JIRA_TOKEN");
        assert_eq!(jira.adapter, "jira");
        assert_eq!(jira.url, "https://acme.atlassian.net");
    }

    #[test]
    fn notification_payload_slack_format() {
        let payload = build_notification_payload("slack", "BALONCORE CI passed");
        assert_eq!(payload["adapter"], serde_json::Value::Null);
        assert!(payload
            .get("text")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("passed"));
        assert!(payload.get("blocks").is_some());
    }

    #[test]
    fn notification_payload_linear_format() {
        let payload = build_notification_payload("linear", "BALONCORE CI FAILED: 1 blocking");
        assert!(payload
            .get("title")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("failed"));
        assert!(payload.get("description").is_some());
    }

    #[test]
    fn notification_payload_jira_format() {
        let payload = build_notification_payload("jira", "CI passed");
        assert!(payload.get("fields").is_some());
        assert!(payload["fields"]["labels"].as_array().unwrap().len() == 3);
    }

    #[test]
    fn github_actions_config_default_workflow_name() {
        let gh = GitHubActionsConfig::new("acme/api");
        assert_eq!(gh.workflow_name, "baloncore-ci");
        assert_eq!(gh.branch, "main");
        assert!(gh.upload_sarif);
        assert!(gh.post_pr_comment);
    }

    #[test]
    fn ci_pipeline_result_serialization() {
        let result = CIPipelineResult {
            passed: true,
            project: "test".to_string(),
            stages: vec![StageResult {
                stage: "gate".to_string(),
                passed: true,
                message: "CI PASSED".to_string(),
                duration_ms: 42,
            }],
            gate: CIGateResult {
                passed: true,
                total_findings: 3,
                new_findings: 1,
                baseline_findings: 2,
                suppressed_findings: 0,
                blocking_findings: vec![],
                exit_code: 0,
                summary: "CI PASSED".to_string(),
            },
            notification_results: vec![],
            summary_path: Some("/tmp/summary.md".to_string()),
            sarif_path: None,
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        let parsed: CIPipelineResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.passed);
        assert_eq!(parsed.stages.len(), 1);
        assert_eq!(parsed.gate.total_findings, 3);
    }

    #[test]
    fn github_actions_config_validation_rejects_empty_repo() {
        let config = CIPipelineConfig {
            version: 1,
            project: "test".to_string(),
            stages: vec![],
            policy: PolicyConfig::default(),
            notifications: vec![],
            github_actions: Some(GitHubActionsConfig {
                repository: String::new(),
                branch: "main".to_string(),
                workflow_name: "baloncore-ci".to_string(),
                schedule_cron: "0 6 * * 1-5".to_string(),
                upload_sarif: true,
                post_pr_comment: true,
                baloncore_version: "0.1.0".to_string(),
                extra_env: vec![],
            }),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn pipeline_with_no_notifications_skips_notify() {
        let config = CIPipelineConfig {
            version: 1,
            project: "test".to_string(),
            stages: vec![CIPipelineStage::Gate, CIPipelineStage::Summary],
            policy: PolicyConfig::default(),
            notifications: vec![],
            github_actions: None,
        };
        let yaml = generate_github_actions_workflow(&config);
        assert!(!yaml.contains("Notify"));
    }

    #[test]
    fn disabled_notification_skipped_in_workflow() {
        let mut disabled = NotificationTarget::slack("https://hooks.slack.com/test", "SLACK_KEY");
        disabled.enabled = false;
        let config = CIPipelineConfig {
            version: 1,
            project: "test".to_string(),
            stages: vec![
                CIPipelineStage::Gate,
                CIPipelineStage::Sarif,
                CIPipelineStage::Notify,
            ],
            policy: PolicyConfig::default(),
            notifications: vec![disabled],
            github_actions: Some(GitHubActionsConfig::new("acme/api")),
        };
        let yaml = generate_github_actions_workflow(&config);
        assert!(!yaml.contains("Notify slack"));
    }

    #[test]
    fn render_pipeline_summary_includes_gate_and_notifications() {
        let gate = CIGateResult {
            passed: true,
            total_findings: 5,
            new_findings: 1,
            baseline_findings: 3,
            suppressed_findings: 1,
            blocking_findings: vec![],
            exit_code: 0,
            summary: "CI PASSED".to_string(),
        };
        let notif = NotificationResult {
            adapter: "slack".to_string(),
            url: "https://hooks.slack.com/test".to_string(),
            delivered: true,
            status_code: Some(200),
            error: None,
            retries: 0,
        };
        let md = render_ci_pipeline_summary("CI PASSED", &gate, &[notif]);
        assert!(md.contains("BALONCORE CI Pipeline Summary"));
        assert!(md.contains("delivered"));
        assert!(md.contains("slack"));
    }
}
