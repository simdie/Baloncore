use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CIProvider {
    GitHubActions,
    GitLabCI,
    CircleCI,
    Jenkins,
    Buildkite,
    BitbucketPipelines,
    AzureDevOps,
    Local,
    Unknown,
}

impl CIProvider {
    pub fn name(&self) -> &'static str {
        match self {
            Self::GitHubActions => "github-actions",
            Self::GitLabCI => "gitlab-ci",
            Self::CircleCI => "circleci",
            Self::Jenkins => "jenkins",
            Self::Buildkite => "buildkite",
            Self::BitbucketPipelines => "bitbucket-pipelines",
            Self::AzureDevOps => "azure-devops",
            Self::Local => "local",
            Self::Unknown => "unknown",
        }
    }

    pub fn detect() -> Self {
        if std::env::var("GITHUB_ACTIONS").is_ok() {
            Self::GitHubActions
        } else if std::env::var("GITLAB_CI").is_ok() {
            Self::GitLabCI
        } else if std::env::var("CIRCLECI").is_ok() {
            Self::CircleCI
        } else if std::env::var("JENKINS_URL").is_ok() {
            Self::Jenkins
        } else if std::env::var("BUILDKITE").is_ok() {
            Self::Buildkite
        } else if std::env::var("BITBUCKET_BUILD_NUMBER").is_ok() {
            Self::BitbucketPipelines
        } else if std::env::var("TF_BUILD").is_ok()
            || std::env::var("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI").is_ok()
        {
            Self::AzureDevOps
        } else if std::env::var("CI").is_ok() {
            Self::Unknown
        } else {
            Self::Local
        }
    }

    pub fn is_ci(&self) -> bool {
        !matches!(self, Self::Local)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CIRuntime {
    pub provider: CIProvider,
    pub workspace: String,
    pub repository: String,
    pub branch: String,
    pub commit_sha: String,
    pub commit_message: String,
    pub pr_number: Option<u64>,
    pub pr_branch: Option<String>,
    pub pr_base_branch: Option<String>,
    pub run_id: String,
    pub run_number: String,
    pub run_url: Option<String>,
    pub job_name: String,
    pub actor: String,
    pub is_pr: bool,
    pub event_name: String,
}

impl CIRuntime {
    pub fn detect() -> Self {
        let provider = CIProvider::detect();
        match provider {
            CIProvider::GitHubActions => Self::from_github_actions(),
            CIProvider::GitLabCI => Self::from_gitlab_ci(),
            CIProvider::CircleCI => Self::from_circle_ci(),
            CIProvider::Jenkins => Self::from_jenkins(),
            CIProvider::Buildkite => Self::from_buildkite(),
            CIProvider::BitbucketPipelines => Self::from_bitbucket(),
            CIProvider::AzureDevOps => Self::from_azure(),
            CIProvider::Local => Self::local(),
            CIProvider::Unknown => Self::unknown_ci(),
        }
    }

    fn from_github_actions() -> Self {
        let is_pr = std::env::var("GITHUB_EVENT_NAME")
            .map(|v| v == "pull_request")
            .unwrap_or(false);
        let event_name = std::env::var("GITHUB_EVENT_NAME").unwrap_or_else(|_| "push".to_string());
        let pr_number = if is_pr {
            std::env::var("GITHUB_REF").ok().and_then(|r| {
                r.strip_prefix("refs/pull/")
                    .and_then(|s| s.split('/').next())
                    .and_then(|n| n.parse().ok())
            })
        } else {
            None
        };
        let pr_branch = if is_pr {
            std::env::var("GITHUB_HEAD_REF").ok()
        } else {
            None
        };
        let pr_base_branch = if is_pr {
            std::env::var("GITHUB_BASE_REF").ok()
        } else {
            None
        };

        Self {
            provider: CIProvider::GitHubActions,
            workspace: std::env::var("GITHUB_WORKSPACE").unwrap_or_else(|_| ".".to_string()),
            repository: std::env::var("GITHUB_REPOSITORY")
                .unwrap_or_else(|_| "unknown/repo".to_string()),
            branch: pr_base_branch
                .clone()
                .or_else(|| {
                    std::env::var("GITHUB_REF")
                        .ok()
                        .and_then(|r| r.strip_prefix("refs/heads/").map(String::from))
                })
                .unwrap_or_else(|| "main".to_string()),
            commit_sha: std::env::var("GITHUB_SHA").unwrap_or_else(|_| String::new()),
            commit_message: std::env::var("GITHUB_COMMIT_MESSAGE")
                .unwrap_or_else(|_| String::new()),
            pr_number,
            pr_branch,
            pr_base_branch,
            run_id: std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| String::new()),
            run_number: std::env::var("GITHUB_RUN_NUMBER").unwrap_or_else(|_| "1".to_string()),
            run_url: std::env::var("GITHUB_RUN_ID").ok().map(|id| {
                let repo = std::env::var("GITHUB_REPOSITORY")
                    .unwrap_or_else(|_| "unknown/repo".to_string());
                format!("https://github.com/{repo}/actions/runs/{id}")
            }),
            job_name: std::env::var("GITHUB_JOB").unwrap_or_else(|_| "baloncore".to_string()),
            actor: std::env::var("GITHUB_ACTOR").unwrap_or_else(|_| "unknown".to_string()),
            is_pr,
            event_name,
        }
    }

    fn from_gitlab_ci() -> Self {
        let is_pr = std::env::var("CI_MERGE_REQUEST_IID").is_ok();
        let project_url = std::env::var("CI_PROJECT_URL").unwrap_or_default();
        Self {
            provider: CIProvider::GitLabCI,
            workspace: std::env::var("CI_PROJECT_DIR").unwrap_or_else(|_| ".".to_string()),
            repository: std::env::var("CI_PROJECT_PATH")
                .unwrap_or_else(|_| "unknown/repo".to_string()),
            branch: std::env::var("CI_COMMIT_REF_NAME").unwrap_or_else(|_| "main".to_string()),
            commit_sha: std::env::var("CI_COMMIT_SHA").unwrap_or_else(|_| String::new()),
            commit_message: std::env::var("CI_COMMIT_MESSAGE").unwrap_or_else(|_| String::new()),
            pr_number: std::env::var("CI_MERGE_REQUEST_IID")
                .ok()
                .and_then(|v| v.parse().ok()),
            pr_branch: std::env::var("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME").ok(),
            pr_base_branch: std::env::var("CI_MERGE_REQUEST_TARGET_BRANCH_NAME").ok(),
            run_id: std::env::var("CI_PIPELINE_ID").unwrap_or_else(|_| String::new()),
            run_number: std::env::var("CI_PIPELINE_IID").unwrap_or_else(|_| "1".to_string()),
            run_url: std::env::var("CI_PIPELINE_URL").ok().or_else(|| {
                if project_url.is_empty() {
                    None
                } else {
                    let pipeline_id =
                        std::env::var("CI_PIPELINE_ID").unwrap_or_else(|_| String::new());
                    Some(format!("{project_url}/-/pipelines/{pipeline_id}"))
                }
            }),
            job_name: std::env::var("CI_JOB_NAME").unwrap_or_else(|_| "baloncore".to_string()),
            actor: std::env::var("GITLAB_USER_LOGIN")
                .or_else(|_| std::env::var("GITLAB_USER_NAME"))
                .unwrap_or_else(|_| "unknown".to_string()),
            is_pr,
            event_name: if is_pr {
                "merge_request_event".to_string()
            } else {
                "push".to_string()
            },
        }
    }

    fn from_circle_ci() -> Self {
        Self {
            provider: CIProvider::CircleCI,
            workspace: std::env::var("CIRCLE_WORKING_DIRECTORY")
                .unwrap_or_else(|_| ".".to_string()),
            repository: format!(
                "{}/{}",
                std::env::var("CIRCLE_PROJECT_USERNAME").unwrap_or_else(|_| "unknown".to_string()),
                std::env::var("CIRCLE_PROJECT_REPONAME").unwrap_or_else(|_| "repo".to_string())
            ),
            branch: std::env::var("CIRCLE_BRANCH").unwrap_or_else(|_| "main".to_string()),
            commit_sha: std::env::var("CIRCLE_SHA1").unwrap_or_else(|_| String::new()),
            commit_message: String::new(),
            pr_number: std::env::var("CIRCLE_PR_NUMBER")
                .ok()
                .and_then(|v| v.parse().ok()),
            pr_branch: std::env::var("CIRCLE_BRANCH").ok(),
            pr_base_branch: None,
            run_id: std::env::var("CIRCLE_WORKFLOW_ID").unwrap_or_else(|_| String::new()),
            run_number: std::env::var("CIRCLE_BUILD_NUM").unwrap_or_else(|_| "1".to_string()),
            run_url: std::env::var("CIRCLE_BUILD_URL").ok(),
            job_name: std::env::var("CIRCLE_JOB").unwrap_or_else(|_| "baloncore".to_string()),
            actor: std::env::var("CIRCLE_USERNAME").unwrap_or_else(|_| "unknown".to_string()),
            is_pr: std::env::var("CIRCLE_PR_NUMBER").is_ok(),
            event_name: std::env::var("CIRCLE_PR_NUMBER")
                .map(|_| "pull_request".to_string())
                .unwrap_or_else(|_| "push".to_string()),
        }
    }

    fn from_jenkins() -> Self {
        Self {
            provider: CIProvider::Jenkins,
            workspace: std::env::var("WORKSPACE").unwrap_or_else(|_| ".".to_string()),
            repository: std::env::var("GIT_URL").unwrap_or_else(|_| {
                std::env::var("GIT_REPO_URL").unwrap_or_else(|_| "unknown/repo".to_string())
            }),
            branch: std::env::var("GIT_BRANCH").unwrap_or_else(|_| {
                std::env::var("BRANCH_NAME").unwrap_or_else(|_| "main".to_string())
            }),
            commit_sha: std::env::var("GIT_COMMIT").unwrap_or_else(|_| String::new()),
            commit_message: String::new(),
            pr_number: std::env::var("CHANGE_ID").ok().and_then(|v| v.parse().ok()),
            pr_branch: std::env::var("CHANGE_BRANCH").ok(),
            pr_base_branch: std::env::var("CHANGE_TARGET").ok(),
            run_id: std::env::var("BUILD_ID").unwrap_or_else(|_| String::new()),
            run_number: std::env::var("BUILD_NUMBER").unwrap_or_else(|_| "1".to_string()),
            run_url: std::env::var("BUILD_URL").ok(),
            job_name: std::env::var("JOB_NAME").unwrap_or_else(|_| "baloncore".to_string()),
            actor: String::new(),
            is_pr: std::env::var("CHANGE_ID").is_ok(),
            event_name: std::env::var("CHANGE_ID")
                .map(|_| "pull_request".to_string())
                .unwrap_or_else(|_| "push".to_string()),
        }
    }

    fn from_buildkite() -> Self {
        Self {
            provider: CIProvider::Buildkite,
            workspace: std::env::var("BUILDKITE_BUILD_CHECKOUT_PATH")
                .unwrap_or_else(|_| ".".to_string()),
            repository: std::env::var("BUILDKITE_REPO").unwrap_or_else(|_| String::new()),
            branch: std::env::var("BUILDKITE_BRANCH").unwrap_or_else(|_| "main".to_string()),
            commit_sha: std::env::var("BUILDKITE_COMMIT").unwrap_or_else(|_| String::new()),
            commit_message: std::env::var("BUILDKITE_MESSAGE").unwrap_or_else(|_| String::new()),
            pr_number: std::env::var("BUILDKITE_PULL_REQUEST").ok().and_then(|v| {
                if v == "false" {
                    None
                } else {
                    v.parse().ok()
                }
            }),
            pr_branch: std::env::var("BUILDKITE_BRANCH").ok(),
            pr_base_branch: std::env::var("BUILDKITE_PULL_REQUEST_BASE_BRANCH").ok(),
            run_id: std::env::var("BUILDKITE_BUILD_ID").unwrap_or_else(|_| String::new()),
            run_number: std::env::var("BUILDKITE_BUILD_NUMBER").unwrap_or_else(|_| "1".to_string()),
            run_url: std::env::var("BUILDKITE_BUILD_URL").ok(),
            job_name: std::env::var("BUILDKITE_LABEL").unwrap_or_else(|_| "baloncore".to_string()),
            actor: std::env::var("BUILDKITE_BUILD_CREATOR")
                .unwrap_or_else(|_| "unknown".to_string()),
            is_pr: std::env::var("BUILDKITE_PULL_REQUEST")
                .map(|v| v != "false")
                .unwrap_or(false),
            event_name: std::env::var("BUILDKITE_PULL_REQUEST")
                .map(|v| {
                    if v == "false" {
                        "push".to_string()
                    } else {
                        "pull_request".to_string()
                    }
                })
                .unwrap_or_else(|_| "push".to_string()),
        }
    }

    fn from_bitbucket() -> Self {
        Self {
            provider: CIProvider::BitbucketPipelines,
            workspace: std::env::var("BITBUCKET_CLONE_DIR").unwrap_or_else(|_| ".".to_string()),
            repository: std::env::var("BITBUCKET_REPO_FULL_NAME")
                .unwrap_or_else(|_| "unknown/repo".to_string()),
            branch: std::env::var("BITBUCKET_BRANCH").unwrap_or_else(|_| "main".to_string()),
            commit_sha: std::env::var("BITBUCKET_COMMIT").unwrap_or_else(|_| String::new()),
            commit_message: String::new(),
            pr_number: std::env::var("BITBUCKET_PR_ID")
                .ok()
                .and_then(|v| v.parse().ok()),
            pr_branch: std::env::var("BITBUCKET_BRANCH").ok(),
            pr_base_branch: std::env::var("BITBUCKET_PR_DESTINATION_BRANCH").ok(),
            run_id: std::env::var("BITBUCKET_BUILD_NUMBER").unwrap_or_else(|_| String::new()),
            run_number: std::env::var("BITBUCKET_BUILD_NUMBER").unwrap_or_else(|_| "1".to_string()),
            run_url: None,
            job_name: "baloncore".to_string(),
            actor: String::new(),
            is_pr: std::env::var("BITBUCKET_PR_ID").is_ok(),
            event_name: std::env::var("BITBUCKET_PR_ID")
                .map(|_| "pull_request".to_string())
                .unwrap_or_else(|_| "push".to_string()),
        }
    }

    fn from_azure() -> Self {
        let is_pr = std::env::var("SYSTEM_PULLREQUEST_PULLREQUESTID").is_ok();
        Self {
            provider: CIProvider::AzureDevOps,
            workspace: std::env::var("BUILD_SOURCESDIRECTORY").unwrap_or_else(|_| ".".to_string()),
            repository: std::env::var("BUILD_REPOSITORY_NAME")
                .unwrap_or_else(|_| "unknown/repo".to_string()),
            branch: std::env::var("BUILD_SOURCEBRANCHNAME").unwrap_or_else(|_| "main".to_string()),
            commit_sha: std::env::var("BUILD_SOURCEVERSION").unwrap_or_else(|_| String::new()),
            commit_message: String::new(),
            pr_number: std::env::var("SYSTEM_PULLREQUEST_PULLREQUESTID")
                .ok()
                .and_then(|v| v.parse().ok()),
            pr_branch: std::env::var("SYSTEM_PULLREQUEST_SOURCEBRANCH").ok(),
            pr_base_branch: std::env::var("SYSTEM_PULLREQUEST_TARGETBRANCH").ok(),
            run_id: std::env::var("BUILD_BUILDID").unwrap_or_else(|_| String::new()),
            run_number: std::env::var("BUILD_BUILDNUMBER").unwrap_or_else(|_| "1".to_string()),
            run_url: Some(format!(
                "{}/{}/_build/results?buildId={}",
                std::env::var("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI")
                    .unwrap_or_else(|_| String::new()),
                std::env::var("SYSTEM_TEAMPROJECT").unwrap_or_else(|_| String::new()),
                std::env::var("BUILD_BUILDID").unwrap_or_else(|_| String::new())
            )),
            job_name: std::env::var("AGENT_JOBNAME").unwrap_or_else(|_| "baloncore".to_string()),
            actor: std::env::var("BUILD_REQUESTEDFOR").unwrap_or_else(|_| "unknown".to_string()),
            is_pr,
            event_name: if is_pr {
                "pull_request".to_string()
            } else {
                "push".to_string()
            },
        }
    }

    fn local() -> Self {
        Self {
            provider: CIProvider::Local,
            workspace: std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| ".".to_string()),
            repository: String::new(),
            branch: String::new(),
            commit_sha: String::new(),
            commit_message: String::new(),
            pr_number: None,
            pr_branch: None,
            pr_base_branch: None,
            run_id: "local".to_string(),
            run_number: "0".to_string(),
            run_url: None,
            job_name: "local".to_string(),
            actor: std::env::var("USER").unwrap_or_else(|_| "unknown".to_string()),
            is_pr: false,
            event_name: "manual".to_string(),
        }
    }

    fn unknown_ci() -> Self {
        let mut runtime = Self::local();
        runtime.provider = CIProvider::Unknown;
        runtime.run_id = std::env::var("BUILD_ID")
            .or_else(|_| std::env::var("BUILD_NUMBER"))
            .or_else(|_| std::env::var("CI_BUILD_ID"))
            .unwrap_or_else(|_| "ci-unknown".to_string());
        runtime
    }

    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("provider: {}", self.provider.name()));
        lines.push(format!("repository: {}", self.repository));
        lines.push(format!("branch: {}", self.branch));
        lines.push(format!(
            "commit: {}",
            &self.commit_sha[..self.commit_sha.len().min(8)]
        ));
        lines.push(format!("run: {} (#{})", self.run_id, self.run_number));
        if self.is_pr {
            lines.push(format!(
                "PR: #{} ({} -> {})",
                self.pr_number.unwrap_or(0),
                self.pr_branch.as_deref().unwrap_or("?"),
                self.pr_base_branch.as_deref().unwrap_or("?")
            ));
        }
        lines.push(format!("event: {}", self.event_name));
        lines.push(format!("actor: {}", self.actor));
        lines.join("\n")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CICheckRun {
    pub name: String,
    pub head_sha: String,
    pub status: CheckRunStatus,
    pub conclusion: Option<CheckRunConclusion>,
    pub title: String,
    pub summary: String,
    pub text: String,
    pub annotations: Vec<CICheckAnnotation>,
    pub external_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CheckRunStatus {
    Queued,
    InProgress,
    Completed,
}

impl CheckRunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CheckRunConclusion {
    Success,
    Failure,
    Neutral,
    Cancelled,
    Skipped,
    TimedOut,
    ActionRequired,
}

impl CheckRunConclusion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Neutral => "neutral",
            Self::Cancelled => "cancelled",
            Self::Skipped => "skipped",
            Self::TimedOut => "timed_out",
            Self::ActionRequired => "action_required",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CICheckAnnotation {
    pub path: String,
    pub start_line: u64,
    pub end_line: u64,
    pub annotation_level: AnnotationLevel,
    pub message: String,
    pub title: String,
    pub raw_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnnotationLevel {
    Notice,
    Warning,
    Failure,
}

impl AnnotationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Failure => "failure",
        }
    }

    pub fn from_severity(severity: &str) -> Self {
        match severity.to_lowercase().as_str() {
            "critical" => Self::Failure,
            "high" => Self::Failure,
            "medium" => Self::Warning,
            "low" => Self::Notice,
            _ => Self::Warning,
        }
    }
}

pub fn build_check_run_from_gate(
    gate: &crate::ci::CIGateResult,
    head_sha: &str,
    is_pr: bool,
) -> CICheckRun {
    let conclusion = if gate.passed {
        CheckRunConclusion::Success
    } else {
        CheckRunConclusion::Failure
    };

    let mut annotations = Vec::new();
    for finding in &gate.blocking_findings {
        annotations.push(CICheckAnnotation {
            path: extract_path_from_endpoint(&finding.endpoint),
            start_line: 1,
            end_line: 1,
            annotation_level: AnnotationLevel::from_severity(&finding.severity),
            message: format!(
                "{} finding: {} at {}. {}",
                finding.severity, finding.classification, finding.endpoint, finding.reason
            ),
            title: format!("{}: {}", finding.severity, finding.classification),
            raw_details: Some(format!(
                "Finding ID: {}\nSeverity: {}\nState: {}\nReason: {}",
                finding.finding_id, finding.severity, finding.state, finding.reason
            )),
        });
    }

    let title = if is_pr {
        format!("BALONCORE PR Review — {} findings", gate.total_findings)
    } else {
        format!("BALONCORE CI Gate — {} findings", gate.total_findings)
    };

    let mut text = String::new();
    text.push_str(&format!(
        "## CI Gate Result: {}\n\n",
        if gate.passed { "PASSED" } else { "FAILED" }
    ));
    text.push_str(&format!(
        "- Total findings: `{}`\n- New findings: `{}`\n- Blocking: `{}`\n- Suppressed: `{}`\n",
        gate.total_findings,
        gate.new_findings,
        gate.blocking_findings.len(),
        gate.suppressed_findings
    ));

    if !gate.blocking_findings.is_empty() {
        text.push_str("\n### Blocking Findings\n\n");
        for finding in &gate.blocking_findings {
            text.push_str(&format!(
                "- `{}` `{}` at `{}`: {}\n",
                finding.severity, finding.classification, finding.endpoint, finding.reason
            ));
        }
    }

    CICheckRun {
        name: "baloncore-security".to_string(),
        head_sha: head_sha.to_string(),
        status: CheckRunStatus::Completed,
        conclusion: Some(conclusion),
        title,
        summary: gate.summary.clone(),
        text,
        annotations,
        external_id: Some("baloncore-ci-gate".to_string()),
    }
}

fn extract_path_from_endpoint(endpoint: &str) -> String {
    if let Some(path_start) = endpoint.find(' ') {
        let path_part = &endpoint[path_start + 1..];
        path_part.split(' ').next().unwrap_or(endpoint).to_string()
    } else {
        endpoint.to_string()
    }
}

#[cfg(feature = "live-models")]
pub fn create_github_check_run(
    owner: &str,
    repo: &str,
    check: &CICheckRun,
    token_env: &str,
) -> Result<u64, String> {
    let token = std::env::var(token_env).map_err(|e| format!("missing env {token_env}: {e}"))?;
    let url = format!("https://api.github.com/repos/{owner}/{repo}/check-runs");
    let payload = serde_json::json!({
        "name": check.name,
        "head_sha": check.head_sha,
        "status": check.status.as_str(),
        "conclusion": check.conclusion.as_ref().map(|c| c.as_str()),
        "output": {
            "title": check.title,
            "summary": check.summary,
            "text": check.text,
            "annotations": check.annotations.iter().map(|a| serde_json::json!({
                "path": a.path,
                "start_line": a.start_line,
                "end_line": a.end_line,
                "annotation_level": a.annotation_level.as_str(),
                "message": a.message,
                "title": a.title,
                "raw_details": a.raw_details,
            })).collect::<Vec<_>>(),
        },
        "external_id": check.external_id,
    });

    let auth_header = if token.starts_with("ghp_") || token.starts_with("github_pat_") {
        format!("Bearer {token}")
    } else {
        format!("token {token}")
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let response = client
        .post(&url)
        .header("Authorization", &auth_header)
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "baloncore")
        .json(&payload)
        .send()
        .map_err(|e| format!("GitHub API request failed: {e}"))?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .map_err(|e| format!("failed to read response: {e}"))?;
    if status != 201 {
        return Err(format!("GitHub API returned {status}: {body}"));
    }
    let result: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("failed to parse response: {e}"))?;
    result
        .get("id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "check run id not found".to_string())
}

#[cfg(not(feature = "live-models"))]
pub fn create_github_check_run(
    _owner: &str,
    _repo: &str,
    _check: &CICheckRun,
    _token_env: &str,
) -> Result<u64, String> {
    Err("create_github_check_run requires --features live-models".to_string())
}

pub fn render_ci_status_markdown(runtime: &CIRuntime, gate: &crate::ci::CIGateResult) -> String {
    let mut md = String::new();
    md.push_str("## BALONCORE CI Status\n\n");
    md.push_str("| Field | Value |\n");
    md.push_str("|-------|-------|\n");
    md.push_str(&format!("| Provider | {} |\n", runtime.provider.name()));
    md.push_str(&format!("| Repository | {} |\n", runtime.repository));
    md.push_str(&format!(
        "| Branch | {} |\n",
        if runtime.is_pr {
            runtime.pr_branch.as_deref().unwrap_or(&runtime.branch)
        } else {
            &runtime.branch
        }
    ));
    md.push_str(&format!(
        "| Commit | {} |\n",
        &runtime.commit_sha[..runtime.commit_sha.len().min(8)]
    ));
    md.push_str(&format!(
        "| Gate | {} |\n",
        if gate.passed { "PASSED" } else { "FAILED" }
    ));
    md.push_str(&format!(
        "| Findings | {} total, {} blocking |\n",
        gate.total_findings,
        gate.blocking_findings.len()
    ));
    if runtime.is_pr {
        md.push_str(&format!(
            "| PR | #{} ({}) |\n",
            runtime.pr_number.unwrap_or(0),
            runtime.pr_branch.as_deref().unwrap_or("?")
        ));
    }
    md.push_str(&format!("| Run | {} |\n", runtime.run_id));
    md.push('\n');
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_provider_local_when_no_env() {
        let provider = CIProvider::detect();
        assert_eq!(provider, CIProvider::Local);
    }

    #[test]
    fn ci_provider_names() {
        assert_eq!(CIProvider::GitHubActions.name(), "github-actions");
        assert_eq!(CIProvider::GitLabCI.name(), "gitlab-ci");
        assert_eq!(CIProvider::CircleCI.name(), "circleci");
        assert_eq!(CIProvider::Jenkins.name(), "jenkins");
        assert_eq!(CIProvider::Local.name(), "local");
        assert_eq!(CIProvider::Unknown.name(), "unknown");
    }

    #[test]
    fn local_runtime_has_sensible_defaults() {
        let runtime = CIRuntime::local();
        assert_eq!(runtime.provider, CIProvider::Local);
        assert_eq!(runtime.is_pr, false);
        assert_eq!(runtime.event_name, "manual");
        assert!(
            runtime.workspace.contains('/')
                || runtime.workspace.contains('\\')
                || !runtime.workspace.is_empty()
        );
    }

    #[test]
    fn ci_provider_is_ci() {
        assert!(CIProvider::GitHubActions.is_ci());
        assert!(CIProvider::GitLabCI.is_ci());
        assert!(!CIProvider::Local.is_ci());
    }

    #[test]
    fn check_run_status_values() {
        assert_eq!(CheckRunStatus::Queued.as_str(), "queued");
        assert_eq!(CheckRunStatus::InProgress.as_str(), "in_progress");
        assert_eq!(CheckRunStatus::Completed.as_str(), "completed");
    }

    #[test]
    fn check_run_conclusion_values() {
        assert_eq!(CheckRunConclusion::Success.as_str(), "success");
        assert_eq!(CheckRunConclusion::Failure.as_str(), "failure");
        assert_eq!(CheckRunConclusion::Neutral.as_str(), "neutral");
        assert_eq!(
            CheckRunConclusion::ActionRequired.as_str(),
            "action_required"
        );
    }

    #[test]
    fn annotation_level_from_severity() {
        assert_eq!(
            AnnotationLevel::from_severity("critical"),
            AnnotationLevel::Failure
        );
        assert_eq!(
            AnnotationLevel::from_severity("high"),
            AnnotationLevel::Failure
        );
        assert_eq!(
            AnnotationLevel::from_severity("medium"),
            AnnotationLevel::Warning
        );
        assert_eq!(
            AnnotationLevel::from_severity("low"),
            AnnotationLevel::Notice
        );
        assert_eq!(
            AnnotationLevel::from_severity("info"),
            AnnotationLevel::Warning
        );
    }

    #[test]
    fn build_check_run_for_passing_gate() {
        let gate = crate::ci::CIGateResult {
            passed: true,
            total_findings: 5,
            new_findings: 0,
            baseline_findings: 5,
            suppressed_findings: 0,
            blocking_findings: vec![],
            exit_code: 0,
            summary: "CI PASSED".to_string(),
        };
        let check = build_check_run_from_gate(&gate, "abc123def", true);
        assert_eq!(check.name, "baloncore-security");
        assert_eq!(check.head_sha, "abc123def");
        assert_eq!(check.status, CheckRunStatus::Completed);
        assert_eq!(check.conclusion, Some(CheckRunConclusion::Success));
        assert!(check.annotations.is_empty());
        assert!(check.title.contains("PR Review"));
    }

    #[test]
    fn build_check_run_for_failing_gate_with_blocking() {
        let gate = crate::ci::CIGateResult {
            passed: false,
            total_findings: 10,
            new_findings: 3,
            baseline_findings: 7,
            suppressed_findings: 0,
            blocking_findings: vec![
                crate::ci::BlockingFinding {
                    finding_id: "f-1".to_string(),
                    classification: "BrokenObjectLevelAuthorization".to_string(),
                    severity: "high".to_string(),
                    endpoint: "GET /api/invoices/{id}".to_string(),
                    reason: "high severity finding in Verified state".to_string(),
                    state: "Verified".to_string(),
                },
                crate::ci::BlockingFinding {
                    finding_id: "f-2".to_string(),
                    classification: "MissingAuthentication".to_string(),
                    severity: "critical".to_string(),
                    endpoint: "POST /api/admin".to_string(),
                    reason: "critical severity finding in Reported state".to_string(),
                    state: "Reported".to_string(),
                },
            ],
            exit_code: 1,
            summary: "CI FAILED".to_string(),
        };
        let check = build_check_run_from_gate(&gate, "def456abc", false);
        assert_eq!(check.conclusion, Some(CheckRunConclusion::Failure));
        assert_eq!(check.annotations.len(), 2);
        assert_eq!(
            check.annotations[0].annotation_level,
            AnnotationLevel::Failure
        );
        assert_eq!(
            check.annotations[1].annotation_level,
            AnnotationLevel::Failure
        );
        assert!(check.title.contains("CI Gate"));
    }

    #[test]
    fn extract_path_from_endpoint_works() {
        assert_eq!(
            extract_path_from_endpoint("GET /api/invoices/{id}"),
            "/api/invoices/{id}"
        );
        assert_eq!(
            extract_path_from_endpoint("POST /api/admin/users"),
            "/api/admin/users"
        );
        assert_eq!(extract_path_from_endpoint("nospace"), "nospace");
    }

    #[test]
    fn build_check_run_non_pr_title() {
        let gate = crate::ci::CIGateResult {
            passed: true,
            total_findings: 0,
            new_findings: 0,
            baseline_findings: 0,
            suppressed_findings: 0,
            blocking_findings: vec![],
            exit_code: 0,
            summary: String::new(),
        };
        let check = build_check_run_from_gate(&gate, "sha", false);
        assert!(check.title.contains("CI Gate"));
        assert!(!check.title.contains("PR Review"));
    }

    #[test]
    fn runtime_local_summary_includes_workspace() {
        let runtime = CIRuntime::local();
        let summary = runtime.summary();
        assert!(summary.contains("provider: local"));
        assert!(summary.contains("event: manual"));
    }

    #[test]
    fn render_ci_status_markdown_includes_provider() {
        let runtime = CIRuntime::local();
        let gate = crate::ci::CIGateResult {
            passed: true,
            total_findings: 3,
            new_findings: 0,
            baseline_findings: 3,
            suppressed_findings: 0,
            blocking_findings: vec![],
            exit_code: 0,
            summary: "OK".to_string(),
        };
        let md = render_ci_status_markdown(&runtime, &gate);
        assert!(md.contains("local"));
        assert!(md.contains("PASSED"));
        assert!(md.contains("3 total"));
    }

    #[test]
    fn annotation_level_serialization() {
        let notice = AnnotationLevel::Notice;
        let warning = AnnotationLevel::Warning;
        let failure = AnnotationLevel::Failure;
        assert_eq!(notice.as_str(), "notice");
        assert_eq!(warning.as_str(), "warning");
        assert_eq!(failure.as_str(), "failure");
    }

    #[test]
    fn check_run_serialization() {
        let check = CICheckRun {
            name: "test".to_string(),
            head_sha: "abc".to_string(),
            status: CheckRunStatus::Completed,
            conclusion: Some(CheckRunConclusion::Success),
            title: "title".to_string(),
            summary: "summary".to_string(),
            text: "text".to_string(),
            annotations: vec![CICheckAnnotation {
                path: "openapi.yaml".to_string(),
                start_line: 42,
                end_line: 42,
                annotation_level: AnnotationLevel::Warning,
                message: "missing auth".to_string(),
                title: "BOLA risk".to_string(),
                raw_details: None,
            }],
            external_id: Some("x".to_string()),
        };
        let json = serde_json::to_string_pretty(&check).unwrap();
        let parsed: CICheckRun = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.annotations.len(), 1);
        assert_eq!(parsed.annotations[0].path, "openapi.yaml");
        assert_eq!(
            parsed.annotations[0].annotation_level,
            AnnotationLevel::Warning
        );
    }
}
