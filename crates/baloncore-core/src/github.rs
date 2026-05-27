use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GitHubClient {
    pub owner: String,
    pub repo: String,
    pub token_env: String,
    #[serde(default)]
    pub api_base: String,
}

impl GitHubClient {
    pub fn new(owner: &str, repo: &str, token_env: &str) -> Self {
        Self {
            owner: owner.to_string(),
            repo: repo.to_string(),
            token_env: token_env.to_string(),
            api_base: "https://api.github.com".to_string(),
        }
    }

    pub fn repo_url(&self) -> String {
        format!("{}/repos/{}/{}", self.api_base, self.owner, self.repo)
    }

    #[allow(dead_code)]
    fn token(&self) -> String {
        std::env::var(&self.token_env).unwrap_or_default()
    }

    #[allow(dead_code)]
    fn auth_header(&self) -> String {
        let token = self.token();
        if token.starts_with("ghp_") || token.starts_with("github_pat_") {
            format!("Bearer {token}")
        } else {
            format!("token {token}")
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GitHubPR {
    pub number: u64,
    pub title: String,
    pub body: Option<String>,
    pub state: String,
    pub head_sha: String,
    pub base_sha: String,
    pub head_branch: String,
    pub base_branch: String,
    pub html_url: String,
    pub user_login: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub mergeable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GitHubPRFile {
    pub filename: String,
    pub status: String,
    pub additions: u64,
    pub deletions: u64,
    pub changes: u64,
    #[serde(default)]
    pub patch: Option<String>,
    pub blob_url: String,
    pub raw_url: String,
}

impl GitHubPRFile {
    pub fn is_security_relevant(&self) -> bool {
        self.is_api_spec() || self.is_auth_config() || self.is_middleware() || self.is_endpoint()
    }

    pub fn is_api_spec(&self) -> bool {
        let name = self.filename.to_lowercase();
        name.contains("openapi")
            || name.contains("swagger")
            || name.ends_with(".graphql")
            || name.contains("schema")
    }

    pub fn is_auth_config(&self) -> bool {
        let name = self.filename.to_lowercase();
        name.contains("auth")
            || name.contains("security")
            || name.contains("policy")
            || name.contains("permission")
            || name.contains("role")
            || name.contains("csrf")
    }

    pub fn is_middleware(&self) -> bool {
        let name = self.filename.to_lowercase();
        (name.contains("middleware") && !name.contains("test"))
            || name.contains("guard")
            || name.contains("interceptor")
    }

    pub fn is_endpoint(&self) -> bool {
        let name = self.filename.to_lowercase();
        name.contains("route")
            || name.contains("controller")
            || name.contains("handler")
            || name.contains("endpoint")
    }

    pub fn change_category(&self) -> &'static str {
        if self.is_endpoint() {
            "endpoint"
        } else if self.is_middleware() {
            "middleware"
        } else if self.is_api_spec() {
            "api-spec"
        } else if self.is_auth_config() {
            "auth-config"
        } else {
            "other"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GitHubPRComment {
    pub id: u64,
    pub body: String,
    pub user_login: String,
    pub created_at: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub line: Option<u64>,
    #[serde(default)]
    pub commit_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GitHubReview {
    pub id: u64,
    pub body: String,
    pub state: String,
    pub user_login: String,
    pub submitted_at: String,
    pub commit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PRComparison {
    pub total_commits: u64,
    pub changed_files: u64,
    pub additions: u64,
    pub deletions: u64,
    pub files: Vec<GitHubPRFile>,
    pub base_commit: String,
    pub head_commit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PRDiffAnalysis {
    pub pr_number: u64,
    pub total_files: usize,
    pub security_relevant_files: Vec<SecurityRelevantFile>,
    pub endpoint_changes: Vec<EndpointChange>,
    pub auth_changes: Vec<AuthChange>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityRelevantFile {
    pub filename: String,
    pub status: String,
    pub category: String,
    pub additions: u64,
    pub deletions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EndpointChange {
    pub filename: String,
    pub kind: String,
    pub path_hint: Option<String>,
    pub method_hint: Option<String>,
    pub auth_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthChange {
    pub filename: String,
    pub kind: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RevalidationPlan {
    pub pr_number: u64,
    pub affected_endpoints: Vec<String>,
    pub affected_findings: Vec<RevalidationTarget>,
    pub retest_commands: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RevalidationTarget {
    pub finding_id: String,
    pub endpoint: String,
    pub classification: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubWebhookEvent {
    pub event_type: String,
    pub action: Option<String>,
    pub pr_number: Option<u64>,
    pub repository_owner: Option<String>,
    pub repository_name: Option<String>,
    pub head_sha: Option<String>,
    pub base_sha: Option<String>,
    pub head_branch: Option<String>,
    pub base_branch: Option<String>,
    pub sender_login: Option<String>,
    pub installation_id: Option<u64>,
}

impl GitHubWebhookEvent {
    pub fn from_payload(event_type: &str, payload: &serde_json::Value) -> Self {
        let action = payload
            .get("action")
            .and_then(|v| v.as_str())
            .map(String::from);
        let pr_number = payload
            .get("pull_request")
            .or_else(|| payload.get("issue"))
            .and_then(|pr| pr.get("number"))
            .and_then(|v| v.as_u64());
        let repo = payload.get("repository").or_else(|| payload.get("repo"));
        let repository_owner = repo
            .and_then(|r| r.get("owner"))
            .and_then(|o| o.get("login"))
            .or_else(|| repo.and_then(|r| r.get("full_name").or_else(|| r.get("name"))))
            .and_then(|v| v.as_str())
            .and_then(|full| full.split('/').next())
            .map(String::from);
        let repository_name = repo
            .and_then(|r| r.get("name").or_else(|| r.get("full_name")))
            .and_then(|v| v.as_str())
            .map(|v| {
                if let Some(name) = v.split('/').nth(1) {
                    name.to_string()
                } else {
                    v.to_string()
                }
            });
        let pr = payload.get("pull_request");
        let head_sha = pr
            .and_then(|p| p.get("head"))
            .and_then(|h| h.get("sha"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let base_sha = pr
            .and_then(|p| p.get("base"))
            .and_then(|b| b.get("sha"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let head_branch = pr
            .and_then(|p| p.get("head"))
            .and_then(|h| h.get("ref"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let base_branch = pr
            .and_then(|p| p.get("base"))
            .and_then(|b| b.get("ref"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let sender_login = payload
            .get("sender")
            .and_then(|s| s.get("login"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let installation_id = payload
            .get("installation")
            .and_then(|i| i.get("id"))
            .and_then(|v| v.as_u64());

        Self {
            event_type: event_type.to_string(),
            action,
            pr_number,
            repository_owner,
            repository_name,
            head_sha,
            base_sha,
            head_branch,
            base_branch,
            sender_login,
            installation_id,
        }
    }

    pub fn is_pr_event(&self) -> bool {
        self.event_type == "pull_request"
    }

    pub fn should_scan(&self) -> bool {
        if !self.is_pr_event() {
            return false;
        }
        matches!(
            self.action.as_deref(),
            Some("opened") | Some("synchronize") | Some("reopened")
        )
    }

    pub fn summary(&self) -> String {
        format!(
            "{} {} PR #{} ({}/{})",
            self.event_type,
            self.action.as_deref().unwrap_or("unknown"),
            self.pr_number.unwrap_or(0),
            self.repository_owner.as_deref().unwrap_or("unknown"),
            self.repository_name.as_deref().unwrap_or("unknown")
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubWebhookResponse {
    pub event: String,
    pub action_taken: String,
    pub pr_scanned: Option<u64>,
    pub findings_blocking: usize,
    pub review_posted: bool,
    pub message: String,
}

pub fn parse_github_webhook(
    event_type: &str,
    body: &str,
    signature: Option<&str>,
    webhook_secret_env: Option<&str>,
) -> Result<(GitHubWebhookEvent, bool), String> {
    let payload: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("failed to parse webhook payload: {e}"))?;
    let event = GitHubWebhookEvent::from_payload(event_type, &payload);

    let verified = if let (Some(sig), Some(secret_env)) = (signature, webhook_secret_env) {
        verify_webhook_signature(body, sig, secret_env)
    } else {
        true
    };

    Ok((event, verified))
}

fn verify_webhook_signature(body: &str, signature: &str, secret_env: &str) -> bool {
    let secret = std::env::var(secret_env).unwrap_or_default();
    if secret.is_empty() {
        return false;
    }

    #[cfg(feature = "live-models")]
    {
        use sha2::Digest;
        let expected_prefix = "sha256=";
        if !signature.starts_with(expected_prefix) {
            return false;
        }
        let expected_hex = &signature[expected_prefix.len()..];
        let mut mac = sha2::Sha256::new();
        mac.update(secret.as_bytes());
        mac.update(body.as_bytes());
        let computed = hex_lower(&mac.finalize());
        computed == expected_hex
    }

    #[cfg(not(feature = "live-models"))]
    {
        let _ = (body, signature, secret_env);
        true
    }
}

#[allow(dead_code)]
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn analyze_pr_diff(files: &[GitHubPRFile], pr_number: u64) -> PRDiffAnalysis {
    let security_relevant: Vec<SecurityRelevantFile> = files
        .iter()
        .filter(|f| f.is_security_relevant())
        .map(|f| SecurityRelevantFile {
            filename: f.filename.clone(),
            status: f.status.clone(),
            category: f.change_category().to_string(),
            additions: f.additions,
            deletions: f.deletions,
        })
        .collect();

    let endpoint_changes: Vec<EndpointChange> = files
        .iter()
        .filter(|f| f.is_endpoint() || f.is_api_spec())
        .map(|f| {
            let path_hint = f.patch.as_ref().and_then(|patch| extract_path_hint(patch));
            let method_hint = f
                .patch
                .as_ref()
                .and_then(|patch| extract_method_hint(patch));
            let auth_changed = f.patch.as_ref().is_some_and(|p| {
                p.contains("auth") || p.contains("security") || p.contains("role")
            });
            EndpointChange {
                filename: f.filename.clone(),
                kind: if f.is_api_spec() {
                    "api-spec".to_string()
                } else {
                    "endpoint".to_string()
                },
                path_hint,
                method_hint,
                auth_changed,
            }
        })
        .collect();

    let auth_changes: Vec<AuthChange> = files
        .iter()
        .filter(|f| f.is_auth_config() || f.is_middleware())
        .map(|f| AuthChange {
            filename: f.filename.clone(),
            kind: if f.is_auth_config() {
                "auth-config".to_string()
            } else {
                "middleware".to_string()
            },
            description: f.patch.as_ref().map_or_else(
                || "file changed".to_string(),
                |p| summarize_patch(p, &f.filename),
            ),
        })
        .collect();

    let summary = format!(
        "PR #{}: {} files changed, {} security-relevant ({} endpoints, {} auth/middleware)",
        pr_number,
        files.len(),
        security_relevant.len(),
        endpoint_changes.len(),
        auth_changes.len()
    );

    PRDiffAnalysis {
        pr_number,
        total_files: files.len(),
        security_relevant_files: security_relevant,
        endpoint_changes,
        auth_changes,
        summary,
    }
}

fn extract_path_hint(patch: &str) -> Option<String> {
    for line in patch.lines() {
        if line.starts_with('+') || line.starts_with('-') {
            let trimmed = &line[1..].trim();
            for keyword in [
                "/api/", "/v1/", "/v2/", "\"/", "'/", "path", "url", "endpoint", "route",
            ] {
                if let Some(idx) = trimmed.find(keyword) {
                    let start =
                        if trimmed.as_bytes()[idx] == b'"' || trimmed.as_bytes()[idx] == b'\'' {
                            idx + 1
                        } else {
                            idx
                        };
                    let rest = &trimmed[start..];
                    let end = rest
                        .find(|c| c == '"' || c == '\'' || c == ',' || c == ' ')
                        .unwrap_or(rest.len());
                    return Some(rest[..end].to_string());
                }
            }
        }
    }
    None
}

fn extract_method_hint(patch: &str) -> Option<String> {
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        let lower = method.to_lowercase();
        if patch.contains(&format!(".{lower}("))
            || patch.contains(&format!("\"{method}\""))
            || patch.contains(&format!("'{method}'"))
            || patch.contains(&format!("{lower}("))
        {
            return Some(method.to_string());
        }
    }
    None
}

fn summarize_patch(patch: &str, filename: &str) -> String {
    let added_lines = patch.lines().filter(|l| l.starts_with('+')).count();
    let removed_lines = patch.lines().filter(|l| l.starts_with('-')).count();
    if patch.contains("role") && patch.contains("permission") {
        format!(
            "{}: +{} / -{} lines (role/permission changes)",
            filename, added_lines, removed_lines
        )
    } else if patch.contains("auth") {
        format!(
            "{}: +{} / -{} lines (auth changes)",
            filename, added_lines, removed_lines
        )
    } else if patch.contains("csrf") {
        format!(
            "{}: +{} / -{} lines (CSRF changes)",
            filename, added_lines, removed_lines
        )
    } else {
        format!("{}: +{} / -{} lines", filename, added_lines, removed_lines)
    }
}

pub fn build_revalidation_plan(
    pr_number: u64,
    diff: &PRDiffAnalysis,
    findings: &[crate::lifecycle::FindingRecord],
) -> RevalidationPlan {
    let mut affected_endpoints = Vec::new();
    let mut affected_findings = Vec::new();
    let mut retest_commands = Vec::new();

    for change in &diff.endpoint_changes {
        if let Some(path) = &change.path_hint {
            affected_endpoints.push(path.clone());
        }
    }

    for finding in findings {
        if finding.state != crate::lifecycle::FindingState::Verified
            && finding.state != crate::lifecycle::FindingState::Reported
        {
            continue;
        }

        let endpoint_matches = affected_endpoints
            .iter()
            .any(|ep| finding.endpoint.contains(ep.as_str()));
        let has_path_overlap = diff.security_relevant_files.iter().any(|f| {
            finding.endpoint.contains(&f.filename) || f.filename.contains(&finding.endpoint)
        });

        if endpoint_matches || has_path_overlap || !diff.auth_changes.is_empty() {
            let reason = if endpoint_matches {
                "endpoint modified in this PR".to_string()
            } else if has_path_overlap {
                "file overlap with security-relevant changes".to_string()
            } else {
                "auth/middleware changes may affect this finding".to_string()
            };

            affected_findings.push(RevalidationTarget {
                finding_id: finding.finding_id.clone(),
                endpoint: finding.endpoint.clone(),
                classification: finding.classification.clone(),
                reason,
            });

            retest_commands.push(format!(
                "cargo run -p baloncore -- run-regression .baloncore/runs/{}/remediation.json --ci",
                finding.scan_id
            ));
        }
    }

    let summary = format!(
        "PR #{}: {} endpoint(s) affected, {} finding(s) need revalidation",
        pr_number,
        affected_endpoints.len(),
        affected_findings.len()
    );

    RevalidationPlan {
        pr_number,
        affected_endpoints,
        affected_findings,
        retest_commands,
        summary,
    }
}

pub fn render_pr_review_comment(diff: &PRDiffAnalysis, revalidation: &RevalidationPlan) -> String {
    let mut md = String::new();
    md.push_str("## BALONCORE Security Review\n\n");
    md.push_str(&diff.summary);
    md.push_str("\n\n");

    if !diff.endpoint_changes.is_empty() {
        md.push_str("### Endpoint Changes\n\n");
        for change in &diff.endpoint_changes {
            md.push_str(&format!("- `{}` ({})", change.filename, change.kind));
            if let Some(path) = &change.path_hint {
                md.push_str(&format!(" → `{}`", path));
            }
            if let Some(method) = &change.method_hint {
                md.push_str(&format!(" [{}]", method));
            }
            if change.auth_changed {
                md.push_str(" **auth changed**");
            }
            md.push('\n');
        }
        md.push('\n');
    }

    if !diff.auth_changes.is_empty() {
        md.push_str("### Auth/Middleware Changes\n\n");
        for change in &diff.auth_changes {
            md.push_str(&format!("- `{}` ({})\n", change.filename, change.kind));
        }
        md.push('\n');
    }

    md.push_str("### Revalidation Plan\n\n");
    if revalidation.affected_findings.is_empty() {
        md.push_str("No existing findings require revalidation.\n\n");
    } else {
        md.push_str(&format!(
            "{} finding(s) should be retested:\n\n",
            revalidation.affected_findings.len()
        ));
        for target in &revalidation.affected_findings {
            md.push_str(&format!(
                "- `{}` (`{}` at `{}`): {}\n",
                target.finding_id, target.classification, target.endpoint, target.reason
            ));
        }
        md.push('\n');
        md.push_str("#### Retest Commands\n\n");
        md.push_str("```bash\n");
        for cmd in &revalidation.retest_commands {
            md.push_str(cmd);
            md.push('\n');
        }
        md.push_str("```\n\n");
    }

    md.push_str("---\n*Automated review by BALONCORE. AI proposes, validators prove.*\n");

    md
}

#[cfg(feature = "live-models")]
pub fn list_open_prs(client: &GitHubClient) -> Result<Vec<GitHubPR>, String> {
    let url = format!("{}/pulls?state=open&per_page=100", client.repo_url());
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let response = http
        .get(&url)
        .header("Authorization", &client.auth_header())
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "baloncore")
        .send()
        .map_err(|e| format!("GitHub API request failed: {e}"))?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .map_err(|e| format!("failed to read response: {e}"))?;
    if status != 200 {
        return Err(format!("GitHub API returned {status}: {body}"));
    }
    let prs: Vec<serde_json::Value> =
        serde_json::from_str(&body).map_err(|e| format!("failed to parse PR list: {e}"))?;
    parse_pr_list(prs)
}

#[cfg(not(feature = "live-models"))]
pub fn list_open_prs(_client: &GitHubClient) -> Result<Vec<GitHubPR>, String> {
    Err("list_open_prs requires --features live-models".to_string())
}

#[cfg(feature = "live-models")]
pub fn get_pr(client: &GitHubClient, pr_number: u64) -> Result<GitHubPR, String> {
    let url = format!("{}/pulls/{}", client.repo_url(), pr_number);
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let response = http
        .get(&url)
        .header("Authorization", &client.auth_header())
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "baloncore")
        .send()
        .map_err(|e| format!("GitHub API request failed: {e}"))?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .map_err(|e| format!("failed to read response: {e}"))?;
    if status != 200 {
        return Err(format!("GitHub API returned {status}: {body}"));
    }
    let pr: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("failed to parse PR: {e}"))?;
    parse_single_pr(&pr)
}

#[cfg(not(feature = "live-models"))]
pub fn get_pr(_client: &GitHubClient, _pr_number: u64) -> Result<GitHubPR, String> {
    Err("get_pr requires --features live-models".to_string())
}

#[cfg(feature = "live-models")]
pub fn get_pr_files(client: &GitHubClient, pr_number: u64) -> Result<Vec<GitHubPRFile>, String> {
    let url = format!("{}/pulls/{}/files", client.repo_url(), pr_number);
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let response = http
        .get(&url)
        .header("Authorization", &client.auth_header())
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "baloncore")
        .send()
        .map_err(|e| format!("GitHub API request failed: {e}"))?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .map_err(|e| format!("failed to read response: {e}"))?;
    if status != 200 {
        return Err(format!("GitHub API returned {status}: {body}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("failed to parse PR files: {e}"))
}

#[cfg(not(feature = "live-models"))]
pub fn get_pr_files(_client: &GitHubClient, _pr_number: u64) -> Result<Vec<GitHubPRFile>, String> {
    Err("get_pr_files requires --features live-models".to_string())
}

#[cfg(feature = "live-models")]
pub fn post_pr_comment(client: &GitHubClient, pr_number: u64, body: &str) -> Result<u64, String> {
    let url = format!("{}/issues/{}/comments", client.repo_url(), pr_number);
    let payload = serde_json::json!({ "body": body });
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let response = http
        .post(&url)
        .header("Authorization", &client.auth_header())
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
    let comment: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("failed to parse comment: {e}"))?;
    comment
        .get("id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "comment id not found in response".to_string())
}

#[cfg(not(feature = "live-models"))]
pub fn post_pr_comment(
    _client: &GitHubClient,
    _pr_number: u64,
    _body: &str,
) -> Result<u64, String> {
    Err("post_pr_comment requires --features live-models".to_string())
}

#[cfg(feature = "live-models")]
pub fn post_pr_review(
    client: &GitHubClient,
    pr_number: u64,
    body: &str,
    event: &str,
    commit_id: &str,
) -> Result<u64, String> {
    let url = format!("{}/pulls/{}/reviews", client.repo_url(), pr_number);
    let payload = serde_json::json!({
        "body": body,
        "event": event,
        "commit_id": commit_id,
    });
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let response = http
        .post(&url)
        .header("Authorization", &client.auth_header())
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "baloncore")
        .json(&payload)
        .send()
        .map_err(|e| format!("GitHub API request failed: {e}"))?;
    let status = response.status().as_u16();
    let response_body = response
        .text()
        .map_err(|e| format!("failed to read response: {e}"))?;
    if status != 200 {
        return Err(format!("GitHub API returned {status}: {response_body}"));
    }
    let review: serde_json::Value =
        serde_json::from_str(&response_body).map_err(|e| format!("failed to parse review: {e}"))?;
    review
        .get("id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "review id not found in response".to_string())
}

#[cfg(not(feature = "live-models"))]
pub fn post_pr_review(
    _client: &GitHubClient,
    _pr_number: u64,
    _body: &str,
    _event: &str,
    _commit_id: &str,
) -> Result<u64, String> {
    Err("post_pr_review requires --features live-models".to_string())
}

#[allow(dead_code)]
fn parse_pr_list(prs: Vec<serde_json::Value>) -> Result<Vec<GitHubPR>, String> {
    prs.iter()
        .map(parse_single_pr)
        .collect::<Result<Vec<_>, String>>()
}

#[allow(dead_code)]
fn parse_single_pr(pr: &serde_json::Value) -> Result<GitHubPR, String> {
    let number = pr
        .get("number")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing PR number".to_string())?;
    let title = pr
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let body = pr.get("body").and_then(|v| v.as_str()).map(String::from);
    let state = pr
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let head_sha = pr
        .get("head")
        .and_then(|h| h.get("sha"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let base_sha = pr
        .get("base")
        .and_then(|b| b.get("sha"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let head_branch = pr
        .get("head")
        .and_then(|h| h.get("ref"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let base_branch = pr
        .get("base")
        .and_then(|b| b.get("ref"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let html_url = pr
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let user_login = pr
        .get("user")
        .and_then(|u| u.get("login"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let created_at = pr
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let updated_at = pr
        .get("updated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let labels = pr
        .get("labels")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|l| l.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let draft = pr.get("draft").and_then(|v| v.as_bool()).unwrap_or(false);
    let mergeable = pr.get("mergeable").and_then(|v| v.as_bool());

    Ok(GitHubPR {
        number,
        title,
        body,
        state,
        head_sha,
        base_sha,
        head_branch,
        base_branch,
        html_url,
        user_login,
        created_at,
        updated_at,
        labels,
        draft,
        mergeable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_client_constructors() {
        let client = GitHubClient::new("acme", "api", "GITHUB_TOKEN");
        assert_eq!(client.owner, "acme");
        assert_eq!(client.repo, "api");
        assert_eq!(client.repo_url(), "https://api.github.com/repos/acme/api");
    }

    #[test]
    fn pr_file_detects_api_spec() {
        let file = GitHubPRFile {
            filename: "openapi.yaml".to_string(),
            status: "modified".to_string(),
            additions: 10,
            deletions: 2,
            changes: 12,
            patch: None,
            blob_url: String::new(),
            raw_url: String::new(),
        };
        assert!(file.is_api_spec());
        assert!(file.is_security_relevant());
        assert_eq!(file.change_category(), "api-spec");
    }

    #[test]
    fn pr_file_detects_auth_config() {
        let file = GitHubPRFile {
            filename: "config/security_policy.yaml".to_string(),
            status: "modified".to_string(),
            additions: 5,
            deletions: 3,
            changes: 8,
            patch: None,
            blob_url: String::new(),
            raw_url: String::new(),
        };
        assert!(file.is_auth_config());
        assert!(file.is_security_relevant());
        assert_eq!(file.change_category(), "auth-config");
    }

    #[test]
    fn pr_file_detects_middleware() {
        let file = GitHubPRFile {
            filename: "src/middleware/csrf.js".to_string(),
            status: "added".to_string(),
            additions: 20,
            deletions: 0,
            changes: 20,
            patch: None,
            blob_url: String::new(),
            raw_url: String::new(),
        };
        assert!(file.is_middleware());
        assert!(file.is_security_relevant());
        assert_eq!(file.change_category(), "middleware");
    }

    #[test]
    fn pr_file_detects_endpoint() {
        let file = GitHubPRFile {
            filename: "src/routes/orders.ts".to_string(),
            status: "modified".to_string(),
            additions: 15,
            deletions: 5,
            changes: 20,
            patch: None,
            blob_url: String::new(),
            raw_url: String::new(),
        };
        assert!(file.is_endpoint());
        assert!(file.is_security_relevant());
        assert_eq!(file.change_category(), "endpoint");
    }

    #[test]
    fn pr_file_ignores_non_security() {
        let file = GitHubPRFile {
            filename: "README.md".to_string(),
            status: "modified".to_string(),
            additions: 3,
            deletions: 1,
            changes: 4,
            patch: None,
            blob_url: String::new(),
            raw_url: String::new(),
        };
        assert!(!file.is_security_relevant());
        assert_eq!(file.change_category(), "other");
    }

    #[test]
    fn webhook_event_from_pull_request_payload() {
        let payload = serde_json::json!({
            "action": "opened",
            "pull_request": {
                "number": 42,
                "head": {"sha": "abc123", "ref": "feature/new-endpoint"},
                "base": {"sha": "def456", "ref": "main"}
            },
            "repository": {
                "owner": {"login": "acme"},
                "name": "api",
                "full_name": "acme/api"
            },
            "sender": {"login": "dev1"}
        });
        let event = GitHubWebhookEvent::from_payload("pull_request", &payload);
        assert!(event.is_pr_event());
        assert!(event.should_scan());
        assert_eq!(event.pr_number, Some(42));
        assert_eq!(event.action.as_deref(), Some("opened"));
        assert_eq!(event.head_sha.as_deref(), Some("abc123"));
        assert_eq!(event.head_branch.as_deref(), Some("feature/new-endpoint"));
        assert_eq!(event.base_branch.as_deref(), Some("main"));
        assert_eq!(event.repository_owner.as_deref(), Some("acme"));
        assert_eq!(event.repository_name.as_deref(), Some("api"));
        assert_eq!(event.sender_login.as_deref(), Some("dev1"));
    }

    #[test]
    fn webhook_event_closed_pr_should_not_scan() {
        let payload = serde_json::json!({
            "action": "closed",
            "pull_request": {"number": 10},
            "repository": {"full_name": "acme/api"}
        });
        let event = GitHubWebhookEvent::from_payload("pull_request", &payload);
        assert!(!event.should_scan());
    }

    #[test]
    fn webhook_event_non_pr_should_not_scan() {
        let payload = serde_json::json!({
            "ref": "refs/heads/main",
            "repository": {"full_name": "acme/api"}
        });
        let event = GitHubWebhookEvent::from_payload("push", &payload);
        assert!(!event.is_pr_event());
        assert!(!event.should_scan());
    }

    #[test]
    fn webhook_event_synchronize_should_scan() {
        let payload = serde_json::json!({
            "action": "synchronize",
            "pull_request": {"number": 5, "head": {"sha": "xyz"}, "base": {"sha": "abc"}},
            "repository": {"full_name": "acme/api"}
        });
        let event = GitHubWebhookEvent::from_payload("pull_request", &payload);
        assert!(event.should_scan());
    }

    #[test]
    fn analyze_pr_diff_detects_security_changes() {
        let files = vec![
            GitHubPRFile {
                filename: "openapi.yaml".to_string(),
                status: "modified".to_string(),
                additions: 10,
                deletions: 5,
                changes: 15,
                patch: Some("+  /api/admin:\n+    post:\n+      security:\n+        - bearerAuth: []".to_string()),
                blob_url: String::new(),
                raw_url: String::new(),
            },
            GitHubPRFile {
                filename: "src/middleware/auth.ts".to_string(),
                status: "modified".to_string(),
                additions: 8,
                deletions: 2,
                changes: 10,
                patch: Some("+  if (!req.user || !req.user.roles.includes('admin')) {\n+    return res.status(403).json({error: 'forbidden'})\n+  }".to_string()),
                blob_url: String::new(),
                raw_url: String::new(),
            },
            GitHubPRFile {
                filename: "README.md".to_string(),
                status: "modified".to_string(),
                additions: 2,
                deletions: 1,
                changes: 3,
                patch: None,
                blob_url: String::new(),
                raw_url: String::new(),
            },
        ];
        let analysis = analyze_pr_diff(&files, 99);
        assert_eq!(analysis.total_files, 3);
        assert_eq!(analysis.security_relevant_files.len(), 2);
        assert_eq!(analysis.endpoint_changes.len(), 1);
        assert_eq!(analysis.auth_changes.len(), 1);
        assert!(analysis.summary.contains("PR #99"));
        assert!(analysis.summary.contains("2 security-relevant"));
    }

    #[test]
    fn analyze_pr_diff_empty_returns_zero() {
        let analysis = analyze_pr_diff(&[], 1);
        assert_eq!(analysis.total_files, 0);
        assert_eq!(analysis.security_relevant_files.len(), 0);
        assert_eq!(analysis.endpoint_changes.len(), 0);
        assert_eq!(analysis.auth_changes.len(), 0);
    }

    #[test]
    fn pr_review_comment_renders_changes() {
        let diff = PRDiffAnalysis {
            pr_number: 42,
            total_files: 3,
            security_relevant_files: vec![],
            endpoint_changes: vec![EndpointChange {
                filename: "openapi.yaml".to_string(),
                kind: "api-spec".to_string(),
                path_hint: Some("/api/admin".to_string()),
                method_hint: Some("POST".to_string()),
                auth_changed: true,
            }],
            auth_changes: vec![AuthChange {
                filename: "src/middleware/auth.ts".to_string(),
                kind: "middleware".to_string(),
                description: "Added role check".to_string(),
            }],
            summary: "PR #42: 3 files changed".to_string(),
        };
        let revalidation = RevalidationPlan {
            pr_number: 42,
            affected_endpoints: vec!["/api/admin".to_string()],
            affected_findings: vec![RevalidationTarget {
                finding_id: "f-123".to_string(),
                endpoint: "POST /api/admin".to_string(),
                classification: "BOLA".to_string(),
                reason: "endpoint modified in this PR".to_string(),
            }],
            retest_commands: vec!["cargo run -- run-regression test.json".to_string()],
            summary: "1 finding needs revalidation".to_string(),
        };
        let comment = render_pr_review_comment(&diff, &revalidation);
        assert!(comment.contains("BALONCORE Security Review"));
        assert!(comment.contains("PR #42"));
        assert!(comment.contains("openapi.yaml"));
        assert!(comment.contains("/api/admin"));
        assert!(comment.contains("POST"));
        assert!(comment.contains("auth changed"));
        assert!(comment.contains("f-123"));
        assert!(comment.contains("BOLA"));
        assert!(comment.contains("Retest Commands"));
        assert!(comment.contains("cargo run"));
    }

    #[test]
    fn revalidation_plan_finds_affected_findings() {
        let diff = PRDiffAnalysis {
            pr_number: 1,
            total_files: 2,
            security_relevant_files: vec![SecurityRelevantFile {
                filename: "openapi.yaml".to_string(),
                status: "modified".to_string(),
                category: "api-spec".to_string(),
                additions: 5,
                deletions: 1,
            }],
            endpoint_changes: vec![EndpointChange {
                filename: "openapi.yaml".to_string(),
                kind: "api-spec".to_string(),
                path_hint: Some("/api/invoices/{id}".to_string()),
                method_hint: Some("GET".to_string()),
                auth_changed: false,
            }],
            auth_changes: vec![],
            summary: String::new(),
        };
        let findings = vec![
            crate::lifecycle::FindingRecord {
                finding_id: "f-bola".to_string(),
                scan_id: "scan-1".to_string(),
                fingerprint: "fp-1".to_string(),
                classification: "BOLA".to_string(),
                vulnerability_class: "bola".to_string(),
                endpoint: "GET /api/invoices/{id}".to_string(),
                object_id: "inv_2002".to_string(),
                owner_profile: "user_b".to_string(),
                tested_profile: "user_a".to_string(),
                severity: "high".to_string(),
                score: 80,
                state: crate::lifecycle::FindingState::Verified,
                first_seen_run: "run-1".to_string(),
                last_seen_run: "run-1".to_string(),
                first_seen_at: 1000,
                last_seen_at: 1000,
                seen_count: 1,
                latest_artifacts: String::new(),
                latest_evidence_dir: String::new(),
                transitions: vec![],
                defense_classifications: vec![],
            },
            crate::lifecycle::FindingRecord {
                finding_id: "f-rejected".to_string(),
                scan_id: "scan-1".to_string(),
                fingerprint: "fp-2".to_string(),
                classification: "BOLA".to_string(),
                vulnerability_class: "bola".to_string(),
                endpoint: "GET /api/users/{id}".to_string(),
                object_id: "user_1".to_string(),
                owner_profile: "user_b".to_string(),
                tested_profile: "user_a".to_string(),
                severity: "low".to_string(),
                score: 10,
                state: crate::lifecycle::FindingState::Rejected,
                first_seen_run: "run-1".to_string(),
                last_seen_run: "run-1".to_string(),
                first_seen_at: 1000,
                last_seen_at: 1000,
                seen_count: 1,
                latest_artifacts: String::new(),
                latest_evidence_dir: String::new(),
                transitions: vec![],
                defense_classifications: vec![],
            },
        ];
        let plan = build_revalidation_plan(42, &diff, &findings);
        assert_eq!(plan.pr_number, 42);
        assert_eq!(plan.affected_findings.len(), 1);
        assert_eq!(plan.affected_findings[0].finding_id, "f-bola");
        assert_eq!(plan.retest_commands.len(), 1);
    }

    #[test]
    fn webhook_parse_invalid_json_returns_error() {
        let result = parse_github_webhook("pull_request", "not json", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn github_client_with_custom_api_base() {
        let client = GitHubClient {
            owner: "acme".to_string(),
            repo: "api".to_string(),
            token_env: "GITHUB_TOKEN".to_string(),
            api_base: "https://github.acme.com/api/v3".to_string(),
        };
        assert_eq!(
            client.repo_url(),
            "https://github.acme.com/api/v3/repos/acme/api"
        );
    }

    #[test]
    fn extract_path_hint_from_patch() {
        let patch = "+  app.post('/api/admin/users', authenticate, (req, res) => {";
        let hint = extract_path_hint(patch);
        assert_eq!(hint, Some("/api/admin/users".to_string()));
    }

    #[test]
    fn extract_method_hint_from_patch() {
        let patch = "+  router.get('/api/orders', auth, listOrders);";
        let hint = extract_method_hint(patch);
        assert_eq!(hint, Some("GET".to_string()));
    }

    #[test]
    fn method_hint_detects_post() {
        let patch = "-  app.post(\"/api/health\"";
        let hint = extract_method_hint(patch);
        assert_eq!(hint, Some("POST".to_string()));
    }

    #[test]
    fn no_method_hint_for_non_http_code() {
        let patch = "  console.log('starting server')";
        let hint = extract_method_hint(patch);
        assert_eq!(hint, None);
    }
}
