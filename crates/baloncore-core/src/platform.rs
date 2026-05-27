use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub created_at_unix_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Workspace {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub environment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformUser {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub roles: Vec<RoleAssignment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleAssignment {
    pub organization_id: String,
    pub workspace_id: Option<String>,
    pub role: PlatformRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PlatformRole {
    Owner,
    Admin,
    Analyst,
    Viewer,
    Billing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PlatformPermission {
    ManageOrganization,
    ManageWorkspace,
    ManageUsers,
    ManageScope,
    RunScan,
    ViewFinding,
    ViewEvidence,
    ExportReport,
    ManageBilling,
    ViewMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Project {
    pub id: String,
    pub organization_id: String,
    pub workspace_id: String,
    pub name: String,
    pub target_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformScan {
    pub id: String,
    pub organization_id: String,
    pub workspace_id: String,
    pub project_id: String,
    pub scan_type: String,
    pub status: String,
    pub verified_findings: usize,
    pub started_at_unix_seconds: u64,
    pub finished_at_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformFinding {
    pub id: String,
    pub organization_id: String,
    pub workspace_id: String,
    pub project_id: String,
    pub scan_id: String,
    pub classification: String,
    pub severity: String,
    pub state: String,
    pub time_to_proof_seconds: Option<u64>,
    pub time_to_fix_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceBundleRef {
    pub id: String,
    pub organization_id: String,
    pub workspace_id: String,
    pub finding_id: String,
    pub path: String,
    /// Whether the on-disk bundle bytes were transformed by `obfuscate_evidence`.
    /// **This is XOR-with-constant-key obfuscation, NOT cryptographic encryption.**
    /// Anyone with the source code can recover plaintext. Do not rely on this for
    /// confidentiality against any threat model. Real encryption is NEEDS-HUMAN
    /// (real KMS or env-managed AES-GCM keys). See `docs/VERIFICATION/V0_GROUND_TRUTH.md` §6.3.
    pub obfuscated_at_rest: bool,
    pub signed: bool,
    pub trusted_signer: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: String,
    pub at_unix_seconds: u64,
    pub organization_id: String,
    pub workspace_id: Option<String>,
    pub actor_user_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BillingAccount {
    pub id: String,
    pub organization_id: String,
    pub plan: String,
    pub monthly_scan_limit: usize,
    pub monthly_validation_limit: usize,
    pub storage_limit_mb: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsageMetrics {
    pub organization_id: String,
    pub workspace_id: String,
    pub scans: usize,
    pub verified_findings: usize,
    pub evidence_bundles: usize,
    pub ci_blocked_criticals: usize,
    pub average_time_to_proof_seconds: Option<f64>,
    pub average_time_to_fix_seconds: Option<f64>,
    pub retest_success_rate: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PlatformState {
    pub version: u32,
    pub organizations: Vec<Organization>,
    pub workspaces: Vec<Workspace>,
    pub users: Vec<PlatformUser>,
    pub projects: Vec<Project>,
    pub scans: Vec<PlatformScan>,
    pub findings: Vec<PlatformFinding>,
    pub evidence_bundles: Vec<EvidenceBundleRef>,
    pub audit_events: Vec<AuditEvent>,
    pub billing_accounts: Vec<BillingAccount>,
}

impl PlatformRole {
    pub fn permissions(&self) -> Vec<PlatformPermission> {
        use PlatformPermission::*;
        match self {
            Self::Owner => vec![
                ManageOrganization,
                ManageWorkspace,
                ManageUsers,
                ManageScope,
                RunScan,
                ViewFinding,
                ViewEvidence,
                ExportReport,
                ManageBilling,
                ViewMetrics,
            ],
            Self::Admin => vec![
                ManageWorkspace,
                ManageUsers,
                ManageScope,
                RunScan,
                ViewFinding,
                ViewEvidence,
                ExportReport,
                ViewMetrics,
            ],
            Self::Analyst => vec![
                RunScan,
                ViewFinding,
                ViewEvidence,
                ExportReport,
                ViewMetrics,
            ],
            Self::Viewer => vec![ViewFinding, ViewEvidence, ViewMetrics],
            Self::Billing => vec![ManageBilling, ViewMetrics],
        }
    }
}

impl PlatformState {
    pub fn new() -> Self {
        Self {
            version: 1,
            ..Self::default()
        }
    }

    pub fn authorize_workspace(
        &self,
        user_id: &str,
        workspace_id: &str,
        permission: &PlatformPermission,
    ) -> bool {
        let Some(workspace) = self.workspaces.iter().find(|w| w.id == workspace_id) else {
            return false;
        };
        let Some(user) = self.users.iter().find(|u| u.id == user_id) else {
            return false;
        };
        user.roles.iter().any(|assignment| {
            assignment.organization_id == workspace.organization_id
                && assignment
                    .workspace_id
                    .as_ref()
                    .map_or(true, |assigned_workspace| {
                        assigned_workspace == workspace_id
                    })
                && assignment.role.permissions().contains(permission)
        })
    }

    pub fn can_access_evidence(&self, user_id: &str, evidence_bundle_id: &str) -> bool {
        let Some(bundle) = self
            .evidence_bundles
            .iter()
            .find(|bundle| bundle.id == evidence_bundle_id)
        else {
            return false;
        };
        self.authorize_workspace(
            user_id,
            &bundle.workspace_id,
            &PlatformPermission::ViewEvidence,
        )
    }

    pub fn record_audit_event(&mut self, event: AuditEvent) {
        self.audit_events.push(event);
        self.audit_events.sort_by(|a, b| {
            a.at_unix_seconds
                .cmp(&b.at_unix_seconds)
                .then_with(|| a.id.cmp(&b.id))
        });
    }

    pub fn usage_metrics(&self, workspace_id: &str) -> Option<UsageMetrics> {
        let workspace = self.workspaces.iter().find(|w| w.id == workspace_id)?;
        let scans: Vec<&PlatformScan> = self
            .scans
            .iter()
            .filter(|scan| scan.workspace_id == workspace_id)
            .collect();
        let findings: Vec<&PlatformFinding> = self
            .findings
            .iter()
            .filter(|finding| finding.workspace_id == workspace_id)
            .collect();
        let proof_times: Vec<u64> = findings
            .iter()
            .filter_map(|finding| finding.time_to_proof_seconds)
            .collect();
        let fix_times: Vec<u64> = findings
            .iter()
            .filter_map(|finding| finding.time_to_fix_seconds)
            .collect();
        let fixed = findings
            .iter()
            .filter(|finding| finding.state == "fixed" || finding.state == "closed")
            .count();
        let retested = findings
            .iter()
            .filter(|finding| {
                finding.state == "retested" || finding.state == "closed" || finding.state == "fixed"
            })
            .count();

        Some(UsageMetrics {
            organization_id: workspace.organization_id.clone(),
            workspace_id: workspace_id.to_string(),
            scans: scans.len(),
            verified_findings: findings
                .iter()
                .filter(|finding| {
                    finding.state == "verified"
                        || finding.state == "reported"
                        || finding.state == "fixed"
                        || finding.state == "retested"
                        || finding.state == "closed"
                })
                .count(),
            evidence_bundles: self
                .evidence_bundles
                .iter()
                .filter(|bundle| bundle.workspace_id == workspace_id)
                .count(),
            ci_blocked_criticals: findings
                .iter()
                .filter(|finding| {
                    finding.severity.eq_ignore_ascii_case("critical") && finding.state == "verified"
                })
                .count(),
            average_time_to_proof_seconds: average(&proof_times),
            average_time_to_fix_seconds: average(&fix_times),
            retest_success_rate: if retested == 0 {
                None
            } else {
                Some(fixed as f64 / retested as f64)
            },
        })
    }
}

fn average(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<u64>() as f64 / values.len() as f64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PlatformPlan {
    Free,
    Starter,
    Professional,
    Enterprise,
}

impl PlatformPlan {
    pub fn limits(&self) -> PlanLimits {
        match self {
            PlatformPlan::Free => PlanLimits {
                max_workspaces: 1,
                max_users_per_workspace: 3,
                max_scans_per_month: 10,
                max_endpoints_per_scan: 50,
                max_verified_findings: 25,
                max_storage_mb: 100,
                max_ci_gates_per_month: 20,
                sso_enabled: false,
                custom_compliance: false,
            },
            PlatformPlan::Starter => PlanLimits {
                max_workspaces: 3,
                max_users_per_workspace: 10,
                max_scans_per_month: 50,
                max_endpoints_per_scan: 500,
                max_verified_findings: 200,
                max_storage_mb: 1000,
                max_ci_gates_per_month: 100,
                sso_enabled: false,
                custom_compliance: false,
            },
            PlatformPlan::Professional => PlanLimits {
                max_workspaces: 20,
                max_users_per_workspace: 50,
                max_scans_per_month: 500,
                max_endpoints_per_scan: 5000,
                max_verified_findings: 5000,
                max_storage_mb: 10000,
                max_ci_gates_per_month: 0,
                sso_enabled: true,
                custom_compliance: true,
            },
            PlatformPlan::Enterprise => PlanLimits {
                max_workspaces: 0,
                max_users_per_workspace: 0,
                max_scans_per_month: 0,
                max_endpoints_per_scan: 0,
                max_verified_findings: 0,
                max_storage_mb: 0,
                max_ci_gates_per_month: 0,
                sso_enabled: true,
                custom_compliance: true,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanLimits {
    pub max_workspaces: u64,
    pub max_users_per_workspace: u64,
    pub max_scans_per_month: u64,
    pub max_endpoints_per_scan: u64,
    pub max_verified_findings: u64,
    pub max_storage_mb: u64,
    pub max_ci_gates_per_month: u64,
    pub sso_enabled: bool,
    pub custom_compliance: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OnboardingStep {
    CreateOrg,
    ConfigureScope,
    AddAuthProfile,
    RunLabScan,
    ExportReport,
}

impl OnboardingStep {
    pub fn all() -> Vec<OnboardingStep> {
        vec![
            OnboardingStep::CreateOrg,
            OnboardingStep::ConfigureScope,
            OnboardingStep::AddAuthProfile,
            OnboardingStep::RunLabScan,
            OnboardingStep::ExportReport,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardingTracker {
    pub org_id: String,
    pub step: OnboardingStep,
    pub completed_steps: Vec<OnboardingStep>,
    pub created_at: u64,
    pub completed_at: Option<u64>,
}

impl OnboardingTracker {
    pub fn start(org_id: &str, now: u64) -> Self {
        Self {
            org_id: org_id.to_string(),
            step: OnboardingStep::CreateOrg,
            completed_steps: vec![],
            created_at: now,
            completed_at: None,
        }
    }

    pub fn complete_step(&mut self, step: OnboardingStep) {
        if !self.completed_steps.contains(&step) {
            self.completed_steps.push(step.clone());
        }
        self.step = step;
        if self.completed_steps.len() >= OnboardingStep::all().len() {
            self.completed_at = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
        }
    }

    pub fn is_complete(&self) -> bool {
        self.completed_at.is_some()
    }
}

/// **OBFUSCATION (XOR) PARAMETERS — NOT CRYPTOGRAPHIC.**
///
/// The fields below describe `obfuscate_evidence`, which XORs each input byte
/// with a constant-string-derived key/nonce. This is reversible by anyone with
/// the source code. Do not treat the `algorithm` field as a security claim.
///
/// Real evidence encryption is currently NEEDS-HUMAN: a real KMS provider or
/// env-managed AES-GCM key must be wired before any production confidentiality
/// claim can be made.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObfuscationConfig {
    /// Human-readable algorithm tag. MUST be the literal string
    /// `"xor-with-constant-key (NOT CRYPTOGRAPHIC)"` or another non-misleading
    /// value. Never set to a real cipher name like "AES-256-GCM" unless the
    /// underlying implementation is actually that cipher.
    pub algorithm: String,
    pub key_id: String,
    pub key_derivation: String,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            algorithm: "xor-with-constant-key (NOT CRYPTOGRAPHIC)".to_string(),
            key_id: "default".to_string(),
            key_derivation: "constant-string-xor".to_string(),
        }
    }
}

/// **OBFUSCATION, NOT ENCRYPTION.** XORs each input byte with a key/nonce
/// derived deterministically from a constant string and `config.key_id`.
/// Reversible by anyone with this source. Provides ZERO confidentiality.
///
/// Kept only so on-disk bytes do not display as obvious plaintext during
/// local-dev demos. The corresponding `deobfuscate_evidence` is the same
/// function (XOR is involutive).
///
/// Real encryption is NEEDS-HUMAN — see `docs/VERIFICATION/V0_GROUND_TRUTH.md`
/// §6.3 and the corresponding entry in `PROGRESS.md`.
pub fn obfuscate_evidence(data: &[u8], config: &ObfuscationConfig) -> Vec<u8> {
    let key_material = format!("baloncore-evidence-v1-key-{}", config.key_id);
    let mut key = [0u8; 32];
    let key_bytes = key_material.as_bytes();
    for (i, k) in key.iter_mut().enumerate() {
        *k = key_bytes[i % key_bytes.len()];
    }
    let nonce_material = format!("baloncore-evidence-v1-nonce-{}", config.key_id);
    let mut nonce = [0u8; 12];
    let nonce_bytes = nonce_material.as_bytes();
    for (i, n) in nonce.iter_mut().enumerate() {
        *n = nonce_bytes[i % nonce_bytes.len()];
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % 32] ^ nonce[i % 12])
        .collect()
}

/// Inverse of `obfuscate_evidence`. Provides ZERO confidentiality — see that
/// function's doc comment.
pub fn deobfuscate_evidence(obfuscated: &[u8], config: &ObfuscationConfig) -> Vec<u8> {
    obfuscate_evidence(obfuscated, config)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKey {
    pub id: String,
    pub organization_id: String,
    pub workspace_id: String,
    pub name: String,
    pub hashed_secret: String,
    pub prefix: String,
    pub role: PlatformRole,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub last_used_at: Option<u64>,
}

impl PlatformState {
    pub fn create_api_key(
        &mut self,
        org_id: &str,
        workspace_id: &str,
        name: &str,
        role: PlatformRole,
        now: u64,
    ) -> ApiKey {
        let id = format!(
            "bco_{}",
            stable_platform_id("key", &format!("{}-{}", org_id, name))
        );
        let secret = format!("bco_sec_{}_{}", org_id, now);
        let hashed = format!("{:x}", simple_hash(&secret));
        let prefix = format!("{}...", &hashed[..8.min(hashed.len())]);
        let api_key = ApiKey {
            id,
            organization_id: org_id.to_string(),
            workspace_id: workspace_id.to_string(),
            name: name.to_string(),
            hashed_secret: hashed,
            prefix,
            role,
            created_at: now,
            expires_at: None,
            last_used_at: None,
        };
        self.record_audit_event(AuditEvent {
            id: stable_platform_id("audit", &format!("apikey-{}-{}", org_id, now)),
            at_unix_seconds: now,
            organization_id: org_id.to_string(),
            workspace_id: Some(workspace_id.to_string()),
            actor_user_id: "system".to_string(),
            action: "api_key_created".to_string(),
            resource_type: "api_key".to_string(),
            resource_id: name.to_string(),
            outcome: "success".to_string(),
        });
        api_key
    }

    pub fn suspend_user(&mut self, user_id: &str) -> Result<(), String> {
        let user = self
            .users
            .iter_mut()
            .find(|u| u.id == user_id)
            .ok_or("User not found")?;
        user.roles.clear();
        Ok(())
    }

    pub fn add_workspace(&mut self, org_id: &str, name: &str, environment: &str) -> Workspace {
        let ws_id = stable_platform_id("ws", name);
        let ws = Workspace {
            id: ws_id.clone(),
            organization_id: org_id.to_string(),
            name: name.to_string(),
            environment: environment.to_string(),
        };
        self.workspaces.push(ws.clone());
        ws
    }

    pub fn add_user_to_workspace(
        &mut self,
        user_id: &str,
        org_id: &str,
        workspace_id: &str,
        role: PlatformRole,
    ) -> Result<(), String> {
        let user = self
            .users
            .iter_mut()
            .find(|u| u.id == user_id)
            .ok_or("User not found")?;
        user.roles.push(RoleAssignment {
            organization_id: org_id.to_string(),
            workspace_id: Some(workspace_id.to_string()),
            role,
        });
        Ok(())
    }

    pub fn add_platform_user(
        &mut self,
        email: &str,
        display_name: &str,
        org_id: &str,
        role: PlatformRole,
    ) -> PlatformUser {
        let user_id = stable_platform_id("user", email);
        let user = PlatformUser {
            id: user_id.clone(),
            email: email.to_string(),
            display_name: display_name.to_string(),
            roles: vec![RoleAssignment {
                organization_id: org_id.to_string(),
                workspace_id: None,
                role,
            }],
        };
        self.users.push(user.clone());
        user
    }

    pub fn investor_metrics(&self) -> InvestorMetrics {
        let total_verified = self
            .findings
            .iter()
            .filter(|f| {
                matches!(
                    f.state.as_str(),
                    "verified" | "reported" | "fixed" | "retested" | "closed"
                )
            })
            .count();
        let total_hypotheses = self
            .findings
            .iter()
            .filter(|f| f.state == "hypothesis")
            .count();
        let total_rejected = self
            .findings
            .iter()
            .filter(|f| f.state == "rejected")
            .count();
        let total_fixed = self.findings.iter().filter(|f| f.state == "fixed").count();
        let total_scans = self.scans.len();
        let verified_per_scan = if total_scans > 0 {
            total_verified as f64 / total_scans as f64
        } else {
            0.0
        };
        let total_hypothesized = total_verified + total_hypotheses + total_rejected;
        let false_positive_reduction = if total_hypothesized > 0 {
            1.0 - (total_hypotheses as f64 / total_hypothesized as f64)
        } else {
            1.0
        };
        let proof_times: Vec<u64> = self
            .findings
            .iter()
            .filter_map(|f| f.time_to_proof_seconds)
            .collect();
        let avg_time_to_proof = average(&proof_times);
        let fix_times: Vec<u64> = self
            .findings
            .iter()
            .filter_map(|f| f.time_to_fix_seconds)
            .collect();
        let avg_time_to_fix = average(&fix_times);
        let retested_or_closed = self
            .findings
            .iter()
            .filter(|f| f.state == "retested" || f.state == "closed")
            .count();
        let retest_success = if total_fixed > 0 {
            retested_or_closed as f64 / total_fixed as f64
        } else {
            0.0
        };
        InvestorMetrics {
            verified_findings_per_scan: verified_per_scan,
            false_positive_reduction_rate: false_positive_reduction,
            avg_time_to_proof_hours: avg_time_to_proof.map(|s| s / 3600.0).unwrap_or(0.0),
            avg_time_to_fix_hours: avg_time_to_fix.map(|s| s / 3600.0),
            retest_success_rate: retest_success,
            ci_blocked_criticals: self
                .findings
                .iter()
                .filter(|f| f.severity.eq_ignore_ascii_case("critical") && f.state == "verified")
                .count(),
            total_scans: total_scans as u64,
            total_verified_findings: total_verified as u64,
            total_hypotheses: total_hypotheses as u64,
            total_rejected: total_rejected as u64,
            total_fixed: total_fixed as u64,
            total_retested_closed: (total_fixed + retested_or_closed) as u64,
            scans_last_30_days: total_scans as u64,
            active_organizations: self.organizations.len() as u64,
            active_workspaces: self.workspaces.len() as u64,
            active_users: self.users.len() as u64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InvestorMetrics {
    pub verified_findings_per_scan: f64,
    pub false_positive_reduction_rate: f64,
    pub avg_time_to_proof_hours: f64,
    pub avg_time_to_fix_hours: Option<f64>,
    pub retest_success_rate: f64,
    pub ci_blocked_criticals: usize,
    pub total_scans: u64,
    pub total_verified_findings: u64,
    pub total_hypotheses: u64,
    pub total_rejected: u64,
    pub total_fixed: u64,
    pub total_retested_closed: u64,
    pub scans_last_30_days: u64,
    pub active_organizations: u64,
    pub active_workspaces: u64,
    pub active_users: u64,
}

fn simple_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub struct ComplianceMapping;

impl ComplianceMapping {
    pub fn for_classification(classification: &str) -> Vec<ComplianceControl> {
        let lower = classification.to_ascii_lowercase().replace(' ', "_");
        match lower.as_str() {
            "idor" | "broken_object_level_authorization" | "bola" => vec![
                ComplianceControl { framework: "OWASP API Top 10".to_string(), control_id: "API1".to_string(), control_name: "Broken Object Level Authorization".to_string(), description: "API endpoints expose object-level access without proper authorization checks".to_string(), evidence_guidance: "Show verified IDOR finding with request/response evidence demonstrating unauthorized access".to_string() },
                ComplianceControl { framework: "SOC 2".to_string(), control_id: "CC6.1".to_string(), control_name: "Logical Access Security".to_string(), description: "Entity implements logical access security over information assets".to_string(), evidence_guidance: "Verified authorization bypass finding serves as evidence of access control deficiency".to_string() },
            ],
            "broken_function_level_authorization" | "bfla" => vec![
                ComplianceControl { framework: "OWASP API Top 10".to_string(), control_id: "API5".to_string(), control_name: "Broken Function Level Authorization".to_string(), description: "API endpoints expose administrative functions to unauthorized users".to_string(), evidence_guidance: "Demonstrate verified BFLA finding showing privilege escalation via function access".to_string() },
            ],
            "xss" => vec![
                ComplianceControl { framework: "OWASP API Top 10".to_string(), control_id: "API8".to_string(), control_name: "Security Misconfiguration".to_string(), description: "API fails to properly sanitize input, allowing script injection".to_string(), evidence_guidance: "Show XSS payload execution evidence with affected endpoint and response".to_string() },
                ComplianceControl { framework: "SOC 2".to_string(), control_id: "CC6.7".to_string(), control_name: "Data Input Controls".to_string(), description: "Entity implements controls to prevent unauthorized access to data".to_string(), evidence_guidance: "XSS finding demonstrates input validation failure".to_string() },
            ],
            "ssrf" => vec![
                ComplianceControl { framework: "OWASP API Top 10".to_string(), control_id: "API7".to_string(), control_name: "Server Side Request Forgery".to_string(), description: "API allows requests to internal resources through user-controlled URLs".to_string(), evidence_guidance: "Show SSRF evidence with internal resource access demonstrated".to_string() },
                ComplianceControl { framework: "AWS Well-Architected".to_string(), control_id: "SEC10".to_string(), control_name: "Network Request Validation".to_string(), description: "Validate and restrict outbound network requests from application layer".to_string(), evidence_guidance: "SSRF finding demonstrates ability to bypass network boundaries via API".to_string() },
            ],
            "reentrancy" => vec![
                ComplianceControl { framework: "Web3 Audit".to_string(), control_id: "SWC107".to_string(), control_name: "Reentrancy".to_string(), description: "Smart contract allows external calls to reenter before state updates complete".to_string(), evidence_guidance: "Show reentrancy evidence with exploit proof test demonstrating fund drainage".to_string() },
            ],
            "cloud_iam" => vec![
                ComplianceControl { framework: "AWS Well-Architected".to_string(), control_id: "SEC1".to_string(), control_name: "IAM Least Privilege".to_string(), description: "IAM policies should grant least privilege access".to_string(), evidence_guidance: "Show privilege path evidence from public principal to sensitive resource".to_string() },
                ComplianceControl { framework: "SOC 2".to_string(), control_id: "CC6.1".to_string(), control_name: "Logical Access Security".to_string(), description: "Cloud IAM policies properly restrict access".to_string(), evidence_guidance: "Cloud finding demonstrates over-permissive IAM path".to_string() },
            ],
            "tenant_isolation" => vec![
                ComplianceControl { framework: "SOC 2".to_string(), control_id: "CC6.3".to_string(), control_name: "Data Isolation".to_string(), description: "Multi-tenant data is properly isolated between customers".to_string(), evidence_guidance: "Tenant isolation finding demonstrates cross-tenant data access".to_string() },
                ComplianceControl { framework: "OWASP API Top 10".to_string(), control_id: "API1".to_string(), control_name: "Broken Object Level Authorization".to_string(), description: "Tenant boundaries are not enforced at the API layer".to_string(), evidence_guidance: "Show verified IDOR finding across tenant boundary".to_string() },
            ],
            _ => vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceControl {
    pub framework: String,
    pub control_id: String,
    pub control_name: String,
    pub description: String,
    pub evidence_guidance: String,
}

pub fn bootstrap_platform_state(
    organization_name: &str,
    workspace_name: &str,
    owner_email: &str,
    now: u64,
) -> PlatformState {
    let org_id = stable_platform_id("org", organization_name);
    let workspace_id = stable_platform_id("ws", workspace_name);
    let owner_id = stable_platform_id("user", owner_email);
    let project_id = stable_platform_id("project", workspace_name);
    let mut state = PlatformState::new();
    state.organizations.push(Organization {
        id: org_id.clone(),
        name: organization_name.to_string(),
        created_at_unix_seconds: now,
    });
    state.workspaces.push(Workspace {
        id: workspace_id.clone(),
        organization_id: org_id.clone(),
        name: workspace_name.to_string(),
        environment: "production-like".to_string(),
    });
    state.users.push(PlatformUser {
        id: owner_id.clone(),
        email: owner_email.to_string(),
        display_name: owner_email.split('@').next().unwrap_or("owner").to_string(),
        roles: vec![RoleAssignment {
            organization_id: org_id.clone(),
            workspace_id: None,
            role: PlatformRole::Owner,
        }],
    });
    state.projects.push(Project {
        id: project_id.clone(),
        organization_id: org_id.clone(),
        workspace_id: workspace_id.clone(),
        name: format!("{workspace_name} API"),
        target_kind: "web-api".to_string(),
    });
    state.billing_accounts.push(BillingAccount {
        id: stable_platform_id("billing", organization_name),
        organization_id: org_id.clone(),
        plan: "founder".to_string(),
        monthly_scan_limit: 100,
        monthly_validation_limit: 25_000,
        storage_limit_mb: 10_240,
    });
    state.record_audit_event(AuditEvent {
        id: stable_platform_id("audit", &format!("{org_id}-{now}")),
        at_unix_seconds: now,
        organization_id: org_id,
        workspace_id: Some(workspace_id),
        actor_user_id: owner_id,
        action: "platform_bootstrap".to_string(),
        resource_type: "organization".to_string(),
        resource_id: organization_name.to_string(),
        outcome: "success".to_string(),
    });
    state
}

pub fn render_platform_onboarding(state: &PlatformState) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Platform Onboarding\n\n");
    for org in &state.organizations {
        md.push_str(&format!("## {}\n\n", org.name));
        md.push_str("1. Confirm organization owner and SSO identity source.\n");
        md.push_str("2. Create workspaces for production, staging, cloud, and Web3 programs.\n");
        md.push_str("3. Configure authorized scopes and auth profiles per workspace.\n");
        md.push_str("4. Run the local lab scan, then a scoped customer scan.\n");
        md.push_str("5. Export evidence report, CI summary, defense bundle, and audit log.\n\n");
    }
    md
}

pub fn render_platform_audit_log(state: &PlatformState) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Audit Log\n\n");
    for event in &state.audit_events {
        md.push_str(&format!(
            "- `{}` `{}` by `{}` on `{}` `{}`: `{}`\n",
            event.at_unix_seconds,
            event.action,
            event.actor_user_id,
            event.resource_type,
            event.resource_id,
            event.outcome
        ));
    }
    md
}

pub fn compliance_mapping() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "OWASP API Top 10",
            "BOLA, BFLA, missing authentication, evidence-backed remediation",
        ),
        (
            "SOC 2 Security",
            "audit events, access control, evidence integrity, change validation",
        ),
        (
            "CIS Cloud Benchmarks",
            "public exposure, least privilege, risky trust paths",
        ),
        (
            "Web3 Audit Categories",
            "access control, accounting invariants, reentrancy, oracle risk",
        ),
    ]
}

fn stable_platform_id(prefix: &str, value: &str) -> String {
    let slug = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    format!("{prefix}-{slug}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_can_access_workspace_evidence() {
        let mut state = bootstrap_platform_state("Acme", "Prod", "owner@example.test", 10);
        let org_id = state.organizations[0].id.clone();
        let workspace_id = state.workspaces[0].id.clone();
        state.evidence_bundles.push(EvidenceBundleRef {
            id: "bundle-1".to_string(),
            organization_id: org_id,
            workspace_id,
            finding_id: "finding-1".to_string(),
            path: ".baloncore/evidence/bundle".to_string(),
            obfuscated_at_rest: true,
            signed: true,
            trusted_signer: true,
        });
        assert!(state.can_access_evidence("user-owner-example-test", "bundle-1"));
        assert!(state.authorize_workspace(
            "user-owner-example-test",
            "ws-prod",
            &PlatformPermission::ExportReport
        ));
    }

    #[test]
    fn workspace_rbac_blocks_cross_workspace_evidence() {
        let mut state = bootstrap_platform_state("Acme", "Prod", "owner@example.test", 10);
        let org_id = state.organizations[0].id.clone();
        state.workspaces.push(Workspace {
            id: "ws-dev".to_string(),
            organization_id: org_id.clone(),
            name: "Dev".to_string(),
            environment: "development".to_string(),
        });
        state.users.push(PlatformUser {
            id: "user-analyst".to_string(),
            email: "analyst@example.test".to_string(),
            display_name: "analyst".to_string(),
            roles: vec![RoleAssignment {
                organization_id: org_id.clone(),
                workspace_id: Some("ws-dev".to_string()),
                role: PlatformRole::Analyst,
            }],
        });
        state.evidence_bundles.push(EvidenceBundleRef {
            id: "prod-bundle".to_string(),
            organization_id: org_id,
            workspace_id: "ws-prod".to_string(),
            finding_id: "finding-1".to_string(),
            path: ".baloncore/evidence/prod".to_string(),
            obfuscated_at_rest: true,
            signed: true,
            trusted_signer: true,
        });
        assert!(!state.can_access_evidence("user-analyst", "prod-bundle"));
    }

    #[test]
    fn usage_metrics_compute_time_and_counts() {
        let mut state = bootstrap_platform_state("Acme", "Prod", "owner@example.test", 10);
        let org_id = state.organizations[0].id.clone();
        let workspace_id = state.workspaces[0].id.clone();
        let project_id = state.projects[0].id.clone();
        state.scans.push(PlatformScan {
            id: "scan-1".to_string(),
            organization_id: org_id.clone(),
            workspace_id: workspace_id.clone(),
            project_id: project_id.clone(),
            scan_type: "web-api".to_string(),
            status: "complete".to_string(),
            verified_findings: 1,
            started_at_unix_seconds: 10,
            finished_at_unix_seconds: Some(20),
        });
        state.findings.push(PlatformFinding {
            id: "finding-1".to_string(),
            organization_id: org_id,
            workspace_id: workspace_id.clone(),
            project_id,
            scan_id: "scan-1".to_string(),
            classification: "BrokenObjectLevelAuthorization".to_string(),
            severity: "high".to_string(),
            state: "fixed".to_string(),
            time_to_proof_seconds: Some(30),
            time_to_fix_seconds: Some(120),
        });
        let metrics = state.usage_metrics(&workspace_id).unwrap();
        assert_eq!(metrics.scans, 1);
        assert_eq!(metrics.verified_findings, 1);
        assert_eq!(metrics.average_time_to_proof_seconds, Some(30.0));
        assert_eq!(metrics.retest_success_rate, Some(1.0));
    }

    // --- T0.c regression test --------------------------------------------------------
    //
    // V0_GROUND_TRUTH.md §6.3 flagged that `EncryptionConfig.algorithm = "AES-256-GCM"`
    // was decorative on top of an XOR obfuscator. This guard prevents the misleading
    // label from being reintroduced.
    #[test]
    fn obfuscation_config_default_does_not_claim_a_real_cipher() {
        let cfg = ObfuscationConfig::default();
        let banned = [
            "AES", "aes", "GCM", "gcm", "CHACHA", "ChaCha", "ChaCha20", "chacha",
            "RSA", "rsa", "Curve25519", "curve25519",
        ];
        for b in banned {
            assert!(
                !cfg.algorithm.contains(b),
                "ObfuscationConfig.default().algorithm must not contain real cipher \
                 names; obfuscate_evidence is XOR-with-constant-key and provides ZERO \
                 confidentiality. Got: `{}` (banned substring `{}`)",
                cfg.algorithm,
                b
            );
        }
        assert!(
            cfg.algorithm.contains("NOT CRYPTOGRAPHIC")
                || cfg.algorithm.contains("not cryptographic"),
            "ObfuscationConfig.default().algorithm must spell out it is not cryptographic, got: `{}`",
            cfg.algorithm
        );
    }

    #[test]
    fn obfuscate_evidence_is_only_obfuscation_not_secure_encryption() {
        // Sanity contract: the function is self-inverse and the output bytes are
        // recovered without a secret — pinning that we never accidentally treat it
        // as real encryption.
        let cfg = ObfuscationConfig::default();
        let plaintext = b"secret bearer token=sk-abc123";
        let obf = obfuscate_evidence(plaintext, &cfg);
        let recovered = deobfuscate_evidence(&obf, &cfg);
        assert_eq!(
            recovered.as_slice(),
            plaintext,
            "deobfuscate_evidence must invert obfuscate_evidence (XOR is involutive)"
        );
        // The mere fact that the same default config recovers plaintext proves
        // there is no secret key — anyone with the source can decrypt.
    }
}
