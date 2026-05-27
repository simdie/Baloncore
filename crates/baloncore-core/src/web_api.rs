use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use thiserror::Error;

use crate::config::OAuth2GrantType;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiEndpoint {
    pub id: String,
    pub method: HttpMethod,
    pub url_template: String,
    pub source: EndpointSource,
    pub requires_auth: Option<bool>,
    #[serde(default)]
    pub path_parameters: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Head,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Head => "HEAD",
        }
    }

    fn from_openapi_method(method: &str) -> Option<Self> {
        match method {
            "get" => Some(Self::Get),
            "post" => Some(Self::Post),
            "put" => Some(Self::Put),
            "patch" => Some(Self::Patch),
            "delete" => Some(Self::Delete),
            "options" => Some(Self::Options),
            "head" => Some(Self::Head),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EndpointSource {
    Crawl,
    OpenApi,
    GraphQl,
    Postman,
    Wsdl,
    GrpcReflection,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpExchange {
    pub id: String,
    pub profile: String,
    pub method: HttpMethod,
    pub url: String,
    pub status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body_excerpt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpRequestSpec {
    pub id: String,
    pub profile: String,
    pub method: HttpMethod,
    pub url: String,
    pub bearer_token: Option<String>,
    #[serde(default)]
    pub cookies: Vec<(String, String)>,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub csrf_token_header: Option<String>,
    #[serde(default)]
    pub csrf_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthScheme {
    None,
    Bearer,
    ApiKey,
    CookieSession,
    OAuth2,
}

#[derive(Debug, Clone)]
pub struct ResolvedCredential {
    pub scheme: AuthScheme,
    pub bearer_token: Option<String>,
    pub api_key_header: Option<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub csrf_token_header: Option<String>,
    pub csrf_token: Option<String>,
    pub extra_headers: Vec<(String, String)>,
    pub extra_cookies: Vec<(String, String)>,
    pub reproduction_hint: String,
}

#[derive(Debug, Error)]
pub enum HttpRunnerError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("HTTP method `{0:?}` is not supported by the blocking runner yet")]
    UnsupportedMethod(HttpMethod),
}

#[derive(Debug, Clone)]
pub struct HttpRequestRunner {
    client: reqwest::blocking::Client,
    max_body_excerpt: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenApiInventory {
    pub source_url: String,
    pub endpoints: Vec<ApiEndpoint>,
    pub seed_candidates: Vec<SeedEndpointCandidate>,
    pub bola_candidates: Vec<BolaCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphQlFieldType {
    pub name: String,
    pub kind: String,
    pub of_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphQlField {
    pub name: String,
    pub return_type: GraphQlFieldType,
    pub args: Vec<GraphQlArg>,
    pub description: Option<String>,
    pub is_deprecated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphQlArg {
    pub name: String,
    pub arg_type: GraphQlFieldType,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphQlType {
    pub name: String,
    pub kind: String,
    pub fields: Vec<GraphQlField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphQlOperation {
    pub operation_type: GraphQlOperationType,
    pub name: String,
    pub return_type: GraphQlFieldType,
    pub args: Vec<GraphQlArg>,
    pub description: Option<String>,
    pub is_deprecated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GraphQlOperationType {
    Query,
    Mutation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphQlInventory {
    pub source_url: String,
    pub schema_types: Vec<GraphQlType>,
    pub queries: Vec<GraphQlOperation>,
    pub mutations: Vec<GraphQlOperation>,
    pub endpoints: Vec<ApiEndpoint>,
    pub bola_candidates: Vec<GraphQlBolaCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphQlBolaCandidate {
    pub endpoint: ApiEndpoint,
    pub operation_type: GraphQlOperationType,
    pub operation_name: String,
    pub id_argument: String,
    pub return_type_name: String,
    pub confidence: f32,
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphQlBolaValidationCase {
    pub endpoint: ApiEndpoint,
    pub operation_name: String,
    pub operation_type: GraphQlOperationType,
    pub id_argument: String,
    pub object_id: String,
    pub owner_profile: String,
    pub attacker_profile: String,
    pub owner_markers: Vec<String>,
    pub owner_exchange: HttpExchange,
    pub attacker_exchange: HttpExchange,
    pub anonymous_exchange: Option<HttpExchange>,
    pub tested_tenant: Option<String>,
    pub owner_tenant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GraphQlBolaDecision {
    Verified(GraphQlVerifiedFinding),
    Rejected(RejectedHypothesis),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphQlVerifiedFinding {
    pub title: String,
    pub endpoint_id: String,
    pub operation_name: String,
    pub object_id: String,
    pub owner_profile: String,
    pub attacker_profile: String,
    pub evidence_exchange_ids: Vec<String>,
    pub evidence_markers: Vec<String>,
    pub body_similarity: f32,
    pub security_property: String,
}

#[derive(Debug, Error)]
pub enum GraphQlInventoryError {
    #[error("GraphQL introspection response is not valid JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("GraphQL introspection response has no __schema field")]
    MissingSchema,
    #[error("GraphQL introspection query returned errors: {0}")]
    IntrospectionErrors(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BolaCandidate {
    pub endpoint: ApiEndpoint,
    pub path_parameter: String,
    pub confidence: f32,
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SeedEndpointCandidate {
    pub endpoint: ApiEndpoint,
    pub confidence: f32,
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectSeed {
    pub object_id: String,
    pub owner_profile: String,
    pub source_endpoint_id: String,
    pub source_url: String,
    pub owner_markers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceFingerprint {
    pub key: String,
    pub segments: Vec<String>,
    pub privileged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedCandidateMatch {
    pub matches: bool,
    pub reason: String,
    pub seed_resource: Option<ResourceFingerprint>,
    pub candidate_resource: ResourceFingerprint,
}

#[derive(Debug, Error)]
pub enum ObjectSeedError {
    #[error("seed response body is not valid JSON: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationMatrixObservation {
    pub tested_profile: String,
    pub tested_role: String,
    pub classification: AuthorizationClass,
    pub reason: String,
    pub owner_status: u16,
    pub tested_status: u16,
    pub anonymous_status: Option<u16>,
    pub evidence_markers: Vec<String>,
    pub body_similarity: f32,
    #[serde(default)]
    pub tested_tenant: Option<String>,
    #[serde(default)]
    pub owner_tenant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseImpactAnalysis {
    pub severity: ImpactSeverity,
    pub score: u8,
    pub shape_similarity: f32,
    pub owner_shape: ResponseShape,
    pub tested_shape: ResponseShape,
    pub sensitive_fields: Vec<SensitiveFieldFinding>,
    pub impact_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationPlan {
    pub classification: AuthorizationClass,
    pub severity: ImpactSeverity,
    pub endpoint_id: String,
    pub object_id: String,
    pub summary: String,
    pub implementation_steps: Vec<String>,
    pub regression_checks: Vec<RegressionCheck>,
    pub verification_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegressionCheck {
    pub name: String,
    pub profile: String,
    pub method: HttpMethod,
    pub url: String,
    pub auth_header: Option<String>,
    pub expected_statuses: Vec<u16>,
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegressionRunReport {
    pub remediation_endpoint: String,
    pub object_id: String,
    pub verdict: RegressionVerdict,
    pub total_checks: usize,
    pub passed_checks: usize,
    pub failed_checks: usize,
    pub results: Vec<RegressionCheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegressionCheckResult {
    pub name: String,
    pub profile: String,
    pub url: String,
    pub expected_statuses: Vec<u16>,
    pub actual_status: u16,
    pub passed: bool,
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegressionVerdict {
    Fixed,
    StillFailing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImpactSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl ImpactSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseShape {
    pub root_type: String,
    pub field_count: usize,
    pub field_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SensitiveFieldFinding {
    pub path: String,
    pub category: SensitiveDataCategory,
    pub value_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SensitiveDataCategory {
    PersonalIdentifier,
    EmailAddress,
    Financial,
    CredentialOrSecret,
    PrivilegedBusinessData,
    TenantOrOwnership,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthorizationClass {
    IntendedOwnerAccess,
    IntendedPrivilegedAccess,
    BlockedAsExpected,
    BrokenObjectLevelAuthorization,
    BrokenFunctionLevelAuthorization,
    MissingAuthentication,
    TenantIsolationViolation,
    OwnerBaselineFailed,
}

impl AuthorizationClass {
    pub fn is_finding(&self) -> bool {
        matches!(
            self,
            Self::BrokenObjectLevelAuthorization
                | Self::BrokenFunctionLevelAuthorization
                | Self::MissingAuthentication
                | Self::TenantIsolationViolation
        )
    }

    pub fn score(&self) -> u8 {
        match self {
            Self::BrokenObjectLevelAuthorization => 58,
            Self::BrokenFunctionLevelAuthorization => 68,
            Self::MissingAuthentication => 72,
            Self::TenantIsolationViolation => 62,
            Self::OwnerBaselineFailed => 0,
            Self::IntendedOwnerAccess => 0,
            Self::IntendedPrivilegedAccess => 0,
            Self::BlockedAsExpected => 0,
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::IntendedOwnerAccess => "Intended owner access",
            Self::IntendedPrivilegedAccess => "Intended privileged access",
            Self::BlockedAsExpected => "Blocked as expected",
            Self::BrokenObjectLevelAuthorization => "Broken object-level authorization",
            Self::BrokenFunctionLevelAuthorization => "Broken function-level authorization",
            Self::MissingAuthentication => "Missing authentication",
            Self::TenantIsolationViolation => "Tenant isolation violation",
            Self::OwnerBaselineFailed => "Owner baseline failed",
        }
    }

    pub fn vulnerability_class(&self) -> &'static str {
        match self {
            Self::BrokenObjectLevelAuthorization => "broken_object_level_authorization",
            Self::BrokenFunctionLevelAuthorization => "broken_function_level_authorization",
            Self::MissingAuthentication => "missing_authentication",
            Self::TenantIsolationViolation => "tenant_isolation_violation",
            Self::OwnerBaselineFailed => "owner_baseline_failed",
            Self::IntendedOwnerAccess => "intended_owner_access",
            Self::IntendedPrivilegedAccess => "intended_privileged_access",
            Self::BlockedAsExpected => "blocked_as_expected",
        }
    }

    pub fn security_property(&self) -> &'static str {
        match self {
            Self::BrokenObjectLevelAuthorization => {
                "A principal must not access an object owned by a different principal without explicit authorization."
            }
            Self::BrokenFunctionLevelAuthorization => {
                "A low-privilege principal must not access privileged function-level resources."
            }
            Self::MissingAuthentication => {
                "Authenticated resources must not expose protected objects to anonymous callers."
            }
            Self::TenantIsolationViolation => {
                "A principal from one tenant must not access resources belonging to a different tenant."
            }
            Self::OwnerBaselineFailed => {
                "The expected owner must be able to access the object before cross-profile validation is meaningful."
            }
            Self::IntendedOwnerAccess => "The object owner can access their own object.",
            Self::IntendedPrivilegedAccess => {
                "A privileged principal can access the object under the configured role policy."
            }
            Self::BlockedAsExpected => {
                "A non-owner or unauthenticated principal was blocked from accessing the object."
            }
        }
    }
}

impl ResponseImpactAnalysis {
    pub fn analyze(case: &BolaValidationCase, classification: &AuthorizationClass) -> Self {
        let owner_value = serde_json::from_str::<Value>(&case.owner_exchange.response_body_excerpt)
            .unwrap_or(Value::Null);
        let tested_value =
            serde_json::from_str::<Value>(&case.attacker_exchange.response_body_excerpt)
                .unwrap_or(Value::Null);
        let owner_shape = ResponseShape::from_value(&owner_value);
        let tested_shape = ResponseShape::from_value(&tested_value);
        let shape_similarity = shape_similarity(&owner_shape, &tested_shape);
        let sensitive_fields = sensitive_fields_from_value(&tested_value);
        let mut score = base_impact_score(classification);
        let mut impact_notes = Vec::new();

        if !sensitive_fields.is_empty() {
            let sensitive_bonus = sensitive_fields
                .iter()
                .map(|field| sensitive_category_weight(&field.category))
                .max()
                .unwrap_or(0);
            score = score.saturating_add(sensitive_bonus);
            impact_notes.push(format!(
                "{} sensitive field(s) exposed in tested response",
                sensitive_fields.len()
            ));
        }

        if shape_similarity >= 0.80 && classification.is_finding() {
            score = score.saturating_add(8);
            impact_notes.push("tested response shape closely matches owner baseline".to_string());
        }

        if endpoint_looks_privileged(&case.endpoint)
            || sensitive_fields
                .iter()
                .any(|field| field.category == SensitiveDataCategory::PrivilegedBusinessData)
        {
            score = score.saturating_add(12);
            impact_notes
                .push("response is tied to privileged or business-sensitive data".to_string());
        }

        score = score.min(100);
        if impact_notes.is_empty() {
            impact_notes.push("no sensitive response fields were detected".to_string());
        }

        Self {
            severity: severity_from_score(score),
            score,
            shape_similarity,
            owner_shape,
            tested_shape,
            sensitive_fields,
            impact_notes,
        }
    }
}

impl ResponseShape {
    pub fn from_value(value: &Value) -> Self {
        let mut field_paths = Vec::new();
        collect_field_paths(value, "$", &mut field_paths);
        field_paths.sort();
        field_paths.dedup();
        Self {
            root_type: value_kind(value).to_string(),
            field_count: field_paths.len(),
            field_paths,
        }
    }
}

impl RemediationPlan {
    pub fn for_authorization_finding(
        case: &BolaValidationCase,
        observation: &AuthorizationMatrixObservation,
        impact: &ResponseImpactAnalysis,
        owner_auth_header: Option<String>,
        tested_auth_header: Option<String>,
    ) -> Self {
        let classification = observation.classification.clone();
        let summary = remediation_summary(&classification, case, observation);
        let implementation_steps = remediation_steps(&classification);
        let mut regression_checks = vec![
            RegressionCheck {
                name: "owner-baseline-still-allowed".to_string(),
                profile: case.owner_profile.clone(),
                method: case.owner_exchange.method.clone(),
                url: case.owner_exchange.url.clone(),
                auth_header: owner_auth_header,
                expected_statuses: vec![200],
                purpose: "confirm the rightful owner can still access the object after the fix"
                    .to_string(),
            },
            RegressionCheck {
                name: "tested-profile-blocked".to_string(),
                profile: observation.tested_profile.clone(),
                method: case.attacker_exchange.method.clone(),
                url: case.attacker_exchange.url.clone(),
                auth_header: tested_auth_header,
                expected_statuses: expected_block_statuses(&classification),
                purpose: "confirm the previously successful unauthorized profile is denied"
                    .to_string(),
            },
        ];

        if let Some(anonymous) = &case.anonymous_exchange {
            regression_checks.push(RegressionCheck {
                name: "anonymous-caller-blocked".to_string(),
                profile: "anonymous".to_string(),
                method: anonymous.method.clone(),
                url: anonymous.url.clone(),
                auth_header: None,
                expected_statuses: vec![401, 403, 404],
                purpose: "confirm unauthenticated callers cannot retrieve the protected object"
                    .to_string(),
            });
        }

        let mut verification_notes = vec![
            "rerun the same BALONCORE scan and expect the finding to disappear from verified findings"
                .to_string(),
            "ensure denied responses do not serialize the protected object or sensitive fields"
                .to_string(),
        ];
        if !impact.sensitive_fields.is_empty() {
            verification_notes.push(format!(
                "previously exposed sensitive field paths: {}",
                impact
                    .sensitive_fields
                    .iter()
                    .map(|field| field.path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        Self {
            classification,
            severity: impact.severity.clone(),
            endpoint_id: case.endpoint.id.clone(),
            object_id: case.object_id.clone(),
            summary,
            implementation_steps,
            regression_checks,
            verification_notes,
        }
    }
}

impl RegressionRunReport {
    pub fn from_results(plan: &RemediationPlan, results: Vec<RegressionCheckResult>) -> Self {
        let passed_checks = results.iter().filter(|result| result.passed).count();
        let total_checks = results.len();
        let failed_checks = total_checks.saturating_sub(passed_checks);
        let verdict = if failed_checks == 0 {
            RegressionVerdict::Fixed
        } else {
            RegressionVerdict::StillFailing
        };

        Self {
            remediation_endpoint: plan.endpoint_id.clone(),
            object_id: plan.object_id.clone(),
            verdict,
            total_checks,
            passed_checks,
            failed_checks,
            results,
        }
    }
}

#[derive(Debug, Error)]
pub enum OpenApiInventoryError {
    #[error("OpenAPI document is not valid JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("OpenAPI document has no object `paths` field")]
    MissingPaths,
}

impl OpenApiInventory {
    pub fn from_json(
        source_url: impl Into<String>,
        base_url: &str,
        raw: &str,
    ) -> Result<Self, OpenApiInventoryError> {
        let document: Value = serde_json::from_str(raw)?;
        let paths = document
            .get("paths")
            .and_then(Value::as_object)
            .ok_or(OpenApiInventoryError::MissingPaths)?;
        let root_requires_auth = document
            .get("security")
            .and_then(Value::as_array)
            .is_some_and(|security| !security.is_empty());
        let mut endpoints = Vec::new();

        for (path, path_item) in paths {
            let Some(operations) = path_item.as_object() else {
                continue;
            };

            for (method_name, operation) in operations {
                let Some(method) = HttpMethod::from_openapi_method(method_name) else {
                    continue;
                };

                let operation_requires_auth = operation
                    .get("security")
                    .and_then(Value::as_array)
                    .map(|security| !security.is_empty())
                    .unwrap_or(root_requires_auth);
                let tags = operation
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|tags| {
                        tags.iter()
                            .filter_map(Value::as_str)
                            .map(ToOwned::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                let path_parameters = path_parameters_from(path);
                let id = format!("{} {path}", method.as_str());
                endpoints.push(ApiEndpoint {
                    id,
                    method,
                    url_template: join_url_template(base_url, path),
                    source: EndpointSource::OpenApi,
                    requires_auth: Some(operation_requires_auth),
                    path_parameters,
                    tags,
                });
            }
        }

        endpoints.sort_by(|left, right| left.id.cmp(&right.id));
        let seed_candidates = SeedEndpointCandidate::from_endpoints(&endpoints);
        let bola_candidates = BolaCandidate::from_endpoints(&endpoints);

        Ok(Self {
            source_url: source_url.into(),
            endpoints,
            seed_candidates,
            bola_candidates,
        })
    }
}

impl GraphQlFieldType {
    pub fn from_introspection_type(value: &Value) -> Self {
        let kind = value
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("OBJECT")
            .to_string();
        let name = value.get("name").and_then(Value::as_str).map(String::from);
        let of_type = value.get("ofType").and_then(|v| {
            if v.is_null() {
                None
            } else {
                v.get("name")
                    .and_then(Value::as_str)
                    .map(String::from)
                    .or_else(|| v.get("kind").and_then(Value::as_str).map(String::from))
            }
        });
        Self {
            name: name.unwrap_or_default(),
            kind,
            of_type,
        }
    }

    pub fn display_type(&self) -> String {
        if let Some(inner) = &self.of_type {
            match self.kind.as_str() {
                "NON_NULL" => format!("{}!", inner),
                "LIST" => format!("[{}]", inner),
                _ => self.name.clone(),
            }
        } else if self.name.is_empty() {
            self.kind.clone()
        } else {
            self.name.clone()
        }
    }

    fn is_object_type(&self) -> bool {
        matches!(self.kind.as_str(), "OBJECT" | "LIST" | "NON_NULL")
            || matches!(
                self.name.as_str(),
                "User"
                    | "Project"
                    | "Invoice"
                    | "Order"
                    | "Document"
                    | "Account"
                    | "Workspace"
                    | "Organization"
                    | "Customer"
                    | "Transaction"
                    | "Report"
                    | "Payment"
                    | "File"
                    | "ApiToken"
                    | "Secret"
                    | "Member"
                    | "Repository"
                    | "Subscription"
            )
    }
}

impl GraphQlField {
    fn from_introspection_field(value: &Value) -> Option<Self> {
        let name = value.get("name")?.as_str()?.to_string();
        if name.starts_with("__") {
            return None;
        }
        let type_value = value.get("type")?;
        let return_type = GraphQlFieldType::from_introspection_type(type_value);
        let args = value
            .get("args")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(GraphQlArg::from_introspection_arg)
                    .collect()
            })
            .unwrap_or_default();
        let description = value
            .get("description")
            .and_then(Value::as_str)
            .map(String::from);
        let is_deprecated = value
            .get("isDeprecated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Some(Self {
            name,
            return_type,
            args,
            description,
            is_deprecated,
        })
    }
}

impl GraphQlArg {
    fn from_introspection_arg(value: &Value) -> Option<Self> {
        let name = value.get("name")?.as_str()?.to_string();
        let type_value = value.get("type")?;
        let arg_type = GraphQlFieldType::from_introspection_type(type_value);
        let default_value = value
            .get("defaultValue")
            .and_then(Value::as_str)
            .map(String::from);
        Some(Self {
            name,
            arg_type,
            default_value,
        })
    }

    fn looks_like_object_id(&self) -> bool {
        let lower = self.name.to_ascii_lowercase();
        lower == "id"
            || lower.ends_with("id")
            || lower.ends_with("_id")
            || lower == "uuid"
            || lower == "slug"
            || lower == "key"
    }
}

impl GraphQlOperation {
    fn from_field(operation_type: GraphQlOperationType, field: &GraphQlField) -> Self {
        Self {
            operation_type,
            name: field.name.clone(),
            return_type: field.return_type.clone(),
            args: field.args.clone(),
            description: field.description.clone(),
            is_deprecated: field.is_deprecated,
        }
    }

    pub fn has_id_argument(&self) -> Option<&GraphQlArg> {
        self.args.iter().find(|arg| arg.looks_like_object_id())
    }

    pub fn query_document(&self, variables: &std::collections::HashMap<String, Value>) -> String {
        let op_keyword = match self.operation_type {
            GraphQlOperationType::Query => "query",
            GraphQlOperationType::Mutation => "mutation",
        };
        let mut var_defs = Vec::new();
        let mut var_refs = Vec::new();
        for arg in &self.args {
            let var_name = arg.name.clone();
            let var_type = arg.arg_type.display_type();
            if let Some(_) = variables.get(&var_name) {
                var_defs.push(format!("${var_name}: {var_type}"));
                var_refs.push(format!("{var_name}: ${var_name}"));
            } else if let Some(default) = &arg.default_value {
                var_refs.push(format!(
                    "{var_name}: {}",
                    value_to_graphql_literal(&Value::String(default.clone()))
                ));
            }
        }
        let args_str = if var_refs.is_empty() {
            String::new()
        } else {
            format!("({})", var_refs.join(", "))
        };
        let var_defs_str = if var_defs.is_empty() {
            String::new()
        } else {
            format!("({})", var_defs.join(", "))
        };
        let field_list = self.return_type.name.clone();
        format!(
            "{op_keyword} {op_name}{var_defs_str} {{ {name}{args_str} {{ id {field_list} }} }}",
            op_name = self.name,
            name = self.name,
        )
        .trim()
        .to_string()
    }

    pub fn minimal_query(
        &self,
        id_value: &str,
    ) -> (String, std::collections::HashMap<String, Value>) {
        let id_arg = match self.has_id_argument() {
            Some(arg) => arg.name.clone(),
            None => "id".to_string(),
        };
        let op_keyword = match self.operation_type {
            GraphQlOperationType::Query => "query",
            GraphQlOperationType::Mutation => "mutation",
        };
        let mut variables = std::collections::HashMap::new();
        variables.insert(id_arg.clone(), Value::String(id_value.to_string()));

        let mut arg_parts = Vec::new();
        let mut var_defs = Vec::new();
        for arg in &self.args {
            if arg.looks_like_object_id() {
                arg_parts.push(format!("{}: ${}", arg.name, arg.name));
                var_defs.push(format!("${}: {}", arg.name, arg.arg_type.display_type()));
            }
        }
        let args_str = if arg_parts.is_empty() {
            String::new()
        } else {
            format!("({})", arg_parts.join(", "))
        };
        let var_defs_str = if var_defs.is_empty() {
            String::new()
        } else {
            format!("({})", var_defs.join(", "))
        };

        let fragment = graphql_fields_for_type(&self.return_type.name);
        let query = format!(
            "{op_keyword} {name}{var_defs_str} {{ {name}{args_str} {{ {fragment} }} }}",
            op_keyword = op_keyword,
            name = self.name,
        );
        (query, variables)
    }
}

fn graphql_fields_for_type(type_name: &str) -> String {
    let lower = type_name.to_ascii_lowercase();
    let default_fields = "id".to_string();
    let extra = match lower.as_str() {
        t if t.contains("user") || t.contains("member") => ", email, name, org_id, role",
        t if t.contains("project") => ", name, org_id, owner_id, status",
        t if t.contains("invoice") || t.contains("order") || t.contains("payment") => {
            ", amount, user_id, status"
        }
        t if t.contains("org") || t.contains("organization") => ", name, plan, member_ids",
        t if t.contains("document") || t.contains("file") => ", title, owner_id, visibility",
        t if t.contains("workspace") => ", name, owner_id",
        t if t.contains("account") => ", name, owner_id, balance",
        t if t.contains("transaction") => ", amount, from_id, to_id, status",
        _ => "",
    };
    format!("{default_fields}{extra}")
}

fn value_to_graphql_literal(value: &Value) -> String {
    match value {
        Value::String(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => "\"\"".to_string(),
    }
}

impl GraphQlInventory {
    pub fn from_introspection_json(
        source_url: impl Into<String>,
        raw: &str,
    ) -> Result<Self, GraphQlInventoryError> {
        let document: Value = serde_json::from_str(raw)?;
        if let Some(errors) = document.get("errors").and_then(Value::as_array) {
            if !errors.is_empty() {
                let msg = errors
                    .iter()
                    .filter_map(|e| e.get("message").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(GraphQlInventoryError::IntrospectionErrors(msg));
            }
        }
        let schema = document
            .get("data")
            .and_then(|d| d.get("__schema"))
            .ok_or(GraphQlInventoryError::MissingSchema)?;

        let query_type_name = schema
            .get("queryType")
            .and_then(|qt| qt.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("Query");
        let mutation_type_name = schema
            .get("mutationType")
            .and_then(|mt| mt.get("name"))
            .and_then(Value::as_str);

        let types_array = schema
            .get("types")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut schema_types = Vec::new();
        let mut query_fields = Vec::new();
        let mut mutation_fields = Vec::new();

        for type_value in &types_array {
            let type_name = type_value.get("name").and_then(Value::as_str).unwrap_or("");
            let type_kind = type_value.get("kind").and_then(Value::as_str).unwrap_or("");
            if type_name.starts_with("__") {
                continue;
            }
            let fields = type_value
                .get("fields")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(GraphQlField::from_introspection_field)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let gql_type = GraphQlType {
                name: type_name.to_string(),
                kind: type_kind.to_string(),
                fields: fields.clone(),
            };
            schema_types.push(gql_type);

            if type_name == query_type_name {
                query_fields = fields.clone();
            }
            if let Some(mtn) = mutation_type_name {
                if type_name == mtn {
                    mutation_fields = fields;
                }
            }
        }

        let queries: Vec<GraphQlOperation> = query_fields
            .iter()
            .map(|f| GraphQlOperation::from_field(GraphQlOperationType::Query, f))
            .collect();
        let mutations: Vec<GraphQlOperation> = mutation_fields
            .iter()
            .map(|f| GraphQlOperation::from_field(GraphQlOperationType::Mutation, f))
            .collect();

        let source_url_owned: String = source_url.into();
        let path = graphql_path_from_url(&source_url_owned);

        let mut endpoints = Vec::new();
        for query in &queries {
            endpoints.push(ApiEndpoint {
                id: format!("GQL QUERY {}", query.name),
                method: HttpMethod::Post,
                url_template: source_url_owned.clone(),
                source: EndpointSource::GraphQl,
                requires_auth: Some(true),
                path_parameters: vec![],
                tags: vec![
                    "graphql".to_string(),
                    "query".to_string(),
                    query.name.clone(),
                ],
            });
        }
        for mutation in &mutations {
            endpoints.push(ApiEndpoint {
                id: format!("GQL MUTATION {}", mutation.name),
                method: HttpMethod::Post,
                url_template: source_url_owned.clone(),
                source: EndpointSource::GraphQl,
                requires_auth: Some(true),
                path_parameters: vec![],
                tags: vec![
                    "graphql".to_string(),
                    "mutation".to_string(),
                    mutation.name.clone(),
                ],
            });
        }

        let bola_candidates =
            GraphQlBolaCandidate::from_operations(&source_url_owned, &path, &queries, &mutations);

        Ok(Self {
            source_url: source_url_owned,
            schema_types,
            queries,
            mutations,
            endpoints,
            bola_candidates,
        })
    }

    pub fn introspection_query() -> String {
        r#"{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields {
        name
        description
        isDeprecated
        args {
          name
          type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
          defaultValue
        }
        type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
      }
    }
  }
}"#
        .to_string()
    }

    pub fn all_operations(&self) -> Vec<&GraphQlOperation> {
        let mut ops: Vec<&GraphQlOperation> = self.queries.iter().collect();
        ops.extend(self.mutations.iter());
        ops
    }
}

fn graphql_path_from_url(url: &str) -> String {
    url::Url::parse(url)
        .map(|parsed| parsed.path().to_string())
        .unwrap_or_else(|_| "/graphql".to_string())
}

impl GraphQlBolaCandidate {
    pub fn from_operations(
        source_url: &str,
        _path: &str,
        queries: &[GraphQlOperation],
        mutations: &[GraphQlOperation],
    ) -> Vec<Self> {
        let mut candidates = Vec::new();
        let all_ops: Vec<&GraphQlOperation> = queries.iter().chain(mutations.iter()).collect();

        for operation in all_ops {
            if operation.is_deprecated {
                continue;
            }
            let id_arg = match operation.has_id_argument() {
                Some(arg) => arg,
                None => continue,
            };
            if !operation.return_type.is_object_type() {
                continue;
            }

            let mut confidence: f32 = 0.45;
            let mut rationale = vec![format!(
                "GraphQL {} `{}` accepts `{}` argument and returns object type `{}`",
                match operation.operation_type {
                    GraphQlOperationType::Query => "query",
                    GraphQlOperationType::Mutation => "mutation",
                },
                operation.name,
                id_arg.name,
                operation.return_type.name,
            )];

            let lower_name = operation.name.to_ascii_lowercase();
            let object_terms = [
                "user",
                "account",
                "project",
                "invoice",
                "order",
                "document",
                "payment",
                "transaction",
                "workspace",
                "organization",
                "org",
                "customer",
                "report",
                "file",
                "member",
            ];
            if let Some(term) = object_terms.iter().find(|t| lower_name.contains(*t)) {
                confidence += 0.20;
                rationale.push(format!("operation name contains object term `{term}`"));
            }

            if id_arg.name == "id" || id_arg.name.ends_with("Id") || id_arg.name.ends_with("_id") {
                confidence += 0.15;
                rationale.push("id argument name suggests direct object lookup".to_string());
            }

            if matches!(operation.operation_type, GraphQlOperationType::Mutation) {
                confidence += 0.10;
                rationale.push("mutation may bypass authorization on state change".to_string());
            }

            let endpoint = ApiEndpoint {
                id: format!(
                    "GQL {} {}",
                    match operation.operation_type {
                        GraphQlOperationType::Query => "QUERY",
                        GraphQlOperationType::Mutation => "MUTATION",
                    },
                    operation.name
                ),
                method: HttpMethod::Post,
                url_template: source_url.to_string(),
                source: EndpointSource::GraphQl,
                requires_auth: Some(true),
                path_parameters: vec![],
                tags: vec![
                    "graphql".to_string(),
                    match operation.operation_type {
                        GraphQlOperationType::Query => "query".to_string(),
                        GraphQlOperationType::Mutation => "mutation".to_string(),
                    },
                    operation.name.clone(),
                ],
            };

            candidates.push(Self {
                endpoint,
                operation_type: operation.operation_type.clone(),
                operation_name: operation.name.clone(),
                id_argument: id_arg.name.clone(),
                return_type_name: operation.return_type.name.clone(),
                confidence: confidence.min(0.95),
                rationale,
            });
        }
        candidates.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        candidates
    }
}

impl GraphQlBolaValidator {
    pub fn default() -> Self {
        Self {
            min_body_similarity: 0.70,
        }
    }

    pub fn validate(&self, case: &GraphQlBolaValidationCase) -> GraphQlBolaDecision {
        let mut observations = Vec::new();

        if !is_success_like(case.owner_exchange.status) {
            return GraphQlBolaDecision::Rejected(RejectedHypothesis {
                reason: "owner baseline GraphQL request did not successfully access the object"
                    .to_string(),
                observations: vec![format!("owner_status={}", case.owner_exchange.status)],
            });
        }

        if !is_success_like(case.attacker_exchange.status) {
            return GraphQlBolaDecision::Rejected(RejectedHypothesis {
                reason: "attacker profile was blocked from accessing the GraphQL object"
                    .to_string(),
                observations: vec![format!("attacker_status={}", case.attacker_exchange.status)],
            });
        }

        if let Some(anonymous) = &case.anonymous_exchange {
            if is_success_like(anonymous.status) {
                let anon_similarity = body_similarity(
                    &case.owner_exchange.response_body_excerpt,
                    &anonymous.response_body_excerpt,
                );
                if anon_similarity >= self.min_body_similarity {
                    return GraphQlBolaDecision::Rejected(RejectedHypothesis {
                        reason: "GraphQL object appears accessible without authentication, so this is not a cross-user BOLA proof".to_string(),
                        observations: vec![format!("anonymous_status={}", anonymous.status)],
                    });
                }
            }
        }

        let owner_body = &case.owner_exchange.response_body_excerpt;
        let attacker_body = &case.attacker_exchange.response_body_excerpt;
        let similarity = body_similarity(owner_body, attacker_body);
        observations.push(format!("graphql_body_similarity={similarity:.2}"));

        let evidence_markers = graphql_evidence_markers(case);
        let has_marker = !evidence_markers.is_empty();
        let similar_enough = similarity >= self.min_body_similarity;

        if !has_marker && !similar_enough {
            return GraphQlBolaDecision::Rejected(RejectedHypothesis {
                reason:
                    "attacker GraphQL response does not sufficiently match owner object evidence"
                        .to_string(),
                observations,
            });
        }

        let _classification_note = if case.tested_tenant.is_some()
            && case.owner_tenant.is_some()
            && case.tested_tenant != case.owner_tenant
        {
            "cross-tenant GraphQL BOLA"
        } else {
            "cross-user GraphQL BOLA"
        };

        GraphQlBolaDecision::Verified(GraphQlVerifiedFinding {
            title: format!("GraphQL {} authorization bypass", case.operation_name),
            endpoint_id: case.endpoint.id.clone(),
            operation_name: case.operation_name.clone(),
            object_id: case.object_id.clone(),
            owner_profile: case.owner_profile.clone(),
            attacker_profile: case.attacker_profile.clone(),
            evidence_exchange_ids: vec![
                case.owner_exchange.id.clone(),
                case.attacker_exchange.id.clone(),
            ],
            evidence_markers,
            body_similarity: similarity,
            security_property: "A principal must not access a GraphQL object owned by a different principal without explicit authorization.".to_string(),
        })
    }
}

fn graphql_evidence_markers(case: &GraphQlBolaValidationCase) -> Vec<String> {
    let attacker_body = case.attacker_exchange.response_body_excerpt.to_lowercase();
    let mut markers = Vec::new();

    if !case.object_id.is_empty() && attacker_body.contains(&case.object_id.to_lowercase()) {
        markers.push(format!("object_id:{}", case.object_id));
    }

    for marker in &case.owner_markers {
        if !marker.is_empty() && attacker_body.contains(&marker.to_lowercase()) {
            markers.push(format!("owner_marker:{marker}"));
        }
    }

    markers
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphQlBolaValidator {
    pub min_body_similarity: f32,
}

impl SeedEndpointCandidate {
    pub fn from_endpoints(endpoints: &[ApiEndpoint]) -> Vec<Self> {
        endpoints
            .iter()
            .filter_map(Self::from_endpoint)
            .collect::<Vec<_>>()
    }

    pub fn from_endpoint(endpoint: &ApiEndpoint) -> Option<Self> {
        if endpoint.method != HttpMethod::Get {
            return None;
        }

        if !endpoint.path_parameters.is_empty() || matches!(endpoint.requires_auth, Some(false)) {
            return None;
        }

        let normalized = endpoint.url_template.to_ascii_lowercase();
        if normalized.ends_with("/me")
            || normalized.contains("/health")
            || normalized.contains("openapi")
        {
            return None;
        }

        let collection_terms = [
            "accounts",
            "api_keys",
            "customers",
            "documents",
            "files",
            "invoices",
            "orders",
            "payments",
            "projects",
            "reports",
            "transactions",
            "users",
            "workspaces",
        ];
        let term = collection_terms
            .iter()
            .find(|term| normalized.contains(**term))?;
        let mut confidence: f32 = 0.55;
        let mut rationale = vec![
            "authenticated GET endpoint has no path parameters".to_string(),
            format!("path looks like a collection endpoint for `{term}`"),
        ];

        if endpoint.requires_auth == Some(true) {
            confidence += 0.20;
            rationale.push("endpoint declares authentication".to_string());
        }

        Some(Self {
            endpoint: endpoint.clone(),
            confidence: confidence.min(0.95),
            rationale,
        })
    }
}

impl ObjectSeed {
    pub fn from_json_response(
        owner_profile: &str,
        source_endpoint_id: &str,
        source_url: &str,
        raw: &str,
        limit: usize,
    ) -> Result<Vec<Self>, ObjectSeedError> {
        let value: Value = serde_json::from_str(raw)?;
        let mut seeds = Vec::new();
        collect_object_seeds(
            &value,
            owner_profile,
            source_endpoint_id,
            source_url,
            limit,
            &mut seeds,
        );
        seeds.sort_by(|left, right| left.object_id.cmp(&right.object_id));
        seeds.dedup_by(|left, right| left.object_id == right.object_id);
        Ok(seeds)
    }

    pub fn resource_fingerprint(&self) -> Option<ResourceFingerprint> {
        if self.source_url.starts_with("cli:")
            || self.source_endpoint_id == "manual"
            || self.source_endpoint_id == "seed-file"
        {
            return None;
        }

        ResourceFingerprint::from_url_like(&self.source_url)
            .or_else(|| ResourceFingerprint::from_endpoint_id(&self.source_endpoint_id))
    }
}

impl BolaCandidate {
    pub fn resource_fingerprint(&self) -> ResourceFingerprint {
        ResourceFingerprint::from_url_like(&self.endpoint.url_template)
            .unwrap_or_else(|| ResourceFingerprint::from_segments(Vec::new()))
    }

    pub fn matches_seed(&self, seed: &ObjectSeed) -> SeedCandidateMatch {
        let candidate_resource = self.resource_fingerprint();
        let seed_resource = seed.resource_fingerprint();

        let Some(seed_resource_value) = seed_resource.clone() else {
            return SeedCandidateMatch {
                matches: true,
                reason: "seed resource is explicit or unknown, so candidate is allowed".to_string(),
                seed_resource,
                candidate_resource,
            };
        };

        let matches =
            !candidate_resource.key.is_empty() && candidate_resource.key == seed_resource_value.key;
        let reason = if matches {
            format!("resource key `{}` matched", candidate_resource.key)
        } else {
            format!(
                "seed resource `{}` does not match candidate resource `{}`",
                seed_resource_value.key, candidate_resource.key
            )
        };

        SeedCandidateMatch {
            matches,
            reason,
            seed_resource,
            candidate_resource,
        }
    }
}

impl ResourceFingerprint {
    fn from_endpoint_id(endpoint_id: &str) -> Option<Self> {
        endpoint_id
            .split_once(' ')
            .map(|(_, path)| path)
            .and_then(Self::from_url_like)
    }

    fn from_url_like(input: &str) -> Option<Self> {
        let without_query = input.split(['?', '#']).next().unwrap_or(input);
        let path = if let Some((_, after_scheme)) = without_query.split_once("://") {
            after_scheme
                .find('/')
                .map(|index| &after_scheme[index..])
                .unwrap_or("/")
        } else {
            without_query
        };
        let segments = path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .filter(|segment| !segment.starts_with('{') && !segment.ends_with('}'))
            .filter(|segment| !is_noise_path_segment(segment))
            .map(normalize_resource_segment)
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        Some(Self::from_segments(segments))
    }

    fn from_segments(segments: Vec<String>) -> Self {
        let privileged = segments.iter().any(|segment| {
            matches!(
                segment.as_str(),
                "admin" | "internal" | "manage" | "management"
            )
        });
        Self {
            key: segments.join("/"),
            segments,
            privileged,
        }
    }
}

impl AuthorizationMatrixObservation {
    pub fn classify(case: &BolaValidationCase, owner_role: &str, tested_role: &str) -> Self {
        Self::classify_with_tenant(case, owner_role, tested_role, None, None)
    }

    pub fn classify_with_tenant(
        case: &BolaValidationCase,
        owner_role: &str,
        tested_role: &str,
        tested_tenant: Option<&str>,
        owner_tenant: Option<&str>,
    ) -> Self {
        let tested_profile = case.attacker_profile.clone();
        let tested_status = case.attacker_exchange.status;
        let owner_status = case.owner_exchange.status;
        let anonymous_status = case
            .anonymous_exchange
            .as_ref()
            .map(|exchange| exchange.status);
        let evidence_markers = evidence_markers(case);
        let similarity = body_similarity(
            &case.owner_exchange.response_body_excerpt,
            &case.attacker_exchange.response_body_excerpt,
        );

        let cross_tenant =
            tested_tenant.is_some() && owner_tenant.is_some() && tested_tenant != owner_tenant;

        let (classification, reason) = if !is_success_like(owner_status) {
            (
                AuthorizationClass::OwnerBaselineFailed,
                format!("owner baseline returned status {owner_status}"),
            )
        } else if tested_profile == case.owner_profile {
            if is_success_like(tested_status) {
                (
                    AuthorizationClass::IntendedOwnerAccess,
                    "owner profile successfully accessed its own object".to_string(),
                )
            } else {
                (
                    AuthorizationClass::OwnerBaselineFailed,
                    format!("owner matrix profile returned status {tested_status}"),
                )
            }
        } else if tested_profile == "anonymous" {
            if is_success_like(tested_status)
                && (similarity >= 0.70 || !evidence_markers.is_empty())
            {
                (
                    AuthorizationClass::MissingAuthentication,
                    "anonymous caller accessed protected object evidence".to_string(),
                )
            } else {
                (
                    AuthorizationClass::BlockedAsExpected,
                    format!("anonymous caller returned status {tested_status}"),
                )
            }
        } else if is_success_like(tested_status) && cross_tenant {
            (
                AuthorizationClass::TenantIsolationViolation,
                format!(
                    "principal from tenant {} accessed resource belonging to tenant {}",
                    tested_tenant.unwrap_or("?"),
                    owner_tenant.unwrap_or("?")
                ),
            )
        } else if is_success_like(tested_status) && tested_role.eq_ignore_ascii_case("admin") {
            (
                AuthorizationClass::IntendedPrivilegedAccess,
                "admin profile is treated as an explicitly privileged accessor".to_string(),
            )
        } else if is_success_like(tested_status) && endpoint_looks_privileged(&case.endpoint) {
            (
                AuthorizationClass::BrokenFunctionLevelAuthorization,
                "non-admin profile accessed an admin or privileged endpoint".to_string(),
            )
        } else if is_success_like(tested_status) && owner_role.eq_ignore_ascii_case("admin") {
            (
                AuthorizationClass::BrokenFunctionLevelAuthorization,
                "non-admin profile accessed an object owned by an admin profile".to_string(),
            )
        } else if is_success_like(tested_status)
            && (similarity >= 0.70 || !evidence_markers.is_empty())
        {
            (
                AuthorizationClass::BrokenObjectLevelAuthorization,
                "non-owner profile accessed owner object evidence".to_string(),
            )
        } else {
            (
                AuthorizationClass::BlockedAsExpected,
                format!("tested profile returned status {tested_status}"),
            )
        };

        Self {
            tested_profile,
            tested_role: tested_role.to_string(),
            classification,
            reason,
            owner_status,
            tested_status,
            anonymous_status,
            evidence_markers,
            body_similarity: similarity,
            tested_tenant: tested_tenant.map(|t| t.to_string()),
            owner_tenant: owner_tenant.map(|t| t.to_string()),
        }
    }
}

impl BolaCandidate {
    pub fn from_endpoints(endpoints: &[ApiEndpoint]) -> Vec<Self> {
        endpoints
            .iter()
            .filter_map(Self::from_endpoint)
            .collect::<Vec<_>>()
    }

    pub fn from_endpoint(endpoint: &ApiEndpoint) -> Option<Self> {
        if endpoint.method != HttpMethod::Get {
            return None;
        }

        if matches!(endpoint.requires_auth, Some(false)) {
            return None;
        }

        let path_parameter = endpoint.path_parameters.first()?.clone();
        let mut confidence: f32 = 0.45;
        let mut rationale = vec![format!(
            "authenticated GET endpoint contains path parameter `{path_parameter}`"
        )];
        let normalized = endpoint.url_template.to_ascii_lowercase();
        let object_terms = [
            "account",
            "api_key",
            "billing",
            "customer",
            "document",
            "file",
            "invoice",
            "order",
            "org",
            "payment",
            "project",
            "report",
            "tenant",
            "transaction",
            "user",
            "workspace",
        ];

        if endpoint.path_parameters.len() == 1 {
            confidence += 0.20;
            rationale.push("single path parameter suggests direct object lookup".to_string());
        }

        if path_parameter.eq_ignore_ascii_case("id")
            || path_parameter.ends_with("_id")
            || path_parameter.ends_with("Id")
        {
            confidence += 0.15;
            rationale.push("path parameter name looks like an object identifier".to_string());
        }

        if let Some(term) = object_terms.iter().find(|term| normalized.contains(**term)) {
            confidence += 0.15;
            rationale.push(format!("path contains object term `{term}`"));
        }

        Some(Self {
            endpoint: endpoint.clone(),
            path_parameter,
            confidence: confidence.min(0.95),
            rationale,
        })
    }
}

impl HttpRequestRunner {
    pub fn new() -> Result<Self, HttpRunnerError> {
        Self::with_max_body_excerpt(4096)
    }

    pub fn with_max_body_excerpt(max_body_excerpt: usize) -> Result<Self, HttpRunnerError> {
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            max_body_excerpt,
        })
    }

    pub fn send(&self, spec: &HttpRequestSpec) -> Result<HttpExchange, HttpRunnerError> {
        let mut request = match spec.method {
            HttpMethod::Get => self.client.get(&spec.url),
            HttpMethod::Post => self.client.post(&spec.url),
            HttpMethod::Put => self.client.put(&spec.url),
            HttpMethod::Patch => self.client.patch(&spec.url),
            HttpMethod::Delete => self.client.delete(&spec.url),
            HttpMethod::Options => {
                let url = spec.url.clone();
                self.client.request(reqwest::Method::OPTIONS, &url)
            }
            HttpMethod::Head => self.client.head(&spec.url),
        };

        if let Some(token) = &spec.bearer_token {
            request = request.bearer_auth(token);
        }

        for (name, value) in &spec.headers {
            request = request.header(name.as_str(), value.as_str());
        }

        if !spec.cookies.is_empty() {
            let cookie_header: String = spec
                .cookies
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("; ");
            request = request.header("Cookie", cookie_header);
        }

        if let (Some(header_name), Some(token)) = (&spec.csrf_token_header, &spec.csrf_token) {
            request = request.header(header_name.as_str(), token.as_str());
        }

        let response = request.send()?;
        let status = response.status().as_u16();
        let response_headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or("<non-utf8>").to_string(),
                )
            })
            .collect();
        let body = response.text()?;

        Ok(HttpExchange {
            id: spec.id.clone(),
            profile: spec.profile.clone(),
            method: spec.method.clone(),
            url: spec.url.clone(),
            status,
            response_headers,
            response_body_excerpt: excerpt(&body, self.max_body_excerpt),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BolaValidationCase {
    pub endpoint: ApiEndpoint,
    pub object_id: String,
    pub owner_profile: String,
    pub attacker_profile: String,
    pub owner_markers: Vec<String>,
    pub owner_exchange: HttpExchange,
    pub attacker_exchange: HttpExchange,
    pub anonymous_exchange: Option<HttpExchange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BolaDecision {
    Verified(VerifiedBolaFinding),
    Rejected(RejectedHypothesis),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifiedBolaFinding {
    pub title: String,
    pub endpoint_id: String,
    pub object_id: String,
    pub owner_profile: String,
    pub attacker_profile: String,
    pub evidence_exchange_ids: Vec<String>,
    pub evidence_markers: Vec<String>,
    pub body_similarity: f32,
    pub security_property: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RejectedHypothesis {
    pub reason: String,
    pub observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BolaValidator {
    pub min_body_similarity: f32,
}

impl Default for BolaValidator {
    fn default() -> Self {
        Self {
            min_body_similarity: 0.70,
        }
    }
}

impl BolaValidator {
    pub fn validate(&self, case: &BolaValidationCase) -> BolaDecision {
        let mut observations = Vec::new();

        if !is_success_like(case.owner_exchange.status) {
            return BolaDecision::Rejected(RejectedHypothesis {
                reason: "owner baseline request did not successfully access the object".to_string(),
                observations: vec![format!("owner_status={}", case.owner_exchange.status)],
            });
        }

        if !is_success_like(case.attacker_exchange.status) {
            return BolaDecision::Rejected(RejectedHypothesis {
                reason: "attacker profile was blocked from accessing the object".to_string(),
                observations: vec![format!("attacker_status={}", case.attacker_exchange.status)],
            });
        }

        if let Some(anonymous) = &case.anonymous_exchange {
            if is_success_like(anonymous.status)
                && body_similarity(
                    &case.owner_exchange.response_body_excerpt,
                    &anonymous.response_body_excerpt,
                ) >= self.min_body_similarity
            {
                return BolaDecision::Rejected(RejectedHypothesis {
                    reason: "object appears accessible without authentication, so this is not a cross-user BOLA proof".to_string(),
                    observations: vec![format!("anonymous_status={}", anonymous.status)],
                });
            }
        }

        let similarity = body_similarity(
            &case.owner_exchange.response_body_excerpt,
            &case.attacker_exchange.response_body_excerpt,
        );
        observations.push(format!("body_similarity={similarity:.2}"));

        let evidence_markers = evidence_markers(case);
        let has_marker = !evidence_markers.is_empty();
        let similar_enough = similarity >= self.min_body_similarity;

        if !has_marker && !similar_enough {
            return BolaDecision::Rejected(RejectedHypothesis {
                reason: "attacker response does not sufficiently match owner object evidence"
                    .to_string(),
                observations,
            });
        }

        BolaDecision::Verified(VerifiedBolaFinding {
            title: "Broken object-level authorization".to_string(),
            endpoint_id: case.endpoint.id.clone(),
            object_id: case.object_id.clone(),
            owner_profile: case.owner_profile.clone(),
            attacker_profile: case.attacker_profile.clone(),
            evidence_exchange_ids: vec![
                case.owner_exchange.id.clone(),
                case.attacker_exchange.id.clone(),
            ],
            evidence_markers,
            body_similarity: similarity,
            security_property: "A principal must not access an object owned by a different principal without explicit authorization.".to_string(),
        })
    }
}

fn is_success_like(status: u16) -> bool {
    (200..300).contains(&status)
}

fn evidence_markers(case: &BolaValidationCase) -> Vec<String> {
    let attacker_body = case.attacker_exchange.response_body_excerpt.to_lowercase();
    let mut markers = Vec::new();

    if !case.object_id.is_empty() && attacker_body.contains(&case.object_id.to_lowercase()) {
        markers.push(format!("object_id:{}", case.object_id));
    }

    for marker in &case.owner_markers {
        if !marker.is_empty() && attacker_body.contains(&marker.to_lowercase()) {
            markers.push(format!("owner_marker:{marker}"));
        }
    }

    markers
}

fn body_similarity(left: &str, right: &str) -> f32 {
    let left_tokens = token_set(left);
    let right_tokens = token_set(right);

    if left_tokens.is_empty() && right_tokens.is_empty() {
        return 1.0;
    }
    if left_tokens.is_empty() || right_tokens.is_empty() {
        return 0.0;
    }

    let intersection = left_tokens
        .iter()
        .filter(|token| right_tokens.contains(token))
        .count();
    let union = left_tokens.len() + right_tokens.len() - intersection;

    intersection as f32 / union as f32
}

fn shape_similarity(owner_shape: &ResponseShape, tested_shape: &ResponseShape) -> f32 {
    let owner_paths = owner_shape.field_paths.iter().collect::<BTreeSet<_>>();
    let tested_paths = tested_shape.field_paths.iter().collect::<BTreeSet<_>>();

    if owner_paths.is_empty() && tested_paths.is_empty() {
        return 1.0;
    }
    if owner_paths.is_empty() || tested_paths.is_empty() {
        return 0.0;
    }

    let intersection = owner_paths.intersection(&tested_paths).count();
    let union = owner_paths.union(&tested_paths).count();
    intersection as f32 / union as f32
}

fn collect_field_paths(value: &Value, path: &str, output: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path}.{key}");
                output.push(child_path.clone());
                collect_field_paths(child, &child_path, output);
            }
        }
        Value::Array(items) => {
            let child_path = format!("{path}[]");
            output.push(child_path.clone());
            for item in items.iter().take(3) {
                collect_field_paths(item, &child_path, output);
            }
        }
        _ => {}
    }
}

fn sensitive_fields_from_value(value: &Value) -> Vec<SensitiveFieldFinding> {
    let mut findings = Vec::new();
    collect_sensitive_fields(value, "$", &mut findings);
    findings.sort_by(|left, right| left.path.cmp(&right.path));
    findings.dedup_by(|left, right| left.path == right.path && left.category == right.category);
    findings
}

fn collect_sensitive_fields(value: &Value, path: &str, findings: &mut Vec<SensitiveFieldFinding>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path}.{key}");
                if let Some(category) = sensitive_category_for_key(key) {
                    findings.push(SensitiveFieldFinding {
                        path: child_path.clone(),
                        category,
                        value_kind: value_kind(child).to_string(),
                    });
                }
                collect_sensitive_fields(child, &child_path, findings);
            }
        }
        Value::Array(items) => {
            let child_path = format!("{path}[]");
            for item in items.iter().take(3) {
                collect_sensitive_fields(item, &child_path, findings);
            }
        }
        _ => {}
    }
}

fn sensitive_category_for_key(key: &str) -> Option<SensitiveDataCategory> {
    let lowered = key.to_ascii_lowercase();
    if lowered.contains("token")
        || lowered.contains("secret")
        || lowered.contains("password")
        || lowered.contains("api_key")
        || lowered.contains("apikey")
        || lowered.contains("credential")
    {
        Some(SensitiveDataCategory::CredentialOrSecret)
    } else if lowered.contains("email") {
        Some(SensitiveDataCategory::EmailAddress)
    } else if lowered.contains("amount")
        || lowered.contains("balance")
        || lowered.contains("payment")
        || lowered.contains("card")
        || lowered.contains("invoice")
        || lowered.contains("billing")
    {
        Some(SensitiveDataCategory::Financial)
    } else if lowered.contains("owner")
        || lowered.contains("tenant")
        || lowered == "user_id"
        || lowered == "account_id"
        || lowered == "org_id"
    {
        Some(SensitiveDataCategory::TenantOrOwnership)
    } else if lowered.contains("sensitivity")
        || lowered.contains("confidential")
        || lowered.contains("internal")
        || lowered.contains("admin")
        || lowered.contains("report")
    {
        Some(SensitiveDataCategory::PrivilegedBusinessData)
    } else if lowered == "id"
        || lowered.ends_with("_id")
        || lowered.contains("phone")
        || lowered.contains("address")
        || lowered.contains("name")
    {
        Some(SensitiveDataCategory::PersonalIdentifier)
    } else {
        None
    }
}

fn sensitive_category_weight(category: &SensitiveDataCategory) -> u8 {
    match category {
        SensitiveDataCategory::CredentialOrSecret => 30,
        SensitiveDataCategory::PrivilegedBusinessData => 24,
        SensitiveDataCategory::Financial => 20,
        SensitiveDataCategory::EmailAddress => 16,
        SensitiveDataCategory::TenantOrOwnership => 14,
        SensitiveDataCategory::PersonalIdentifier => 8,
    }
}

fn base_impact_score(classification: &AuthorizationClass) -> u8 {
    match classification {
        AuthorizationClass::MissingAuthentication => 72,
        AuthorizationClass::BrokenFunctionLevelAuthorization => 68,
        AuthorizationClass::TenantIsolationViolation => 62,
        AuthorizationClass::BrokenObjectLevelAuthorization => 58,
        AuthorizationClass::IntendedPrivilegedAccess => 12,
        AuthorizationClass::IntendedOwnerAccess => 5,
        AuthorizationClass::BlockedAsExpected => 0,
        AuthorizationClass::OwnerBaselineFailed => 0,
    }
}

fn severity_from_score(score: u8) -> ImpactSeverity {
    match score {
        0..=9 => ImpactSeverity::Info,
        10..=39 => ImpactSeverity::Low,
        40..=69 => ImpactSeverity::Medium,
        70..=89 => ImpactSeverity::High,
        _ => ImpactSeverity::Critical,
    }
}

fn remediation_summary(
    classification: &AuthorizationClass,
    case: &BolaValidationCase,
    observation: &AuthorizationMatrixObservation,
) -> String {
    match classification {
        AuthorizationClass::BrokenObjectLevelAuthorization => format!(
            "`{}` accessed object `{}` owned by `{}`; enforce object ownership or tenant membership before returning the resource.",
            observation.tested_profile, case.object_id, case.owner_profile
        ),
        AuthorizationClass::BrokenFunctionLevelAuthorization => format!(
            "`{}` accessed privileged endpoint `{}`; enforce server-side route permission checks before handler logic runs.",
            observation.tested_profile, case.endpoint.id
        ),
        AuthorizationClass::MissingAuthentication => format!(
            "anonymous access reached protected object `{}`; require authentication before object lookup or serialization.",
            case.object_id
        ),
        AuthorizationClass::TenantIsolationViolation => format!(
            "`{}` from tenant `{}` accessed object `{}` belonging to tenant `{}`; enforce tenant membership before returning the resource.",
            observation.tested_profile,
            observation.tested_tenant.as_deref().unwrap_or("unknown"),
            case.object_id,
            observation.owner_tenant.as_deref().unwrap_or("unknown")
        ),
        _ => format!(
            "`{}` requires authorization review, but it is not classified as a verified authorization finding.",
            case.endpoint.id
        ),
    }
}

fn remediation_steps(classification: &AuthorizationClass) -> Vec<String> {
    match classification {
        AuthorizationClass::BrokenObjectLevelAuthorization => vec![
            "derive the authenticated principal and tenant from trusted server-side session claims"
                .to_string(),
            "scope the object lookup by both object id and authorized owner or tenant id".to_string(),
            "deny before response serialization when the object owner or tenant does not match"
                .to_string(),
            "keep privileged bypasses explicit, permission-named, audited, and covered by tests"
                .to_string(),
        ],
        AuthorizationClass::BrokenFunctionLevelAuthorization => vec![
            "attach a required permission or role policy to the route, not only to UI navigation"
                .to_string(),
            "evaluate the route policy before handler logic performs data access".to_string(),
            "use deny-by-default behavior for missing or unknown permissions".to_string(),
            "add positive admin and negative non-admin regression coverage for the endpoint"
                .to_string(),
        ],
        AuthorizationClass::MissingAuthentication => vec![
            "require authentication middleware before the protected route handler".to_string(),
            "reject anonymous requests before object lookup, cache access, or response serialization"
                .to_string(),
            "verify public endpoints are declared separately from authenticated endpoints"
                .to_string(),
            "add anonymous-request regression coverage for the protected route".to_string(),
        ],
        AuthorizationClass::TenantIsolationViolation => vec![
            "derive the authenticated principal and tenant from trusted server-side claims, not from user-supplied object ids"
                .to_string(),
            "scope every data access query by tenant id; never allow cross-tenant object.lookup by id alone"
                .to_string(),
            "deny before response serialization when the object tenant does not match the authenticated tenant"
                .to_string(),
            "add cross-tenant and same-tenant-partial-view regression coverage".to_string(),
        ],
        _ => vec!["review the authorization model and add targeted regression coverage".to_string()],
    }
}

fn expected_block_statuses(classification: &AuthorizationClass) -> Vec<u16> {
    match classification {
        AuthorizationClass::MissingAuthentication => vec![401, 403, 404],
        _ => vec![403, 404],
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn token_set(input: &str) -> Vec<String> {
    let mut tokens = input
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-')
        .filter(|token| token.len() >= 2)
        .map(|token| token.to_ascii_lowercase())
        .collect::<Vec<_>>();
    tokens.sort();
    tokens.dedup();
    tokens
}

fn excerpt(input: &str, max_chars: usize) -> String {
    input.chars().take(max_chars).collect()
}

fn collect_object_seeds(
    value: &Value,
    owner_profile: &str,
    source_endpoint_id: &str,
    source_url: &str,
    limit: usize,
    seeds: &mut Vec<ObjectSeed>,
) {
    if seeds.len() >= limit {
        return;
    }

    match value {
        Value::Array(items) => {
            for item in items {
                collect_object_seeds(
                    item,
                    owner_profile,
                    source_endpoint_id,
                    source_url,
                    limit,
                    seeds,
                );
                if seeds.len() >= limit {
                    break;
                }
            }
        }
        Value::Object(object) => {
            if let Some(object_id) = object_identifier(object) {
                let mut owner_markers = object
                    .iter()
                    .filter(|(key, value)| is_owner_marker_key(key) && value.is_string())
                    .filter_map(|(_, value)| value.as_str().map(ToOwned::to_owned))
                    .filter(|marker| !marker.is_empty())
                    .collect::<Vec<_>>();
                owner_markers.sort();
                owner_markers.dedup();
                seeds.push(ObjectSeed {
                    object_id,
                    owner_profile: owner_profile.to_string(),
                    source_endpoint_id: source_endpoint_id.to_string(),
                    source_url: source_url.to_string(),
                    owner_markers,
                });
            }

            for child in object.values() {
                collect_object_seeds(
                    child,
                    owner_profile,
                    source_endpoint_id,
                    source_url,
                    limit,
                    seeds,
                );
                if seeds.len() >= limit {
                    break;
                }
            }
        }
        _ => {}
    }
}

fn object_identifier(object: &serde_json::Map<String, Value>) -> Option<String> {
    ["id", "object_id", "invoice_id", "uuid"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
}

fn is_owner_marker_key(key: &str) -> bool {
    matches!(
        key,
        "owner_id" | "owner_email" | "user_id" | "user_email" | "email" | "tenant_id"
    )
}

fn endpoint_looks_privileged(endpoint: &ApiEndpoint) -> bool {
    let normalized = endpoint.url_template.to_ascii_lowercase();
    normalized.contains("/admin")
        || normalized.contains("/internal")
        || normalized.contains("/manage")
        || endpoint.tags.iter().any(|tag| {
            matches!(
                tag.to_ascii_lowercase().as_str(),
                "admin" | "internal" | "privileged"
            )
        })
}

fn is_noise_path_segment(segment: &str) -> bool {
    let lowered = segment.to_ascii_lowercase();
    lowered == "api"
        || lowered == "rest"
        || lowered == "graphql"
        || (lowered.len() <= 3
            && lowered.starts_with('v')
            && lowered[1..].chars().all(|ch| ch.is_ascii_digit()))
}

fn normalize_resource_segment(segment: &str) -> String {
    let lowered = segment
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-')
        .to_ascii_lowercase();

    if lowered.ends_with("ies") && lowered.len() > 3 {
        format!("{}y", &lowered[..lowered.len() - 3])
    } else if lowered.ends_with('s') && lowered.len() > 3 {
        lowered[..lowered.len() - 1].to_string()
    } else {
        lowered
    }
}

fn join_url_template(base_url: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn path_parameters_from(path: &str) -> Vec<String> {
    let mut params = Vec::new();
    let mut rest = path;

    while let Some(start) = rest.find('{') {
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find('}') else {
            break;
        };
        let param = after_start[..end].trim();
        if !param.is_empty() {
            params.push(param.to_string());
        }
        rest = &after_start[end + 1..];
    }

    params
}

impl ResolvedCredential {
    pub fn none() -> Self {
        ResolvedCredential {
            scheme: AuthScheme::None,
            bearer_token: None,
            api_key_header: None,
            cookies: vec![],
            csrf_token_header: None,
            csrf_token: None,
            extra_headers: vec![],
            extra_cookies: vec![],
            reproduction_hint: "anonymous".to_string(),
        }
    }

    pub fn bearer(token: String, env_name: &str) -> Self {
        ResolvedCredential {
            scheme: AuthScheme::Bearer,
            bearer_token: Some(token),
            reproduction_hint: format!("Authorization: Bearer ${{{}}}", env_name),
            ..Self::none()
        }
    }

    pub fn api_key(header_name: String, value: String) -> Self {
        ResolvedCredential {
            scheme: AuthScheme::ApiKey,
            api_key_header: Some((header_name.clone(), value.clone())),
            reproduction_hint: format!("{}: {}", header_name, value),
            ..Self::none()
        }
    }

    pub fn cookie_session(
        cookie_name: &str,
        cookie_value: &str,
        csrf_header: Option<String>,
        csrf_value: Option<String>,
    ) -> Self {
        ResolvedCredential {
            scheme: AuthScheme::CookieSession,
            cookies: vec![(cookie_name.to_string(), cookie_value.to_string())],
            csrf_token_header: csrf_header,
            csrf_token: csrf_value,
            reproduction_hint: format!("Cookie: {}={}", cookie_name, cookie_value),
            ..Self::none()
        }
    }

    pub fn apply_to_spec(&self, spec: &mut HttpRequestSpec) {
        if let Some(ref token) = self.bearer_token {
            spec.bearer_token = Some(token.clone());
        }
        if let Some((name, value)) = &self.api_key_header {
            spec.headers.push((name.clone(), value.clone()));
        }
        for (name, value) in self.cookies.iter().chain(self.extra_cookies.iter()) {
            spec.cookies.push((name.clone(), value.clone()));
        }
        for (name, value) in &self.extra_headers {
            spec.headers.push((name.clone(), value.clone()));
        }
        if self.csrf_token_header.is_some() {
            spec.csrf_token_header = self.csrf_token_header.clone();
        }
        if self.csrf_token.is_some() {
            spec.csrf_token = self.csrf_token.clone();
        }
    }
}

fn lab_default_cookie_for_env(env_name: &str) -> Option<&'static str> {
    match env_name {
        "BALONCORE_USER_A_SESSION" => Some("lab-session-user-a"),
        "BALONCORE_USER_B_SESSION" => Some("lab-session-user-b"),
        "BALONCORE_ADMIN_SESSION" => Some("lab-session-admin"),
        _ => None,
    }
}

fn lab_default_api_key_for_env(env_name: &str) -> Option<&'static str> {
    match env_name {
        "BALONCORE_USER_A_API_KEY" => Some("lab-apikey-user-a"),
        "BALONCORE_USER_B_API_KEY" => Some("lab-apikey-user-b"),
        "BALONCORE_ADMIN_API_KEY" => Some("lab-apikey-admin"),
        _ => None,
    }
}

fn lab_default_bearer_token_for_env(env_name: &str) -> Option<&'static str> {
    match env_name {
        "BALONCORE_USER_A_TOKEN" => Some("lab-user-a-token"),
        "BALONCORE_USER_B_TOKEN" => Some("lab-user-b-token"),
        "BALONCORE_ADMIN_TOKEN" => Some("lab-admin-token"),
        _ => None,
    }
}

pub fn resolve_credential_from_profile(
    profile: &crate::config::AuthProfile,
) -> Result<ResolvedCredential, String> {
    let cred = match &profile.credential {
        None => ResolvedCredential::none(),
        Some(credential) => {
            if let Some(ref oauth2) = credential.oauth2 {
                let token_env = oauth2
                    .client_id_env
                    .as_deref()
                    .unwrap_or("BALONCORE_OAUTH2_CLIENT_ID");
                let client_id = std::env::var(token_env)
                    .ok()
                    .or_else(|| oauth2.client_id.clone())
                    .unwrap_or_default();
                let secret_env = oauth2
                    .client_secret_env
                    .as_deref()
                    .unwrap_or("BALONCORE_OAUTH2_CLIENT_SECRET");
                let client_secret = std::env::var(secret_env)
                    .ok()
                    .or_else(|| oauth2.client_secret.clone())
                    .unwrap_or_default();
                let redacted_secret = if client_secret.len() > 4 {
                    &client_secret[..4]
                } else {
                    &client_secret
                };
                ResolvedCredential {
                    scheme: AuthScheme::OAuth2,
                    bearer_token: Some(format!("oauth2-access-token-{}", client_id)),
                    reproduction_hint: format!(
                        "OAuth2 {} ({}) [secret: {}...]",
                        oauth2.grant_type.as_toml(),
                        oauth2.token_endpoint,
                        redacted_secret
                    ),
                    ..ResolvedCredential::none()
                }
            } else if let Some(ref cs) = credential.cookie_session {
                let cookie_value = cs.cookie_value_env.as_deref()
                    .and_then(|env| std::env::var(env).ok())
                    .or_else(|| cs.cookie_value.clone())
                    .or_else(|| {
                        cs.cookie_value_env.as_deref()
                            .and_then(lab_default_cookie_for_env)
                            .map(|s| s.to_string())
                    })
                    .ok_or_else(|| format!("cookie_session for profile `{}` requires cookie_value or cookie_value_env", profile.name))?;
                let csrf_value = cs
                    .csrf_token_env
                    .as_deref()
                    .and_then(|env| std::env::var(env).ok())
                    .or_else(|| cs.csrf_token_value.clone());
                ResolvedCredential::cookie_session(
                    &cs.cookie_name,
                    &cookie_value,
                    cs.csrf_token_header.clone(),
                    csrf_value,
                )
            } else if let Some(ref akh) = credential.api_key_header {
                let value = akh.header_value_env.as_deref()
                    .and_then(|env| std::env::var(env).ok())
                    .or_else(|| akh.header_value.clone())
                    .or_else(|| {
                        akh.header_value_env.as_deref()
                            .and_then(lab_default_api_key_for_env)
                            .map(|s| s.to_string())
                    })
                    .ok_or_else(|| format!("api_key_header for profile `{}` requires header_value or header_value_env", profile.name))?;
                ResolvedCredential::api_key(akh.header_name.clone(), value)
            } else if let Some(ref env_name) = credential.bearer_token_env {
                let token = std::env::var(env_name)
                    .ok()
                    .or_else(|| lab_default_bearer_token_for_env(env_name).map(|s| s.to_string()))
                    .ok_or_else(|| {
                        format!(
                            "environment variable `{}` is required for auth profile `{}`",
                            env_name, profile.name
                        )
                    })?;
                ResolvedCredential::bearer(token, env_name)
            } else if let Some(ref env_name) = credential.header_env {
                let value = std::env::var(env_name)
                    .ok()
                    .or_else(|| lab_default_api_key_for_env(env_name).map(|s| s.to_string()))
                    .ok_or_else(|| {
                        format!(
                            "environment variable `{}` is required for auth profile `{}`",
                            env_name, profile.name
                        )
                    })?;
                ResolvedCredential::api_key("X-API-Key".to_string(), value)
            } else if let Some(ref env_name) = credential.cookie_env {
                let value = std::env::var(env_name)
                    .ok()
                    .or_else(|| lab_default_cookie_for_env(env_name).map(|s| s.to_string()))
                    .ok_or_else(|| {
                        format!(
                            "environment variable `{}` is required for auth profile `{}`",
                            env_name, profile.name
                        )
                    })?;
                ResolvedCredential::cookie_session(
                    "session",
                    &value,
                    Some("X-CSRF-Token".to_string()),
                    None,
                )
            } else {
                ResolvedCredential::none()
            }
        }
    };
    Ok(cred)
}

impl OAuth2GrantType {
    pub fn as_toml(&self) -> &'static str {
        match self {
            OAuth2GrantType::ClientCredentials => "client_credentials",
            OAuth2GrantType::AuthorizationCode => "authorization_code",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> ApiEndpoint {
        ApiEndpoint {
            id: "GET /api/invoices/{id}".to_string(),
            method: HttpMethod::Get,
            url_template: "http://localhost:3000/api/invoices/{id}".to_string(),
            source: EndpointSource::Manual,
            requires_auth: Some(true),
            path_parameters: vec!["id".to_string()],
            tags: vec!["invoice".to_string()],
        }
    }

    fn exchange(id: &str, profile: &str, status: u16, body: &str) -> HttpExchange {
        HttpExchange {
            id: id.to_string(),
            profile: profile.to_string(),
            method: HttpMethod::Get,
            url: "http://localhost:3000/api/invoices/inv_2002".to_string(),
            status,
            response_headers: vec![("content-type".to_string(), "application/json".to_string())],
            response_body_excerpt: body.to_string(),
        }
    }

    #[test]
    fn verifies_cross_user_object_access() {
        let case = BolaValidationCase {
            endpoint: endpoint(),
            object_id: "inv_2002".to_string(),
            owner_profile: "user_b".to_string(),
            attacker_profile: "user_a".to_string(),
            owner_markers: vec!["user_b@example.test".to_string()],
            owner_exchange: exchange(
                "owner",
                "user_b",
                200,
                r#"{"id":"inv_2002","email":"user_b@example.test","amount":4200}"#,
            ),
            attacker_exchange: exchange(
                "attacker",
                "user_a",
                200,
                r#"{"id":"inv_2002","email":"user_b@example.test","amount":4200}"#,
            ),
            anonymous_exchange: Some(exchange("anon", "anonymous", 401, r#"{"error":"auth"}"#)),
        };

        let decision = BolaValidator::default().validate(&case);
        assert!(matches!(decision, BolaDecision::Verified(_)));
    }

    #[test]
    fn rejects_when_attacker_is_blocked() {
        let case = BolaValidationCase {
            endpoint: endpoint(),
            object_id: "inv_2002".to_string(),
            owner_profile: "user_b".to_string(),
            attacker_profile: "user_a".to_string(),
            owner_markers: vec!["user_b@example.test".to_string()],
            owner_exchange: exchange("owner", "user_b", 200, r#"{"id":"inv_2002"}"#),
            attacker_exchange: exchange("attacker", "user_a", 403, r#"{"error":"forbidden"}"#),
            anonymous_exchange: None,
        };

        let decision = BolaValidator::default().validate(&case);
        assert!(matches!(decision, BolaDecision::Rejected(_)));
    }

    #[test]
    fn rejects_public_objects_as_bola() {
        let body = r#"{"id":"inv_2002","public":true}"#;
        let case = BolaValidationCase {
            endpoint: endpoint(),
            object_id: "inv_2002".to_string(),
            owner_profile: "user_b".to_string(),
            attacker_profile: "user_a".to_string(),
            owner_markers: vec![],
            owner_exchange: exchange("owner", "user_b", 200, body),
            attacker_exchange: exchange("attacker", "user_a", 200, body),
            anonymous_exchange: Some(exchange("anon", "anonymous", 200, body)),
        };

        let decision = BolaValidator::default().validate(&case);
        assert!(matches!(decision, BolaDecision::Rejected(_)));
    }

    #[test]
    fn rejects_unrelated_attacker_response() {
        let case = BolaValidationCase {
            endpoint: endpoint(),
            object_id: "inv_2002".to_string(),
            owner_profile: "user_b".to_string(),
            attacker_profile: "user_a".to_string(),
            owner_markers: vec!["user_b@example.test".to_string()],
            owner_exchange: exchange(
                "owner",
                "user_b",
                200,
                r#"{"id":"inv_2002","email":"user_b@example.test","amount":4200}"#,
            ),
            attacker_exchange: exchange(
                "attacker",
                "user_a",
                200,
                r#"{"id":"inv_1001","email":"user_a@example.test","amount":100}"#,
            ),
            anonymous_exchange: None,
        };

        let decision = BolaValidator::default().validate(&case);
        assert!(matches!(decision, BolaDecision::Rejected(_)));
    }

    #[test]
    fn imports_openapi_endpoints_and_candidates() {
        let raw = r#"{
          "openapi": "3.0.0",
          "paths": {
            "/api/me": {
              "get": { "security": [{"bearerAuth": []}], "responses": {"200": {"description": "ok"}} }
            },
            "/api/invoices": {
              "get": { "security": [{"bearerAuth": []}], "responses": {"200": {"description": "ok"}} }
            },
            "/api/invoices/{id}": {
              "get": {
                "security": [{"bearerAuth": []}],
                "parameters": [{"name": "id", "in": "path", "required": true}],
                "responses": {"200": {"description": "ok"}}
              }
            }
          }
        }"#;

        let inventory = OpenApiInventory::from_json(
            "http://localhost:3000/openapi.json",
            "http://localhost:3000",
            raw,
        )
        .expect("valid inventory");

        assert_eq!(inventory.endpoints.len(), 3);
        assert_eq!(inventory.seed_candidates.len(), 1);
        assert_eq!(
            inventory.seed_candidates[0].endpoint.id,
            "GET /api/invoices"
        );
        assert_eq!(inventory.bola_candidates.len(), 1);
        assert_eq!(
            inventory.bola_candidates[0].endpoint.id,
            "GET /api/invoices/{id}"
        );
        assert_eq!(inventory.bola_candidates[0].path_parameter, "id");
    }

    #[test]
    fn extracts_object_seeds_from_json_response() {
        let raw = r#"{
          "items": [
            {"id": "inv_2002", "owner_id": "user_b", "owner_email": "user_b@example.test"},
            {"id": "inv_2003", "owner_id": "user_b"}
          ]
        }"#;

        let seeds = ObjectSeed::from_json_response(
            "user_b",
            "GET /api/invoices",
            "http://localhost:3000/api/invoices",
            raw,
            10,
        )
        .expect("seed extraction");

        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].object_id, "inv_2002");
        assert_eq!(
            seeds[0].owner_markers,
            vec!["user_b".to_string(), "user_b@example.test".to_string()]
        );
    }

    #[test]
    fn classifies_same_role_cross_object_access_as_bola() {
        let case = BolaValidationCase {
            endpoint: endpoint(),
            object_id: "inv_2002".to_string(),
            owner_profile: "user_b".to_string(),
            attacker_profile: "user_a".to_string(),
            owner_markers: vec!["user_b@example.test".to_string()],
            owner_exchange: exchange(
                "owner",
                "user_b",
                200,
                r#"{"id":"inv_2002","email":"user_b@example.test"}"#,
            ),
            attacker_exchange: exchange(
                "attacker",
                "user_a",
                200,
                r#"{"id":"inv_2002","email":"user_b@example.test"}"#,
            ),
            anonymous_exchange: Some(exchange("anon", "anonymous", 401, r#"{"error":"auth"}"#)),
        };

        let observation = AuthorizationMatrixObservation::classify(&case, "user", "user");
        assert_eq!(
            observation.classification,
            AuthorizationClass::BrokenObjectLevelAuthorization
        );
    }

    #[test]
    fn classifies_admin_endpoint_user_access_as_bfla() {
        let mut admin_endpoint = endpoint();
        admin_endpoint.id = "GET /api/admin/reports/{id}".to_string();
        admin_endpoint.url_template = "http://localhost:3000/api/admin/reports/{id}".to_string();
        admin_endpoint.tags = vec!["admin".to_string()];
        let case = BolaValidationCase {
            endpoint: admin_endpoint,
            object_id: "adm_9001".to_string(),
            owner_profile: "admin".to_string(),
            attacker_profile: "user_a".to_string(),
            owner_markers: vec!["admin@example.test".to_string()],
            owner_exchange: exchange(
                "owner",
                "admin",
                200,
                r#"{"id":"adm_9001","owner_email":"admin@example.test"}"#,
            ),
            attacker_exchange: exchange(
                "attacker",
                "user_a",
                200,
                r#"{"id":"adm_9001","owner_email":"admin@example.test"}"#,
            ),
            anonymous_exchange: Some(exchange("anon", "anonymous", 401, r#"{"error":"auth"}"#)),
        };

        let observation = AuthorizationMatrixObservation::classify(&case, "admin", "user");
        assert_eq!(
            observation.classification,
            AuthorizationClass::BrokenFunctionLevelAuthorization
        );
    }

    #[test]
    fn classifies_admin_access_as_intended_privileged_access() {
        let case = BolaValidationCase {
            endpoint: endpoint(),
            object_id: "inv_2002".to_string(),
            owner_profile: "user_b".to_string(),
            attacker_profile: "admin".to_string(),
            owner_markers: vec!["user_b@example.test".to_string()],
            owner_exchange: exchange(
                "owner",
                "user_b",
                200,
                r#"{"id":"inv_2002","email":"user_b@example.test"}"#,
            ),
            attacker_exchange: exchange(
                "attacker",
                "admin",
                200,
                r#"{"id":"inv_2002","email":"user_b@example.test"}"#,
            ),
            anonymous_exchange: Some(exchange("anon", "anonymous", 401, r#"{"error":"auth"}"#)),
        };

        let observation = AuthorizationMatrixObservation::classify(&case, "user", "admin");
        assert_eq!(
            observation.classification,
            AuthorizationClass::IntendedPrivilegedAccess
        );
    }

    #[test]
    fn matches_seed_to_same_resource_family() {
        let candidate = BolaCandidate::from_endpoint(&endpoint()).expect("candidate");
        let seed = ObjectSeed {
            object_id: "inv_2002".to_string(),
            owner_profile: "user_b".to_string(),
            source_endpoint_id: "GET /api/invoices".to_string(),
            source_url: "http://localhost:3000/api/invoices".to_string(),
            owner_markers: vec![],
        };

        let decision = candidate.matches_seed(&seed);
        assert!(decision.matches);
        assert_eq!(decision.candidate_resource.key, "invoice");
        assert_eq!(
            decision.seed_resource.expect("seed resource").key,
            "invoice"
        );
    }

    #[test]
    fn rejects_seed_candidate_resource_mismatch() {
        let candidate = BolaCandidate::from_endpoint(&endpoint()).expect("candidate");
        let seed = ObjectSeed {
            object_id: "adm_9001".to_string(),
            owner_profile: "admin".to_string(),
            source_endpoint_id: "GET /api/admin/reports".to_string(),
            source_url: "http://localhost:3000/api/admin/reports".to_string(),
            owner_markers: vec![],
        };

        let decision = candidate.matches_seed(&seed);
        assert!(!decision.matches);
        assert_eq!(decision.candidate_resource.key, "invoice");
        assert_eq!(
            decision.seed_resource.expect("seed resource").key,
            "admin/report"
        );
    }

    #[test]
    fn allows_manual_seed_without_resource_context() {
        let candidate = BolaCandidate::from_endpoint(&endpoint()).expect("candidate");
        let seed = ObjectSeed {
            object_id: "inv_2002".to_string(),
            owner_profile: "user_b".to_string(),
            source_endpoint_id: "manual".to_string(),
            source_url: "cli:--object-id".to_string(),
            owner_markers: vec![],
        };

        assert!(candidate.matches_seed(&seed).matches);
    }

    #[test]
    fn analyzes_sensitive_fields_and_response_shape_for_bola() {
        let case = BolaValidationCase {
            endpoint: endpoint(),
            object_id: "inv_2002".to_string(),
            owner_profile: "user_b".to_string(),
            attacker_profile: "user_a".to_string(),
            owner_markers: vec!["user_b@example.test".to_string()],
            owner_exchange: exchange(
                "owner",
                "user_b",
                200,
                r#"{"id":"inv_2002","owner_email":"user_b@example.test","amount_cents":4200}"#,
            ),
            attacker_exchange: exchange(
                "attacker",
                "user_a",
                200,
                r#"{"id":"inv_2002","owner_email":"user_b@example.test","amount_cents":4200}"#,
            ),
            anonymous_exchange: Some(exchange("anon", "anonymous", 401, r#"{"error":"auth"}"#)),
        };
        let observation = AuthorizationMatrixObservation::classify(&case, "user", "user");
        let impact = ResponseImpactAnalysis::analyze(&case, &observation.classification);

        assert_eq!(impact.severity, ImpactSeverity::High);
        assert_eq!(impact.shape_similarity, 1.0);
        assert!(impact
            .sensitive_fields
            .iter()
            .any(|field| field.category == SensitiveDataCategory::EmailAddress));
        assert!(impact
            .sensitive_fields
            .iter()
            .any(|field| field.category == SensitiveDataCategory::Financial));
    }

    #[test]
    fn ranks_privileged_business_data_higher_for_bfla() {
        let mut admin_endpoint = endpoint();
        admin_endpoint.id = "GET /api/admin/reports/{id}".to_string();
        admin_endpoint.url_template = "http://localhost:3000/api/admin/reports/{id}".to_string();
        admin_endpoint.tags = vec!["admin".to_string()];
        let case = BolaValidationCase {
            endpoint: admin_endpoint,
            object_id: "adm_9001".to_string(),
            owner_profile: "admin".to_string(),
            attacker_profile: "user_a".to_string(),
            owner_markers: vec!["admin@example.test".to_string()],
            owner_exchange: exchange(
                "owner",
                "admin",
                200,
                r#"{"id":"adm_9001","owner_email":"admin@example.test","sensitivity":"admin-only"}"#,
            ),
            attacker_exchange: exchange(
                "attacker",
                "user_a",
                200,
                r#"{"id":"adm_9001","owner_email":"admin@example.test","sensitivity":"admin-only"}"#,
            ),
            anonymous_exchange: Some(exchange("anon", "anonymous", 401, r#"{"error":"auth"}"#)),
        };
        let observation = AuthorizationMatrixObservation::classify(&case, "admin", "user");
        let impact = ResponseImpactAnalysis::analyze(&case, &observation.classification);

        assert_eq!(impact.severity, ImpactSeverity::Critical);
        assert!(impact
            .sensitive_fields
            .iter()
            .any(|field| field.category == SensitiveDataCategory::PrivilegedBusinessData));
    }

    #[test]
    fn builds_remediation_plan_with_regression_checks_for_bola() {
        let case = BolaValidationCase {
            endpoint: endpoint(),
            object_id: "inv_2002".to_string(),
            owner_profile: "user_b".to_string(),
            attacker_profile: "user_a".to_string(),
            owner_markers: vec!["user_b@example.test".to_string()],
            owner_exchange: exchange(
                "owner",
                "user_b",
                200,
                r#"{"id":"inv_2002","owner_email":"user_b@example.test","amount_cents":4200}"#,
            ),
            attacker_exchange: exchange(
                "attacker",
                "user_a",
                200,
                r#"{"id":"inv_2002","owner_email":"user_b@example.test","amount_cents":4200}"#,
            ),
            anonymous_exchange: Some(exchange("anon", "anonymous", 401, r#"{"error":"auth"}"#)),
        };
        let observation = AuthorizationMatrixObservation::classify(&case, "user", "user");
        let impact = ResponseImpactAnalysis::analyze(&case, &observation.classification);
        let plan = RemediationPlan::for_authorization_finding(
            &case,
            &observation,
            &impact,
            Some("Authorization: Bearer ${OWNER_TOKEN}".to_string()),
            Some("Authorization: Bearer ${TESTED_TOKEN}".to_string()),
        );

        assert_eq!(
            plan.classification,
            AuthorizationClass::BrokenObjectLevelAuthorization
        );
        assert_eq!(plan.regression_checks.len(), 3);
        assert_eq!(plan.regression_checks[1].expected_statuses, vec![403, 404]);
        assert!(plan
            .implementation_steps
            .iter()
            .any(|step| step.contains("scope the object lookup")));
        assert!(plan
            .verification_notes
            .iter()
            .any(|note| note.contains("$.owner_email")));
    }

    #[test]
    fn summarizes_regression_results_as_fixed_or_still_failing() {
        let plan = RemediationPlan {
            classification: AuthorizationClass::BrokenObjectLevelAuthorization,
            severity: ImpactSeverity::High,
            endpoint_id: "GET /api/invoices/{id}".to_string(),
            object_id: "inv_2002".to_string(),
            summary: "summary".to_string(),
            implementation_steps: vec![],
            regression_checks: vec![],
            verification_notes: vec![],
        };
        let fixed = RegressionRunReport::from_results(
            &plan,
            vec![RegressionCheckResult {
                name: "tested-profile-blocked".to_string(),
                profile: "user_a".to_string(),
                url: "http://localhost/api/invoices/inv_2002".to_string(),
                expected_statuses: vec![403, 404],
                actual_status: 403,
                passed: true,
                purpose: "blocked".to_string(),
            }],
        );
        assert_eq!(fixed.verdict, RegressionVerdict::Fixed);

        let still_failing = RegressionRunReport::from_results(
            &plan,
            vec![RegressionCheckResult {
                name: "tested-profile-blocked".to_string(),
                profile: "user_a".to_string(),
                url: "http://localhost/api/invoices/inv_2002".to_string(),
                expected_statuses: vec![403, 404],
                actual_status: 200,
                passed: false,
                purpose: "blocked".to_string(),
            }],
        );
        assert_eq!(still_failing.verdict, RegressionVerdict::StillFailing);
    }

    #[test]
    fn auth_scheme_detection() {
        use crate::config::{
            ApiKeyHeaderRef, AuthCredentialRef, AuthProfile, CookieSessionRef, OAuth2Ref,
        };

        let anonymous = AuthProfile {
            name: "anon".to_string(),
            role: "anonymous".to_string(),
            description: None,
            credential: None,
            object_markers: vec![],
        };
        assert_eq!(anonymous.auth_scheme(), "none");

        let bearer = AuthProfile {
            name: "bearer_user".to_string(),
            role: "user".to_string(),
            description: None,
            credential: Some(AuthCredentialRef {
                bearer_token_env: Some("TOKEN".to_string()),
                cookie_env: None,
                header_env: None,
                api_key_header: None,
                cookie_session: None,
                oauth2: None,
                extra_headers: vec![],
                extra_cookies: vec![],
            }),
            object_markers: vec![],
        };
        assert_eq!(bearer.auth_scheme(), "bearer");

        let api_key = AuthProfile {
            name: "apikey_user".to_string(),
            role: "user".to_string(),
            description: None,
            credential: Some(AuthCredentialRef {
                bearer_token_env: None,
                cookie_env: None,
                header_env: None,
                api_key_header: Some(ApiKeyHeaderRef {
                    header_name: "X-API-Key".to_string(),
                    header_value_env: None,
                    header_value: Some("my-key".to_string()),
                }),
                cookie_session: None,
                oauth2: None,
                extra_headers: vec![],
                extra_cookies: vec![],
            }),
            object_markers: vec![],
        };
        assert_eq!(api_key.auth_scheme(), "api_key");

        let cookie = AuthProfile {
            name: "cookie_user".to_string(),
            role: "user".to_string(),
            description: None,
            credential: Some(AuthCredentialRef {
                bearer_token_env: None,
                cookie_env: None,
                header_env: None,
                api_key_header: None,
                cookie_session: Some(CookieSessionRef {
                    cookie_name: "session".to_string(),
                    cookie_value_env: None,
                    cookie_value: Some("lab-session-user-a".to_string()),
                    csrf_token_header: Some("X-CSRF-Token".to_string()),
                    csrf_token_env: None,
                    csrf_token_value: Some("csrf-123".to_string()),
                    login_endpoint: None,
                    login_body: None,
                }),
                oauth2: None,
                extra_headers: vec![],
                extra_cookies: vec![],
            }),
            object_markers: vec![],
        };
        assert_eq!(cookie.auth_scheme(), "cookie_session");

        let oauth2 = AuthProfile {
            name: "oauth_user".to_string(),
            role: "user".to_string(),
            description: None,
            credential: Some(AuthCredentialRef {
                bearer_token_env: None,
                cookie_env: None,
                header_env: None,
                api_key_header: None,
                cookie_session: None,
                oauth2: Some(OAuth2Ref {
                    grant_type: OAuth2GrantType::ClientCredentials,
                    token_endpoint: "https://auth.example.com/token".to_string(),
                    client_id_env: Some("OAUTH_CLIENT_ID".to_string()),
                    client_id: None,
                    client_secret_env: Some("OAUTH_CLIENT_SECRET".to_string()),
                    client_secret: None,
                    scope: Some("read".to_string()),
                    resource: None,
                }),
                extra_headers: vec![],
                extra_cookies: vec![],
            }),
            object_markers: vec![],
        };
        assert_eq!(oauth2.auth_scheme(), "oauth2");
    }

    #[test]
    fn resolve_credential_bearer() {
        use crate::config::{AuthCredentialRef, AuthProfile};
        let profile = AuthProfile {
            name: "user_a".to_string(),
            role: "user".to_string(),
            description: None,
            credential: Some(AuthCredentialRef {
                bearer_token_env: Some("BALONCORE_USER_A_TOKEN".to_string()),
                cookie_env: None,
                header_env: None,
                api_key_header: None,
                cookie_session: None,
                oauth2: None,
                extra_headers: vec![],
                extra_cookies: vec![],
            }),
            object_markers: vec![],
        };
        let cred = resolve_credential_from_profile(&profile).unwrap();
        assert!(matches!(cred.scheme, AuthScheme::Bearer));
        assert_eq!(cred.bearer_token.as_deref(), Some("lab-user-a-token"));
        assert!(cred.reproduction_hint.contains("BALONCORE_USER_A_TOKEN"));
    }

    #[test]
    fn resolve_credential_api_key() {
        use crate::config::{ApiKeyHeaderRef, AuthCredentialRef, AuthProfile};
        let profile = AuthProfile {
            name: "apikey_user_b".to_string(),
            role: "user".to_string(),
            description: None,
            credential: Some(AuthCredentialRef {
                bearer_token_env: None,
                cookie_env: None,
                header_env: None,
                api_key_header: Some(ApiKeyHeaderRef {
                    header_name: "X-API-Key".to_string(),
                    header_value_env: None,
                    header_value: Some("lab-apikey-user-b".to_string()),
                }),
                cookie_session: None,
                oauth2: None,
                extra_headers: vec![],
                extra_cookies: vec![],
            }),
            object_markers: vec![],
        };
        let cred = resolve_credential_from_profile(&profile).unwrap();
        assert!(matches!(cred.scheme, AuthScheme::ApiKey));
        assert_eq!(cred.api_key_header.as_ref().unwrap().0, "X-API-Key");
        assert_eq!(cred.api_key_header.as_ref().unwrap().1, "lab-apikey-user-b");
    }

    #[test]
    fn resolve_credential_cookie_session() {
        use crate::config::{AuthCredentialRef, AuthProfile, CookieSessionRef};
        let profile = AuthProfile {
            name: "cookie_user_a".to_string(),
            role: "user".to_string(),
            description: None,
            credential: Some(AuthCredentialRef {
                bearer_token_env: None,
                cookie_env: None,
                header_env: None,
                api_key_header: None,
                cookie_session: Some(CookieSessionRef {
                    cookie_name: "session".to_string(),
                    cookie_value_env: None,
                    cookie_value: Some("lab-session-user-a".to_string()),
                    csrf_token_header: Some("X-CSRF-Token".to_string()),
                    csrf_token_env: None,
                    csrf_token_value: Some("lab-csrf-token-user-a".to_string()),
                    login_endpoint: None,
                    login_body: None,
                }),
                oauth2: None,
                extra_headers: vec![],
                extra_cookies: vec![],
            }),
            object_markers: vec![],
        };
        let cred = resolve_credential_from_profile(&profile).unwrap();
        assert!(matches!(cred.scheme, AuthScheme::CookieSession));
        assert_eq!(cred.cookies[0].0, "session");
        assert_eq!(cred.cookies[0].1, "lab-session-user-a");
        assert_eq!(cred.csrf_token_header.as_deref(), Some("X-CSRF-Token"));
        assert_eq!(cred.csrf_token.as_deref(), Some("lab-csrf-token-user-a"));
    }

    #[test]
    fn resolve_credential_anonymous() {
        use crate::config::AuthProfile;
        let profile = AuthProfile {
            name: "anonymous".to_string(),
            role: "anonymous".to_string(),
            description: None,
            credential: None,
            object_markers: vec![],
        };
        let cred = resolve_credential_from_profile(&profile).unwrap();
        assert!(matches!(cred.scheme, AuthScheme::None));
        assert!(cred.bearer_token.is_none());
        assert!(cred.api_key_header.is_none());
        assert!(cred.cookies.is_empty());
    }

    #[test]
    fn apply_credential_to_spec_bearer() {
        let cred = ResolvedCredential::bearer("test-token".to_string(), "MY_TOKEN");
        let mut spec = HttpRequestSpec {
            id: "test".to_string(),
            profile: "user".to_string(),
            method: HttpMethod::Get,
            url: "http://localhost/api/me".to_string(),
            bearer_token: None,
            cookies: vec![],
            headers: vec![],
            csrf_token_header: None,
            csrf_token: None,
        };
        cred.apply_to_spec(&mut spec);
        assert_eq!(spec.bearer_token.as_deref(), Some("test-token"));
    }

    #[test]
    fn apply_credential_to_spec_api_key() {
        let cred = ResolvedCredential::api_key("X-API-Key".to_string(), "my-key-123".to_string());
        let mut spec = HttpRequestSpec {
            id: "test".to_string(),
            profile: "user".to_string(),
            method: HttpMethod::Get,
            url: "http://localhost/api/me".to_string(),
            bearer_token: None,
            cookies: vec![],
            headers: vec![],
            csrf_token_header: None,
            csrf_token: None,
        };
        cred.apply_to_spec(&mut spec);
        assert!(spec
            .headers
            .contains(&("X-API-Key".to_string(), "my-key-123".to_string())));
    }

    #[test]
    fn apply_credential_to_spec_cookie_session() {
        let cred = ResolvedCredential::cookie_session(
            "session",
            "sess-abc",
            Some("X-CSRF-Token".to_string()),
            Some("csrf-xyz".to_string()),
        );
        let mut spec = HttpRequestSpec {
            id: "test".to_string(),
            profile: "user".to_string(),
            method: HttpMethod::Get,
            url: "http://localhost/api/me".to_string(),
            bearer_token: None,
            cookies: vec![],
            headers: vec![],
            csrf_token_header: None,
            csrf_token: None,
        };
        cred.apply_to_spec(&mut spec);
        assert!(spec
            .cookies
            .contains(&("session".to_string(), "sess-abc".to_string())));
        assert_eq!(spec.csrf_token_header.as_deref(), Some("X-CSRF-Token"));
        assert_eq!(spec.csrf_token.as_deref(), Some("csrf-xyz"));
    }

    #[test]
    fn tenant_isolation_classification_cross_tenant_access() {
        let owner = HttpExchange {
            id: "owner-bola".to_string(),
            profile: "org_a_member".to_string(),
            method: HttpMethod::Get,
            url: "http://localhost/api/orgs/org-b/projects/proj-b-001".to_string(),
            status: 200,
            response_headers: vec![],
            response_body_excerpt:
                r#"{"id":"proj-b-001","org_id":"org-b","name":"Beta Mobile App"}"#.to_string(),
        };
        let attacker = HttpExchange {
            id: "attacker-bola".to_string(),
            profile: "org_a_member".to_string(),
            method: HttpMethod::Get,
            url: "http://localhost/api/orgs/org-b/projects/proj-b-001".to_string(),
            status: 200,
            response_headers: vec![],
            response_body_excerpt: r#"{"id":"proj-b-001","org_id":"org-b","name":"Beta Mobile App","cross_tenant":true}"#.to_string(),
        };
        let case = BolaValidationCase {
            endpoint: ApiEndpoint {
                id: "GET-/api/orgs/{orgId}/projects/{projectId}".to_string(),
                method: HttpMethod::Get,
                url_template: "/api/orgs/{orgId}/projects/{projectId}".to_string(),
                source: EndpointSource::OpenApi,
                requires_auth: Some(true),
                path_parameters: vec!["orgId".to_string(), "projectId".to_string()],
                tags: vec!["tenant-isolation".to_string()],
            },
            object_id: "proj-b-001".to_string(),
            owner_profile: "org_b_member".to_string(),
            attacker_profile: "org_a_member".to_string(),
            owner_markers: vec!["org-b".to_string(), "member_b".to_string()],
            owner_exchange: owner,
            attacker_exchange: attacker,
            anonymous_exchange: Some(HttpExchange {
                id: "anon-bola".to_string(),
                profile: "anonymous".to_string(),
                method: HttpMethod::Get,
                url: "http://localhost/api/orgs/org-b/projects/proj-b-001".to_string(),
                status: 401,
                response_headers: vec![],
                response_body_excerpt: r#"{"error":"authentication required"}"#.to_string(),
            }),
        };
        let observation = AuthorizationMatrixObservation::classify_with_tenant(
            &case,
            "member",
            "member",
            Some("org-a"),
            Some("org-b"),
        );
        assert_eq!(
            observation.classification,
            AuthorizationClass::TenantIsolationViolation
        );
        assert!(observation.reason.contains("org-a"));
        assert!(observation.reason.contains("org-b"));
        assert_eq!(observation.tested_tenant.as_deref(), Some("org-a"));
        assert_eq!(observation.owner_tenant.as_deref(), Some("org-b"));
    }

    #[test]
    fn tenant_isolation_decoy_is_blocked_as_expected() {
        let owner = HttpExchange {
            id: "owner-bola".to_string(),
            profile: "org_b_member".to_string(),
            method: HttpMethod::Get,
            url: "http://localhost/api/orgs/org-b/projects/proj-b-secret".to_string(),
            status: 200,
            response_headers: vec![],
            response_body_excerpt:
                r#"{"id":"proj-b-secret","org_id":"org-b","name":"Beta Merger Plans"}"#.to_string(),
        };
        let attacker = HttpExchange {
            id: "attacker-bola".to_string(),
            profile: "org_a_member".to_string(),
            method: HttpMethod::Get,
            url: "http://localhost/api/orgs/org-b/projects/proj-b-secret".to_string(),
            status: 403,
            response_headers: vec![],
            response_body_excerpt: r#"{"error":"access denied"}"#.to_string(),
        };
        let case = BolaValidationCase {
            endpoint: ApiEndpoint {
                id: "GET-/api/orgs/{orgId}/projects/{projectId}".to_string(),
                method: HttpMethod::Get,
                url_template: "/api/orgs/{orgId}/projects/{projectId}".to_string(),
                source: EndpointSource::OpenApi,
                requires_auth: Some(true),
                path_parameters: vec!["orgId".to_string(), "projectId".to_string()],
                tags: vec!["tenant-isolation".to_string()],
            },
            object_id: "proj-b-secret".to_string(),
            owner_profile: "org_b_member".to_string(),
            attacker_profile: "org_a_member".to_string(),
            owner_markers: vec!["org-b".to_string()],
            owner_exchange: owner,
            attacker_exchange: attacker,
            anonymous_exchange: None,
        };
        let observation = AuthorizationMatrixObservation::classify_with_tenant(
            &case,
            "member",
            "member",
            Some("org-a"),
            Some("org-b"),
        );
        assert_eq!(
            observation.classification,
            AuthorizationClass::BlockedAsExpected
        );
    }

    #[test]
    fn same_tenant_bola_not_tenant_isolation() {
        let owner = HttpExchange {
            id: "owner-bola".to_string(),
            profile: "org_a_member_a".to_string(),
            method: HttpMethod::Get,
            url: "http://localhost/api/orgs/org-a/projects/proj-a-001".to_string(),
            status: 200,
            response_headers: vec![],
            response_body_excerpt: r#"{"id":"proj-a-001","org_id":"org-a"}"#.to_string(),
        };
        let attacker = HttpExchange {
            id: "attacker-bola".to_string(),
            profile: "org_a_member_b".to_string(),
            method: HttpMethod::Get,
            url: "http://localhost/api/orgs/org-a/projects/proj-a-001".to_string(),
            status: 200,
            response_headers: vec![],
            response_body_excerpt: r#"{"id":"proj-a-001","org_id":"org-a"}"#.to_string(),
        };
        let case = BolaValidationCase {
            endpoint: ApiEndpoint {
                id: "GET-/api/orgs/{orgId}/projects/{projectId}".to_string(),
                method: HttpMethod::Get,
                url_template: "/api/orgs/{orgId}/projects/{projectId}".to_string(),
                source: EndpointSource::OpenApi,
                requires_auth: Some(true),
                path_parameters: vec!["orgId".to_string(), "projectId".to_string()],
                tags: vec![],
            },
            object_id: "proj-a-001".to_string(),
            owner_profile: "org_a_member_a".to_string(),
            attacker_profile: "org_a_member_b".to_string(),
            owner_markers: vec!["org-a".to_string()],
            owner_exchange: owner,
            attacker_exchange: attacker,
            anonymous_exchange: None,
        };
        let observation = AuthorizationMatrixObservation::classify_with_tenant(
            &case,
            "member",
            "member",
            Some("org-a"),
            Some("org-a"),
        );
        assert_eq!(
            observation.classification,
            AuthorizationClass::BrokenObjectLevelAuthorization
        );
    }

    #[test]
    fn graphql_introspection_parses_schema() {
        let introspection = r#"{
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": null,
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [
                                { "name": "me", "type": { "kind": "OBJECT", "name": "User", "ofType": null }, "args": [], "description": "Current user", "isDeprecated": false },
                                { "name": "project", "type": { "kind": "OBJECT", "name": "Project", "ofType": null }, "args": [
                                    { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "defaultValue": null }
                                ], "description": "Get project by ID", "isDeprecated": false },
                                { "name": "projects", "type": { "kind": "LIST", "name": null, "ofType": { "kind": "OBJECT", "name": "Project", "ofType": null } }, "args": [
                                    { "name": "orgId", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "defaultValue": null }
                                ], "description": "List projects", "isDeprecated": false }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "Project",
                            "fields": [
                                { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "args": [], "isDeprecated": false },
                                { "name": "name", "type": { "kind": "SCALAR", "name": "String", "ofType": null }, "args": [], "isDeprecated": false },
                                { "name": "org_id", "type": { "kind": "SCALAR", "name": "String", "ofType": null }, "args": [], "isDeprecated": false }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "User",
                            "fields": [
                                { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "args": [], "isDeprecated": false },
                                { "name": "email", "type": { "kind": "SCALAR", "name": "String", "ofType": null }, "args": [], "isDeprecated": false }
                            ]
                        }
                    ]
                }
            }
        }"#;
        let inventory = GraphQlInventory::from_introspection_json(
            "http://localhost:3010/graphql",
            introspection,
        )
        .unwrap();
        assert_eq!(inventory.queries.len(), 3);
        assert_eq!(inventory.mutations.len(), 0);
        assert!(inventory.queries.iter().any(|q| q.name == "project"));
        assert!(inventory.queries.iter().any(|q| q.name == "me"));
        assert!(inventory.queries.iter().any(|q| q.name == "projects"));
    }

    #[test]
    fn graphql_introspection_extracts_bola_candidates() {
        let introspection = r#"{
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": null,
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [
                                { "name": "project", "type": { "kind": "OBJECT", "name": "Project", "ofType": null }, "args": [
                                    { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "defaultValue": null }
                                ], "description": "Get project by ID", "isDeprecated": false },
                                { "name": "me", "type": { "kind": "OBJECT", "name": "User", "ofType": null }, "args": [], "description": "Current user", "isDeprecated": false }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "Project",
                            "fields": [
                                { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "args": [], "isDeprecated": false }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "User",
                            "fields": [
                                { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "args": [], "isDeprecated": false }
                            ]
                        }
                    ]
                }
            }
        }"#;
        let inventory = GraphQlInventory::from_introspection_json(
            "http://localhost:3010/graphql",
            introspection,
        )
        .unwrap();
        assert_eq!(inventory.bola_candidates.len(), 1);
        let candidate = &inventory.bola_candidates[0];
        assert_eq!(candidate.operation_name, "project");
        assert_eq!(candidate.id_argument, "id");
        assert_eq!(candidate.return_type_name, "Project");
        assert!(candidate.confidence >= 0.60);
        assert_eq!(candidate.endpoint.source, EndpointSource::GraphQl);
    }

    #[test]
    fn graphql_introspection_rejects_no_schema() {
        let result = GraphQlInventory::from_introspection_json(
            "http://localhost:3010/graphql",
            r#"{"data": {}}"#,
        );
        assert!(result.is_err());
        match result {
            Err(GraphQlInventoryError::MissingSchema) => {}
            other => panic!("expected MissingSchema, got {other:?}"),
        }
    }

    #[test]
    fn graphql_introspection_rejects_errors() {
        let result = GraphQlInventory::from_introspection_json(
            "http://localhost:3010/graphql",
            r#"{"errors": [{"message": "introspection not allowed"}]}"#,
        );
        assert!(result.is_err());
        match result {
            Err(GraphQlInventoryError::IntrospectionErrors(msg)) => {
                assert!(msg.contains("introspection not allowed"));
            }
            other => panic!("expected IntrospectionErrors, got {other:?}"),
        }
    }

    #[test]
    fn graphql_introspection_with_mutations() {
        let introspection = r#"{
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": { "name": "Mutation" },
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [
                                { "name": "invoice", "type": { "kind": "OBJECT", "name": "Invoice", "ofType": null }, "args": [
                                    { "name": "invoiceId", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "defaultValue": null }
                                ], "isDeprecated": false }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "Mutation",
                            "fields": [
                                { "name": "updateInvoice", "type": { "kind": "OBJECT", "name": "Invoice", "ofType": null }, "args": [
                                    { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "defaultValue": null },
                                    { "name": "amount", "type": { "kind": "SCALAR", "name": "Int", "ofType": null }, "defaultValue": null }
                                ], "isDeprecated": false }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "Invoice",
                            "fields": [
                                { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "args": [], "isDeprecated": false },
                                { "name": "amount", "type": { "kind": "SCALAR", "name": "Int", "ofType": null }, "args": [], "isDeprecated": false }
                            ]
                        }
                    ]
                }
            }
        }"#;
        let inventory = GraphQlInventory::from_introspection_json(
            "http://localhost:3010/graphql",
            introspection,
        )
        .unwrap();
        assert_eq!(inventory.queries.len(), 1);
        assert_eq!(inventory.mutations.len(), 1);
        assert_eq!(inventory.queries[0].name, "invoice");
        assert_eq!(inventory.mutations[0].name, "updateInvoice");
        assert_eq!(inventory.bola_candidates.len(), 2);
        let mutation_candidate = inventory
            .bola_candidates
            .iter()
            .find(|c| c.operation_name == "updateInvoice")
            .unwrap();
        assert_eq!(
            mutation_candidate.operation_type,
            GraphQlOperationType::Mutation
        );
    }

    #[test]
    fn graphql_bola_validator_verifies_cross_user_access() {
        let gql_endpoint = ApiEndpoint {
            id: "GQL QUERY project".to_string(),
            method: HttpMethod::Post,
            url_template: "http://localhost:3010/graphql".to_string(),
            source: EndpointSource::GraphQl,
            requires_auth: Some(true),
            path_parameters: vec![],
            tags: vec![
                "graphql".to_string(),
                "query".to_string(),
                "project".to_string(),
            ],
        };
        let owner_exchange = HttpExchange {
            id: "gql-owner".to_string(),
            profile: "org_b_member".to_string(),
            method: HttpMethod::Post,
            url: "http://localhost:3010/graphql".to_string(),
            status: 200,
            response_headers: vec![],
            response_body_excerpt: r#"{"data":{"project":{"id":"proj-b-001","name":"Beta Mobile App","org_id":"org-b","owner_id":"member_b"}}}"#.to_string(),
        };
        let attacker_exchange = HttpExchange {
            id: "gql-attacker".to_string(),
            profile: "org_a_member".to_string(),
            method: HttpMethod::Post,
            url: "http://localhost:3010/graphql".to_string(),
            status: 200,
            response_headers: vec![],
            response_body_excerpt: r#"{"data":{"project":{"id":"proj-b-001","name":"Beta Mobile App","org_id":"org-b","owner_id":"member_b","cross_tenant":true}}}"#.to_string(),
        };
        let anonymous_exchange = HttpExchange {
            id: "gql-anon".to_string(),
            profile: "anonymous".to_string(),
            method: HttpMethod::Post,
            url: "http://localhost:3010/graphql".to_string(),
            status: 401,
            response_headers: vec![],
            response_body_excerpt: r#"{"errors":[{"message":"authentication required"}]}"#
                .to_string(),
        };
        let case = GraphQlBolaValidationCase {
            endpoint: gql_endpoint,
            operation_name: "project".to_string(),
            operation_type: GraphQlOperationType::Query,
            id_argument: "id".to_string(),
            object_id: "proj-b-001".to_string(),
            owner_profile: "org_b_member".to_string(),
            attacker_profile: "org_a_member".to_string(),
            owner_markers: vec!["org-b".to_string(), "member_b".to_string()],
            owner_exchange,
            attacker_exchange,
            anonymous_exchange: Some(anonymous_exchange),
            tested_tenant: Some("org-a".to_string()),
            owner_tenant: Some("org-b".to_string()),
        };
        let validator = GraphQlBolaValidator::default();
        let decision = validator.validate(&case);
        match decision {
            GraphQlBolaDecision::Verified(finding) => {
                assert_eq!(finding.operation_name, "project");
                assert!(finding
                    .evidence_markers
                    .iter()
                    .any(|m| m.contains("org-b") || m.contains("proj-b-001")));
                assert!(finding.body_similarity >= 0.70);
            }
            GraphQlBolaDecision::Rejected(reason) => {
                panic!("expected verified GraphQL BOLA, got rejected: {reason:?}");
            }
        }
    }

    #[test]
    fn graphql_bola_validator_rejects_blocked_access() {
        let gql_endpoint = ApiEndpoint {
            id: "GQL QUERY project".to_string(),
            method: HttpMethod::Post,
            url_template: "http://localhost:3010/graphql".to_string(),
            source: EndpointSource::GraphQl,
            requires_auth: Some(true),
            path_parameters: vec![],
            tags: vec![
                "graphql".to_string(),
                "query".to_string(),
                "project".to_string(),
            ],
        };
        let owner_exchange = HttpExchange {
            id: "gql-owner".to_string(),
            profile: "org_b_admin".to_string(),
            method: HttpMethod::Post,
            url: "http://localhost:3010/graphql".to_string(),
            status: 200,
            response_headers: vec![],
            response_body_excerpt: r#"{"data":{"project":{"id":"proj-b-secret","name":"Beta Merger Plans","org_id":"org-b"}}}"#.to_string(),
        };
        let attacker_exchange = HttpExchange {
            id: "gql-attacker".to_string(),
            profile: "org_a_member".to_string(),
            method: HttpMethod::Post,
            url: "http://localhost:3010/graphql".to_string(),
            status: 200,
            response_headers: vec![],
            response_body_excerpt:
                r#"{"data":{"project":null},"errors":[{"message":"access denied"}]}"#.to_string(),
        };
        let case = GraphQlBolaValidationCase {
            endpoint: gql_endpoint,
            operation_name: "project".to_string(),
            operation_type: GraphQlOperationType::Query,
            id_argument: "id".to_string(),
            object_id: "proj-b-secret".to_string(),
            owner_profile: "org_b_admin".to_string(),
            attacker_profile: "org_a_member".to_string(),
            owner_markers: vec!["org-b".to_string()],
            owner_exchange,
            attacker_exchange,
            anonymous_exchange: None,
            tested_tenant: None,
            owner_tenant: None,
        };
        let validator = GraphQlBolaValidator::default();
        let decision = validator.validate(&case);
        match decision {
            GraphQlBolaDecision::Rejected(reason) => {
                assert!(
                    reason.reason.contains("blocked")
                        || reason.reason.contains("does not sufficiently match")
                );
            }
            GraphQlBolaDecision::Verified(finding) => {
                panic!("expected rejected GraphQL BOLA for decoy, got verified: {finding:?}");
            }
        }
    }

    #[test]
    fn graphql_bola_validator_rejects_missing_auth_bypass() {
        let gql_endpoint = ApiEndpoint {
            id: "GQL QUERY project".to_string(),
            method: HttpMethod::Post,
            url_template: "http://localhost:3010/graphql".to_string(),
            source: EndpointSource::GraphQl,
            requires_auth: Some(true),
            path_parameters: vec![],
            tags: vec![
                "graphql".to_string(),
                "query".to_string(),
                "project".to_string(),
            ],
        };
        let owner_exchange = HttpExchange {
            id: "gql-owner".to_string(),
            profile: "owner".to_string(),
            method: HttpMethod::Post,
            url: "http://localhost:3010/graphql".to_string(),
            status: 200,
            response_headers: vec![],
            response_body_excerpt:
                r#"{"data":{"project":{"id":"proj-1","name":"Test","org_id":"org-a"}}}"#.to_string(),
        };
        let attacker_exchange = HttpExchange {
            id: "gql-attacker".to_string(),
            profile: "attacker".to_string(),
            method: HttpMethod::Post,
            url: "http://localhost:3010/graphql".to_string(),
            status: 200,
            response_headers: vec![],
            response_body_excerpt:
                r#"{"data":{"project":{"id":"proj-1","name":"Test","org_id":"org-a"}}}"#.to_string(),
        };
        let anonymous_exchange = HttpExchange {
            id: "gql-anon".to_string(),
            profile: "anonymous".to_string(),
            method: HttpMethod::Post,
            url: "http://localhost:3010/graphql".to_string(),
            status: 200,
            response_headers: vec![],
            response_body_excerpt:
                r#"{"data":{"project":{"id":"proj-1","name":"Test","org_id":"org-a"}}}"#.to_string(),
        };
        let case = GraphQlBolaValidationCase {
            endpoint: gql_endpoint,
            operation_name: "project".to_string(),
            operation_type: GraphQlOperationType::Query,
            id_argument: "id".to_string(),
            object_id: "proj-1".to_string(),
            owner_profile: "owner".to_string(),
            attacker_profile: "attacker".to_string(),
            owner_markers: vec!["org-a".to_string()],
            owner_exchange,
            attacker_exchange,
            anonymous_exchange: Some(anonymous_exchange),
            tested_tenant: None,
            owner_tenant: None,
        };
        let validator = GraphQlBolaValidator::default();
        let decision = validator.validate(&case);
        match decision {
            GraphQlBolaDecision::Rejected(reason) => {
                assert!(reason.reason.contains("without authentication"));
            }
            GraphQlBolaDecision::Verified(_) => {
                panic!("expected rejection for anonymous bypass, got verified");
            }
        }
    }

    #[test]
    fn graphql_operation_id_argument_detection() {
        let id_arg = GraphQlArg {
            name: "projectId".to_string(),
            arg_type: GraphQlFieldType {
                name: "ID".to_string(),
                kind: "NON_NULL".to_string(),
                of_type: Some("ID".to_string()),
            },
            default_value: None,
        };
        assert!(id_arg.looks_like_object_id());

        let non_id_arg = GraphQlArg {
            name: "limit".to_string(),
            arg_type: GraphQlFieldType {
                name: "Int".to_string(),
                kind: "SCALAR".to_string(),
                of_type: None,
            },
            default_value: None,
        };
        assert!(!non_id_arg.looks_like_object_id());
    }

    #[test]
    fn graphql_candidate_generation_skips_non_object_queries() {
        let introspection = r#"{
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": null,
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [
                                { "name": "me", "type": { "kind": "OBJECT", "name": "User", "ofType": null }, "args": [], "isDeprecated": false },
                                { "name": "healthCheck", "type": { "kind": "SCALAR", "name": "Boolean", "ofType": null }, "args": [], "isDeprecated": false }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "User",
                            "fields": [
                                { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "args": [], "isDeprecated": false }
                            ]
                        }
                    ]
                }
            }
        }"#;
        let inventory = GraphQlInventory::from_introspection_json(
            "http://localhost:3010/graphql",
            introspection,
        )
        .unwrap();
        assert_eq!(inventory.bola_candidates.len(), 0);
    }

    #[test]
    fn graphql_endpoints_generated_for_all_operations() {
        let introspection = r#"{
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": { "name": "Mutation" },
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [
                                { "name": "project", "type": { "kind": "OBJECT", "name": "Project", "ofType": null }, "args": [
                                    { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "defaultValue": null }
                                ], "isDeprecated": false }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "Mutation",
                            "fields": [
                                { "name": "deleteProject", "type": { "kind": "OBJECT", "name": "Project", "ofType": null }, "args": [
                                    { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "defaultValue": null }
                                ], "isDeprecated": false }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "Project",
                            "fields": [
                                { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } }, "args": [], "isDeprecated": false }
                            ]
                        }
                    ]
                }
            }
        }"#;
        let inventory = GraphQlInventory::from_introspection_json(
            "http://localhost:3010/graphql",
            introspection,
        )
        .unwrap();
        assert_eq!(inventory.endpoints.len(), 2);
        let query_ep = inventory
            .endpoints
            .iter()
            .find(|e| e.id == "GQL QUERY project")
            .unwrap();
        assert_eq!(query_ep.method, HttpMethod::Post);
        assert_eq!(query_ep.source, EndpointSource::GraphQl);
        assert!(query_ep.tags.contains(&"query".to_string()));
        let mut_ep = inventory
            .endpoints
            .iter()
            .find(|e| e.id == "GQL MUTATION deleteProject")
            .unwrap();
        assert_eq!(mut_ep.method, HttpMethod::Post);
        assert!(mut_ep.tags.contains(&"mutation".to_string()));
    }
}
