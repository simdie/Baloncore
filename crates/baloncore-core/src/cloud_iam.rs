use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CloudProvider {
    AWS,
    GCP,
    Azure,
    Kubernetes,
    Generic,
}

impl CloudProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AWS => "aws",
            Self::GCP => "gcp",
            Self::Azure => "azure",
            Self::Kubernetes => "kubernetes",
            Self::Generic => "generic",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "aws" => Self::AWS,
            "gcp" | "google" => Self::GCP,
            "azure" => Self::Azure,
            "kubernetes" | "k8s" => Self::Kubernetes,
            _ => Self::Generic,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PrincipalKind {
    User,
    Group,
    Role,
    ServiceAccount,
    ManagedIdentity,
    FederatedIdentity,
    ExternalAccount,
    CiCdIdentity,
}

impl PrincipalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
            Self::Role => "role",
            Self::ServiceAccount => "service_account",
            Self::ManagedIdentity => "managed_identity",
            Self::FederatedIdentity => "federated_identity",
            Self::ExternalAccount => "external_account",
            Self::CiCdIdentity => "cicd_identity",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IAMPrincipal {
    pub id: String,
    pub provider: CloudProvider,
    pub kind: PrincipalKind,
    pub name: String,
    pub arn: Option<String>,
    pub account_id: Option<String>,
    pub policies: Vec<String>,
    pub is_public: bool,
    pub tags: HashMap<String, String>,
}

impl IAMPrincipal {
    pub fn new(
        id: impl Into<String>,
        provider: CloudProvider,
        kind: PrincipalKind,
        name: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            provider,
            kind,
            name: name.into(),
            arn: None,
            account_id: None,
            policies: Vec::new(),
            is_public: false,
            tags: HashMap::new(),
        }
    }

    pub fn with_arn(mut self, arn: impl Into<String>) -> Self {
        self.arn = Some(arn.into());
        self
    }

    pub fn with_account(mut self, account_id: impl Into<String>) -> Self {
        self.account_id = Some(account_id.into());
        self
    }

    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policies.push(policy.into());
        self
    }

    pub fn display_name(&self) -> &str {
        if let Some(arn) = &self.arn {
            arn
        } else {
            &self.name
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Effect {
    Allow,
    Deny,
}

impl Effect {
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "allow" => Self::Allow,
            "deny" => Self::Deny,
            _ => Self::Allow,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IAMStatement {
    pub id: String,
    pub effect: Effect,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    pub conditions: Vec<IAMCondition>,
    pub source_doc: String,
}

impl IAMStatement {
    pub fn new_allow(id: impl Into<String>, actions: Vec<String>, resources: Vec<String>) -> Self {
        Self {
            id: id.into(),
            effect: Effect::Allow,
            actions,
            resources,
            conditions: Vec::new(),
            source_doc: String::new(),
        }
    }

    pub fn new_deny(id: impl Into<String>, actions: Vec<String>, resources: Vec<String>) -> Self {
        Self {
            id: id.into(),
            effect: Effect::Deny,
            actions,
            resources,
            conditions: Vec::new(),
            source_doc: String::new(),
        }
    }

    pub fn with_condition(mut self, condition: IAMCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    pub fn matches_action(&self, action: &str) -> bool {
        self.actions.iter().any(|a| pattern_matches(a, action))
    }

    pub fn matches_resource(&self, resource: &str) -> bool {
        self.resources.iter().any(|r| pattern_matches(r, resource))
    }

    pub fn is_privileged(&self) -> bool {
        PRIVILEGED_ACTIONS.iter().any(|pa| self.matches_action(pa))
    }
}

static PRIVILEGED_ACTIONS: &[&str] = &[
    "*",
    "iam:*",
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
    "ec2:*",
    "s3:*",
    "admin:*",
    "storage.*",
    "compute.*",
    "container.*",
];

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == value {
        return true;
    }
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let prefix = parts[0];
            let suffix = parts[1];
            return value.starts_with(prefix) && value.ends_with(suffix);
        }
        if parts.len() > 2 {
            let mut remaining = value;
            for (i, part) in parts.iter().enumerate() {
                if part.is_empty() {
                    continue;
                }
                if i == 0 {
                    if !remaining.starts_with(part) {
                        return false;
                    }
                    remaining = &remaining[part.len()..];
                } else if i == parts.len() - 1 {
                    if !remaining.ends_with(part) {
                        return false;
                    }
                } else {
                    if let Some(pos) = remaining.find(part) {
                        remaining = &remaining[pos + part.len()..];
                    } else {
                        return false;
                    }
                }
            }
            return true;
        }
    }
    if pattern.contains('?') {
        if pattern.len() != value.len() {
            return false;
        }
        return pattern
            .chars()
            .zip(value.chars())
            .all(|(p, v)| p == '?' || p == v);
    }
    false
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IAMCondition {
    pub operator: String,
    pub key: String,
    pub values: Vec<String>,
}

impl IAMCondition {
    pub fn new(operator: impl Into<String>, key: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            operator: operator.into(),
            key: key.into(),
            values,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IAMPolicy {
    pub id: String,
    pub name: String,
    pub provider: CloudProvider,
    pub statements: Vec<IAMStatement>,
    pub source_doc: String,
    pub source_type: PolicySourceType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicySourceType {
    AWSManaged,
    AWSInline,
    AWSCustom,
    GCPRole,
    AzureBuiltIn,
    AzureCustom,
    K8sClusterRole,
    K8sRole,
    Terraform,
    CloudFormation,
    Manual,
}

impl PolicySourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AWSManaged => "aws_managed",
            Self::AWSInline => "aws_inline",
            Self::AWSCustom => "aws_custom",
            Self::GCPRole => "gcp_role",
            Self::AzureBuiltIn => "azure_built_in",
            Self::AzureCustom => "azure_custom",
            Self::K8sClusterRole => "k8s_cluster_role",
            Self::K8sRole => "k8s_role",
            Self::Terraform => "terraform",
            Self::CloudFormation => "cloudformation",
            Self::Manual => "manual",
        }
    }
}

impl IAMPolicy {
    pub fn new(id: impl Into<String>, name: impl Into<String>, provider: CloudProvider) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            provider,
            statements: Vec::new(),
            source_doc: String::new(),
            source_type: PolicySourceType::Manual,
        }
    }

    pub fn with_statement(mut self, statement: IAMStatement) -> Self {
        self.statements.push(statement);
        self
    }

    pub fn allows(&self, action: &str, resource: &str) -> bool {
        self.statements.iter().any(|s| {
            s.effect == Effect::Allow && s.matches_action(action) && s.matches_resource(resource)
        })
    }

    pub fn explicit_denies(&self, action: &str, resource: &str) -> bool {
        self.statements.iter().any(|s| {
            s.effect == Effect::Deny && s.matches_action(action) && s.matches_resource(resource)
        })
    }

    pub fn privileged_statements(&self) -> Vec<&IAMStatement> {
        self.statements
            .iter()
            .filter(|s| s.is_privileged())
            .collect()
    }

    pub fn is_over_privileged(&self) -> bool {
        self.statements.iter().any(|s| {
            s.effect == Effect::Allow
                && (s
                    .actions
                    .iter()
                    .any(|a| a == "*" || a.ends_with(":*") || a == "k8s:*")
                    || s.resources.iter().any(|r| r == "*"))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustRelationship {
    pub id: String,
    pub trustee_principal: String,
    pub trusted_principal: String,
    pub trusted_provider: Option<CloudProvider>,
    pub conditions: Vec<IAMCondition>,
    pub source_doc: String,
    pub allows_external: bool,
}

impl TrustRelationship {
    pub fn new(
        id: impl Into<String>,
        trustee: impl Into<String>,
        trusted: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            trustee_principal: trustee.into(),
            trusted_principal: trusted.into(),
            trusted_provider: None,
            conditions: Vec::new(),
            source_doc: String::new(),
            allows_external: false,
        }
    }

    pub fn with_external(mut self) -> Self {
        self.allows_external = true;
        self
    }

    pub fn with_condition(mut self, condition: IAMCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    pub fn is_oidc_trust(&self) -> bool {
        self.trusted_principal.contains("oidc")
            || self.conditions.iter().any(|c| {
                c.key.contains("oidc")
                    || c.key.contains("token")
                    || c.key.contains("Token")
                    || (c.operator.contains("StringEquals")
                        && c.values.iter().any(|v| {
                            v.contains("oidc") || v.contains("token.actions.githubusercontent.com")
                        }))
            })
    }

    pub fn is_over_privileged(&self) -> bool {
        if self.allows_external && self.conditions.is_empty() {
            return true;
        }
        if self.trusted_principal == "*" {
            return true;
        }
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AmazonResourceType {
    S3Bucket,
    EC2Instance,
    LambdaFunction,
    DynamoDBTable,
    IAMRole,
    IAMUser,
    IAMPolicy,
    EKSCluster,
    CloudFrontDistribution,
    RDSInstance,
    SQSQueue,
    SNSTopic,
    KMSKey,
    SecretsManagerSecret,
    Other(String),
}

impl AmazonResourceType {
    pub fn from_service_action(action: &str) -> Self {
        let service = action.split(':').next().unwrap_or("");
        match service {
            "s3" => Self::S3Bucket,
            "ec2" => Self::EC2Instance,
            "lambda" => Self::LambdaFunction,
            "dynamodb" => Self::DynamoDBTable,
            "iam" => Self::IAMRole,
            "eks" => Self::EKSCluster,
            "cloudfront" => Self::CloudFrontDistribution,
            "rds" => Self::RDSInstance,
            "sqs" => Self::SQSQueue,
            "sns" => Self::SNSTopic,
            "kms" => Self::KMSKey,
            "secretsmanager" => Self::SecretsManagerSecret,
            _ => Self::Other(service.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudResource {
    pub id: String,
    pub provider: CloudProvider,
    pub resource_type: String,
    pub name: String,
    pub arn: Option<String>,
    pub region: Option<String>,
    pub account_id: Option<String>,
    pub is_public: bool,
    pub public_access_details: Vec<String>,
    pub tags: HashMap<String, String>,
    pub raw_config: Option<serde_json::Value>,
}

impl CloudResource {
    pub fn new(
        id: impl Into<String>,
        provider: CloudProvider,
        resource_type: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            provider,
            resource_type: resource_type.into(),
            name: name.into(),
            arn: None,
            region: None,
            account_id: None,
            is_public: false,
            public_access_details: Vec::new(),
            tags: HashMap::new(),
            raw_config: None,
        }
    }

    pub fn with_arn(mut self, arn: impl Into<String>) -> Self {
        self.arn = Some(arn.into());
        self
    }

    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    pub fn with_public_access(mut self, details: Vec<String>) -> Self {
        self.is_public = true;
        self.public_access_details = details;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IAMGraph {
    pub id: String,
    pub provider: CloudProvider,
    pub account_id: Option<String>,
    pub principals: HashMap<String, IAMPrincipal>,
    pub policies: HashMap<String, IAMPolicy>,
    pub trust_relationships: Vec<TrustRelationship>,
    pub resources: HashMap<String, CloudResource>,
    pub edges: Vec<IAMEdge>,
    pub findings: Vec<CloudFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IAMEdge {
    pub id: String,
    pub from_principal: String,
    pub to_principal: Option<String>,
    pub to_resource: Option<String>,
    pub edge_kind: IAMEdgeKind,
    pub policy_id: Option<String>,
    pub actions: Vec<String>,
    pub conditions: Vec<IAMCondition>,
    pub is_deny: bool,
    pub confidence: f64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IAMEdgeKind {
    AssumeRole,
    PolicyAttachment,
    GroupMembership,
    TrustPolicy,
    PermissionGrant,
    AdminAccess,
    PublicAccess,
    PrivilegeEscalation,
    CrossAccount,
    CrossService,
    CiCdTrust,
}

impl IAMEdgeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AssumeRole => "assume_role",
            Self::PolicyAttachment => "policy_attachment",
            Self::GroupMembership => "group_membership",
            Self::TrustPolicy => "trust_policy",
            Self::PermissionGrant => "permission_grant",
            Self::AdminAccess => "admin_access",
            Self::PublicAccess => "public_access",
            Self::PrivilegeEscalation => "privilege_escalation",
            Self::CrossAccount => "cross_account",
            Self::CrossService => "cross_service",
            Self::CiCdTrust => "cicd_trust",
        }
    }
}

impl IAMGraph {
    pub fn new(id: impl Into<String>, provider: CloudProvider) -> Self {
        Self {
            id: id.into(),
            provider,
            account_id: None,
            principals: HashMap::new(),
            policies: HashMap::new(),
            trust_relationships: Vec::new(),
            resources: HashMap::new(),
            edges: Vec::new(),
            findings: Vec::new(),
        }
    }

    pub fn add_principal(&mut self, principal: IAMPrincipal) {
        self.principals.insert(principal.id.clone(), principal);
    }

    pub fn add_policy(&mut self, policy: IAMPolicy) {
        self.policies.insert(policy.id.clone(), policy);
    }

    pub fn add_resource(&mut self, resource: CloudResource) {
        self.resources.insert(resource.id.clone(), resource);
    }

    pub fn add_trust(&mut self, trust: TrustRelationship) {
        self.trust_relationships.push(trust);
    }

    pub fn add_edge(&mut self, edge: IAMEdge) {
        self.edges.push(edge);
    }

    pub fn add_finding(&mut self, finding: CloudFinding) {
        self.findings.push(finding);
    }

    pub fn resolve_policy_attachments(&mut self) {
        for (_, policy) in &self.policies {
            let policy_id = policy.id.clone();
            for statement in &policy.statements {
                for (principal_id, principal) in &self.principals {
                    if principal.policies.contains(&policy.name)
                        || principal.policies.contains(&policy.id)
                    {
                        let edge = IAMEdge {
                            id: format!("edge-{}-{}", principal_id, policy_id),
                            from_principal: principal_id.clone(),
                            to_principal: None,
                            to_resource: None,
                            edge_kind: if statement.is_privileged() {
                                IAMEdgeKind::AdminAccess
                            } else {
                                IAMEdgeKind::PolicyAttachment
                            },
                            policy_id: Some(policy_id.clone()),
                            actions: statement.actions.clone(),
                            conditions: statement.conditions.clone(),
                            is_deny: statement.effect == Effect::Deny,
                            confidence: 1.0,
                            source: policy.source_doc.clone(),
                        };
                        self.edges.push(edge);
                    }
                }
            }
        }
    }

    pub fn resolve_trust_chains(&mut self) {
        for trust in &self.trust_relationships {
            let edge = IAMEdge {
                id: format!("trust-{}", trust.id),
                from_principal: trust.trusted_principal.clone(),
                to_principal: Some(trust.trustee_principal.clone()),
                to_resource: None,
                edge_kind: if trust.is_oidc_trust() {
                    IAMEdgeKind::CiCdTrust
                } else {
                    IAMEdgeKind::TrustPolicy
                },
                policy_id: None,
                actions: vec!["sts:AssumeRole".to_string()],
                conditions: trust.conditions.clone(),
                is_deny: false,
                confidence: if trust.allows_external { 1.0 } else { 0.8 },
                source: trust.source_doc.clone(),
            };
            self.edges.push(edge);
        }
    }

    pub fn resolve_group_memberships(&mut self, groups: &[(String, String)]) {
        for (user_id, group_id) in groups {
            if self.principals.contains_key(user_id) && self.principals.contains_key(group_id) {
                let edge = IAMEdge {
                    id: format!("group-{}-{}", user_id, group_id),
                    from_principal: user_id.clone(),
                    to_principal: Some(group_id.clone()),
                    to_resource: None,
                    edge_kind: IAMEdgeKind::GroupMembership,
                    policy_id: None,
                    actions: vec![],
                    conditions: vec![],
                    is_deny: false,
                    confidence: 1.0,
                    source: String::new(),
                };
                self.edges.push(edge);
            }
        }
    }

    pub fn find_privilege_paths(&self, max_depth: usize) -> Vec<PrivilegePath> {
        let mut paths = Vec::new();
        let public_principals: Vec<_> = self.principals.values().filter(|p| p.is_public).collect();

        for public_principal in &public_principals {
            let reachable = self.bfs_reachable(&public_principal.id, max_depth);
            for (target_id, path_edges) in reachable {
                let target_principal = match self.principals.get(&target_id) {
                    Some(p) => p,
                    None => continue,
                };
                let max_privilege = path_edges
                    .iter()
                    .filter(|e| !e.is_deny)
                    .any(|e| e.edge_kind == IAMEdgeKind::AdminAccess);
                let is_privilege_escalation = path_edges
                    .iter()
                    .filter(|e| !e.is_deny)
                    .any(|e| e.edge_kind == IAMEdgeKind::PrivilegeEscalation);

                if max_privilege || is_privilege_escalation {
                    let path = PrivilegePath {
                        id: format!("path-{}-{}", public_principal.id, target_id),
                        from_principal: public_principal.id.clone(),
                        from_principal_name: public_principal.name.clone(),
                        to_principal: target_id.clone(),
                        to_principal_name: target_principal.name.clone(),
                        edges: path_edges,
                        is_reachable: true,
                        is_theoretical: false,
                        privilege_level: if max_privilege {
                            PrivilegeLevel::Admin
                        } else {
                            PrivilegeLevel::Elevated
                        },
                        identity_chain: self.build_identity_chain(&public_principal.id, &target_id),
                        summary: String::new(),
                    };
                    paths.push(path);
                }
            }
        }

        let high_privilege_principals: Vec<_> = self
            .principals
            .values()
            .filter(|p| {
                self.edges.iter().any(|e| {
                    e.from_principal == p.id
                        && e.edge_kind == IAMEdgeKind::AdminAccess
                        && !e.is_deny
                })
            })
            .collect();

        for principal in &high_privilege_principals {
            if principal.is_public {
                continue;
            }
            let reachable = self.bfs_reachable(&principal.id, max_depth);
            for (target_id, path_edges) in reachable {
                let target = match self.principals.get(&target_id) {
                    Some(p) => p,
                    None => continue,
                };
                if target.kind == PrincipalKind::Role
                    && path_edges.iter().any(|e| {
                        e.edge_kind == IAMEdgeKind::TrustPolicy
                            || e.edge_kind == IAMEdgeKind::AssumeRole
                    })
                {
                    let already_found = paths
                        .iter()
                        .any(|p| p.to_principal == target_id && p.from_principal == principal.id);
                    if !already_found {
                        let path = PrivilegePath {
                            id: format!("path-{}-{}", principal.id, target_id),
                            from_principal: principal.id.clone(),
                            from_principal_name: principal.name.clone(),
                            to_principal: target_id.clone(),
                            to_principal_name: target.name.clone(),
                            edges: path_edges,
                            is_reachable: true,
                            is_theoretical: false,
                            privilege_level: PrivilegeLevel::Elevated,
                            identity_chain: self.build_identity_chain(&principal.id, &target_id),
                            summary: String::new(),
                        };
                        paths.push(path);
                    }
                }
            }
        }

        for path in &mut paths {
            path.summary = path.render_summary();
        }

        paths
    }

    fn bfs_reachable(&self, start: &str, max_depth: usize) -> HashMap<String, Vec<IAMEdge>> {
        let mut reachable = HashMap::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back((start.to_string(), Vec::<IAMEdge>::new(), 0usize));
        visited.insert(start.to_string());

        while let Some((current, path, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            for edge in &self.edges {
                if edge.from_principal != current || edge.is_deny {
                    continue;
                }

                let next = if let Some(ref to_principal) = edge.to_principal {
                    to_principal.clone()
                } else {
                    continue;
                };

                if visited.contains(&next) {
                    continue;
                }

                let mut new_path = path.clone();
                new_path.push(edge.clone());
                reachable.insert(next.clone(), new_path.clone());
                visited.insert(next.clone());
                queue.push_back((next, new_path, depth + 1));
            }

            for (principal_id, principal) in &self.principals {
                if principal.policies.iter().any(|p| {
                    self.policies.contains_key(p)
                        && self.policies[p].allows(&format!("*"), &format!("*"))
                }) {
                    if !visited.contains(principal_id) && principal_id != start {
                        let edge = IAMEdge {
                            id: format!("indirect-{}", principal_id),
                            from_principal: current.clone(),
                            to_principal: Some(principal_id.clone()),
                            to_resource: None,
                            edge_kind: IAMEdgeKind::PrivilegeEscalation,
                            policy_id: None,
                            actions: vec!["*".to_string()],
                            conditions: vec![],
                            is_deny: false,
                            confidence: 0.7,
                            source: String::new(),
                        };
                        let mut new_path = path.clone();
                        new_path.push(edge);
                        reachable.insert(principal_id.clone(), new_path.clone());
                        visited.insert(principal_id.clone());
                    }
                }
            }
        }

        reachable
    }

    fn build_identity_chain(&self, from: &str, to: &str) -> Vec<IdentityChainEntry> {
        let mut chain = Vec::new();
        if let Some(from_principal) = self.principals.get(from) {
            chain.push(IdentityChainEntry {
                principal_id: from.to_string(),
                principal_name: from_principal.name.clone(),
                principal_kind: from_principal.kind.as_str().to_string(),
                provider: from_principal.provider.as_str().to_string(),
                action: "starts_as".to_string(),
            });
        }

        for trust in &self.trust_relationships {
            if trust.trusted_principal == from && trust.trustee_principal == to {
                chain.push(IdentityChainEntry {
                    principal_id: to.to_string(),
                    principal_name: to.to_string(),
                    principal_kind: "role".to_string(),
                    provider: trust
                        .trusted_provider
                        .as_ref()
                        .map(|p| p.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    action: "assumes_role".to_string(),
                });
            }
        }

        for edge in &self.edges {
            if edge.from_principal == from {
                if let Some(ref to_principal) = edge.to_principal {
                    if to_principal == to {
                        chain.push(IdentityChainEntry {
                            principal_id: to.to_string(),
                            principal_name: to.to_string(),
                            principal_kind: "role".to_string(),
                            provider: self.provider.as_str().to_string(),
                            action: edge.edge_kind.as_str().to_string(),
                        });
                    }
                }
            }
        }

        if chain.is_empty() {
            chain.push(IdentityChainEntry {
                principal_id: to.to_string(),
                principal_name: to.to_string(),
                principal_kind: "unknown".to_string(),
                provider: self.provider.as_str().to_string(),
                action: "reaches".to_string(),
            });
        }

        chain
    }

    pub fn check_public_exposure(&mut self) -> Vec<CloudFinding> {
        let mut findings = Vec::new();

        for (_, resource) in &self.resources {
            if resource.is_public {
                let finding = CloudFinding {
                    id: format!("public-exposure-{}", resource.id),
                    classification: "PublicResourceExposure".to_string(),
                    severity: CloudSeverity::High,
                    provider: resource.provider.clone(),
                    affected_resource: resource.name.clone(),
                    affected_resource_arn: resource.arn.clone(),
                    description: format!(
                        "Resource {} of type {} is publicly accessible: {}",
                        resource.name,
                        resource.resource_type,
                        resource.public_access_details.join(", ")
                    ),
                    identity_chain: vec![IdentityChainEntry {
                        principal_id: "*".to_string(),
                        principal_name: "public".to_string(),
                        principal_kind: "public".to_string(),
                        provider: resource.provider.as_str().to_string(),
                        action: "access".to_string(),
                    }],
                    remediation: Self::public_exposure_remediation(resource),
                    evidence: vec![CloudEvidence {
                        id: format!("evidence-public-{}", resource.id),
                        kind: CloudEvidenceKind::PublicAccessConfig,
                        source: resource.arn.clone().unwrap_or_else(|| resource.id.clone()),
                        detail: resource.public_access_details.join("; "),
                        raw_config: resource.raw_config.clone(),
                    }],
                    is_reachable: true,
                    is_theoretical: false,
                    privilege_level: PrivilegeLevel::Elevated,
                };
                findings.push(finding);
            }
        }

        for (_, policy) in &self.policies {
            if policy.is_over_privileged() {
                let principal_ids: Vec<String> = self
                    .principals
                    .iter()
                    .filter(|(_, p)| {
                        p.policies.contains(&policy.name) || p.policies.contains(&policy.id)
                    })
                    .map(|(id, _)| id.clone())
                    .collect();

                for principal_id in &principal_ids {
                    let principal = self.principals.get(principal_id).unwrap();
                    let privileged_stmts: Vec<&IAMStatement> = policy.privileged_statements();
                    let action_list: Vec<String> = privileged_stmts
                        .iter()
                        .flat_map(|s| s.actions.iter())
                        .cloned()
                        .collect();

                    findings.push(CloudFinding {
                        id: format!("over-privileged-{}-{}", principal_id, policy.id),
                        classification: "OverPrivilegedPolicy".to_string(),
                        severity: if action_list.iter().any(|a| a == "*") {
                            CloudSeverity::Critical
                        } else {
                            CloudSeverity::High
                        },
                        provider: policy.provider.clone(),
                        affected_resource: format!("{} -> {}", principal.name, policy.name),
                        affected_resource_arn: principal.arn.clone(),
                        description: format!(
                            "Principal {} has policy {} with overly broad permissions: {}",
                            principal.display_name(),
                            policy.name,
                            action_list.join(", ")
                        ),
                        identity_chain: vec![IdentityChainEntry {
                            principal_id: principal_id.clone(),
                            principal_name: principal.name.clone(),
                            principal_kind: principal.kind.as_str().to_string(),
                            provider: principal.provider.as_str().to_string(),
                            action: "has_policy".to_string(),
                        }],
                        remediation: Self::over_privileged_remediation(principal, policy),
                        evidence: vec![CloudEvidence {
                            id: format!("evidence-policy-{}-{}", principal_id, policy.id),
                            kind: CloudEvidenceKind::PolicyDocument,
                            source: policy.source_doc.clone(),
                            detail: format!(
                                "Policy {} grants: {}",
                                policy.name,
                                action_list.join(", ")
                            ),
                            raw_config: None,
                        }],
                        is_reachable: true,
                        is_theoretical: false,
                        privilege_level: if action_list.iter().any(|a| a == "*") {
                            PrivilegeLevel::Admin
                        } else {
                            PrivilegeLevel::Elevated
                        },
                    });
                }
            }
        }

        for trust in &self.trust_relationships {
            if trust.is_over_privileged() {
                findings.push(CloudFinding {
                    id: format!("trust-over-privilege-{}", trust.id),
                    classification: "OverPrivilegedTrustPolicy".to_string(),
                    severity: CloudSeverity::Critical,
                    provider: trust
                        .trusted_provider
                        .clone()
                        .unwrap_or(CloudProvider::Generic),
                    affected_resource: trust.trustee_principal.clone(),
                    affected_resource_arn: None,
                    description: format!(
                        "Trust relationship on {} allows {} without sufficient conditions",
                        trust.trustee_principal, trust.trusted_principal
                    ),
                    identity_chain: vec![IdentityChainEntry {
                        principal_id: trust.trusted_principal.clone(),
                        principal_name: trust.trusted_principal.clone(),
                        principal_kind: "trusted_principal".to_string(),
                        provider: trust
                            .trusted_provider
                            .as_ref()
                            .map(|p| p.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        action: "assume_role".to_string(),
                    }],
                    remediation: Self::trust_remediation(trust),
                    evidence: vec![CloudEvidence {
                        id: format!("evidence-trust-{}", trust.id),
                        kind: CloudEvidenceKind::TrustPolicy,
                        source: trust.trustee_principal.clone(),
                        detail: format!(
                            "Trust policy allows {} to assume {}",
                            trust.trusted_principal, trust.trustee_principal
                        ),
                        raw_config: None,
                    }],
                    is_reachable: true,
                    is_theoretical: false,
                    privilege_level: PrivilegeLevel::Admin,
                });
            }
        }

        self.findings.extend(findings.clone());
        findings
    }

    fn public_exposure_remediation(resource: &CloudResource) -> String {
        format!(
            "Restrict public access on resource {} of type {}. {}",
            resource.name,
            resource.resource_type,
            if resource.provider == CloudProvider::AWS {
                "For S3 buckets, enable 'Block Public Access' at the bucket and account level. For other resources, review the resource policy and remove wildcard principals."
            } else if resource.provider == CloudProvider::GCP {
                "Remove 'allUsers' and 'allAuthenticatedUsers' bindings from IAM policies. Use organization policy constraints to prevent public access."
            } else if resource.provider == CloudProvider::Azure {
                "Remove anonymous access from storage containers and blobs. Set public access level to 'None' and review stored access policies."
            } else {
                "Review access control policies and remove public access grants."
            }
        )
    }

    fn over_privileged_remediation(principal: &IAMPrincipal, policy: &IAMPolicy) -> String {
        format!(
            "Replace wildcard permissions in policy '{}' attached to principal '{}' with specific actions and resources following least-privilege principle. Consider using access analyzer to generate scoped policies based on recent usage.",
            policy.name,
            principal.display_name()
        )
    }

    fn trust_remediation(trust: &TrustRelationship) -> String {
        format!(
            "Add conditions to the trust policy on '{}' to restrict which external principals can assume the role. Require specific organizational IDs, source ARNs, or external IDs. Avoid using wildcard principals in trust policies.",
            trust.trustee_principal
        )
    }

    pub fn check_cicd_trust(&mut self) -> Vec<CloudFinding> {
        let mut findings = Vec::new();

        for edge in &self.edges {
            if edge.edge_kind == IAMEdgeKind::CiCdTrust {
                if let Some(to_principal_id) = &edge.to_principal {
                    let target_role = match self.principals.get(to_principal_id) {
                        Some(p) => p,
                        None => continue,
                    };

                    let target_policies: Vec<&IAMPolicy> = target_role
                        .policies
                        .iter()
                        .filter_map(|p| {
                            self.policies
                                .get(p)
                                .or_else(|| self.policies.values().find(|policy| policy.name == *p))
                        })
                        .collect();

                    let is_admin = target_policies.iter().any(|p| p.is_over_privileged());
                    let privileged = target_policies
                        .iter()
                        .any(|p| !p.privileged_statements().is_empty());

                    if is_admin || privileged {
                        findings.push(CloudFinding {
                            id: format!("cicd-trust-{}", edge.id),
                            classification: "CiCdPrivilegeEscalation".to_string(),
                            severity: if is_admin {
                                CloudSeverity::Critical
                            } else {
                                CloudSeverity::High
                            },
                            provider: self.provider.clone(),
                            affected_resource: format!(
                                "CI/CD identity {} can assume role {} which has {}",
                                edge.from_principal,
                                target_role.name,
                                if is_admin { "admin access" } else { "privileged access" }
                            ),
                            affected_resource_arn: target_role.arn.clone(),
                            description: format!(
                                "This CI/CD identity can request an OIDC token. The token can assume {}. {} can pass {} to a compute service. That path gives effective administrative control.",
                                to_principal_id,
                                edge.from_principal,
                                target_role.name
                            ),
                            identity_chain: vec![
                                IdentityChainEntry {
                                    principal_id: edge.from_principal.clone(),
                                    principal_name: edge.from_principal.clone(),
                                    principal_kind: "cicd_identity".to_string(),
                                    provider: self.provider.as_str().to_string(),
                                    action: "requests_oidc_token".to_string(),
                                },
                                IdentityChainEntry {
                                    principal_id: to_principal_id.clone(),
                                    principal_name: target_role.name.clone(),
                                    principal_kind: "role".to_string(),
                                    provider: self.provider.as_str().to_string(),
                                    action: "assumes_role".to_string(),
                                },
                            ],
                            remediation: format!(
                                "Restrict the trust policy on {} to only valid repository refs and environments. Scope the role's permissions to minimum required. Consider using ephemeral credentials and requiring approval gates.",
                                to_principal_id
                            ),
                            evidence: vec![CloudEvidence {
                                id: format!("evidence-cicd-{}", edge.id),
                                kind: CloudEvidenceKind::TrustPolicy,
                                source: edge.from_principal.clone(),
                                detail: format!(
                                    "OIDC trust from {} to {} with actions: {}",
                                    edge.from_principal,
                                    to_principal_id,
                                    edge.actions.join(", ")
                                ),
                                raw_config: None,
                            }],
                            is_reachable: true,
                            is_theoretical: false,
                            privilege_level: if is_admin {
                                PrivilegeLevel::Admin
                            } else {
                                PrivilegeLevel::Elevated
                            },
                        });
                    }
                }
            }
        }

        self.findings.extend(findings.clone());
        findings
    }

    pub fn analyze(&mut self) -> CloudAnalysisResult {
        self.resolve_policy_attachments();
        self.resolve_trust_chains();

        let public_findings = self.check_public_exposure();
        let cicd_findings = self.check_cicd_trust();
        let privilege_paths = self.find_privilege_paths(6);

        let path_findings: Vec<CloudFinding> = privilege_paths
            .iter()
            .filter(|p| {
                p.privilege_level == PrivilegeLevel::Admin
                    || p.privilege_level == PrivilegeLevel::Elevated
            })
            .map(|path| CloudFinding {
                id: path.id.clone(),
                classification: "PrivilegeEscalationPath".to_string(),
                severity: match path.privilege_level {
                    PrivilegeLevel::Admin => CloudSeverity::Critical,
                    PrivilegeLevel::Elevated => CloudSeverity::High,
                    _ => CloudSeverity::Medium,
                },
                provider: self.provider.clone(),
                affected_resource: format!(
                    "{} -> {}",
                    path.from_principal_name, path.to_principal_name
                ),
                affected_resource_arn: None,
                description: path.render_summary(),
                identity_chain: path.identity_chain.clone(),
                remediation: Self::path_remediation(path),
                evidence: path
                    .edges
                    .iter()
                    .enumerate()
                    .map(|(i, e)| CloudEvidence {
                        id: format!("evidence-path-{}-{}", path.id, i),
                        kind: CloudEvidenceKind::TrustPolicy,
                        source: e.from_principal.clone(),
                        detail: format!(
                            "{}: {} -> {:?}",
                            e.edge_kind.as_str(),
                            e.from_principal,
                            e.to_principal
                        ),
                        raw_config: None,
                    })
                    .collect(),
                is_reachable: path.is_reachable,
                is_theoretical: path.is_theoretical,
                privilege_level: path.privilege_level.clone(),
            })
            .collect();

        let mut all_findings = Vec::new();
        all_findings.extend(public_findings);
        all_findings.extend(cicd_findings);
        all_findings.extend(path_findings);

        all_findings.sort_by(|a, b| b.severity.ordinal().cmp(&a.severity.ordinal()));

        let summary = CloudAnalysisSummary {
            provider: self.provider.clone(),
            account_id: self.account_id.clone(),
            principal_count: self.principals.len(),
            policy_count: self.policies.len(),
            resource_count: self.resources.len(),
            trust_count: self.trust_relationships.len(),
            edge_count: self.edges.len(),
            finding_count: all_findings.len(),
            critical_count: all_findings
                .iter()
                .filter(|f| f.severity == CloudSeverity::Critical)
                .count(),
            high_count: all_findings
                .iter()
                .filter(|f| f.severity == CloudSeverity::High)
                .count(),
            medium_count: all_findings
                .iter()
                .filter(|f| f.severity == CloudSeverity::Medium)
                .count(),
            privilege_path_count: privilege_paths.len(),
            public_resource_count: self.resources.values().filter(|r| r.is_public).count(),
            over_privileged_count: self
                .policies
                .values()
                .filter(|p| p.is_over_privileged())
                .count(),
        };

        CloudAnalysisResult {
            graph_id: self.id.clone(),
            summary,
            findings: all_findings,
            privilege_paths,
        }
    }

    fn path_remediation(path: &PrivilegePath) -> String {
        format!(
            "Break the privilege escalation path from '{}' to '{}'. Review each trust relationship and policy in the chain. Apply least-privilege principle: restrict which principals can assume each role and what actions each role can perform. Add conditions (org ID, source ARN, external ID) to trust policies.",
            path.from_principal_name, path.to_principal_name
        )
    }

    pub fn render_attack_path_report(&self, result: &CloudAnalysisResult) -> String {
        let mut report = String::new();

        report.push_str("# BALONCORE Cloud/IAM Attack Path Report\n\n");
        report.push_str(&format!("Provider: {}\n", self.provider.as_str()));
        if let Some(ref account_id) = self.account_id {
            report.push_str(&format!("Account: {}\n", account_id));
        }
        report.push_str(&format!("Principals: {}\n", self.principals.len()));
        report.push_str(&format!("Policies: {}\n", self.policies.len()));
        report.push_str(&format!("Resources: {}\n", self.resources.len()));
        report.push_str(&format!(
            "Trust relationships: {}\n",
            self.trust_relationships.len()
        ));
        report.push_str(&format!("Findings: {}\n\n", result.findings.len()));

        if !result.findings.is_empty() {
            report.push_str("## Findings\n\n");
            for finding in &result.findings {
                report.push_str(&format!(
                    "### {} [{}]\n\n{}\n\n**Affected resource:** {}\n\n**Identity chain:**\n\n",
                    finding.classification,
                    finding.severity.as_str(),
                    finding.description,
                    finding.affected_resource,
                ));
                for entry in &finding.identity_chain {
                    report.push_str(&format!(
                        "- {} ({}) -- {} --> {}\n",
                        entry.principal_name, entry.principal_kind, entry.action, entry.provider,
                    ));
                }
                report.push_str(&format!("\n**Remediation:** {}\n\n", finding.remediation));
                if finding.is_theoretical {
                    report.push_str("**Note:** This finding is theoretical and has not been validated by a live check.\n\n");
                }
            }
        }

        if !result.privilege_paths.is_empty() {
            report.push_str("## Privilege Escalation Paths\n\n");
            for path in &result.privilege_paths {
                report.push_str(&format!(
                    "### {} -> {} [{}]\n\n{}\n\n",
                    path.from_principal_name,
                    path.to_principal_name,
                    path.privilege_level.as_str(),
                    path.render_summary(),
                ));
                report.push_str("**Path:**\n\n");
                report.push_str(&format!(
                    "1. {} ({})\n",
                    path.from_principal, path.from_principal_name
                ));
                for entry in &path.identity_chain {
                    report.push_str(&format!(
                        "2. {} ({}) -- {} --> {}\n",
                        entry.principal_id, entry.principal_name, entry.action, entry.provider,
                    ));
                }
                report.push_str("\n");
            }
        }

        report
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrivilegePath {
    pub id: String,
    pub from_principal: String,
    pub from_principal_name: String,
    pub to_principal: String,
    pub to_principal_name: String,
    pub edges: Vec<IAMEdge>,
    pub is_reachable: bool,
    pub is_theoretical: bool,
    pub privilege_level: PrivilegeLevel,
    pub identity_chain: Vec<IdentityChainEntry>,
    pub summary: String,
}

impl PrivilegePath {
    pub fn render_summary(&self) -> String {
        if !self.summary.is_empty() {
            return self.summary.clone();
        }

        let mut parts = Vec::new();
        for entry in &self.identity_chain {
            parts.push(format!(
                "{} ({}) -- {} --> {}",
                entry.principal_id, entry.principal_kind, entry.action, entry.provider
            ));
        }
        format!(
            "Privilege path from {} to {} ({}): {}",
            self.from_principal_name,
            self.to_principal_name,
            self.privilege_level.as_str(),
            parts.join(" → ")
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PrivilegeLevel {
    None,
    Read,
    Write,
    Elevated,
    Admin,
}

impl PrivilegeLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
            Self::Elevated => "elevated",
            Self::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash)]
pub enum CloudSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl CloudSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn ordinal(&self) -> u8 {
        match self {
            Self::Informational => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudFinding {
    pub id: String,
    pub classification: String,
    pub severity: CloudSeverity,
    pub provider: CloudProvider,
    pub affected_resource: String,
    pub affected_resource_arn: Option<String>,
    pub description: String,
    pub identity_chain: Vec<IdentityChainEntry>,
    pub remediation: String,
    pub evidence: Vec<CloudEvidence>,
    pub is_reachable: bool,
    pub is_theoretical: bool,
    pub privilege_level: PrivilegeLevel,
}

impl CloudFinding {
    pub fn to_finding_record(&self, scan_id: &str) -> crate::lifecycle::FindingRecord {
        crate::lifecycle::FindingRecord {
            finding_id: self.id.clone(),
            scan_id: scan_id.to_string(),
            fingerprint: format!(
                "cloud-iam-{}-{}",
                self.classification.to_lowercase(),
                self.affected_resource
            ),
            classification: self.classification.clone(),
            vulnerability_class: "cloud_iam".to_string(),
            endpoint: self.affected_resource.clone(),
            object_id: self.affected_resource.clone(),
            owner_profile: "cloud-iam".to_string(),
            tested_profile: "cloud-iam".to_string(),
            severity: self.severity.as_str().to_string(),
            score: self.severity.ordinal() as u64 * 2,
            state: crate::lifecycle::FindingState::Verified,
            first_seen_run: scan_id.to_string(),
            last_seen_run: scan_id.to_string(),
            first_seen_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_seen_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            seen_count: 1,
            latest_artifacts: ".baloncore/cloud-iam".to_string(),
            latest_evidence_dir: ".baloncore/cloud-iam".to_string(),
            transitions: vec![crate::lifecycle::FindingTransition {
                from_state: "hypothesis".to_string(),
                to_state: "verified".to_string(),
                reason: "cloud iam analysis".to_string(),
                at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                actor: "cloud-iam-analyzer".to_string(),
            }],
            defense_classifications: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityChainEntry {
    pub principal_id: String,
    pub principal_name: String,
    pub principal_kind: String,
    pub provider: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CloudEvidenceKind {
    PolicyDocument,
    TrustPolicy,
    PublicAccessConfig,
    ResourceConfiguration,
    IaCSource,
    CloudAuditLog,
    ManualObservation,
}

impl CloudEvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PolicyDocument => "policy_document",
            Self::TrustPolicy => "trust_policy",
            Self::PublicAccessConfig => "public_access_config",
            Self::ResourceConfiguration => "resource_configuration",
            Self::IaCSource => "iac_source",
            Self::CloudAuditLog => "cloud_audit_log",
            Self::ManualObservation => "manual_observation",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudEvidence {
    pub id: String,
    pub kind: CloudEvidenceKind,
    pub source: String,
    pub detail: String,
    pub raw_config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudReachabilityProof {
    pub finding_id: String,
    pub classification: String,
    pub severity: CloudSeverity,
    pub affected_resource: String,
    pub proof_status: String,
    pub privilege_level: PrivilegeLevel,
    pub chain_steps: Vec<CloudProofStep>,
    pub evidence_steps: Vec<CloudProofEvidenceStep>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudProofStep {
    pub step_number: usize,
    pub principal_id: String,
    pub principal_name: String,
    pub principal_kind: String,
    pub action: String,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudProofEvidenceStep {
    pub evidence_id: String,
    pub kind: String,
    pub source: String,
    pub detail: String,
}

pub fn cloud_reachability_proofs(result: &CloudAnalysisResult) -> Vec<CloudReachabilityProof> {
    result
        .findings
        .iter()
        .map(|finding| CloudReachabilityProof {
            finding_id: finding.id.clone(),
            classification: finding.classification.clone(),
            severity: finding.severity.clone(),
            affected_resource: finding.affected_resource.clone(),
            proof_status: if finding.is_reachable {
                "reachable".to_string()
            } else if finding.is_theoretical {
                "theoretical".to_string()
            } else {
                "unproven".to_string()
            },
            privilege_level: finding.privilege_level.clone(),
            chain_steps: finding
                .identity_chain
                .iter()
                .enumerate()
                .map(|(index, entry)| CloudProofStep {
                    step_number: index + 1,
                    principal_id: entry.principal_id.clone(),
                    principal_name: entry.principal_name.clone(),
                    principal_kind: entry.principal_kind.clone(),
                    action: entry.action.clone(),
                    provider: entry.provider.clone(),
                })
                .collect(),
            evidence_steps: finding
                .evidence
                .iter()
                .map(|evidence| CloudProofEvidenceStep {
                    evidence_id: evidence.id.clone(),
                    kind: evidence.kind.as_str().to_string(),
                    source: evidence.source.clone(),
                    detail: evidence.detail.clone(),
                })
                .collect(),
            remediation: finding.remediation.clone(),
        })
        .collect()
}

pub fn render_cloud_reachability_proofs(proofs: &[CloudReachabilityProof]) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Cloud Reachability Proofs\n\n");
    if proofs.is_empty() {
        md.push_str("No cloud reachability proofs were produced.\n");
        return md;
    }
    for proof in proofs {
        md.push_str(&format!(
            "## {} [{}]\n\n",
            proof.classification,
            proof.severity.as_str()
        ));
        md.push_str(&format!("- Finding ID: `{}`\n", proof.finding_id));
        md.push_str(&format!(
            "- Affected resource: `{}`\n",
            proof.affected_resource
        ));
        md.push_str(&format!("- Proof status: `{}`\n", proof.proof_status));
        md.push_str(&format!(
            "- Privilege level: `{}`\n\n",
            proof.privilege_level.as_str()
        ));
        md.push_str("### Identity Chain\n\n");
        if proof.chain_steps.is_empty() {
            md.push_str("- No identity-chain steps were available.\n");
        } else {
            for step in &proof.chain_steps {
                md.push_str(&format!(
                    "{}. `{}` ({}) performs `{}` in `{}`\n",
                    step.step_number,
                    step.principal_name,
                    step.principal_kind,
                    step.action,
                    step.provider
                ));
            }
        }
        md.push_str("\n### Evidence\n\n");
        if proof.evidence_steps.is_empty() {
            md.push_str("- No evidence records were attached.\n");
        } else {
            for evidence in &proof.evidence_steps {
                md.push_str(&format!(
                    "- `{}` from `{}`: {}\n",
                    evidence.kind, evidence.source, evidence.detail
                ));
            }
        }
        md.push_str(&format!("\n### Remediation\n\n{}\n\n", proof.remediation));
    }
    md
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudAnalysisResult {
    pub graph_id: String,
    pub summary: CloudAnalysisSummary,
    pub findings: Vec<CloudFinding>,
    pub privilege_paths: Vec<PrivilegePath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudAnalysisSummary {
    pub provider: CloudProvider,
    pub account_id: Option<String>,
    pub principal_count: usize,
    pub policy_count: usize,
    pub resource_count: usize,
    pub trust_count: usize,
    pub edge_count: usize,
    pub finding_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub privilege_path_count: usize,
    pub public_resource_count: usize,
    pub over_privileged_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_provider_round_trip() {
        assert_eq!(CloudProvider::AWS.as_str(), "aws");
        assert_eq!(CloudProvider::from_str_lossy("aws"), CloudProvider::AWS);
        assert_eq!(CloudProvider::from_str_lossy("gcp"), CloudProvider::GCP);
        assert_eq!(CloudProvider::from_str_lossy("azure"), CloudProvider::Azure);
        assert_eq!(
            CloudProvider::from_str_lossy("kubernetes"),
            CloudProvider::Kubernetes
        );
    }

    #[test]
    fn test_principal_builder() {
        let principal =
            IAMPrincipal::new("user-1", CloudProvider::AWS, PrincipalKind::User, "alice")
                .with_arn("arn:aws:iam::123456789012:user/alice")
                .with_account("123456789012");
        assert_eq!(principal.id, "user-1");
        assert_eq!(
            principal.arn,
            Some("arn:aws:iam::123456789012:user/alice".to_string())
        );
        assert_eq!(principal.account_id, Some("123456789012".to_string()));
        assert_eq!(
            principal.display_name(),
            "arn:aws:iam::123456789012:user/alice"
        );
    }

    #[test]
    fn test_iam_statement_matching() {
        let stmt = IAMStatement::new_allow(
            "stmt-1",
            vec!["s3:GetObject".to_string(), "s3:PutObject".to_string()],
            vec!["arn:aws:s3:::my-bucket/*".to_string()],
        );
        assert!(stmt.matches_action("s3:GetObject"));
        assert!(!stmt.matches_action("ec2:RunInstances"));
        assert!(stmt.matches_resource("arn:aws:s3:::my-bucket/file.txt"));
        assert!(!stmt.matches_resource("arn:aws:s3:::other-bucket/file.txt"));
    }

    #[test]
    fn test_wildcard_matching() {
        let stmt = IAMStatement::new_allow("stmt-1", vec!["*".to_string()], vec!["*".to_string()]);
        assert!(stmt.matches_action("s3:GetObject"));
        assert!(stmt.matches_resource("anything"));
        assert!(stmt.is_privileged());
    }

    #[test]
    fn test_policy_allows_denies() {
        let mut policy = IAMPolicy::new("pol-1", "admin-policy", CloudProvider::AWS);
        policy = policy
            .with_statement(IAMStatement::new_allow(
                "s1",
                vec!["s3:*".to_string()],
                vec!["*".to_string()],
            ))
            .with_statement(IAMStatement::new_deny(
                "s2",
                vec!["s3:DeleteBucket".to_string()],
                vec!["*".to_string()],
            ));

        assert!(policy.allows("s3:GetObject", "arn:aws:s3:::bucket/key"));
        assert!(policy.explicit_denies("s3:DeleteBucket", "arn:aws:s3:::bucket"));
        assert!(policy.is_over_privileged());
    }

    #[test]
    fn test_trust_relationship_over_privileged() {
        let trust =
            TrustRelationship::new("trust-1", "arn:aws:iam::123456789012:role/AdminRole", "*")
                .with_external();
        assert!(trust.is_over_privileged());

        let safe_trust = TrustRelationship::new(
            "trust-2",
            "arn:aws:iam::123456789012:role/AdminRole",
            "arn:aws:iam::123456789012:user/bob",
        );
        assert!(!safe_trust.is_over_privileged());
    }

    #[test]
    fn test_oidc_trust_detection() {
        let trust = TrustRelationship::new(
            "trust-1",
            "arn:aws:iam::123456789012:role/DeployRole",
            "repo:my-org/my-repo",
        )
        .with_condition(IAMCondition::new(
            "StringEquals",
            "token.actions.githubusercontent.com:sub",
            vec!["repo:my-org/my-repo:ref:refs/heads/main".to_string()],
        ));
        assert!(trust.is_oidc_trust());
    }

    #[test]
    fn test_iam_graph_basic_analysis() {
        let mut graph = IAMGraph::new("test-graph-1", CloudProvider::AWS);

        let admin_role = IAMPrincipal::new(
            "admin-role",
            CloudProvider::AWS,
            PrincipalKind::Role,
            "AdminRole",
        )
        .with_arn("arn:aws:iam::123456789012:role/AdminRole");
        graph.add_principal(admin_role);

        let deploy_role = IAMPrincipal::new(
            "deploy-role",
            CloudProvider::AWS,
            PrincipalKind::Role,
            "DeployRole",
        )
        .with_arn("arn:aws:iam::123456789012:role/DeployRole")
        .with_policy("admin-policy");
        graph.add_principal(deploy_role);

        let mut admin_policy = IAMPolicy::new("pol-admin", "admin-policy", CloudProvider::AWS);
        admin_policy = admin_policy.with_statement(IAMStatement::new_allow(
            "s1",
            vec!["*".to_string()],
            vec!["*".to_string()],
        ));
        graph.add_policy(admin_policy);

        let trust = TrustRelationship::new(
            "trust-deploy",
            "arn:aws:iam::123456789012:role/DeployRole",
            "repo:my-org/my-repo",
        )
        .with_condition(IAMCondition::new(
            "StringEquals",
            "token.actions.githubusercontent.com:sub",
            vec!["repo:my-org/my-repo:ref:refs/heads/main".to_string()],
        ));
        graph.add_trust(trust);

        let public_bucket = CloudResource::new(
            "bucket-1",
            CloudProvider::AWS,
            "s3-bucket",
            "public-data-bucket",
        )
        .with_arn("arn:aws:s3:::public-data-bucket")
        .with_public_access(vec!["Public read access enabled".to_string()]);
        graph.add_resource(public_bucket);

        let result = graph.analyze();
        assert!(
            result.findings.len() >= 2,
            "Expected at least 2 findings, got {}",
            result.findings.len()
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.classification == "PublicResourceExposure"),
            "Expected public exposure finding"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.classification == "OverPrivilegedPolicy"),
            "Expected over-privileged policy finding"
        );
    }

    #[test]
    fn test_cicd_trust_finding() {
        let mut graph = IAMGraph::new("cicd-graph-1", CloudProvider::AWS);

        let github_actions = IAMPrincipal::new(
            "github-actions",
            CloudProvider::AWS,
            PrincipalKind::CiCdIdentity,
            "github-actions",
        );
        graph.add_principal(github_actions);

        let deploy_role = IAMPrincipal::new(
            "deploy-role",
            CloudProvider::AWS,
            PrincipalKind::Role,
            "DeployRole",
        )
        .with_arn("arn:aws:iam::123456789012:role/DeployRole")
        .with_policy("deploy-policy");
        graph.add_principal(deploy_role);

        let mut deploy_policy = IAMPolicy::new("pol-deploy", "deploy-policy", CloudProvider::AWS);
        deploy_policy = deploy_policy.with_statement(IAMStatement::new_allow(
            "s1",
            vec!["*".to_string()],
            vec!["*".to_string()],
        ));
        graph.add_policy(deploy_policy);

        graph.edges.push(IAMEdge {
            id: "edge-cicd-1".to_string(),
            from_principal: "github-actions".to_string(),
            to_principal: Some("deploy-role".to_string()),
            to_resource: None,
            edge_kind: IAMEdgeKind::CiCdTrust,
            policy_id: None,
            actions: vec!["sts:AssumeRole".to_string()],
            conditions: vec![],
            is_deny: false,
            confidence: 1.0,
            source: String::new(),
        });

        let result = graph.analyze();
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.classification == "CiCdPrivilegeEscalation"),
            "Expected CI/CD privilege escalation finding"
        );
    }

    #[test]
    fn test_privilege_path_discovery() {
        let mut graph = IAMGraph::new("path-graph-1", CloudProvider::AWS);

        let mut public_user = IAMPrincipal::new(
            "public-user",
            CloudProvider::AWS,
            PrincipalKind::User,
            "PublicUser",
        );
        public_user.is_public = true;
        graph.add_principal(public_user);

        let admin_role = IAMPrincipal::new(
            "admin-role",
            CloudProvider::AWS,
            PrincipalKind::Role,
            "AdminRole",
        )
        .with_policy("admin-policy");
        graph.add_principal(admin_role);

        let mut admin_policy = IAMPolicy::new("pol-admin", "admin-policy", CloudProvider::AWS);
        admin_policy = admin_policy.with_statement(IAMStatement::new_allow(
            "s1",
            vec!["*".to_string()],
            vec!["*".to_string()],
        ));
        graph.add_policy(admin_policy);

        // Trust: anyone can assume admin role (over-privileged trust)
        graph.add_trust(
            TrustRelationship::new("trust-1", "admin-role", "public-user").with_external(),
        );

        let result = graph.analyze();
        // The public user with external trust to admin role should create findings
        assert!(
            result.findings.len() > 0,
            "Expected findings from privilege path, got {} findings",
            result.findings.len()
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.classification == "OverPrivilegedTrustPolicy"
                    || f.classification == "OverPrivilegedPolicy"),
            "Expected over-privileged finding, got {:?}",
            result
                .findings
                .iter()
                .map(|f| &f.classification)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_resource_builder() {
        let resource = CloudResource::new("bucket-1", CloudProvider::AWS, "s3-bucket", "my-bucket")
            .with_arn("arn:aws:s3:::my-bucket")
            .with_region("us-east-1")
            .with_public_access(vec!["Public read via bucket policy".to_string()]);

        assert!(resource.is_public);
        assert_eq!(resource.public_access_details.len(), 1);
        assert_eq!(resource.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn test_render_attack_path_report() {
        let mut graph = IAMGraph::new("report-graph-1", CloudProvider::AWS);
        graph.account_id = Some("123456789012".to_string());

        let bucket =
            CloudResource::new("bucket-1", CloudProvider::AWS, "s3-bucket", "public-bucket")
                .with_public_access(vec!["AllUsers read access".to_string()]);
        graph.add_resource(bucket);

        let result = graph.analyze();
        let report = graph.render_attack_path_report(&result);
        assert!(report.contains("BALONCORE Cloud/IAM Attack Path Report"));
        assert!(report.contains("PublicResourceExposure"));
    }

    #[test]
    fn test_cloud_finding_to_lifecycle_record() {
        let finding = CloudFinding {
            id: "test-finding-1".to_string(),
            classification: "PublicResourceExposure".to_string(),
            severity: CloudSeverity::High,
            provider: CloudProvider::AWS,
            affected_resource: "my-bucket".to_string(),
            affected_resource_arn: Some("arn:aws:s3:::my-bucket".to_string()),
            description: "Bucket is public".to_string(),
            identity_chain: vec![],
            remediation: "Restrict access".to_string(),
            evidence: vec![],
            is_reachable: true,
            is_theoretical: false,
            privilege_level: PrivilegeLevel::Elevated,
        };

        let record = finding.to_finding_record("cloud-iam-scan-1");
        assert_eq!(record.finding_id, "test-finding-1");
        assert_eq!(record.classification, "PublicResourceExposure");
        assert_eq!(record.vulnerability_class, "cloud_iam");
        assert_eq!(record.severity, "high");
        assert_eq!(record.state, crate::lifecycle::FindingState::Verified);
    }

    #[test]
    fn test_reachability_proofs_include_chain_and_evidence() {
        let mut graph = IAMGraph::new("proof-graph-1", CloudProvider::AWS);
        let bucket =
            CloudResource::new("bucket-1", CloudProvider::AWS, "s3-bucket", "public-bucket")
                .with_arn("arn:aws:s3:::public-bucket")
                .with_public_access(vec!["bucket policy allows Principal *".to_string()]);
        graph.add_resource(bucket);

        let result = graph.analyze();
        let proofs = cloud_reachability_proofs(&result);
        assert!(!proofs.is_empty());
        let proof = &proofs[0];
        assert_eq!(proof.proof_status, "reachable");
        assert!(!proof.chain_steps.is_empty());
        assert!(!proof.evidence_steps.is_empty());

        let rendered = render_cloud_reachability_proofs(&proofs);
        assert!(rendered.contains("Cloud Reachability Proofs"));
        assert!(rendered.contains("bucket policy allows Principal"));
    }

    #[test]
    fn test_pattern_matches() {
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("s3:*", "s3:GetObject"));
        assert!(!pattern_matches("s3:*", "ec2:RunInstances"));
        assert!(pattern_matches(
            "arn:aws:s3:::my-bucket/*",
            "arn:aws:s3:::my-bucket/file.txt"
        ));
        assert!(!pattern_matches(
            "arn:aws:s3:::my-bucket/*",
            "arn:aws:s3:::other-bucket/file.txt"
        ));
    }

    #[test]
    fn test_privileged_statements() {
        let stmt = IAMStatement::new_allow("s1", vec!["iam:*".to_string()], vec!["*".to_string()]);
        assert!(stmt.is_privileged());

        let safe_stmt = IAMStatement::new_allow(
            "s2",
            vec!["s3:GetObject".to_string()],
            vec!["arn:aws:s3:::bucket/key".to_string()],
        );
        assert!(!safe_stmt.is_privileged());
    }

    #[test]
    fn test_empty_graph_analysis() {
        let mut graph = IAMGraph::new("empty-graph", CloudProvider::AWS);
        let result = graph.analyze();
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.summary.principal_count, 0);
        assert_eq!(result.summary.policy_count, 0);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(CloudSeverity::Critical.ordinal() > CloudSeverity::High.ordinal());
        assert!(CloudSeverity::High.ordinal() > CloudSeverity::Medium.ordinal());
        assert!(CloudSeverity::Medium.ordinal() > CloudSeverity::Low.ordinal());
        assert!(CloudSeverity::Low.ordinal() > CloudSeverity::Informational.ordinal());
    }
}
