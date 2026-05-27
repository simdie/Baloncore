use crate::cloud_iam::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AWSPolicyDocument {
    #[serde(default, rename = "Version")]
    pub version: Option<String>,
    #[serde(default, rename = "Statement")]
    pub statement: Vec<AWSPolicyStatement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AWSPolicyStatement {
    #[serde(default, rename = "Sid")]
    pub sid: Option<String>,
    #[serde(default, rename = "Effect")]
    pub effect: String,
    #[serde(default, rename = "Action")]
    pub action: AWSActionField,
    #[serde(default, rename = "Resource")]
    pub resource: AWSResourceField,
    #[serde(default, rename = "Condition")]
    pub condition: Option<serde_json::Value>,
    #[serde(default, rename = "Principal")]
    pub principal: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum AWSActionField {
    Single(String),
    Multiple(Vec<String>),
}

impl Default for AWSActionField {
    fn default() -> Self {
        Self::Multiple(Vec::new())
    }
}

impl AWSActionField {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::Single(s) => vec![s.clone()],
            Self::Multiple(v) => v.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum AWSResourceField {
    Single(String),
    Multiple(Vec<String>),
}

impl Default for AWSResourceField {
    fn default() -> Self {
        Self::Multiple(Vec::new())
    }
}

impl AWSResourceField {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::Single(s) => vec![s.clone()],
            Self::Multiple(v) => v.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AWSIAMConfig {
    #[serde(default)]
    pub users: Vec<AWSUserConfig>,
    #[serde(default)]
    pub groups: Vec<AWSGroupConfig>,
    #[serde(default)]
    pub roles: Vec<AWSRoleConfig>,
    #[serde(default)]
    pub policies: Vec<AWSPolicyConfig>,
    #[serde(default)]
    pub bucket_policies: Vec<AWSBucketPolicyConfig>,
    #[serde(default)]
    pub account_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AWSUserConfig {
    pub name: String,
    #[serde(default)]
    pub arn: Option<String>,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub attached_policies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AWSGroupConfig {
    pub name: String,
    #[serde(default)]
    pub arn: Option<String>,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub attached_policies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AWSRoleConfig {
    pub name: String,
    #[serde(default)]
    pub arn: Option<String>,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub attached_policies: Vec<String>,
    #[serde(default)]
    pub trust_policy: Option<serde_json::Value>,
    #[serde(default)]
    pub trust_policy_json: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AWSPolicyConfig {
    pub name: String,
    #[serde(default)]
    pub arn: Option<String>,
    #[serde(default)]
    pub policy_type: Option<String>,
    #[serde(default)]
    pub document: Option<serde_json::Value>,
    #[serde(default)]
    pub document_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AWSBucketPolicyConfig {
    pub bucket: String,
    #[serde(default)]
    pub arn: Option<String>,
    pub policy: serde_json::Value,
    #[serde(default)]
    pub public_access_block: Option<AWSPublicAccessBlock>,
    #[serde(default)]
    pub acl: Option<String>,
    #[serde(default)]
    pub encryption: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AWSPublicAccessBlock {
    pub block_public_acls: bool,
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    pub restrict_public_buckets: bool,
}

pub struct AWSIAMIngestor;

impl AWSIAMIngestor {
    pub fn ingest(config: &AWSIAMConfig) -> IAMGraph {
        let account_id = config
            .account_id
            .clone()
            .unwrap_or_else(|| "000000000000".to_string());
        let mut graph = IAMGraph::new(format!("aws-iam-{}", account_id), CloudProvider::AWS);
        graph.account_id = Some(account_id.clone());

        for user in &config.users {
            let mut principal = IAMPrincipal::new(
                format!("aws-user-{}", user.name),
                CloudProvider::AWS,
                PrincipalKind::User,
                user.name.clone(),
            );
            if let Some(ref arn) = user.arn {
                principal = principal.with_arn(arn.clone());
            }
            principal = principal.with_account(&account_id);
            for policy_name in &user.policies {
                principal = principal.with_policy(policy_name.clone());
            }
            for policy_name in &user.attached_policies {
                principal = principal.with_policy(policy_name.clone());
            }
            graph.add_principal(principal);
        }

        for group in &config.groups {
            let mut principal = IAMPrincipal::new(
                format!("aws-group-{}", group.name),
                CloudProvider::AWS,
                PrincipalKind::Group,
                group.name.clone(),
            );
            if let Some(ref arn) = group.arn {
                principal = principal.with_arn(arn.clone());
            }
            principal = principal.with_account(&account_id);
            for policy_name in &group.policies {
                principal = principal.with_policy(policy_name.clone());
            }
            for policy_name in &group.attached_policies {
                principal = principal.with_policy(policy_name.clone());
            }
            graph.add_principal(principal);
        }

        for role in &config.roles {
            let mut principal = IAMPrincipal::new(
                format!("aws-role-{}", role.name),
                CloudProvider::AWS,
                PrincipalKind::Role,
                role.name.clone(),
            );
            if let Some(ref arn) = role.arn {
                principal = principal.with_arn(arn.clone());
            }
            principal = principal.with_account(&account_id);
            for policy_name in &role.policies {
                principal = principal.with_policy(policy_name.clone());
            }
            for policy_name in &role.attached_policies {
                principal = principal.with_policy(policy_name.clone());
            }
            graph.add_principal(principal);

            if let Some(trust_policy) = &role.trust_policy {
                if let Some(trust) = Self::parse_trust_policy(
                    &format!("trust-{}", role.name),
                    role.arn.as_deref().unwrap_or(&role.name),
                    trust_policy,
                ) {
                    graph.add_trust(trust);
                }
            } else if let Some(trust_json) = &role.trust_policy_json {
                if let Ok(trust_doc) = serde_json::from_str::<AWSPolicyDocument>(trust_json) {
                    if let Some(trust) = Self::parse_trust_document(
                        &format!("trust-{}", role.name),
                        role.arn.as_deref().unwrap_or(&role.name),
                        &trust_doc,
                    ) {
                        graph.add_trust(trust);
                    }
                }
            }

            for policy_name in &role.policies {
                if let Some(policy_config) = config.policies.iter().find(|p| &p.name == policy_name)
                {
                    let iam_policy = Self::parse_policy_config(policy_config, CloudProvider::AWS);
                    graph.add_policy(iam_policy);
                }
            }
            for policy_name in &role.attached_policies {
                if let Some(policy_config) = config.policies.iter().find(|p| &p.name == policy_name)
                {
                    let iam_policy = Self::parse_policy_config(policy_config, CloudProvider::AWS);
                    graph.add_policy(iam_policy);
                }
            }
        }

        for policy_config in &config.policies {
            if !graph
                .policies
                .contains_key(&format!("aws-policy-{}", policy_config.name))
            {
                let iam_policy = Self::parse_policy_config(policy_config, CloudProvider::AWS);
                graph.add_policy(iam_policy);
            }
        }

        for bucket_config in &config.bucket_policies {
            let mut resource = CloudResource::new(
                format!("aws-s3-{}", bucket_config.bucket),
                CloudProvider::AWS,
                "s3-bucket",
                bucket_config.bucket.clone(),
            );
            if let Some(ref arn) = bucket_config.arn {
                resource = resource.with_arn(arn.clone());
            }

            let is_public = Self::is_bucket_public(bucket_config);
            if is_public {
                resource = resource.with_public_access(Self::bucket_public_details(bucket_config));
            }
            resource.raw_config = Some(bucket_config.policy.clone());
            graph.add_resource(resource);
        }

        let mut group_memberships = Vec::new();
        for user in &config.users {
            for group_name in &user.groups {
                group_memberships.push((
                    format!("aws-user-{}", user.name),
                    format!("aws-group-{}", group_name),
                ));
            }
        }
        graph.resolve_group_memberships(&group_memberships);

        graph
    }

    pub fn ingest_json(json: &str) -> Result<IAMGraph, String> {
        let config: AWSIAMConfig = serde_json::from_str(json)
            .map_err(|e| format!("failed to parse AWS IAM config: {e}"))?;
        Ok(Self::ingest(&config))
    }

    pub fn ingest_file(path: &std::path::Path) -> Result<IAMGraph, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read AWS IAM config: {e}"))?;
        Self::ingest_json(&raw)
    }

    pub fn parse_policy_config(
        policy_config: &AWSPolicyConfig,
        provider: CloudProvider,
    ) -> IAMPolicy {
        let policy_id = format!("aws-policy-{}", policy_config.name);
        let mut policy = IAMPolicy::new(&policy_id, &policy_config.name, provider);
        policy.source_type = match policy_config.policy_type.as_deref() {
            Some("managed") => PolicySourceType::AWSManaged,
            Some("inline") => PolicySourceType::AWSInline,
            Some("custom") | _ => PolicySourceType::AWSCustom,
        };

        if let Some(doc) = &policy_config.document {
            Self::parse_policy_document_into(doc, &mut policy);
        } else if let Some(doc_json) = &policy_config.document_json {
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(doc_json) {
                Self::parse_policy_document_into(&doc, &mut policy);
            }
        }
        policy
    }

    pub fn parse_policy_document_into(doc: &serde_json::Value, policy: &mut IAMPolicy) {
        let statements = if let Some(stmts) = doc.get("Statement").or_else(|| doc.get("statement"))
        {
            if let Some(arr) = stmts.as_array() {
                arr.iter()
                    .filter_map(|s| Self::parse_statement(s))
                    .collect()
            } else {
                Self::parse_statement(stmts).into_iter().collect()
            }
        } else {
            Vec::new()
        };
        policy.statements = statements;
    }

    fn parse_statement(stmt: &serde_json::Value) -> Option<IAMStatement> {
        let id = stmt
            .get("Sid")
            .or_else(|| stmt.get("sid"))
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed")
            .to_string();

        let effect = stmt
            .get("Effect")
            .or_else(|| stmt.get("effect"))
            .and_then(|v| v.as_str())
            .unwrap_or("Allow");

        let effect = Effect::from_str_lossy(effect);

        let actions = stmt
            .get("Action")
            .or_else(|| stmt.get("action"))
            .map(|v| {
                if let Some(arr) = v.as_array() {
                    arr.iter()
                        .filter_map(|a| a.as_str().map(String::from))
                        .collect()
                } else if let Some(s) = v.as_str() {
                    vec![s.to_string()]
                } else {
                    vec![]
                }
            })
            .unwrap_or_default();

        let resources = stmt
            .get("Resource")
            .or_else(|| stmt.get("resource"))
            .map(|v| {
                if let Some(arr) = v.as_array() {
                    arr.iter()
                        .filter_map(|a| a.as_str().map(String::from))
                        .collect()
                } else if let Some(s) = v.as_str() {
                    vec![s.to_string()]
                } else {
                    vec![]
                }
            })
            .unwrap_or_default();

        let conditions =
            Self::parse_conditions(stmt.get("Condition").or_else(|| stmt.get("condition")));

        let source_doc = serde_json::to_string(stmt).unwrap_or_default();

        Some(IAMStatement {
            id,
            effect,
            actions,
            resources,
            conditions,
            source_doc,
        })
    }

    fn parse_conditions(cond: Option<&serde_json::Value>) -> Vec<IAMCondition> {
        let mut result = Vec::new();
        if let Some(cond_obj) = cond {
            if let Some(obj) = cond_obj.as_object() {
                for (operator, conditions) in obj {
                    if let Some(cond_map) = conditions.as_object() {
                        for (key, values) in cond_map {
                            let value_list = if let Some(arr) = values.as_array() {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            } else if let Some(s) = values.as_str() {
                                vec![s.to_string()]
                            } else {
                                vec![]
                            };
                            result.push(IAMCondition::new(operator, key, value_list));
                        }
                    }
                }
            }
        }
        result
    }

    pub fn parse_trust_policy(
        id: &str,
        role_arn: &str,
        trust_policy: &serde_json::Value,
    ) -> Option<TrustRelationship> {
        let statements_field = trust_policy
            .get("Statement")
            .or_else(|| trust_policy.get("statement"));
        let statements_raw = if let Some(stmts) = statements_field {
            if let Some(arr) = stmts.as_array() {
                arr.clone()
            } else {
                vec![stmts.clone()]
            }
        } else {
            vec![]
        };

        let mut trusted_principals = Vec::new();
        let mut conditions = Vec::new();

        for stmt in &statements_raw {
            if let Some(principal) = stmt.get("Principal").or_else(|| stmt.get("principal")) {
                let principals = Self::extract_principals(principal);
                trusted_principals.extend(principals);
            }
            if let Some(cond) = stmt.get("Condition").or_else(|| stmt.get("condition")) {
                conditions.extend(Self::parse_conditions(Some(cond)));
            }
        }

        if trusted_principals.is_empty() {
            return None;
        }

        let trusted_principal = if trusted_principals.len() == 1 {
            trusted_principals.into_iter().next().unwrap()
        } else {
            trusted_principals.into_iter().collect::<Vec<_>>().join(",")
        };

        let allows_external = trusted_principal == "*";

        let mut trust = TrustRelationship::new(id, role_arn.to_string(), trusted_principal);
        trust.allows_external = allows_external;
        trust.conditions = conditions;
        trust.source_doc = serde_json::to_string(trust_policy).unwrap_or_default();
        Some(trust)
    }

    fn extract_principals(principal: &serde_json::Value) -> Vec<String> {
        let mut result = Vec::new();
        if let Some(s) = principal.as_str() {
            result.push(s.to_string());
        } else if let Some(obj) = principal.as_object() {
            if let Some(aws) = obj.get("AWS") {
                if let Some(s) = aws.as_str() {
                    result.push(s.to_string());
                } else if let Some(arr) = aws.as_array() {
                    for v in arr {
                        if let Some(s) = v.as_str() {
                            result.push(s.to_string());
                        }
                    }
                }
            }
            if let Some(service) = obj.get("Service") {
                if let Some(s) = service.as_str() {
                    result.push(s.to_string());
                } else if let Some(arr) = service.as_array() {
                    for v in arr {
                        if let Some(s) = v.as_str() {
                            result.push(s.to_string());
                        }
                    }
                }
            }
            if let Some(fed) = obj.get("Federated") {
                if let Some(s) = fed.as_str() {
                    result.push(s.to_string());
                }
            }
        } else if let Some(arr) = principal.as_array() {
            for v in arr {
                if let Some(s) = v.as_str() {
                    result.push(s.to_string());
                }
            }
        }
        result
    }

    fn parse_trust_document(
        id: &str,
        role_arn: &str,
        doc: &AWSPolicyDocument,
    ) -> Option<TrustRelationship> {
        if doc.statement.is_empty() {
            return None;
        }

        let stmt = &doc.statement[0];
        let effect = Effect::from_str_lossy(&stmt.effect);
        if effect == Effect::Deny {
            return None;
        }

        let mut trust = TrustRelationship::new(id, role_arn.to_string(), "unknown".to_string());

        let principal_value = &stmt.principal;
        if let Some(pv) = principal_value {
            if let Some(s) = pv.as_str() {
                trust.trusted_principal = s.to_string();
                if s == "*" {
                    trust.allows_external = true;
                }
            } else if let Some(obj) = pv.as_object() {
                if let Some(aws) = obj.get("AWS") {
                    trust.trusted_principal = if let Some(s) = aws.as_str() {
                        s.to_string()
                    } else if let Some(arr) = aws.as_array() {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect::<Vec<_>>()
                            .join(",")
                    } else {
                        "unknown".to_string()
                    };
                } else if let Some(service) = obj.get("Service") {
                    trust.trusted_principal = if let Some(s) = service.as_str() {
                        s.to_string()
                    } else {
                        "service".to_string()
                    };
                } else if let Some(fed) = obj.get("Federated") {
                    trust.trusted_principal = if let Some(s) = fed.as_str() {
                        s.to_string()
                    } else {
                        "federated".to_string()
                    };
                }
            }
        }

        let conditions = Self::parse_conditions(stmt.condition.as_ref());
        trust.conditions = conditions;
        trust.source_doc = serde_json::to_string(doc).unwrap_or_default();
        Some(trust)
    }

    fn is_bucket_public(bucket: &AWSBucketPolicyConfig) -> bool {
        if let Some(pab) = &bucket.public_access_block {
            if pab.block_public_acls
                && pab.ignore_public_acls
                && pab.block_public_policy
                && pab.restrict_public_buckets
            {
                return false;
            }
        }

        if let Some(statements) = bucket.policy.get("Statement").and_then(|s| s.as_array()) {
            for stmt in statements {
                let effect = stmt
                    .get("Effect")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Deny");
                if effect != "Allow" {
                    continue;
                }

                let principal = stmt.get("Principal");
                if let Some(p) = principal {
                    if p.as_str() == Some("*") {
                        return true;
                    }
                    if let Some(obj) = p.as_object() {
                        if let Some(aws) = obj.get("AWS") {
                            if aws.as_str() == Some("*") {
                                return true;
                            }
                            if let Some(arr) = aws.as_array() {
                                if arr.iter().any(|v| v.as_str() == Some("*")) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(acl) = &bucket.acl {
            if acl.contains("public-read") || acl.contains("public-read-write") {
                return true;
            }
        }

        false
    }

    fn bucket_public_details(bucket: &AWSBucketPolicyConfig) -> Vec<String> {
        let mut details = Vec::new();

        if let Some(pab) = &bucket.public_access_block {
            if !pab.block_public_policy {
                details.push("Block Public Policy is disabled".to_string());
            }
            if !pab.restrict_public_buckets {
                details.push("Restrict Public Buckets is disabled".to_string());
            }
        } else {
            details.push("No public access block configuration".to_string());
        }

        if let Some(statements) = bucket.policy.get("Statement").and_then(|s| s.as_array()) {
            for stmt in statements {
                let principal = stmt.get("Principal");
                if let Some(p) = principal {
                    if p.as_str() == Some("*") {
                        details.push("Bucket policy grants access to principal '*'".to_string());
                    }
                }
            }
        }

        if let Some(acl) = &bucket.acl {
            if acl.contains("public-read") {
                details.push(format!("Bucket ACL is {}", acl));
            }
        }

        if details.is_empty() {
            details.push("Bucket may be publicly accessible".to_string());
        }

        details
    }

    pub fn ingest_aws_iam_get_policy_output(json: &str) -> Result<Vec<IAMStatement>, String> {
        let doc: AWSPolicyDocument = serde_json::from_str(json)
            .map_err(|e| format!("failed to parse AWS policy document: {e}"))?;
        Ok(doc
            .statement
            .iter()
            .filter_map(|s| {
                let id = s.sid.clone().unwrap_or_else(|| "unnamed".to_string());
                let effect = Effect::from_str_lossy(&s.effect);
                let actions = s.action.to_vec();
                let resources = s.resource.to_vec();
                let conditions = Self::parse_conditions(s.condition.as_ref().map(|v| v));
                let source_doc = serde_json::to_string(s).unwrap_or_default();
                Some(IAMStatement {
                    id,
                    effect,
                    actions,
                    resources,
                    conditions,
                    source_doc,
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_iam_ingest_basic() {
        let config = AWSIAMConfig {
            users: vec![AWSUserConfig {
                name: "alice".to_string(),
                arn: Some("arn:aws:iam::123456789012:user/alice".to_string()),
                policies: vec!["admin-policy".to_string()],
                groups: vec!["admins".to_string()],
                attached_policies: vec![],
            }],
            groups: vec![AWSGroupConfig {
                name: "admins".to_string(),
                arn: Some("arn:aws:iam::123456789012:group/admins".to_string()),
                policies: vec!["admin-policy".to_string()],
                attached_policies: vec![],
            }],
            roles: vec![AWSRoleConfig {
                name: "DeployRole".to_string(),
                arn: Some("arn:aws:iam::123456789012:role/DeployRole".to_string()),
                policies: vec!["deploy-policy".to_string()],
                attached_policies: vec![],
                trust_policy: Some(serde_json::json!({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:user/github-actions"},
                        "Action": "sts:AssumeRole"
                    }]
                })),
                trust_policy_json: None,
                path: None,
            }],
            policies: vec![
                AWSPolicyConfig {
                    name: "admin-policy".to_string(),
                    arn: Some("arn:aws:iam::aws:policy/AdminAccess".to_string()),
                    policy_type: Some("managed".to_string()),
                    document: Some(serde_json::json!({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": ["*"],
                            "Resource": ["*"]
                        }]
                    })),
                    document_json: None,
                },
                AWSPolicyConfig {
                    name: "deploy-policy".to_string(),
                    arn: None,
                    policy_type: Some("inline".to_string()),
                    document: Some(serde_json::json!({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": ["ec2:*", "s3:GetObject"],
                            "Resource": ["*"]
                        }]
                    })),
                    document_json: None,
                },
            ],
            bucket_policies: vec![AWSBucketPolicyConfig {
                bucket: "public-data-bucket".to_string(),
                arn: Some("arn:aws:s3:::public-data-bucket".to_string()),
                policy: serde_json::json!({
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::public-data-bucket/*"
                    }]
                }),
                public_access_block: Some(AWSPublicAccessBlock {
                    block_public_acls: false,
                    ignore_public_acls: false,
                    block_public_policy: false,
                    restrict_public_buckets: false,
                }),
                acl: None,
                encryption: None,
            }],
            account_id: Some("123456789012".to_string()),
        };

        let mut graph = AWSIAMIngestor::ingest(&config);
        assert!(graph.principals.contains_key("aws-user-alice"));
        assert!(graph.principals.contains_key("aws-group-admins"));
        assert!(graph.principals.contains_key("aws-role-DeployRole"));
        assert_eq!(graph.policies.len(), 2);
        assert_eq!(graph.resources.len(), 1);
        assert!(!graph.trust_relationships.is_empty());

        let result = graph.analyze();
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
    fn test_aws_iam_ingest_json() {
        let json = r#"{
            "users": [],
            "groups": [],
            "roles": [],
            "policies": [],
            "bucket_policies": [],
            "account_id": "999999999999"
        }"#;
        let graph = AWSIAMIngestor::ingest_json(json).unwrap();
        assert_eq!(graph.principals.len(), 0);
        assert_eq!(graph.account_id, Some("999999999999".to_string()));
    }

    #[test]
    fn test_aws_trust_policy_parsing() {
        let trust = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:user/deploy"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": "unique-id"
                    }
                }
            }]
        });
        let result = AWSIAMIngestor::parse_trust_policy(
            "trust-1",
            "arn:aws:iam::123456789012:role/DeployRole",
            &trust,
        );
        assert!(result.is_some());
        let t = result.unwrap();
        assert_eq!(t.trusted_principal, "arn:aws:iam::123456789012:user/deploy");
        assert!(!t.allows_external);
    }

    #[test]
    fn test_aws_wildcard_trust() {
        let trust = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole"
            }]
        });
        let result = AWSIAMIngestor::parse_trust_policy(
            "trust-wildcard",
            "arn:aws:iam::123456789012:role/OpenRole",
            &trust,
        );
        assert!(result.is_some());
        let t = result.unwrap();
        assert!(t.allows_external);
        assert!(t.is_over_privileged());
    }

    #[test]
    fn test_public_bucket_detection() {
        let bucket = AWSBucketPolicyConfig {
            bucket: "open-bucket".to_string(),
            arn: Some("arn:aws:s3:::open-bucket".to_string()),
            policy: serde_json::json!({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::open-bucket/*"
                }]
            }),
            public_access_block: Some(AWSPublicAccessBlock {
                block_public_acls: false,
                ignore_public_acls: false,
                block_public_policy: false,
                restrict_public_buckets: false,
            }),
            acl: None,
            encryption: None,
        };
        assert!(AWSIAMIngestor::is_bucket_public(&bucket));
    }

    #[test]
    fn test_restricted_bucket_not_public() {
        let bucket = AWSBucketPolicyConfig {
            bucket: "locked-bucket".to_string(),
            arn: Some("arn:aws:s3:::locked-bucket".to_string()),
            policy: serde_json::json!({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::locked-bucket/*"
                }]
            }),
            public_access_block: Some(AWSPublicAccessBlock {
                block_public_acls: true,
                ignore_public_acls: true,
                block_public_policy: true,
                restrict_public_buckets: true,
            }),
            acl: None,
            encryption: None,
        };
        assert!(!AWSIAMIngestor::is_bucket_public(&bucket));
    }

    #[test]
    fn test_oidc_trust_in_role() {
        let trust = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                    },
                    "StringLike": {
                        "token.actions.githubusercontent.com:sub": "repo:my-org/*"
                    }
                }
            }]
        });
        let result = AWSIAMIngestor::parse_trust_policy(
            "trust-oidc",
            "arn:aws:iam::123456789012:role/GitHubActionsRole",
            &trust,
        );
        assert!(result.is_some());
        let t = result.unwrap();
        assert!(t.is_oidc_trust());
    }
}
