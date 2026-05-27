use crate::cloud_iam::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudFormationTemplate {
    #[serde(default, rename = "AWSTemplateFormatVersion")]
    pub format_version: Option<String>,
    #[serde(default, rename = "Description")]
    pub description: Option<String>,
    #[serde(default, rename = "Resources")]
    pub resources: serde_json::Value,
    #[serde(default, rename = "Parameters")]
    pub parameters: Option<serde_json::Value>,
    #[serde(default, rename = "Outputs")]
    pub outputs: Option<serde_json::Value>,
}

pub struct CloudFormationIngestor;

impl CloudFormationIngestor {
    pub fn ingest(template: &CloudFormationTemplate, account_id: Option<&str>) -> IAMGraph {
        let aid = account_id.unwrap_or("cloudformation-managed");
        let mut graph = IAMGraph::new(format!("cloudformation-{}", aid), CloudProvider::AWS);
        graph.account_id = Some(aid.to_string());

        if let Some(resources) = template.resources.as_object() {
            for (logical_id, resource_def) in resources {
                let resource_type = resource_def
                    .get("Type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");

                match resource_type {
                    "AWS::IAM::Role" => {
                        Self::ingest_role(&mut graph, logical_id, resource_def, aid)
                    }
                    "AWS::IAM::User" => {
                        Self::ingest_user(&mut graph, logical_id, resource_def, aid)
                    }
                    "AWS::IAM::Group" => {
                        Self::ingest_group(&mut graph, logical_id, resource_def, aid)
                    }
                    "AWS::IAM::Policy" | "AWS::IAM::ManagedPolicy" => {
                        Self::ingest_policy(&mut graph, logical_id, resource_def)
                    }
                    "AWS::S3::Bucket" | "AWS::S3::BucketPolicy" => {
                        Self::ingest_s3_bucket(&mut graph, logical_id, resource_def)
                    }
                    "AWS::IAM::RolePolicy" | "AWS::IAM::UserPolicy" | "AWS::IAM::GroupPolicy" => {
                        Self::ingest_inline_policy(&mut graph, logical_id, resource_def)
                    }
                    _ => Self::ingest_generic_resource(
                        &mut graph,
                        logical_id,
                        resource_type,
                        resource_def,
                    ),
                }
            }
        }

        graph
    }

    pub fn ingest_json(json: &str) -> Result<IAMGraph, String> {
        let template: CloudFormationTemplate = serde_json::from_str(json)
            .map_err(|e| format!("failed to parse CloudFormation template: {e}"))?;
        Ok(Self::ingest(&template, None))
    }

    pub fn ingest_yaml(yaml_str: &str) -> Result<IAMGraph, String> {
        let json_value: serde_json::Value = serde_yaml::from_str(yaml_str)
            .map_err(|e| format!("failed to parse YAML CloudFormation template: {e}"))?;
        let json_str = serde_json::to_string(&json_value)
            .map_err(|e| format!("failed to convert YAML to JSON: {e}"))?;
        Self::ingest_json(&json_str)
    }

    pub fn ingest_file(path: &std::path::Path) -> Result<IAMGraph, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read CloudFormation template: {e}"))?;
        if path.extension().and_then(|e| e.to_str()) == Some("yaml")
            || path.extension().and_then(|e| e.to_str()) == Some("yml")
        {
            Self::ingest_yaml(&raw)
        } else {
            Self::ingest_json(&raw)
        }
    }

    fn ingest_role(
        graph: &mut IAMGraph,
        logical_id: &str,
        resource_def: &serde_json::Value,
        account_id: &str,
    ) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let role_name = properties
            .get("RoleName")
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let arn = properties
            .get("Arn")
            .and_then(|v| v.as_str())
            .unwrap_or(&format!("arn:aws:iam::{}:role/{}", account_id, role_name))
            .to_string();

        let mut principal = IAMPrincipal::new(
            format!("cf-role-{}", logical_id),
            CloudProvider::AWS,
            PrincipalKind::Role,
            role_name.clone(),
        )
        .with_arn(&arn)
        .with_account(account_id);

        if let Some(policies) = properties
            .get("ManagedPolicyArns")
            .and_then(|v| v.as_array())
        {
            for p in policies {
                if let Some(s) = p.as_str() {
                    let policy_name = s.rsplit('/').next().unwrap_or(s).to_string();
                    principal = principal.with_policy(policy_name);
                }
            }
        }

        graph.add_principal(principal);

        if let Some(trust_policy) = properties.get("AssumeRolePolicyDocument") {
            if let Some(trust) = crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_trust_policy(
                &format!("cf-trust-{}", logical_id),
                &arn,
                trust_policy,
            ) {
                graph.add_trust(trust);
            }
        }

        if let Some(policies) = properties.get("Policies").and_then(|v| v.as_array()) {
            for (idx, policy) in policies.iter().enumerate() {
                let policy_name = policy
                    .get("PolicyName")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&format!("cf-inline-{}", idx))
                    .to_string();
                let mut iam_policy = IAMPolicy::new(
                    format!("cf-policy-{}-{}", logical_id, idx),
                    policy_name,
                    CloudProvider::AWS,
                );
                iam_policy.source_type = PolicySourceType::CloudFormation;
                if let Some(doc) = policy.get("PolicyDocument") {
                    crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_policy_document_into(
                        doc,
                        &mut iam_policy,
                    );
                    iam_policy.source_doc = serde_json::to_string(doc).unwrap_or_default();
                }
                graph.add_policy(iam_policy);
                // Attach to role
                if let Some(role) = graph.principals.get_mut(&format!("cf-role-{}", logical_id)) {
                    role.policies
                        .push(format!("cf-policy-{}-{}", logical_id, idx));
                }
            }
        }
    }

    fn ingest_user(
        graph: &mut IAMGraph,
        logical_id: &str,
        resource_def: &serde_json::Value,
        account_id: &str,
    ) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let user_name = properties
            .get("UserName")
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let principal = IAMPrincipal::new(
            format!("cf-user-{}", logical_id),
            CloudProvider::AWS,
            PrincipalKind::User,
            user_name,
        )
        .with_account(account_id);

        graph.add_principal(principal);
    }

    fn ingest_group(
        graph: &mut IAMGraph,
        logical_id: &str,
        resource_def: &serde_json::Value,
        account_id: &str,
    ) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let group_name = properties
            .get("GroupName")
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let principal = IAMPrincipal::new(
            format!("cf-group-{}", logical_id),
            CloudProvider::AWS,
            PrincipalKind::Group,
            group_name,
        )
        .with_account(account_id);

        graph.add_principal(principal);
    }

    fn ingest_policy(graph: &mut IAMGraph, logical_id: &str, resource_def: &serde_json::Value) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let policy_name = properties
            .get("PolicyName")
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let mut policy = IAMPolicy::new(
            format!("cf-policy-{}", logical_id),
            policy_name,
            CloudProvider::AWS,
        );
        policy.source_type = PolicySourceType::CloudFormation;

        if let Some(doc) = properties.get("PolicyDocument") {
            crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_policy_document_into(
                doc,
                &mut policy,
            );
            policy.source_doc = serde_json::to_string(doc).unwrap_or_default();
        }

        if let Some(roles) = properties.get("Roles").and_then(|v| v.as_array()) {
            for role_ref in roles {
                if let Some(role_name) = role_ref.as_str() {
                    if let Some(role) = graph.principals.get_mut(&format!("cf-role-{}", role_name))
                    {
                        role.policies.push(format!("cf-policy-{}", logical_id));
                    }
                } else if let Some(ref_val) = role_ref.get("Ref").and_then(|v| v.as_str()) {
                    if let Some(role) = graph.principals.get_mut(&format!("cf-role-{}", ref_val)) {
                        role.policies.push(format!("cf-policy-{}", logical_id));
                    }
                }
            }
        }

        graph.add_policy(policy);
    }

    fn ingest_inline_policy(
        graph: &mut IAMGraph,
        logical_id: &str,
        resource_def: &serde_json::Value,
    ) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let policy_name = properties
            .get("PolicyName")
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let mut policy = IAMPolicy::new(
            format!("cf-inline-{}", logical_id),
            policy_name,
            CloudProvider::AWS,
        );
        policy.source_type = PolicySourceType::CloudFormation;

        if let Some(doc) = properties.get("PolicyDocument") {
            crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_policy_document_into(
                doc,
                &mut policy,
            );
            policy.source_doc = serde_json::to_string(doc).unwrap_or_default();
        }

        graph.add_policy(policy);

        // Attach to role/user/group
        if let Some(role_name) = properties.get("RoleName").and_then(|v| v.as_str()) {
            if let Some(role) = graph.principals.get_mut(&format!("cf-role-{}", role_name)) {
                role.policies.push(format!("cf-inline-{}", logical_id));
            }
        }
    }

    fn ingest_s3_bucket(graph: &mut IAMGraph, logical_id: &str, resource_def: &serde_json::Value) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let bucket_name = properties
            .get("BucketName")
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let mut bucket = CloudResource::new(
            format!("cf-s3-{}", logical_id),
            CloudProvider::AWS,
            "s3-bucket",
            bucket_name.clone(),
        );

        if let Some(access_config) = properties.get("PublicAccessBlockConfiguration") {
            let block_public_acls = access_config
                .get("BlockPublicAcls")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let block_public_policy = access_config
                .get("BlockPublicPolicy")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let restrict_public_buckets = access_config
                .get("RestrictPublicBuckets")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if !block_public_acls || !block_public_policy || !restrict_public_buckets {
                let mut details = Vec::new();
                if !block_public_acls {
                    details.push("BlockPublicAcls is false".to_string());
                }
                if !block_public_policy {
                    details.push("BlockPublicPolicy is false".to_string());
                }
                if !restrict_public_buckets {
                    details.push("RestrictPublicBuckets is false".to_string());
                }
                bucket = bucket.with_public_access(details);
            }
        }

        bucket.raw_config = Some(properties.clone());
        graph.add_resource(bucket);
    }

    fn ingest_generic_resource(
        graph: &mut IAMGraph,
        logical_id: &str,
        resource_type: &str,
        resource_def: &serde_json::Value,
    ) {
        let properties = resource_def.get("Properties").unwrap_or(resource_def);
        let name = properties
            .get("Name")
            .or_else(|| properties.get("BucketName"))
            .or_else(|| properties.get("DBInstanceIdentifier"))
            .and_then(|v| v.as_str())
            .unwrap_or(logical_id)
            .to_string();

        let resource = CloudResource::new(
            format!(
                "cf-{}-{}",
                resource_type.replace("::", "-").to_lowercase(),
                logical_id
            ),
            CloudProvider::AWS,
            resource_type.to_string(),
            name,
        );

        graph.add_resource(resource);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudformation_ingest_role_with_trust() {
        let json = r#"{
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "DeployRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": "DeployRole",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }]
                        },
                        "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdminAccess"]
                    }
                }
            }
        }"#;
        let graph = CloudFormationIngestor::ingest_json(json).unwrap();
        assert!(graph.principals.contains_key("cf-role-DeployRole"));
        assert!(!graph.trust_relationships.is_empty());
    }

    #[test]
    fn test_cloudformation_ingest_s3_bucket() {
        let json = r#"{
            "Resources": {
                "PublicBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "my-public-bucket",
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": false,
                            "BlockPublicPolicy": false,
                            "RestrictPublicBuckets": false
                        }
                    }
                }
            }
        }"#;
        let graph = CloudFormationIngestor::ingest_json(json).unwrap();
        assert!(graph.resources.contains_key("cf-s3-PublicBucket"));
        let bucket = graph.resources.get("cf-s3-PublicBucket").unwrap();
        assert!(bucket.is_public);
    }

    #[test]
    fn test_cloudformation_ingest_empty() {
        let json = r#"{ "Resources": {} }"#;
        let graph = CloudFormationIngestor::ingest_json(json).unwrap();
        assert_eq!(graph.principals.len(), 0);
        assert_eq!(graph.resources.len(), 0);
    }

    #[test]
    fn test_cloudformation_yaml() {
        let yaml = r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: AdminRole
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: "*"
            Action: sts:AssumeRole
"#;
        let graph = CloudFormationIngestor::ingest_yaml(yaml).unwrap();
        assert!(graph.principals.contains_key("cf-role-AdminRole"));
        assert!(graph.trust_relationships.iter().any(|t| t.allows_external));
    }
}
