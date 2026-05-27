use crate::cloud_iam::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TerraformState {
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default)]
    pub terraform_version: Option<String>,
    #[serde(default)]
    pub serial: Option<u64>,
    #[serde(default)]
    pub outputs: Option<serde_json::Value>,
    #[serde(default)]
    pub resources: Vec<TerraformResource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TerraformResource {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub instances: Vec<TerraformInstance>,
    #[serde(default)]
    pub values: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TerraformInstance {
    #[serde(default)]
    pub attributes: Option<serde_json::Value>,
    #[serde(default)]
    pub attributes_flat: Option<serde_json::Value>,
    #[serde(default)]
    pub schema_version: Option<u64>,
    #[serde(default)]
    pub sensitive_attributes: Option<serde_json::Value>,
    #[serde(default)]
    pub private: Option<String>,
    #[serde(default)]
    pub dependencies: Option<Vec<String>>,
    #[serde(default)]
    pub create_before_destroy: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TerraformPlan {
    #[serde(default)]
    pub format_version: Option<String>,
    #[serde(default)]
    pub planned_values: Option<serde_json::Value>,
    #[serde(default)]
    pub resource_changes: Vec<TerraformResourceChange>,
    #[serde(default)]
    pub configuration: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TerraformResourceChange {
    #[serde(default)]
    pub mode: Option<String>,
    pub r#type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub provider_name: Option<String>,
    #[serde(default)]
    pub change: Option<TerraformChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TerraformChange {
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub before: Option<serde_json::Value>,
    #[serde(default)]
    pub after: Option<serde_json::Value>,
    #[serde(default)]
    pub after_unknown: Option<serde_json::Value>,
}

pub struct TerraformIngestor;

impl TerraformIngestor {
    pub fn ingest_state(tfstate: &TerraformState, account_id: Option<&str>) -> IAMGraph {
        let aid = account_id.unwrap_or("terraform-managed");
        let mut graph = IAMGraph::new(format!("terraform-{}", aid), CloudProvider::Generic);
        graph.account_id = Some(aid.to_string());

        for resource in &tfstate.resources {
            match resource.r#type.as_str() {
                "aws_iam_role" => Self::ingest_iam_role(&mut graph, resource, aid),
                "aws_iam_user" => Self::ingest_iam_user(&mut graph, resource, aid),
                "aws_iam_group" => Self::ingest_iam_group(&mut graph, resource, aid),
                "aws_iam_policy" | "aws_iam_policy_document" => {
                    Self::ingest_iam_policy(&mut graph, resource)
                }
                "aws_iam_role_policy_attachment"
                | "aws_iam_user_policy_attachment"
                | "aws_iam_group_policy_attachment" => {
                    Self::ingest_policy_attachment(&mut graph, resource)
                }
                "aws_iam_role_policy" | "aws_iam_user_policy" | "aws_iam_group_policy" => {
                    Self::ingest_inline_policy(&mut graph, resource)
                }
                "aws_s3_bucket" | "aws_s3_bucket_policy" => {
                    Self::ingest_s3_bucket(&mut graph, resource, aid)
                }
                "aws_s3_bucket_public_access_block" => {
                    Self::ingest_s3_public_access(&mut graph, resource, aid)
                }
                "google_storage_bucket" | "google_storage_bucket_iam_policy" => {
                    Self::ingest_gcs_bucket(&mut graph, resource)
                }
                "azurerm_storage_container" | "azurerm_storage_blob" => {
                    Self::ingest_azure_storage(&mut graph, resource)
                }
                "kubernetes_cluster_role" | "kubernetes_cluster_role_binding" => {
                    Self::ingest_k8s_role(&mut graph, resource)
                }
                "kubernetes_role" | "kubernetes_role_binding" => {
                    Self::ingest_k8s_role(&mut graph, resource)
                }
                _ => Self::ingest_generic_resource(&mut graph, resource),
            }
        }

        graph
    }

    pub fn ingest_state_json(json: &str) -> Result<IAMGraph, String> {
        let state: TerraformState = serde_json::from_str(json)
            .map_err(|e| format!("failed to parse Terraform state: {e}"))?;
        Ok(Self::ingest_state(&state, None))
    }

    pub fn ingest_state_file(path: &std::path::Path) -> Result<IAMGraph, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read Terraform state file: {e}"))?;
        Self::ingest_state_json(&raw)
    }

    pub fn ingest_plan(tfplan: &TerraformPlan, account_id: Option<&str>) -> IAMGraph {
        let aid = account_id.unwrap_or("terraform-plan");
        let mut graph = IAMGraph::new(format!("terraform-plan-{}", aid), CloudProvider::Generic);
        graph.account_id = Some(aid.to_string());

        for change in &tfplan.resource_changes {
            let before = change.change.as_ref().and_then(|c| c.before.as_ref());
            let after = change.change.as_ref().and_then(|c| c.after.as_ref());

            let config = after.or(before);

            if let Some(cfg) = config {
                match change.r#type.as_str() {
                    "aws_iam_role" => {
                        let name = cfg
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&change.name);
                        let mut principal = IAMPrincipal::new(
                            format!("tf-aws-role-{}", name),
                            CloudProvider::AWS,
                            PrincipalKind::Role,
                            name.to_string(),
                        );
                        if let Some(arn) = cfg.get("arn").and_then(|v| v.as_str()) {
                            principal = principal.with_arn(arn);
                        }
                        graph.add_principal(principal);

                        if let Some(trust) = cfg.get("assume_role_policy") {
                            if let Some(trust_str) = trust.as_str() {
                                if let Ok(trust_doc) =
                                    serde_json::from_str::<serde_json::Value>(trust_str)
                                {
                                    if let Some(rel) = crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_trust_policy(
                                        &format!("tf-trust-{}", name),
                                        &format!("arn:aws:iam::{}:role/{}", aid, name),
                                        &trust_doc,
                                    ) {
                                        graph.add_trust(rel);
                                    }
                                }
                            }
                        }
                    }
                    "aws_iam_user" => {
                        let name = cfg
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&change.name);
                        let principal = IAMPrincipal::new(
                            format!("tf-aws-user-{}", name),
                            CloudProvider::AWS,
                            PrincipalKind::User,
                            name.to_string(),
                        );
                        graph.add_principal(principal);
                    }
                    "aws_iam_policy" => {
                        let name = cfg
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&change.name);
                        let mut policy = IAMPolicy::new(
                            format!("tf-aws-policy-{}", name),
                            name.to_string(),
                            CloudProvider::AWS,
                        );
                        policy.source_type = PolicySourceType::Terraform;
                        if let Some(doc) = cfg.get("policy") {
                            crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_policy_document_into(doc, &mut policy);
                        }
                        graph.add_policy(policy);
                    }
                    _ => {}
                }
            }
        }

        graph
    }

    pub fn ingest_plan_json(json: &str) -> Result<IAMGraph, String> {
        let plan: TerraformPlan = serde_json::from_str(json)
            .map_err(|e| format!("failed to parse Terraform plan: {e}"))?;
        Ok(Self::ingest_plan(&plan, None))
    }

    fn extract_name(resource: &TerraformResource) -> String {
        resource
            .instances
            .first()
            .and_then(|inst| inst.attributes.as_ref())
            .and_then(|attrs| attrs.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.name)
            .to_string()
    }

    fn ingest_iam_role(graph: &mut IAMGraph, resource: &TerraformResource, account_id: &str) {
        let name = Self::extract_name(resource);
        let mut principal = IAMPrincipal::new(
            format!("tf-role-{}", name),
            CloudProvider::AWS,
            PrincipalKind::Role,
            name.clone(),
        );

        for inst in &resource.instances {
            if let Some(attrs) = &inst.attributes {
                if let Some(arn) = attrs.get("arn").and_then(|v| v.as_str()) {
                    principal = principal.with_arn(arn);
                }
                if let Some(policies) = attrs.get("managed_policy_arns").and_then(|v| v.as_array())
                {
                    for p in policies {
                        if let Some(s) = p.as_str() {
                            principal = principal
                                .with_policy(s.rsplit('/').next().unwrap_or(s).to_string());
                        }
                    }
                }
                if let Some(trust) = attrs.get("assume_role_policy") {
                    if let Some(trust_str) = trust.as_str() {
                        if let Ok(trust_doc) = serde_json::from_str::<serde_json::Value>(trust_str)
                        {
                            if let Some(rel) =
                                crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_trust_policy(
                                    &format!("tf-trust-{}", name),
                                    principal.arn.as_deref().unwrap_or(&name),
                                    &trust_doc,
                                )
                            {
                                graph.add_trust(rel);
                            }
                        }
                    }
                }
            }
        }

        principal = principal.with_account(account_id);
        graph.add_principal(principal);
    }

    fn ingest_iam_user(graph: &mut IAMGraph, resource: &TerraformResource, account_id: &str) {
        let name = Self::extract_name(resource);
        let mut principal = IAMPrincipal::new(
            format!("tf-user-{}", name),
            CloudProvider::AWS,
            PrincipalKind::User,
            name.clone(),
        );

        for inst in &resource.instances {
            if let Some(attrs) = &inst.attributes {
                if let Some(arn) = attrs.get("arn").and_then(|v| v.as_str()) {
                    principal = principal.with_arn(arn);
                }
            }
        }

        principal = principal.with_account(account_id);
        graph.add_principal(principal);
    }

    fn ingest_iam_group(graph: &mut IAMGraph, resource: &TerraformResource, account_id: &str) {
        let name = Self::extract_name(resource);
        let mut principal = IAMPrincipal::new(
            format!("tf-group-{}", name),
            CloudProvider::AWS,
            PrincipalKind::Group,
            name.clone(),
        );

        for inst in &resource.instances {
            if let Some(attrs) = &inst.attributes {
                if let Some(arn) = attrs.get("arn").and_then(|v| v.as_str()) {
                    principal = principal.with_arn(arn);
                }
            }
        }

        principal = principal.with_account(account_id);
        graph.add_principal(principal);
    }

    fn ingest_iam_policy(graph: &mut IAMGraph, resource: &TerraformResource) {
        let name = Self::extract_name(resource);
        let mut policy = IAMPolicy::new(
            format!("tf-policy-{}", name),
            name.clone(),
            CloudProvider::AWS,
        );
        policy.source_type = PolicySourceType::Terraform;

        for inst in &resource.instances {
            if let Some(attrs) = &inst.attributes {
                if let Some(doc) = attrs.get("policy") {
                    crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_policy_document_into(
                        doc,
                        &mut policy,
                    );
                }
                policy.source_doc = serde_json::to_string(attrs).unwrap_or_default();
            }
        }

        graph.add_policy(policy);
    }

    fn ingest_policy_attachment(graph: &mut IAMGraph, resource: &TerraformResource) {
        for inst in &resource.instances {
            if let Some(attrs) = &inst.attributes {
                let role_name = attrs.get("role").and_then(|v| v.as_str()).map(String::from);
                let policy_arn = attrs
                    .get("policy_arn")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                if let (Some(role_name), Some(policy_arn)) = (role_name, policy_arn) {
                    let key1 = format!("tf-role-{}", role_name);
                    let key2 = role_name.clone();
                    let policy_short = policy_arn
                        .rsplit('/')
                        .next()
                        .unwrap_or(&policy_arn)
                        .to_string();
                    let key = if graph.principals.contains_key(&key1) {
                        key1
                    } else {
                        key2
                    };
                    if let Some(principal) = graph.principals.get_mut(&key) {
                        principal.policies.push(policy_short);
                    }
                }
            }
        }
    }

    fn ingest_inline_policy(graph: &mut IAMGraph, resource: &TerraformResource) {
        let name = resource.name.clone();
        let mut policy = IAMPolicy::new(
            format!("tf-inline-{}", name),
            name.clone(),
            CloudProvider::AWS,
        );
        policy.source_type = PolicySourceType::Terraform;

        for inst in &resource.instances {
            if let Some(attrs) = &inst.attributes {
                if let Some(doc) = attrs.get("policy") {
                    crate::cloud_providers::aws_iam::AWSIAMIngestor::parse_policy_document_into(
                        doc,
                        &mut policy,
                    );
                }
                policy.source_doc = serde_json::to_string(attrs).unwrap_or_default();
            }
        }

        graph.add_policy(policy);
    }

    fn ingest_s3_bucket(graph: &mut IAMGraph, resource: &TerraformResource, _account_id: &str) {
        let name = Self::extract_name(resource);
        let mut bucket = CloudResource::new(
            format!("tf-s3-{}", name),
            CloudProvider::AWS,
            "s3-bucket",
            name.clone(),
        );

        for inst in &resource.instances {
            if let Some(attrs) = &inst.attributes {
                if let Some(arn) = attrs.get("arn").and_then(|v| v.as_str()) {
                    bucket = bucket.with_arn(arn);
                }
                if let Some(region) = attrs.get("region").and_then(|v| v.as_str()) {
                    bucket = bucket.with_region(region);
                }
                bucket.raw_config = inst.attributes.clone();
            }
        }

        graph.add_resource(bucket);
    }

    fn ingest_s3_public_access(
        graph: &mut IAMGraph,
        resource: &TerraformResource,
        _account_id: &str,
    ) {
        let name = Self::extract_name(resource);
        let bucket_id = format!("tf-s3-{}", name);

        for inst in &resource.instances {
            if let Some(attrs) = &inst.attributes {
                let block_public_acls = attrs
                    .get("block_public_acls")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let block_public_policy = attrs
                    .get("block_public_policy")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let restrict_public_buckets = attrs
                    .get("restrict_public_buckets")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                let is_public =
                    !block_public_acls || !block_public_policy || !restrict_public_buckets;
                if is_public {
                    if let Some(bucket) = graph.resources.get_mut(&bucket_id) {
                        let mut details = Vec::new();
                        if !block_public_acls {
                            details.push("Block Public ACLs is disabled".to_string());
                        }
                        if !block_public_policy {
                            details.push("Block Public Policy is disabled".to_string());
                        }
                        if !restrict_public_buckets {
                            details.push("Restrict Public Buckets is disabled".to_string());
                        }
                        bucket.is_public = true;
                        bucket.public_access_details = details;
                    }
                }
            }
        }
    }

    fn ingest_gcs_bucket(graph: &mut IAMGraph, resource: &TerraformResource) {
        let name = Self::extract_name(resource);
        let mut bucket = CloudResource::new(
            format!("tf-gcs-{}", name),
            CloudProvider::GCP,
            "gcs-bucket",
            name.clone(),
        );

        for inst in &resource.instances {
            if let Some(attrs) = &inst.attributes {
                if let Some(uniform_bucket_level_access) = attrs
                    .get("uniform_bucket_level_access")
                    .and_then(|v| v.as_bool())
                {
                    if !uniform_bucket_level_access {
                        bucket = bucket.with_public_access(vec![
                            "Uniform bucket-level access is disabled".to_string(),
                        ]);
                    }
                }
                bucket.raw_config = inst.attributes.clone();
            }
        }

        graph.add_resource(bucket);
    }

    fn ingest_azure_storage(_graph: &mut IAMGraph, _resource: &TerraformResource) {
        // Azure storage ingestion from Terraform is handled by Azure ARM adapter
    }

    fn ingest_k8s_role(_graph: &mut IAMGraph, _resource: &TerraformResource) {
        // K8s role ingestion from Terraform is handled by Kubernetes adapter
    }

    fn ingest_generic_resource(graph: &mut IAMGraph, resource: &TerraformResource) {
        let name = Self::extract_name(resource);
        let provider = resource.provider.as_deref().unwrap_or("unknown");
        let mut res = CloudResource::new(
            format!("tf-{}-{}", resource.r#type.replace('_', "-"), name),
            CloudProvider::from_str_lossy(provider),
            resource.r#type.clone(),
            name.clone(),
        );

        for inst in &resource.instances {
            if let Some(attrs) = &inst.attributes {
                if let Some(arn) = attrs.get("arn").and_then(|v| v.as_str()) {
                    res = res.with_arn(arn);
                }
                res.raw_config = inst.attributes.clone();
            }
        }

        graph.add_resource(res);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terraform_state_ingest() {
        let state = TerraformState {
            version: Some(4),
            terraform_version: Some("1.5.0".to_string()),
            serial: Some(1),
            outputs: None,
            resources: vec![
                TerraformResource {
                    mode: Some("managed".to_string()),
                    r#type: "aws_iam_role".to_string(),
                    name: "deploy_role".to_string(),
                    provider: Some("provider[\"registry.terraform.io/hashicorp/aws\"]".to_string()),
                    instances: vec![TerraformInstance {
                        attributes: Some(serde_json::json!({
                            "name": "deploy_role",
                            "arn": "arn:aws:iam::123456789012:role/deploy_role",
                            "assume_role_policy": serde_json::to_string(&serde_json::json!({
                                "Version": "2012-10-17",
                                "Statement": [{
                                    "Effect": "Allow",
                                    "Principal": {"Service": "ec2.amazonaws.com"},
                                    "Action": "sts:AssumeRole"
                                }]
                            })).unwrap(),
                            "managed_policy_arns": ["arn:aws:iam::aws:policy/AdminAccess"]
                        })),
                        attributes_flat: None,
                        schema_version: None,
                        sensitive_attributes: None,
                        private: None,
                        dependencies: None,
                        create_before_destroy: None,
                    }],
                    values: None,
                },
                TerraformResource {
                    mode: Some("managed".to_string()),
                    r#type: "aws_s3_bucket".to_string(),
                    name: "data_bucket".to_string(),
                    provider: Some("provider[\"registry.terraform.io/hashicorp/aws\"]".to_string()),
                    instances: vec![TerraformInstance {
                        attributes: Some(serde_json::json!({
                            "name": "data_bucket",
                            "arn": "arn:aws:s3:::data-bucket",
                            "region": "us-east-1"
                        })),
                        attributes_flat: None,
                        schema_version: None,
                        sensitive_attributes: None,
                        private: None,
                        dependencies: None,
                        create_before_destroy: None,
                    }],
                    values: None,
                },
            ],
        };

        let graph = TerraformIngestor::ingest_state(&state, Some("123456789012"));
        assert!(graph.principals.contains_key("tf-role-deploy_role"));
        assert!(graph.resources.contains_key("tf-s3-data_bucket"));
        assert!(graph
            .trust_relationships
            .iter()
            .any(|t| t.trusted_principal.contains("ec2")));
    }

    #[test]
    fn test_terraform_state_json() {
        let json = r#"{
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "outputs": {},
            "resources": []
        }"#;
        let graph = TerraformIngestor::ingest_state_json(json).unwrap();
        assert_eq!(graph.principals.len(), 0);
    }

    #[test]
    fn test_terraform_plan_ingest() {
        let plan = TerraformPlan {
            format_version: Some("1.2".to_string()),
            planned_values: None,
            resource_changes: vec![TerraformResourceChange {
                mode: Some("managed".to_string()),
                r#type: "aws_iam_role".to_string(),
                name: "test_role".to_string(),
                provider_name: Some(
                    "provider[\"registry.terraform.io/hashicorp/aws\"]".to_string(),
                ),
                change: Some(TerraformChange {
                    actions: vec!["create".to_string()],
                    before: None,
                    after: Some(serde_json::json!({
                        "name": "test_role",
                        "arn": "arn:aws:iam::123456789012:role/test_role"
                    })),
                    after_unknown: None,
                }),
            }],
            configuration: None,
        };

        let graph = TerraformIngestor::ingest_plan(&plan, Some("123456789012"));
        assert!(graph.principals.contains_key("tf-aws-role-test_role"));
    }
}
