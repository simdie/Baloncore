use crate::cloud_iam::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GCPIAMConfig {
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub policies: Vec<GCPIAMPolicy>,
    #[serde(default)]
    pub service_accounts: Vec<GCPServiceAccount>,
    #[serde(default)]
    pub bucket_policies: Vec<GCPBucketPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GCPIAMPolicy {
    pub resource: String,
    #[serde(default)]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub bindings: Vec<GCPBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GCPBinding {
    pub role: String,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub condition: Option<GCPCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GCPCondition {
    pub title: String,
    pub description: Option<String>,
    pub expression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GCPServiceAccount {
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GCPBucketPolicy {
    pub bucket: String,
    #[serde(default)]
    pub bindings: Vec<GCPBinding>,
    #[serde(default)]
    pub uniform_bucket_level_access: Option<bool>,
}

pub struct GCPIAMIngestor;

impl GCPIAMIngestor {
    pub fn ingest(config: &GCPIAMConfig) -> IAMGraph {
        let project_id = config.project_id.as_deref().unwrap_or("gcp-project");
        let mut graph = IAMGraph::new(format!("gcp-iam-{}", project_id), CloudProvider::GCP);
        graph.account_id = Some(project_id.to_string());

        for sa in &config.service_accounts {
            let mut principal = IAMPrincipal::new(
                format!("gcp-sa-{}", sa.name),
                CloudProvider::GCP,
                PrincipalKind::ServiceAccount,
                sa.email.as_deref().unwrap_or(&sa.name).to_string(),
            );
            principal.is_public = false;
            graph.add_principal(principal);
        }

        for policy in &config.policies {
            for binding in &policy.bindings {
                let policy_name = format!(
                    "gcp-policy-{}-{}",
                    policy.resource,
                    binding.role.replace('/', "-").replace('.', "-")
                );
                let mut iam_policy = IAMPolicy::new(
                    &policy_name,
                    format!("{}:{}", policy.resource, binding.role),
                    CloudProvider::GCP,
                );
                iam_policy.source_type = PolicySourceType::GCPRole;

                let is_admin = binding.role.contains("admin")
                    || binding.role.contains("Admin")
                    || binding.role == "roles/owner"
                    || binding.role == "roles/editor";
                let actions = if is_admin {
                    vec!["*".to_string()]
                } else {
                    vec![binding.role.clone()]
                };
                let resources = vec![policy.resource.clone()];

                iam_policy.statements.push(IAMStatement {
                    id: format!("gcp-{}-{}", policy.resource, binding.role.replace('/', "-")),
                    effect: Effect::Allow,
                    actions,
                    resources,
                    conditions: if let Some(cond) = &binding.condition {
                        vec![IAMCondition {
                            operator: "condition".to_string(),
                            key: cond.title.clone(),
                            values: vec![cond.expression.clone()],
                        }]
                    } else {
                        vec![]
                    },
                    source_doc: format!("GCP IAM binding: {} on {}", binding.role, policy.resource),
                });

                graph.add_policy(iam_policy);

                for member in &binding.members {
                    let (member_kind, member_id) = Self::parse_gcp_member(member);

                    if !graph.principals.contains_key(&member_id) {
                        let principal = IAMPrincipal::new(
                            &member_id,
                            CloudProvider::GCP,
                            member_kind,
                            member.clone(),
                        );
                        graph.add_principal(principal);
                    }

                    if let Some(principal) = graph.principals.get_mut(&member_id) {
                        principal.policies.push(policy_name.clone());
                    }
                }
            }
        }

        for bucket_policy in &config.bucket_policies {
            let mut bucket = CloudResource::new(
                format!("gcp-bucket-{}", bucket_policy.bucket),
                CloudProvider::GCP,
                "gcs-bucket",
                bucket_policy.bucket.clone(),
            );

            let is_public = bucket_policy.bindings.iter().any(|b| {
                b.members
                    .iter()
                    .any(|m| m == "allUsers" || m == "allAuthenticatedUsers")
            });

            if is_public {
                let details = bucket_policy
                    .bindings
                    .iter()
                    .flat_map(|b| {
                        b.members
                            .iter()
                            .filter(|m| m == &"allUsers" || m == &"allAuthenticatedUsers")
                            .map(|m| format!("{} has role {} on bucket", m, b.role))
                    })
                    .collect();
                bucket = bucket.with_public_access(details);
            }

            if let Some(ubla) = bucket_policy.uniform_bucket_level_access {
                if !ubla && !is_public {
                    bucket
                        .public_access_details
                        .push("Uniform bucket-level access is disabled".to_string());
                }
            }

            graph.add_resource(bucket);
        }

        graph
    }

    pub fn ingest_json(json: &str) -> Result<IAMGraph, String> {
        let config: GCPIAMConfig = serde_json::from_str(json)
            .map_err(|e| format!("failed to parse GCP IAM config: {e}"))?;
        Ok(Self::ingest(&config))
    }

    pub fn ingest_file(path: &std::path::Path) -> Result<IAMGraph, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read GCP IAM config: {e}"))?;
        Self::ingest_json(&raw)
    }

    fn parse_gcp_member(member: &str) -> (PrincipalKind, String) {
        if let Some(stripped) = member.strip_prefix("serviceAccount:") {
            (
                PrincipalKind::ServiceAccount,
                format!("gcp-sa-{}", stripped.replace('@', "-").replace('.', "-")),
            )
        } else if let Some(stripped) = member.strip_prefix("user:") {
            (
                PrincipalKind::User,
                format!("gcp-user-{}", stripped.replace('@', "-").replace('.', "-")),
            )
        } else if let Some(stripped) = member.strip_prefix("group:") {
            (
                PrincipalKind::Group,
                format!("gcp-group-{}", stripped.replace('@', "-").replace('.', "-")),
            )
        } else if member == "allUsers" {
            (PrincipalKind::User, "gcp-public-allUsers".to_string())
        } else if member == "allAuthenticatedUsers" {
            (
                PrincipalKind::User,
                "gcp-public-allAuthenticatedUsers".to_string(),
            )
        } else {
            (
                PrincipalKind::User,
                format!("gcp-{}", member.replace(':', "-")),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcp_iam_ingest() {
        let config = GCPIAMConfig {
            organization_id: Some("org-123".to_string()),
            project_id: Some("my-project".to_string()),
            policies: vec![GCPIAMPolicy {
                resource: "projects/my-project".to_string(),
                resource_type: Some("project".to_string()),
                bindings: vec![GCPBinding {
                    role: "roles/owner".to_string(),
                    members: vec!["user:alice@example.com".to_string()],
                    condition: None,
                }],
            }],
            service_accounts: vec![GCPServiceAccount {
                name: "deploy-sa".to_string(),
                email: Some("deploy-sa@my-project.iam.gserviceaccount.com".to_string()),
                display_name: Some("Deploy Service Account".to_string()),
                description: None,
                disabled: false,
            }],
            bucket_policies: vec![GCPBucketPolicy {
                bucket: "public-bucket".to_string(),
                bindings: vec![GCPBinding {
                    role: "roles/storage.objectViewer".to_string(),
                    members: vec!["allUsers".to_string()],
                    condition: None,
                }],
                uniform_bucket_level_access: None,
            }],
        };

        let mut graph = GCPIAMIngestor::ingest(&config);
        assert!(graph.principals.contains_key("gcp-sa-deploy-sa"));
        assert!(graph.resources.contains_key("gcp-bucket-public-bucket"));
        assert!(
            graph
                .resources
                .get("gcp-bucket-public-bucket")
                .unwrap()
                .is_public
        );

        let result = graph.analyze();
        assert!(result
            .findings
            .iter()
            .any(|f| f.classification == "PublicResourceExposure"));
    }

    #[test]
    fn test_gcp_public_bucket_detection() {
        let config = GCPIAMConfig {
            project_id: Some("test".to_string()),
            policies: vec![],
            service_accounts: vec![],
            bucket_policies: vec![GCPBucketPolicy {
                bucket: "open-bucket".to_string(),
                bindings: vec![GCPBinding {
                    role: "roles/storage.objectViewer".to_string(),
                    members: vec!["allAuthenticatedUsers".to_string()],
                    condition: None,
                }],
                uniform_bucket_level_access: Some(false),
            }],
            organization_id: None,
        };

        let graph = GCPIAMIngestor::ingest(&config);
        let bucket = graph.resources.get("gcp-bucket-open-bucket").unwrap();
        assert!(bucket.is_public);
        assert!(bucket
            .public_access_details
            .iter()
            .any(|d| d.contains("allAuthenticatedUsers")));
    }

    #[test]
    fn test_gcp_json_ingest() {
        let json = r#"{
            "project_id": "test-project",
            "policies": [],
            "service_accounts": [],
            "bucket_policies": []
        }"#;
        let graph = GCPIAMIngestor::ingest_json(json).unwrap();
        assert_eq!(graph.account_id, Some("test-project".to_string()));
    }
}
