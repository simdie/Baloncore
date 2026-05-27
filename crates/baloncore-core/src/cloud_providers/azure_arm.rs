use crate::cloud_iam::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AzureARMConfig {
    #[serde(default)]
    pub subscription_id: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub role_definitions: Vec<AzureRoleDefinition>,
    #[serde(default)]
    pub role_assignments: Vec<AzureRoleAssignment>,
    #[serde(default)]
    pub managed_identities: Vec<AzureManagedIdentity>,
    #[serde(default)]
    pub storage_accounts: Vec<AzureStorageAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AzureRoleDefinition {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub role_type: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<AzurePermission>,
    #[serde(default)]
    pub assignable_scopes: Vec<String>,
    #[serde(default)]
    pub is_builtin: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AzurePermission {
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub not_actions: Vec<String>,
    #[serde(default)]
    pub data_actions: Vec<String>,
    #[serde(default)]
    pub not_data_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AzureRoleAssignment {
    pub id: String,
    pub principal_id: String,
    #[serde(default)]
    pub principal_type: Option<String>,
    pub role_definition_id: String,
    pub scope: String,
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default)]
    pub condition_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AzureManagedIdentity {
    pub name: String,
    #[serde(default)]
    pub identity_type: Option<String>,
    #[serde(default)]
    pub principal_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub resource_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AzureStorageAccount {
    pub name: String,
    #[serde(default)]
    pub resource_group: Option<String>,
    #[serde(default)]
    pub allow_blob_public_access: Option<bool>,
    #[serde(default)]
    pub network_rule_default_action: Option<String>,
    #[serde(default)]
    pub containers: Vec<AzureStorageContainer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AzureStorageContainer {
    pub name: String,
    #[serde(default)]
    pub public_access: Option<String>,
}

pub struct AzureARMIngestor;

impl AzureARMIngestor {
    pub fn ingest(config: &AzureARMConfig) -> IAMGraph {
        let subscription_id = config
            .subscription_id
            .as_deref()
            .unwrap_or("azure-subscription");
        let mut graph = IAMGraph::new(
            format!("azure-iam-{}", subscription_id),
            CloudProvider::Azure,
        );
        graph.account_id = Some(subscription_id.to_string());

        for role_def in &config.role_definitions {
            let mut policy = IAMPolicy::new(
                format!("azure-role-{}", role_def.id),
                role_def.name.as_deref().unwrap_or(&role_def.id),
                CloudProvider::Azure,
            );
            policy.source_type = if role_def.is_builtin.unwrap_or(false) {
                PolicySourceType::AzureBuiltIn
            } else {
                PolicySourceType::AzureCustom
            };

            for (perm_idx, permission) in role_def.permissions.iter().enumerate() {
                let actions: Vec<String> = if permission.actions.is_empty() {
                    vec![]
                } else {
                    permission.actions.clone()
                };

                if !actions.is_empty() {
                    let resources = if role_def.assignable_scopes.is_empty() {
                        vec!["*".to_string()]
                    } else {
                        role_def.assignable_scopes.clone()
                    };

                    policy.statements.push(IAMStatement {
                        id: format!("azure-{}-{}", role_def.id, perm_idx),
                        effect: Effect::Allow,
                        actions,
                        resources,
                        conditions: vec![],
                        source_doc: format!("Azure role definition: {}", role_def.id),
                    });
                }

                if !permission.not_actions.is_empty() {
                    policy.statements.push(IAMStatement {
                        id: format!("azure-deny-{}-{}", role_def.id, perm_idx),
                        effect: Effect::Deny,
                        actions: permission.not_actions.clone(),
                        resources: role_def
                            .assignable_scopes
                            .clone()
                            .into_iter()
                            .chain(std::iter::once("*".to_string()))
                            .collect(),
                        conditions: vec![],
                        source_doc: format!("Azure role definition notActions: {}", role_def.id),
                    });
                }
            }

            graph.add_policy(policy);
        }

        for assignment in &config.role_assignments {
            let principal_kind = match assignment.principal_type.as_deref() {
                Some("User") => PrincipalKind::User,
                Some("Group") => PrincipalKind::Group,
                Some("ServicePrincipal") => PrincipalKind::ServiceAccount,
                Some("ManagedIdentity") => PrincipalKind::ManagedIdentity,
                Some("ForeignGroup") => PrincipalKind::ExternalAccount,
                _ => PrincipalKind::User,
            };

            let principal_id = format!("azure-{}", assignment.principal_id);

            if !graph.principals.contains_key(&principal_id) {
                let principal = IAMPrincipal::new(
                    &principal_id,
                    CloudProvider::Azure,
                    principal_kind,
                    assignment.principal_id.clone(),
                );
                graph.add_principal(principal);
            }

            let role_def_key = format!("azure-role-{}", assignment.role_definition_id);
            if let Some(principal) = graph.principals.get_mut(&principal_id) {
                principal.policies.push(role_def_key.clone());
            }

            graph.add_edge(IAMEdge {
                id: format!("azure-assignment-{}", assignment.id),
                from_principal: principal_id,
                to_principal: None,
                to_resource: None,
                edge_kind: IAMEdgeKind::PolicyAttachment,
                policy_id: Some(role_def_key),
                actions: vec![],
                conditions: if let Some(cond) = &assignment.condition {
                    vec![IAMCondition {
                        operator: "condition".to_string(),
                        key: "role_assignment_condition".to_string(),
                        values: vec![cond.clone()],
                    }]
                } else {
                    vec![]
                },
                is_deny: false,
                confidence: 1.0,
                source: format!(
                    "Azure role assignment: {} at scope {}",
                    assignment.id, assignment.scope
                ),
            });
        }

        for identity in &config.managed_identities {
            let mut principal = IAMPrincipal::new(
                format!("azure-mi-{}", identity.name),
                CloudProvider::Azure,
                PrincipalKind::ManagedIdentity,
                identity.name.clone(),
            );
            if let Some(pid) = &identity.principal_id {
                principal = principal.with_arn(pid);
            }
            graph.add_principal(principal);
        }

        for storage in &config.storage_accounts {
            let mut resource = CloudResource::new(
                format!("azure-storage-{}", storage.name),
                CloudProvider::Azure,
                "storage-account",
                storage.name.clone(),
            );

            let is_public = storage.allow_blob_public_access.unwrap_or(true)
                && storage.containers.iter().any(|c| {
                    c.public_access.as_deref() == Some("Blob")
                        || c.public_access.as_deref() == Some("Container")
                });

            if is_public {
                let mut details = Vec::new();
                if storage.allow_blob_public_access.unwrap_or(true) {
                    details.push("Blob public access is allowed".to_string());
                }
                for container in &storage.containers {
                    if let Some(access) = &container.public_access {
                        if access != "None" && !access.is_empty() {
                            details.push(format!(
                                "Container '{}' has public access: {}",
                                container.name, access
                            ));
                        }
                    }
                }
                resource = resource.with_public_access(details);
            }

            if let Some(default_action) = &storage.network_rule_default_action {
                if default_action == "Allow" {
                    if resource.is_public {
                        resource
                            .public_access_details
                            .push("Network default action is Allow".to_string());
                    } else {
                        resource = resource.with_public_access(vec![
                            "Network default action is Allow (open to all networks)".to_string(),
                        ]);
                    }
                }
            }

            graph.add_resource(resource);
        }

        graph
    }

    pub fn ingest_json(json: &str) -> Result<IAMGraph, String> {
        let config: AzureARMConfig = serde_json::from_str(json)
            .map_err(|e| format!("failed to parse Azure ARM config: {e}"))?;
        Ok(Self::ingest(&config))
    }

    pub fn ingest_file(path: &std::path::Path) -> Result<IAMGraph, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read Azure ARM config: {e}"))?;
        Self::ingest_json(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_iam_ingest_basic() {
        let config = AzureARMConfig {
            subscription_id: Some("sub-123".to_string()),
            tenant_id: Some("tenant-456".to_string()),
            role_definitions: vec![AzureRoleDefinition {
                id: "owner-role".to_string(),
                name: Some("Owner".to_string()),
                role_type: Some("BuiltInRole".to_string()),
                description: Some("Full access".to_string()),
                permissions: vec![AzurePermission {
                    actions: vec!["*".to_string()],
                    not_actions: vec![],
                    data_actions: vec![],
                    not_data_actions: vec![],
                }],
                assignable_scopes: vec!["/".to_string()],
                is_builtin: Some(true),
            }],
            role_assignments: vec![AzureRoleAssignment {
                id: "assignment-1".to_string(),
                principal_id: "user-alice".to_string(),
                principal_type: Some("User".to_string()),
                role_definition_id: "owner-role".to_string(),
                scope: "/subscriptions/sub-123".to_string(),
                condition: None,
                condition_version: None,
            }],
            managed_identities: vec![],
            storage_accounts: vec![AzureStorageAccount {
                name: "publicstorage".to_string(),
                resource_group: Some("rg-1".to_string()),
                allow_blob_public_access: Some(true),
                network_rule_default_action: Some("Allow".to_string()),
                containers: vec![AzureStorageContainer {
                    name: "public-container".to_string(),
                    public_access: Some("Blob".to_string()),
                }],
            }],
        };

        let mut graph = AzureARMIngestor::ingest(&config);
        assert!(graph.principals.contains_key("azure-user-alice"));
        assert!(graph.policies.contains_key("azure-role-owner-role"));
        assert!(graph.resources.contains_key("azure-storage-publicstorage"));

        let result = graph.analyze();
        assert!(result
            .findings
            .iter()
            .any(|f| f.classification == "PublicResourceExposure"));
        assert!(result
            .findings
            .iter()
            .any(|f| f.classification == "OverPrivilegedPolicy"));
    }

    #[test]
    fn test_azure_storage_not_public() {
        let config = AzureARMConfig {
            subscription_id: Some("sub-123".to_string()),
            tenant_id: None,
            role_definitions: vec![],
            role_assignments: vec![],
            managed_identities: vec![],
            storage_accounts: vec![AzureStorageAccount {
                name: "securestorage".to_string(),
                resource_group: Some("rg-1".to_string()),
                allow_blob_public_access: Some(false),
                network_rule_default_action: Some("Deny".to_string()),
                containers: vec![AzureStorageContainer {
                    name: "private-container".to_string(),
                    public_access: Some("None".to_string()),
                }],
            }],
        };

        let graph = AzureARMIngestor::ingest(&config);
        let storage = graph.resources.get("azure-storage-securestorage").unwrap();
        assert!(!storage.is_public);
    }

    #[test]
    fn test_azure_json_ingest() {
        let json = r#"{
            "subscription_id": "test-sub",
            "role_definitions": [],
            "role_assignments": [],
            "managed_identities": [],
            "storage_accounts": []
        }"#;
        let graph = AzureARMIngestor::ingest_json(json).unwrap();
        assert_eq!(graph.account_id, Some("test-sub".to_string()));
    }

    #[test]
    fn test_azure_managed_identity() {
        let config = AzureARMConfig {
            subscription_id: Some("sub-123".to_string()),
            tenant_id: None,
            role_definitions: vec![],
            role_assignments: vec![],
            managed_identities: vec![AzureManagedIdentity {
                name: "app-identity".to_string(),
                identity_type: Some("SystemAssigned".to_string()),
                principal_id: Some("uuid-1234".to_string()),
                client_id: Some("client-uuid".to_string()),
                resource_group: Some("rg-app".to_string()),
            }],
            storage_accounts: vec![],
        };

        let graph = AzureARMIngestor::ingest(&config);
        assert!(graph.principals.contains_key("azure-mi-app-identity"));
        let identity = graph.principals.get("azure-mi-app-identity").unwrap();
        assert_eq!(identity.kind, PrincipalKind::ManagedIdentity);
    }
}
