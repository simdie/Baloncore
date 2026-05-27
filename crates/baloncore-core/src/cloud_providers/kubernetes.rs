use crate::cloud_iam::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct K8sClusterRole {
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub rules: Vec<K8sPolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct K8sRole {
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub rules: Vec<K8sPolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct K8sPolicyRule {
    #[serde(default)]
    pub verbs: Vec<String>,
    #[serde(default)]
    pub api_groups: Vec<String>,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub resource_names: Vec<String>,
    #[serde(default)]
    pub non_resource_ur_ls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct K8sClusterRoleBinding {
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    pub role_ref: K8sRoleRef,
    #[serde(default)]
    pub subjects: Vec<K8sSubject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct K8sRoleBinding {
    pub name: String,
    pub namespace: String,
    pub role_ref: K8sRoleRef,
    #[serde(default)]
    pub subjects: Vec<K8sSubject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct K8sRoleRef {
    pub kind: String,
    pub name: String,
    pub api_group: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct K8sSubject {
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub api_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct K8sManifest {
    #[serde(default)]
    pub api_version: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub rules: Option<serde_json::Value>,
    #[serde(default)]
    pub subjects: Option<serde_json::Value>,
    #[serde(default)]
    pub role_ref: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct K8sConfig {
    #[serde(default)]
    pub cluster_roles: Vec<K8sClusterRole>,
    #[serde(default)]
    pub roles: Vec<K8sRole>,
    #[serde(default)]
    pub cluster_role_bindings: Vec<K8sClusterRoleBinding>,
    #[serde(default)]
    pub role_bindings: Vec<K8sRoleBinding>,
    #[serde(default)]
    pub service_accounts: Vec<K8sServiceAccount>,
    #[serde(default)]
    pub cluster_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct K8sServiceAccount {
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub automount_service_account_token: Option<bool>,
}

const K8S_PRIVILEGED_VERBS: &[&str] = &[
    "*",
    "create",
    "delete",
    "deletecollection",
    "patch",
    "update",
    "impersonate",
    "escalate",
    "bind",
];
pub const K8S_PRIVILEGED_RESOURCES: &[&str] = &[
    "*",
    "clusterroles",
    "roles",
    "rolebindings",
    "clusterrolebindings",
    "secrets",
    "pods",
    "nodes",
    "namespaces",
    "persistentvolumes",
    "serviceaccounts",
    "podsecuritypolicies",
];
pub const K8S_PRIVILEGED_API_GROUPS: &[&str] = &[
    "*",
    "",
    "rbac.authorization.k8s.io",
    "certificates.k8s.io",
    "authentication.k8s.io",
    "authorization.k8s.io",
];

pub struct KubernetesIngestor;

impl KubernetesIngestor {
    pub fn ingest(config: &K8sConfig) -> IAMGraph {
        let cluster_name = config.cluster_name.as_deref().unwrap_or("kubernetes");
        let mut graph = IAMGraph::new(format!("k8s-{}", cluster_name), CloudProvider::Kubernetes);
        graph.account_id = Some(cluster_name.to_string());

        for cr in &config.cluster_roles {
            let mut principal = IAMPrincipal::new(
                format!("k8s-clusterrole-{}", cr.name),
                CloudProvider::Kubernetes,
                PrincipalKind::Role,
                cr.name.clone(),
            );
            for (idx, rule) in cr.rules.iter().enumerate() {
                let policy = Self::rule_to_policy(&cr.name, idx, rule, true);
                principal = principal.with_policy(&policy.name);
                graph.add_policy(policy);
            }
            graph.add_principal(principal);
        }

        for role in &config.roles {
            let mut principal = IAMPrincipal::new(
                format!("k8s-role-{}-{}", role.namespace, role.name),
                CloudProvider::Kubernetes,
                PrincipalKind::Role,
                format!("{}/{}", role.namespace, role.name),
            );
            for (idx, rule) in role.rules.iter().enumerate() {
                let policy = Self::rule_to_policy(&role.name, idx, rule, false);
                principal = principal.with_policy(&policy.name);
                graph.add_policy(policy);
            }
            graph.add_principal(principal);
        }

        for binding in &config.cluster_role_bindings {
            let role_principal_id = format!("k8s-clusterrole-{}", binding.role_ref.name);
            for subject in &binding.subjects {
                let (subject_kind, subject_id) = match subject.kind.as_str() {
                    "ServiceAccount" => (
                        PrincipalKind::ServiceAccount,
                        format!(
                            "k8s-sa-{}-{}",
                            subject.namespace.as_deref().unwrap_or("default"),
                            subject.name
                        ),
                    ),
                    "User" => (PrincipalKind::User, format!("k8s-user-{}", subject.name)),
                    "Group" => (PrincipalKind::Group, format!("k8s-group-{}", subject.name)),
                    _ => (PrincipalKind::User, format!("k8s-{}", subject.name)),
                };

                if !graph.principals.contains_key(&subject_id) {
                    let subject_principal = IAMPrincipal::new(
                        &subject_id,
                        CloudProvider::Kubernetes,
                        subject_kind,
                        subject.name.clone(),
                    );
                    graph.add_principal(subject_principal);
                }

                graph.add_edge(IAMEdge {
                    id: format!("k8s-binding-{}-{}", binding.name, subject.name),
                    from_principal: subject_id,
                    to_principal: Some(role_principal_id.clone()),
                    to_resource: None,
                    edge_kind: IAMEdgeKind::GroupMembership,
                    policy_id: None,
                    actions: vec![],
                    conditions: vec![],
                    is_deny: false,
                    confidence: 1.0,
                    source: format!("ClusterRoleBinding/{}", binding.name),
                });
            }
        }

        for binding in &config.role_bindings {
            let role_principal_id =
                format!("k8s-role-{}-{}", binding.namespace, binding.role_ref.name);
            for subject in &binding.subjects {
                let (subject_kind, subject_id) = match subject.kind.as_str() {
                    "ServiceAccount" => (
                        PrincipalKind::ServiceAccount,
                        format!(
                            "k8s-sa-{}-{}",
                            subject.namespace.as_deref().unwrap_or(&binding.namespace),
                            subject.name
                        ),
                    ),
                    "User" => (PrincipalKind::User, format!("k8s-user-{}", subject.name)),
                    "Group" => (PrincipalKind::Group, format!("k8s-group-{}", subject.name)),
                    _ => (PrincipalKind::User, format!("k8s-{}", subject.name)),
                };

                if !graph.principals.contains_key(&subject_id) {
                    let subject_principal = IAMPrincipal::new(
                        &subject_id,
                        CloudProvider::Kubernetes,
                        subject_kind,
                        subject.name.clone(),
                    );
                    graph.add_principal(subject_principal);
                }

                graph.add_edge(IAMEdge {
                    id: format!("k8s-binding-{}-{}", binding.name, subject.name),
                    from_principal: subject_id,
                    to_principal: Some(role_principal_id.clone()),
                    to_resource: None,
                    edge_kind: IAMEdgeKind::GroupMembership,
                    policy_id: None,
                    actions: vec![],
                    conditions: vec![],
                    is_deny: false,
                    confidence: 1.0,
                    source: format!("RoleBinding/{}/{}", binding.namespace, binding.name),
                });
            }
        }

        for sa in &config.service_accounts {
            let sa_id = format!("k8s-sa-{}-{}", sa.namespace, sa.name);
            let mut principal = IAMPrincipal::new(
                &sa_id,
                CloudProvider::Kubernetes,
                PrincipalKind::ServiceAccount,
                format!("{}/{}", sa.namespace, sa.name),
            );
            principal.is_public = sa.automount_service_account_token.unwrap_or(true);
            if principal.is_public {
                principal = principal.with_policy("automount-service-account-token");
            }
            graph.add_principal(principal);
        }

        graph
    }

    pub fn ingest_json(json: &str) -> Result<IAMGraph, String> {
        let config: K8sConfig = serde_json::from_str(json)
            .map_err(|e| format!("failed to parse Kubernetes RBAC config: {e}"))?;
        Ok(Self::ingest(&config))
    }

    pub fn ingest_file(path: &std::path::Path) -> Result<IAMGraph, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read Kubernetes config: {e}"))?;
        Self::ingest_json(&raw)
    }

    pub fn ingest_manifests(manifests: &[K8sManifest]) -> K8sConfig {
        let mut config = K8sConfig {
            cluster_roles: Vec::new(),
            roles: Vec::new(),
            cluster_role_bindings: Vec::new(),
            role_bindings: Vec::new(),
            service_accounts: Vec::new(),
            cluster_name: None,
        };

        for manifest in manifests {
            let kind = manifest.kind.as_deref().unwrap_or("");
            let name = manifest
                .metadata
                .as_ref()
                .and_then(|m| m.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");

            match kind {
                "ClusterRole" => {
                    let rules = Self::parse_rules(manifest.rules.as_ref());
                    config.cluster_roles.push(K8sClusterRole {
                        name: name.to_string(),
                        namespace: None,
                        rules,
                    });
                }
                "Role" => {
                    let namespace = manifest
                        .metadata
                        .as_ref()
                        .and_then(|m| m.get("namespace"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("default");
                    let rules = Self::parse_rules(manifest.rules.as_ref());
                    config.roles.push(K8sRole {
                        name: name.to_string(),
                        namespace: namespace.to_string(),
                        rules,
                    });
                }
                "ClusterRoleBinding" => {
                    let (role_ref, subjects) = Self::parse_binding(manifest);
                    if let Some(role_ref) = role_ref {
                        config.cluster_role_bindings.push(K8sClusterRoleBinding {
                            name: name.to_string(),
                            namespace: None,
                            role_ref,
                            subjects,
                        });
                    }
                }
                "RoleBinding" => {
                    let namespace = manifest
                        .metadata
                        .as_ref()
                        .and_then(|m| m.get("namespace"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("default");
                    let (role_ref, subjects) = Self::parse_binding(manifest);
                    if let Some(role_ref) = role_ref {
                        config.role_bindings.push(K8sRoleBinding {
                            name: name.to_string(),
                            namespace: namespace.to_string(),
                            role_ref,
                            subjects,
                        });
                    }
                }
                "ServiceAccount" => {
                    let namespace = manifest
                        .metadata
                        .as_ref()
                        .and_then(|m| m.get("namespace"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("default");
                    let automount = manifest
                        .metadata
                        .as_ref()
                        .and_then(|m| m.get("automountServiceAccountToken"))
                        .and_then(|v| v.as_bool());
                    config.service_accounts.push(K8sServiceAccount {
                        name: name.to_string(),
                        namespace: namespace.to_string(),
                        automount_service_account_token: automount,
                    });
                }
                _ => {}
            }
        }

        config
    }

    fn rule_to_policy(
        role_name: &str,
        idx: usize,
        rule: &K8sPolicyRule,
        is_cluster: bool,
    ) -> IAMPolicy {
        let scope = if is_cluster { "cluster" } else { "namespace" };
        let mut policy = IAMPolicy::new(
            format!("k8s-policy-{}-{}-{}", scope, role_name, idx),
            format!("{}/{}", role_name, idx),
            CloudProvider::Kubernetes,
        );
        policy.source_type = PolicySourceType::K8sClusterRole;

        let actions: Vec<String> = rule.verbs.iter().map(|v| format!("k8s:{}", v)).collect();
        let resources: Vec<String> = if rule.resources.is_empty() {
            vec!["*".to_string()]
        } else {
            rule.resources
                .iter()
                .map(|r| {
                    if rule.api_groups.is_empty() || rule.api_groups.contains(&"".to_string()) {
                        format!("k8s:core/{}", r)
                    } else {
                        format!(
                            "k8s:{}/{}",
                            rule.api_groups.first().unwrap_or(&"".to_string()),
                            r
                        )
                    }
                })
                .collect()
        };

        let is_privileged = rule.verbs.iter().any(|v| v == "*")
            || (rule
                .resources
                .iter()
                .any(|r| K8S_PRIVILEGED_RESOURCES.contains(&r.as_str()))
                && rule
                    .verbs
                    .iter()
                    .any(|v| K8S_PRIVILEGED_VERBS.contains(&v.as_str())))
            || rule.api_groups.iter().any(|g| {
                K8S_PRIVILEGED_API_GROUPS.contains(&g.as_str())
                    && rule
                        .verbs
                        .iter()
                        .any(|v| v == "*" || v == "create" || v == "update" || v == "delete")
            });

        let statement = IAMStatement {
            id: format!("k8s-rule-{}-{}-{}", scope, role_name, idx),
            effect: Effect::Allow,
            actions,
            resources,
            conditions: vec![],
            source_doc: format!("K8s {} role {} rule {}", scope, role_name, idx),
        };

        policy.statements = vec![statement];
        policy.source_doc = if is_privileged {
            format!("K8s {} role {} (PRIVILEGED)", scope, role_name)
        } else {
            format!("K8s {} role {}", scope, role_name)
        };
        policy
    }

    fn parse_rules(rules: Option<&serde_json::Value>) -> Vec<K8sPolicyRule> {
        let mut result = Vec::new();
        if let Some(rules_val) = rules {
            if let Some(arr) = rules_val.as_array() {
                for rule in arr {
                    result.push(K8sPolicyRule {
                        verbs: rule
                            .get("verbs")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        api_groups: rule
                            .get("apiGroups")
                            .or_else(|| rule.get("api_groups"))
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        resources: rule
                            .get("resources")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        resource_names: rule
                            .get("resourceNames")
                            .or_else(|| rule.get("resource_names"))
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        non_resource_ur_ls: rule
                            .get("nonResourceURLs")
                            .or_else(|| rule.get("non_resource_urls"))
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    });
                }
            }
        }
        result
    }

    fn parse_binding(manifest: &K8sManifest) -> (Option<K8sRoleRef>, Vec<K8sSubject>) {
        let role_ref = manifest.role_ref.as_ref().and_then(|rr| {
            Some(K8sRoleRef {
                kind: rr.get("kind")?.as_str()?.to_string(),
                name: rr.get("name")?.as_str()?.to_string(),
                api_group: rr
                    .get("apiGroup")
                    .or_else(|| rr.get("api_group"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("rbac.authorization.k8s.io")
                    .to_string(),
            })
        });

        let subjects = manifest
            .subjects
            .as_ref()
            .and_then(|s| s.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| {
                        Some(K8sSubject {
                            kind: s.get("kind")?.as_str()?.to_string(),
                            name: s.get("name")?.as_str()?.to_string(),
                            namespace: s
                                .get("namespace")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            api_group: s
                                .get("apiGroup")
                                .or_else(|| s.get("api_group"))
                                .and_then(|v| v.as_str())
                                .map(String::from),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        (role_ref, subjects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k8s_ingest_cluster_role() {
        let config = K8sConfig {
            cluster_roles: vec![K8sClusterRole {
                name: "cluster-admin".to_string(),
                namespace: None,
                rules: vec![K8sPolicyRule {
                    verbs: vec!["*".to_string()],
                    api_groups: vec!["*".to_string()],
                    resources: vec!["*".to_string()],
                    resource_names: vec![],
                    non_resource_ur_ls: vec![],
                }],
            }],
            roles: vec![],
            cluster_role_bindings: vec![K8sClusterRoleBinding {
                name: "admin-binding".to_string(),
                namespace: None,
                role_ref: K8sRoleRef {
                    kind: "ClusterRole".to_string(),
                    name: "cluster-admin".to_string(),
                    api_group: "rbac.authorization.k8s.io".to_string(),
                },
                subjects: vec![K8sSubject {
                    kind: "ServiceAccount".to_string(),
                    name: "ci-deploy".to_string(),
                    namespace: Some("default".to_string()),
                    api_group: None,
                }],
            }],
            role_bindings: vec![],
            service_accounts: vec![K8sServiceAccount {
                name: "ci-deploy".to_string(),
                namespace: "default".to_string(),
                automount_service_account_token: None,
            }],
            cluster_name: Some("test-cluster".to_string()),
        };

        let mut graph = KubernetesIngestor::ingest(&config);
        assert!(graph
            .principals
            .contains_key("k8s-clusterrole-cluster-admin"));
        assert!(graph.principals.contains_key("k8s-sa-default-ci-deploy"));

        let result = graph.analyze();
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.classification == "OverPrivilegedPolicy"),
            "Expected over-privileged policy finding for cluster-admin wildcard rule"
        );
    }

    #[test]
    fn test_k8s_ingest_manifests() {
        let manifests = vec![
            K8sManifest {
                api_version: Some("rbac.authorization.k8s.io/v1".to_string()),
                kind: Some("ClusterRole".to_string()),
                metadata: Some(serde_json::json!({"name": "test-role"})),
                rules: Some(serde_json::json!([{
                    "verbs": ["get", "list"],
                    "apiGroups": [""],
                    "resources": ["pods"]
                }])),
                subjects: None,
                role_ref: None,
            },
            K8sManifest {
                api_version: Some("rbac.authorization.k8s.io/v1".to_string()),
                kind: Some("ClusterRoleBinding".to_string()),
                metadata: Some(serde_json::json!({"name": "test-binding"})),
                rules: None,
                subjects: Some(serde_json::json!([{
                    "kind": "User",
                    "name": "alice"
                }])),
                role_ref: Some(serde_json::json!({
                    "kind": "ClusterRole",
                    "name": "test-role",
                    "apiGroup": "rbac.authorization.k8s.io"
                })),
            },
        ];

        let config = KubernetesIngestor::ingest_manifests(&manifests);
        assert_eq!(config.cluster_roles.len(), 1);
        assert_eq!(config.cluster_role_bindings.len(), 1);
        assert_eq!(config.cluster_role_bindings[0].subjects.len(), 1);
    }

    #[test]
    fn test_k8s_json_ingest() {
        let json = r#"{
            "cluster_roles": [],
            "roles": [],
            "cluster_role_bindings": [],
            "role_bindings": [],
            "service_accounts": [],
            "cluster_name": "prod-cluster"
        }"#;
        let graph = KubernetesIngestor::ingest_json(json).unwrap();
        assert_eq!(graph.account_id, Some("prod-cluster".to_string()));
    }
}
