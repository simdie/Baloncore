use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

use crate::scope::ScopeError;

fn default_provider() -> String {
    "fixture".to_string()
}

fn default_model_name() -> String {
    "baloncore-local-fixture".to_string()
}

fn default_max_tokens() -> u32 {
    4096
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelTable {
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default = "default_model_name")]
    pub model: String,
    #[serde(default)]
    pub api_base: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default)]
    pub temperature: f32,
}

impl ModelTable {
    pub fn to_model_config(&self) -> crate::agent::ModelConfig {
        crate::agent::ModelConfig {
            provider: self.provider.clone(),
            model: self.model.clone(),
            api_base: self.api_base.clone(),
            api_key_env: self.api_key_env.clone(),
            max_tokens: self.max_tokens,
            temperature: self.temperature,
        }
    }
}

impl Default for ModelTable {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            model: default_model_name(),
            api_base: None,
            api_key_env: None,
            max_tokens: default_max_tokens(),
            temperature: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaloncoreConfig {
    pub project: ProjectConfig,
    pub scope: ScopeConfig,
    #[serde(default)]
    pub auth_profiles: Vec<AuthProfile>,
    #[serde(default)]
    pub engines: EngineConfig,
    #[serde(default)]
    pub suppressions: Vec<SuppressionRule>,
    #[serde(default)]
    pub model: ModelTable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectConfig {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeConfig {
    #[serde(default)]
    pub allow_urls: Vec<String>,
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default)]
    pub deny_hosts: Vec<String>,
    #[serde(default = "default_max_depth")]
    pub max_depth: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthProfile {
    pub name: String,
    pub role: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub credential: Option<AuthCredentialRef>,
    #[serde(default)]
    pub object_markers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthCredentialRef {
    #[serde(default)]
    pub bearer_token_env: Option<String>,
    #[serde(default)]
    pub cookie_env: Option<String>,
    #[serde(default)]
    pub header_env: Option<String>,
    #[serde(default)]
    pub api_key_header: Option<ApiKeyHeaderRef>,
    #[serde(default)]
    pub cookie_session: Option<CookieSessionRef>,
    #[serde(default)]
    pub oauth2: Option<OAuth2Ref>,
    #[serde(default)]
    pub extra_headers: Vec<TemplateHeader>,
    #[serde(default)]
    pub extra_cookies: Vec<TemplateCookie>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKeyHeaderRef {
    pub header_name: String,
    pub header_value_env: Option<String>,
    pub header_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CookieSessionRef {
    pub cookie_name: String,
    pub cookie_value_env: Option<String>,
    pub cookie_value: Option<String>,
    pub csrf_token_header: Option<String>,
    pub csrf_token_env: Option<String>,
    pub csrf_token_value: Option<String>,
    pub login_endpoint: Option<String>,
    pub login_body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuth2Ref {
    pub grant_type: OAuth2GrantType,
    pub token_endpoint: String,
    pub client_id_env: Option<String>,
    pub client_id: Option<String>,
    pub client_secret_env: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OAuth2GrantType {
    #[serde(rename = "client_credentials")]
    ClientCredentials,
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateCookie {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuppressionRule {
    pub id: String,
    pub reason: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub classification: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub object_id: Option<String>,
    #[serde(default)]
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineConfig {
    #[serde(default)]
    pub web_api: bool,
    #[serde(default)]
    pub cloud_iam: bool,
    #[serde(default)]
    pub web3: bool,
}

impl BaloncoreConfig {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ScopeError> {
        let raw = fs::read_to_string(path).map_err(ScopeError::ReadConfig)?;
        toml::from_str(&raw).map_err(ScopeError::ParseConfig)
    }

    pub fn example() -> Self {
        Self {
            project: ProjectConfig {
                name: "baloncore-lab".to_string(),
                description: Some("Authorized local target for BALONCORE validation.".to_string()),
                tags: vec!["api".to_string(), "web".to_string()],
            },
            scope: ScopeConfig {
                allow_urls: vec!["http://localhost:3000".to_string()],
                allow_hosts: vec!["localhost".to_string(), "127.0.0.1".to_string()],
                deny_hosts: vec![],
                max_depth: default_max_depth(),
            },
            auth_profiles: vec![
                AuthProfile {
                    name: "anonymous".to_string(),
                    role: "anonymous".to_string(),
                    description: Some("Unauthenticated baseline.".to_string()),
                    credential: None,
                    object_markers: vec![],
                },
                AuthProfile {
                    name: "user_a".to_string(),
                    role: "user".to_string(),
                    description: Some("Standard low-privilege user.".to_string()),
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
                    object_markers: vec!["user_a".to_string()],
                },
                AuthProfile {
                    name: "user_b".to_string(),
                    role: "user".to_string(),
                    description: Some(
                        "Second low-privilege user for cross-account checks.".to_string(),
                    ),
                    credential: Some(AuthCredentialRef {
                        bearer_token_env: Some("BALONCORE_USER_B_TOKEN".to_string()),
                        cookie_env: None,
                        header_env: None,
                        api_key_header: None,
                        cookie_session: None,
                        oauth2: None,
                        extra_headers: vec![],
                        extra_cookies: vec![],
                    }),
                    object_markers: vec!["user_b".to_string(), "user_b@example.test".to_string()],
                },
                AuthProfile {
                    name: "admin".to_string(),
                    role: "admin".to_string(),
                    description: Some("Administrative control profile.".to_string()),
                    credential: Some(AuthCredentialRef {
                        bearer_token_env: Some("BALONCORE_ADMIN_TOKEN".to_string()),
                        cookie_env: None,
                        header_env: None,
                        api_key_header: None,
                        cookie_session: None,
                        oauth2: None,
                        extra_headers: vec![],
                        extra_cookies: vec![],
                    }),
                    object_markers: vec!["admin".to_string()],
                },
                AuthProfile {
                    name: "cookie_user_a".to_string(),
                    role: "user".to_string(),
                    description: Some("User A authenticated via cookie/session.".to_string()),
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
                            login_endpoint: Some("http://localhost:3000/auth/login".to_string()),
                            login_body: Some(
                                "{\"username\":\"user_a\",\"password\":\"lab\"}".to_string(),
                            ),
                        }),
                        oauth2: None,
                        extra_headers: vec![],
                        extra_cookies: vec![],
                    }),
                    object_markers: vec!["user_a".to_string()],
                },
                AuthProfile {
                    name: "apikey_user_b".to_string(),
                    role: "user".to_string(),
                    description: Some("User B authenticated via API key header.".to_string()),
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
                    object_markers: vec!["user_b".to_string(), "user_b@example.test".to_string()],
                },
                AuthProfile {
                    name: "org_a_member".to_string(),
                    role: "member".to_string(),
                    description: Some("Org A member for tenant isolation checks.".to_string()),
                    credential: Some(AuthCredentialRef {
                        bearer_token_env: Some("BALONCORE_ORG_A_MEMBER_TOKEN".to_string()),
                        cookie_env: None,
                        header_env: None,
                        api_key_header: None,
                        cookie_session: None,
                        oauth2: None,
                        extra_headers: vec![],
                        extra_cookies: vec![],
                    }),
                    object_markers: vec!["org-a".to_string(), "member_a".to_string()],
                },
                AuthProfile {
                    name: "org_b_member".to_string(),
                    role: "member".to_string(),
                    description: Some("Org B member for cross-tenant validation.".to_string()),
                    credential: Some(AuthCredentialRef {
                        bearer_token_env: Some("BALONCORE_ORG_B_MEMBER_TOKEN".to_string()),
                        cookie_env: None,
                        header_env: None,
                        api_key_header: None,
                        cookie_session: None,
                        oauth2: None,
                        extra_headers: vec![],
                        extra_cookies: vec![],
                    }),
                    object_markers: vec!["org-b".to_string(), "member_b".to_string()],
                },
            ],
            engines: EngineConfig {
                web_api: true,
                cloud_iam: false,
                web3: false,
            },
            suppressions: vec![],
            model: ModelTable::default(),
        }
    }

    pub fn to_toml_pretty(&self) -> Result<String, ScopeError> {
        toml::to_string_pretty(self).map_err(ScopeError::SerializeConfig)
    }
}

fn default_max_depth() -> u8 {
    3
}

impl AuthCredentialRef {
    pub fn is_bearer_only(&self) -> bool {
        self.bearer_token_env.is_some()
            && self.api_key_header.is_none()
            && self.cookie_session.is_none()
            && self.oauth2.is_none()
            && self.extra_headers.is_empty()
            && self.extra_cookies.is_empty()
    }
}

impl AuthProfile {
    pub fn auth_scheme(&self) -> &'static str {
        match &self.credential {
            None => "none",
            Some(cred) if cred.oauth2.is_some() => "oauth2",
            Some(cred) if cred.cookie_session.is_some() => "cookie_session",
            Some(cred) if cred.api_key_header.is_some() => "api_key",
            Some(cred) if cred.bearer_token_env.is_some() => "bearer",
            Some(cred) if cred.header_env.is_some() => "api_key",
            Some(cred) if cred.cookie_env.is_some() => "cookie_session",
            _ => "unknown",
        }
    }
}
