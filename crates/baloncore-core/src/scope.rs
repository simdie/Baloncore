use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::config::ScopeConfig;

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("failed to read config: {0}")]
    ReadConfig(std::io::Error),
    #[error("failed to parse config: {0}")]
    ParseConfig(toml::de::Error),
    #[error("failed to serialize config: {0}")]
    SerializeConfig(toml::ser::Error),
    #[error("invalid URL `{raw}`: {source}")]
    InvalidUrl {
        raw: String,
        source: url::ParseError,
    },
}

#[derive(Debug, Clone)]
pub struct ScopeGuard {
    config: ScopeConfig,
    allow_urls: Vec<Url>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeDecision {
    Allowed { reason: String },
    Blocked { reason: String },
}

impl ScopeGuard {
    pub fn new(config: ScopeConfig) -> Result<Self, ScopeError> {
        let allow_urls = config
            .allow_urls
            .iter()
            .map(|raw| {
                Url::parse(raw).map_err(|source| ScopeError::InvalidUrl {
                    raw: raw.clone(),
                    source,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { config, allow_urls })
    }

    pub fn evaluate(&self, raw_url: &str) -> ScopeDecision {
        let url = match Url::parse(raw_url) {
            Ok(url) => url,
            Err(err) => {
                return ScopeDecision::Blocked {
                    reason: format!("invalid URL: {err}"),
                }
            }
        };

        if !matches!(url.scheme(), "http" | "https") {
            return ScopeDecision::Blocked {
                reason: "only http and https targets are supported".to_string(),
            };
        }

        let Some(host) = url.host_str() else {
            return ScopeDecision::Blocked {
                reason: "target URL has no host".to_string(),
            };
        };

        if self
            .config
            .deny_hosts
            .iter()
            .any(|entry| host_matches(entry, host))
        {
            return ScopeDecision::Blocked {
                reason: format!("host `{host}` is explicitly denied"),
            };
        }

        if self
            .config
            .allow_hosts
            .iter()
            .any(|entry| host_matches(entry, host))
        {
            return ScopeDecision::Allowed {
                reason: format!("host `{host}` is in allow_hosts"),
            };
        }

        if self
            .allow_urls
            .iter()
            .any(|base| url_is_under_base(base, &url))
        {
            return ScopeDecision::Allowed {
                reason: "URL is under allow_urls".to_string(),
            };
        }

        ScopeDecision::Blocked {
            reason: format!("host `{host}` is outside configured scope"),
        }
    }

    pub fn is_allowed(&self, raw_url: &str) -> bool {
        matches!(self.evaluate(raw_url), ScopeDecision::Allowed { .. })
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();

    if pattern == host {
        return true;
    }

    pattern
        .strip_prefix("*.")
        .is_some_and(|suffix| host.ends_with(&format!(".{suffix}")) || host == suffix)
}

fn url_is_under_base(base: &Url, candidate: &Url) -> bool {
    if base.scheme() != candidate.scheme()
        || base.host_str() != candidate.host_str()
        || base.port_or_known_default() != candidate.port_or_known_default()
    {
        return false;
    }

    candidate.path().starts_with(base.path())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> ScopeGuard {
        ScopeGuard::new(ScopeConfig {
            allow_urls: vec!["https://app.example.com/api/".to_string()],
            allow_hosts: vec!["localhost".to_string(), "*.safe.test".to_string()],
            deny_hosts: vec!["admin.safe.test".to_string()],
            max_depth: 3,
        })
        .unwrap()
    }

    #[test]
    fn allows_explicit_hosts() {
        assert!(guard().is_allowed("http://localhost:3000/health"));
    }

    #[test]
    fn allows_urls_under_configured_base() {
        assert!(guard().is_allowed("https://app.example.com/api/users"));
    }

    #[test]
    fn blocks_out_of_scope_hosts() {
        assert!(!guard().is_allowed("https://evil.example.com/api/users"));
    }

    #[test]
    fn deny_hosts_win_over_wildcards() {
        assert!(!guard().is_allowed("https://admin.safe.test/secrets"));
    }

    #[test]
    fn blocks_non_http_schemes() {
        assert!(!guard().is_allowed("file:///etc/passwd"));
    }
}
