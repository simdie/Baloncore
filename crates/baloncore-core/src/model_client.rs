use std::fmt;

use crate::agent::{run_fixture_agent, AgentInput, ModelConfig};

#[derive(Debug)]
pub enum ModelError {
    Transport(String),
    Status { code: u16, body: String },
    Decode(String),
    Timeout,
    BudgetExceeded(String),
    Refused(String),
    MissingKey(String),
}

impl std::error::Error for ModelError {}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(msg) => write!(f, "model transport error: {msg}"),
            Self::Status { code, body } => {
                write!(f, "model returned status {code}: {body}")
            }
            Self::Decode(msg) => write!(f, "model response decode error: {msg}"),
            Self::Timeout => write!(f, "model request timed out"),
            Self::BudgetExceeded(msg) => write!(f, "model budget exceeded: {msg}"),
            Self::Refused(msg) => write!(f, "model request refused: {msg}"),
            Self::MissingKey(msg) => write!(f, "model api key missing: {msg}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModelRequest {
    pub system: String,
    pub user: String,
    pub max_tokens: u32,
    pub temperature: f32,
    pub stop: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ModelUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

#[derive(Debug, Clone)]
pub struct ModelResponse {
    pub text: String,
    pub usage: ModelUsage,
    pub model: String,
    pub provider: String,
}

pub trait ModelClient: Send + Sync {
    fn complete(&self, req: &ModelRequest) -> Result<ModelResponse, ModelError>;
    fn provider(&self) -> &str;
    fn model(&self) -> &str;
}

pub struct FixtureModelClient {
    model_config: ModelConfig,
}

impl FixtureModelClient {
    pub fn new(model: &ModelConfig) -> Self {
        Self {
            model_config: model.clone(),
        }
    }
}

impl ModelClient for FixtureModelClient {
    fn complete(&self, req: &ModelRequest) -> Result<ModelResponse, ModelError> {
        let role = extract_role_from_system(&req.system);
        let input = AgentInput {
            role: role.clone(),
            run_id: format!(
                "fixture-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            ),
            scope_summary: String::new(),
            endpoints: Vec::new(),
            findings: Vec::new(),
            evidence_refs: Vec::new(),
            context: std::collections::BTreeMap::new(),
        };
        let output = run_fixture_agent(&input, &self.model_config);
        let text = serde_json::to_string(&output)
            .map_err(|e| ModelError::Decode(format!("fixture output serialization failed: {e}")))?;
        let input_tokens = req.system.len() as u32 + req.user.len() as u32;
        let output_tokens = text.len() as u32 / 4;
        Ok(ModelResponse {
            text,
            usage: ModelUsage {
                input_tokens,
                output_tokens,
            },
            model: self.model_config.model.clone(),
            provider: self.model_config.provider.clone(),
        })
    }

    fn provider(&self) -> &str {
        "fixture"
    }

    fn model(&self) -> &str {
        &self.model_config.model
    }
}

fn extract_role_from_system(system_prompt: &str) -> String {
    if let Some(after_prefix) = system_prompt.strip_prefix("You are the BALONCORE ") {
        if let Some(space_pos) = after_prefix.find(' ') {
            return after_prefix[..space_pos].to_string();
        }
    }
    "recon".to_string()
}

#[cfg(feature = "live-models")]
pub struct AnthropicClient {
    model_config: ModelConfig,
    api_key: String,
    api_base: String,
    http: reqwest::blocking::Client,
}

#[cfg(feature = "live-models")]
impl std::fmt::Debug for AnthropicClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnthropicClient")
            .field("model_config", &self.model_config)
            .field("api_key", &"[REDACTED]")
            .field("api_base", &self.api_base)
            .field("http", &"<reqwest::blocking::Client>")
            .finish()
    }
}

#[cfg(feature = "live-models")]
impl AnthropicClient {
    pub fn new(model: &ModelConfig) -> Result<Self, ModelError> {
        let key_env = model.api_key_env.as_deref().unwrap_or("ANTHROPIC_API_KEY");
        let api_key = std::env::var(key_env).map_err(|_| {
            ModelError::MissingKey(format!(
                "environment variable {key_env} is not set; \
                 never read API keys from config files or arguments"
            ))
        })?;
        let api_base = model
            .api_base
            .as_deref()
            .unwrap_or("https://api.anthropic.com")
            .to_string();
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| ModelError::Transport(format!("failed to build http client: {e}")))?;
        Ok(Self {
            model_config: model.clone(),
            api_key,
            api_base,
            http,
        })
    }
}

#[cfg(feature = "live-models")]
impl ModelClient for AnthropicClient {
    fn complete(&self, req: &ModelRequest) -> Result<ModelResponse, ModelError> {
        let mut body = serde_json::json!({
            "model": self.model_config.model,
            "max_tokens": req.max_tokens,
            "messages": [{ "role": "user", "content": req.user }],
        });
        if !req.system.is_empty() {
            body["system"] = serde_json::Value::String(req.system.clone());
        }
        if req.temperature != 0.0 {
            body["temperature"] = serde_json::Value::from(req.temperature as f64);
        }
        if !req.stop.is_empty() {
            body["stop_sequences"] = serde_json::Value::Array(
                req.stop
                    .iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            );
        }
        let url = format!("{}/v1/messages", self.api_base);
        let response = self
            .http
            .post(&url)
            .header("x-api-key", self.api_key.as_str())
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    ModelError::Timeout
                } else {
                    ModelError::Transport(format!("anthropic request failed: {e}"))
                }
            })?;
        let status = response.status();
        if !status.is_success() {
            let body_text = response
                .text()
                .unwrap_or_else(|e| format!("<failed to read response body: {e}>"));
            return Err(ModelError::Status {
                code: status.as_u16(),
                body: body_text,
            });
        }
        let resp_json: serde_json::Value = response
            .json()
            .map_err(|e| ModelError::Decode(format!("failed to parse anthropic response: {e}")))?;
        let text = resp_json
            .get("content")
            .and_then(|c| c.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|block| {
                        if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                            block.get("text").and_then(|t| t.as_str())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("")
            })
            .ok_or_else(|| {
                ModelError::Decode("anthropic response missing content array".to_string())
            })?;
        let input_tokens = resp_json
            .get("usage")
            .and_then(|u| u.get("input_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let output_tokens = resp_json
            .get("usage")
            .and_then(|u| u.get("output_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let resp_model = resp_json
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or(&self.model_config.model)
            .to_string();
        Ok(ModelResponse {
            text,
            usage: ModelUsage {
                input_tokens,
                output_tokens,
            },
            model: resp_model,
            provider: "anthropic".to_string(),
        })
    }

    fn provider(&self) -> &str {
        "anthropic"
    }

    fn model(&self) -> &str {
        &self.model_config.model
    }
}

#[cfg(feature = "live-models")]
pub struct OpenAIClient {
    model_config: ModelConfig,
    api_key: String,
    api_base: String,
    http: reqwest::blocking::Client,
}

#[cfg(feature = "live-models")]
impl std::fmt::Debug for OpenAIClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAIClient")
            .field("model_config", &self.model_config)
            .field("api_key", &"[REDACTED]")
            .field("api_base", &self.api_base)
            .field("http", &"<reqwest::blocking::Client>")
            .finish()
    }
}

#[cfg(feature = "live-models")]
impl OpenAIClient {
    pub fn new(model: &ModelConfig) -> Result<Self, ModelError> {
        let key_env = model.api_key_env.as_deref().unwrap_or("OPENAI_API_KEY");
        let api_key = std::env::var(key_env).map_err(|_| {
            ModelError::MissingKey(format!(
                "environment variable {key_env} is not set; \
                 never read API keys from config files or arguments"
            ))
        })?;
        let api_base = model
            .api_base
            .as_deref()
            .unwrap_or("https://api.openai.com")
            .to_string();
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| ModelError::Transport(format!("failed to build http client: {e}")))?;
        Ok(Self {
            model_config: model.clone(),
            api_key,
            api_base,
            http,
        })
    }
}

#[cfg(feature = "live-models")]
impl ModelClient for OpenAIClient {
    fn complete(&self, req: &ModelRequest) -> Result<ModelResponse, ModelError> {
        let mut messages = Vec::new();
        if !req.system.is_empty() {
            messages.push(serde_json::json!({
                "role": "system",
                "content": req.system,
            }));
        }
        messages.push(serde_json::json!({
            "role": "user",
            "content": req.user,
        }));
        let mut body = serde_json::json!({
            "model": self.model_config.model,
            "max_tokens": req.max_tokens,
            "messages": messages,
        });
        if req.temperature != 0.0 {
            body["temperature"] = serde_json::Value::from(req.temperature as f64);
        }
        if !req.stop.is_empty() {
            body["stop"] = serde_json::Value::Array(
                req.stop
                    .iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            );
        }
        let url = format!("{}/v1/chat/completions", self.api_base);
        let response = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    ModelError::Timeout
                } else {
                    ModelError::Transport(format!("openai request failed: {e}"))
                }
            })?;
        let status = response.status();
        if !status.is_success() {
            let body_text = response
                .text()
                .unwrap_or_else(|e| format!("<failed to read response body: {e}>"));
            return Err(ModelError::Status {
                code: status.as_u16(),
                body: body_text,
            });
        }
        let resp_json: serde_json::Value = response
            .json()
            .map_err(|e| ModelError::Decode(format!("failed to parse openai response: {e}")))?;
        let text = resp_json
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|choice| choice.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();
        let input_tokens = resp_json
            .get("usage")
            .and_then(|u| u.get("prompt_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let output_tokens = resp_json
            .get("usage")
            .and_then(|u| u.get("completion_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let resp_model = resp_json
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or(&self.model_config.model)
            .to_string();
        Ok(ModelResponse {
            text,
            usage: ModelUsage {
                input_tokens,
                output_tokens,
            },
            model: resp_model,
            provider: "openai".to_string(),
        })
    }

    fn provider(&self) -> &str {
        "openai"
    }

    fn model(&self) -> &str {
        &self.model_config.model
    }
}

pub fn client_for(model: &ModelConfig) -> Result<Box<dyn ModelClient>, ModelError> {
    match model.provider.as_str() {
        "fixture" => Ok(Box::new(FixtureModelClient::new(model))),
        #[cfg(feature = "live-models")]
        "anthropic" => {
            let client = AnthropicClient::new(model)?;
            Ok(Box::new(client))
        }
        #[cfg(feature = "live-models")]
        "openai" => {
            let client = OpenAIClient::new(model)?;
            Ok(Box::new(client))
        }
        other => Err(ModelError::Refused(format!(
            "unknown provider '{other}'; build with --features live-models for anthropic and openai providers"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_for_default_returns_fixture() {
        let config = ModelConfig::default();
        let client = client_for(&config).expect("default config should return a fixture client");
        assert_eq!(client.provider(), "fixture");
        assert_eq!(client.model(), "baloncore-local-fixture");
    }

    #[test]
    fn client_for_unknown_provider_is_refused() {
        let config = ModelConfig {
            provider: "unknown-llm".to_string(),
            model: "fake-model".to_string(),
            api_base: None,
            api_key_env: None,
            max_tokens: 1024,
            temperature: 0.0,
        };
        let result = client_for(&config);
        assert!(
            result.is_err(),
            "expected Refused error for unknown provider"
        );
        match result {
            Err(ModelError::Refused(msg)) => {
                assert!(
                    msg.contains("unknown-llm"),
                    "refusal should mention the provider: {msg}"
                );
                assert!(
                    msg.contains("live-models"),
                    "refusal should mention the feature flag: {msg}"
                );
            }
            Err(other) => panic!("expected Refused, got {other}"),
            Ok(_) => panic!("expected error for unknown provider"),
        }
    }

    #[test]
    fn fixture_client_returns_valid_json() {
        let config = ModelConfig::default();
        let client = FixtureModelClient::new(&config);
        let req = ModelRequest {
            system: "You are the BALONCORE api-auth agent. Work only on authorized targets."
                .to_string(),
            user: "Test input".to_string(),
            max_tokens: 1024,
            temperature: 0.0,
            stop: Vec::new(),
        };
        let response = client
            .complete(&req)
            .expect("fixture client should succeed");
        assert!(!response.text.is_empty());
        assert!(
            response.text.contains("agent_role"),
            "fixture output should be valid AgentOutput JSON"
        );
        assert!(response.usage.input_tokens > 0);
        assert_eq!(response.provider, "fixture");
        assert_eq!(response.model, "baloncore-local-fixture");
    }

    #[test]
    fn model_error_display_formats() {
        let err = ModelError::Transport("connection refused".to_string());
        assert!(err.to_string().contains("connection refused"));

        let err = ModelError::Status {
            code: 429,
            body: "rate limited".to_string(),
        };
        assert!(err.to_string().contains("429"));

        let err = ModelError::MissingKey("ANTHROPIC_API_KEY".to_string());
        assert!(err.to_string().contains("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn extract_role_from_system_prompt() {
        assert_eq!(
            extract_role_from_system(
                "You are the BALONCORE api-auth agent. Work only on authorized targets."
            ),
            "api-auth"
        );
        assert_eq!(
            extract_role_from_system(
                "You are the BALONCORE recon agent. Work only on authorized targets."
            ),
            "recon"
        );
        assert_eq!(extract_role_from_system("Some other prompt"), "recon");
    }
}

#[cfg(test)]
#[cfg(feature = "live-models")]
mod live_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn spawn_mock_server(response_body: &str, status_code: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("get mock addr");
        let port = addr.port();
        let response_body = response_body.to_string();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept mock connection");
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).expect("read request");
            let _ = std::str::from_utf8(&buf[..n]);
            let status_text = if status_code == 200 { "OK" } else { "Error" };
            let header = format!(
                "HTTP/1.1 {status_code} {status_text}\r\n\
                 Content-Type: application/json\r\n\
                 Connection: close\r\n\r\n"
            );
            let resp = format!("{header}{response_body}");
            stream.write_all(resp.as_bytes()).expect("write response");
            stream.flush().expect("flush response");
        });
        format!("http://127.0.0.1:{port}")
    }

    fn make_config(api_base: &str, api_key_env: &str) -> ModelConfig {
        ModelConfig {
            provider: "anthropic".to_string(),
            model: "claude-sonnet-4-20250514".to_string(),
            api_base: Some(api_base.to_string()),
            api_key_env: Some(api_key_env.to_string()),
            max_tokens: 1024,
            temperature: 0.0,
        }
    }

    #[test]
    fn anthropic_client_missing_key_returns_error() {
        let env_var = "BALONCORE_TEST_KEY_NOT_SET_12345";
        std::env::remove_var(env_var);
        let config = ModelConfig {
            provider: "anthropic".to_string(),
            model: "claude-sonnet-4-20250514".to_string(),
            api_base: Some("https://api.anthropic.com".to_string()),
            api_key_env: Some(env_var.to_string()),
            max_tokens: 1024,
            temperature: 0.0,
        };
        let result = AnthropicClient::new(&config);
        assert!(result.is_err(), "expected error when API key is missing");
        match result.unwrap_err() {
            ModelError::MissingKey(msg) => {
                assert!(
                    msg.contains(env_var),
                    "error should mention the env var name: {msg}"
                );
            }
            other => panic!("expected MissingKey, got {other}"),
        }
    }

    #[test]
    fn anthropic_client_sends_correct_request_shape() {
        let env_var = "BALONCORE_TEST_MOCK_KEY_SHAPE";
        std::env::set_var(env_var, "sk-test-key-12345");

        let mock_response = serde_json::json!({
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-20250514",
            "content": [{"type": "text", "text": "hello from mock"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 50, "output_tokens": 10}
        });
        let base = spawn_mock_server(&mock_response.to_string(), 200);

        let config = make_config(&base, env_var);
        let key = std::env::var(env_var).expect("key should be set");
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("build client");
        let client = AnthropicClient {
            model_config: config.clone(),
            api_key: key,
            api_base: base,
            http,
        };

        let req = ModelRequest {
            system: "You are the BALONCORE api-auth agent.".to_string(),
            user: "Analyze this endpoint.".to_string(),
            max_tokens: 1024,
            temperature: 0.0,
            stop: Vec::new(),
        };
        let result = client.complete(&req);
        std::env::remove_var(env_var);

        let response = result.expect("mock anthropic call should succeed");
        assert_eq!(response.text, "hello from mock");
        assert_eq!(response.usage.input_tokens, 50);
        assert_eq!(response.usage.output_tokens, 10);
        assert_eq!(response.provider, "anthropic");
    }

    #[test]
    fn anthropic_client_handles_non_200_status() {
        let env_var = "BALONCORE_TEST_MOCK_KEY_STATUS";
        std::env::set_var(env_var, "sk-test-key-status");

        let base = spawn_mock_server("{\"error\":\"rate limited\"}", 429);

        let config = make_config(&base, env_var);
        let key = std::env::var(env_var).expect("key should be set");
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("build client");
        let client = AnthropicClient {
            model_config: config,
            api_key: key,
            api_base: base,
            http,
        };

        let req = ModelRequest {
            system: "You are a test.".to_string(),
            user: "test".to_string(),
            max_tokens: 1024,
            temperature: 0.0,
            stop: Vec::new(),
        };
        let result = client.complete(&req);
        std::env::remove_var(env_var);

        match result {
            Err(ModelError::Status { code, body }) => {
                assert_eq!(code, 429);
                assert!(body.contains("rate limited"), "body: {body}");
            }
            other => panic!("expected Status error, got {other:?}"),
        }
    }

    #[test]
    fn client_for_anthropic_returns_anthropic_client_when_feature_enabled() {
        let env_var = "BALONCORE_TEST_MOCK_KEY_FOR";
        std::env::set_var(env_var, "sk-test-for-client-for");

        let config = ModelConfig {
            provider: "anthropic".to_string(),
            model: "claude-sonnet-4-20250514".to_string(),
            api_base: Some("https://api.anthropic.com".to_string()),
            api_key_env: Some(env_var.to_string()),
            max_tokens: 1024,
            temperature: 0.0,
        };
        let result = client_for(&config);
        std::env::remove_var(env_var);
        assert!(
            result.is_ok(),
            "client_for anthropic should succeed with live-models feature"
        );
        let client = result.expect("should have client");
        assert_eq!(client.provider(), "anthropic");
    }

    #[test]
    fn openai_client_missing_key_returns_error() {
        let env_var = "BALONCORE_TEST_OPENAI_KEY_NOT_SET_XYZ";
        std::env::remove_var(env_var);
        let config = ModelConfig {
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
            api_base: Some("https://api.openai.com".to_string()),
            api_key_env: Some(env_var.to_string()),
            max_tokens: 1024,
            temperature: 0.0,
        };
        let result = OpenAIClient::new(&config);
        assert!(result.is_err(), "expected error when API key is missing");
        match result.unwrap_err() {
            ModelError::MissingKey(msg) => {
                assert!(
                    msg.contains(env_var),
                    "error should mention the env var name: {msg}"
                );
            }
            other => panic!("expected MissingKey, got {other}"),
        }
    }

    #[test]
    fn openai_client_sends_correct_request_shape() {
        let env_var = "BALONCORE_TEST_OPENAI_KEY_SHAPE";
        std::env::set_var(env_var, "sk-openai-test-key");

        let mock_response = serde_json::json!({
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "model": "gpt-4",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hello from openai mock"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 30, "completion_tokens": 8, "total_tokens": 38}
        });
        let base = spawn_mock_server(&mock_response.to_string(), 200);

        let config = ModelConfig {
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
            api_base: Some(base.clone()),
            api_key_env: Some(env_var.to_string()),
            max_tokens: 1024,
            temperature: 0.0,
        };
        let key = std::env::var(env_var).expect("key should be set");
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("build client");
        let client = OpenAIClient {
            model_config: config,
            api_key: key,
            api_base: base,
            http,
        };

        let req = ModelRequest {
            system: "You are the BALONCORE api-auth agent.".to_string(),
            user: "Analyze this endpoint.".to_string(),
            max_tokens: 1024,
            temperature: 0.0,
            stop: Vec::new(),
        };
        let result = client.complete(&req);
        std::env::remove_var(env_var);

        let response = result.expect("mock openai call should succeed");
        assert_eq!(response.text, "hello from openai mock");
        assert_eq!(response.usage.input_tokens, 30);
        assert_eq!(response.usage.output_tokens, 8);
        assert_eq!(response.provider, "openai");
    }

    #[test]
    fn openai_client_handles_non_200_status() {
        let env_var = "BALONCORE_TEST_OPENAI_KEY_STATUS";
        std::env::set_var(env_var, "sk-openai-test-status");

        let base = spawn_mock_server("{\"error\":{\"message\":\"rate limit\"}}", 429);

        let config = ModelConfig {
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
            api_base: Some(base.clone()),
            api_key_env: Some(env_var.to_string()),
            max_tokens: 1024,
            temperature: 0.0,
        };
        let key = std::env::var(env_var).expect("key should be set");
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("build client");
        let client = OpenAIClient {
            model_config: config,
            api_key: key,
            api_base: base,
            http,
        };

        let req = ModelRequest {
            system: "You are a test.".to_string(),
            user: "test".to_string(),
            max_tokens: 1024,
            temperature: 0.0,
            stop: Vec::new(),
        };
        let result = client.complete(&req);
        std::env::remove_var(env_var);

        match result {
            Err(ModelError::Status { code, body }) => {
                assert_eq!(code, 429);
                assert!(body.contains("rate limit"), "body: {body}");
            }
            other => panic!("expected Status error, got {other:?}"),
        }
    }

    #[test]
    fn client_for_openai_returns_openai_client_when_feature_enabled() {
        let env_var = "BALONCORE_TEST_OPENAI_KEY_FOR";
        std::env::set_var(env_var, "sk-test-for-openai-client-for");

        let config = ModelConfig {
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
            api_base: Some("https://api.openai.com".to_string()),
            api_key_env: Some(env_var.to_string()),
            max_tokens: 1024,
            temperature: 0.0,
        };
        let result = client_for(&config);
        std::env::remove_var(env_var);
        assert!(
            result.is_ok(),
            "client_for openai should succeed with live-models feature"
        );
        let client = result.expect("should have client");
        assert_eq!(client.provider(), "openai");
    }

    #[test]
    fn provider_parity_fixture_anthropic_openai_produce_schema_valid_output() {
        use crate::agent_runtime::parse_agent_output;

        let fixture_config = ModelConfig::default();
        let fixture_client = FixtureModelClient::new(&fixture_config);
        let fixture_req = ModelRequest {
            system: "You are the BALONCORE api-auth agent. Work only on authorized targets."
                .to_string(),
            user: "Analyze GET /api/invoices/{id} for broken object level authorization."
                .to_string(),
            max_tokens: 4096,
            temperature: 0.0,
            stop: Vec::new(),
        };
        let fixture_resp = fixture_client
            .complete(&fixture_req)
            .expect("fixture should succeed");
        let fixture_output = parse_agent_output("api-auth", &fixture_resp.text)
            .expect("fixture output should parse");

        let anthropic_mock = serde_json::json!({
            "id": "msg_parity",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-20250514",
            "content": [{"type": "text", "text": fixture_resp.text}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 100, "output_tokens": 50}
        });
        let openai_mock = serde_json::json!({
            "id": "chatcmpl-parity",
            "object": "chat.completion",
            "model": "gpt-4",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": fixture_resp.text},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
        });

        let anthropic_base = spawn_mock_server(&anthropic_mock.to_string(), 200);
        let openai_base = spawn_mock_server(&openai_mock.to_string(), 200);

        let anth_env = "BALONCORE_TEST_PARITY_ANTH_KEY";
        std::env::set_var(anth_env, "sk-parity-anth");
        let oai_env = "BALONCORE_TEST_PARITY_OAI_KEY";
        std::env::set_var(oai_env, "sk-parity-oai");

        let anth_config = ModelConfig {
            provider: "anthropic".to_string(),
            model: "claude-sonnet-4-20250514".to_string(),
            api_base: Some(anthropic_base.clone()),
            api_key_env: Some(anth_env.to_string()),
            max_tokens: 4096,
            temperature: 0.0,
        };
        let oai_config = ModelConfig {
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
            api_base: Some(openai_base.clone()),
            api_key_env: Some(oai_env.to_string()),
            max_tokens: 4096,
            temperature: 0.0,
        };

        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("build client");

        let anth_key = std::env::var(anth_env).expect("anth key");
        let anthropic_client = AnthropicClient {
            model_config: anth_config,
            api_key: anth_key,
            api_base: anthropic_base,
            http: http.clone(),
        };

        let oai_key = std::env::var(oai_env).expect("oai key");
        let openai_client = OpenAIClient {
            model_config: oai_config,
            api_key: oai_key,
            api_base: openai_base,
            http,
        };

        let anth_resp = anthropic_client
            .complete(&fixture_req)
            .expect("anthropic mock should succeed");
        let oai_resp = openai_client
            .complete(&fixture_req)
            .expect("openai mock should succeed");

        std::env::remove_var(anth_env);
        std::env::remove_var(oai_env);

        let anth_output = parse_agent_output("api-auth", &anth_resp.text)
            .expect("anthropic mock output should parse");
        let oai_output = parse_agent_output("api-auth", &oai_resp.text)
            .expect("openai mock output should parse");

        assert_eq!(
            fixture_output.agent_role, anth_output.agent_role,
            "fixture and anthropic roles must match"
        );
        assert_eq!(
            fixture_output.agent_role, oai_output.agent_role,
            "fixture and openai roles must match"
        );
        assert_eq!(
            fixture_output.status, anth_output.status,
            "fixture and anthropic statuses must match"
        );
        assert_eq!(
            fixture_output.status, oai_output.status,
            "fixture and openai statuses must match"
        );
        assert_eq!(
            fixture_output.hypotheses.len(),
            anth_output.hypotheses.len(),
            "fixture and anthropic must have same hypothesis count"
        );
        assert_eq!(
            fixture_output.hypotheses.len(),
            oai_output.hypotheses.len(),
            "fixture and openai must have same hypothesis count"
        );
        assert_eq!(anth_resp.provider, "anthropic");
        assert_eq!(oai_resp.provider, "openai");
    }
}
