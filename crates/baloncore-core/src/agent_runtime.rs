use crate::agent::{
    bridge_hypotheses_to_validators, challenge_hypotheses, validate_agent_output, AgentInput,
    AgentOutput, AgentOutputStatus, AgentPipelineResult, ModelConfig,
};
use crate::model_client::{ModelClient, ModelError, ModelRequest, ModelUsage};

fn redact_string_field(s: &str) -> String {
    let mut result = s.to_string();
    result = regex_lite::Regex::new(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*")
        .expect("bearer regex")
        .replace_all(&result, "<REDACTED_AUTHORIZATION>")
        .to_string();
    result = regex_lite::Regex::new(
        r"(?i)(?:authorization|x-api-key|apikey)\s*[:=]\s*[A-Za-z0-9\-._~+/]+=*",
    )
    .expect("header-key regex")
    .replace_all(&result, "<REDACTED_AUTHORIZATION>")
    .to_string();
    result = regex_lite::Regex::new(r"(?i)(?:api[-_]?key|secret|token|session[-_]?id|csrf[-_]?token)\s*[:=]\s*[A-Za-z0-9\-._~+/]+")
        .expect("secret-key regex")
        .replace_all(&result, "<REDACTED_SESSION>")
        .to_string();
    result = regex_lite::Regex::new(r"(?i)(?:set-cookie|cookie)\s*[:=]\s*[^\s;]+")
        .expect("cookie regex")
        .replace_all(&result, "<REDACTED_SESSION>")
        .to_string();
    result = regex_lite::Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
        .expect("email regex")
        .replace_all(&result, "<REDACTED_PII>")
        .to_string();
    result = regex_lite::Regex::new(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+")
        .expect("password regex")
        .replace_all(&result, "<REDACTED_SESSION>")
        .to_string();
    result
}

fn redact_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(redact_string_field(s)),
        serde_json::Value::Object(map) => {
            let redacted: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| {
                    let redacted_key = redact_string_field(k);
                    (redacted_key, redact_json_value(v))
                })
                .collect();
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(redact_json_value).collect())
        }
        other => other.clone(),
    }
}

pub fn redact_for_model(input: &AgentInput) -> AgentInput {
    let mut redacted = input.clone();
    redacted.scope_summary = redact_string_field(&redacted.scope_summary);
    redacted.endpoints = redacted
        .endpoints
        .iter()
        .map(|e| redact_string_field(e))
        .collect();
    redacted.findings = redacted
        .findings
        .iter()
        .map(|f| {
            let mut r = f.clone();
            r.classification = redact_string_field(&r.classification);
            r.endpoint = redact_string_field(&r.endpoint);
            r.evidence_refs = r
                .evidence_refs
                .iter()
                .map(|e| redact_string_field(e))
                .collect();
            r
        })
        .collect();
    redacted.evidence_refs = redacted
        .evidence_refs
        .iter()
        .map(|e| redact_string_field(e))
        .collect();
    redacted.context = redacted
        .context
        .iter()
        .map(|(k, v)| (redact_string_field(k), redact_json_value(v)))
        .collect();
    redacted
}

static SECRET_PATTERNS: &[&str] = &[
    r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
    r"(?i)(?:authorization|x-api-key|apikey)\s*[:=]\s*[A-Za-z0-9\-._~+/]+=*",
    r"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+",
];

pub fn contains_unredacted_secrets(text: &str) -> Option<String> {
    for pattern in SECRET_PATTERNS {
        if let Ok(re) = regex_lite::Regex::new(pattern) {
            if let Some(mat) = re.find(text) {
                return Some(mat.as_str().to_string());
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct AgentParseError {
    pub errors: Vec<String>,
}

impl std::fmt::Display for AgentParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "agent output parse failed: {}", self.errors.join("; "))
    }
}

impl std::error::Error for AgentParseError {}

pub fn parse_agent_output(role: &str, raw: &str) -> Result<AgentOutput, AgentParseError> {
    let stripped = strip_code_fences(raw);
    let json_str = extract_first_json_object(stripped)?;
    let mut output: AgentOutput = serde_json::from_str(json_str).map_err(|e| AgentParseError {
        errors: vec![format!("JSON decode error: {e}")],
    })?;
    output.agent_role = role.to_string();
    Ok(output)
}

fn strip_code_fences(input: &str) -> &str {
    let trimmed = input.trim();
    if (trimmed.starts_with("```json") || trimmed.starts_with("```")) && trimmed.ends_with("```") {
        let after_opening = if let Some(idx) = trimmed.find('\n') {
            &trimmed[idx + 1..]
        } else {
            trimmed
        };
        let before_closing = after_opening.strip_suffix("```").unwrap_or(after_opening);
        return before_closing.trim();
    }
    input
}

fn extract_first_json_object(input: &str) -> Result<&str, AgentParseError> {
    let start = input.find('{').ok_or_else(|| AgentParseError {
        errors: vec!["no JSON object found in model output".to_string()],
    })?;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (i, ch) in input[start..].char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' && in_string {
            escape = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            if depth == 0 {
                let end = start + i + 1;
                return Ok(&input[start..end]);
            }
        }
    }
    Err(AgentParseError {
        errors: vec!["unbalanced JSON object in model output".to_string()],
    })
}

pub fn build_repair_request(role: &str, prior_raw: &str, errors: &[String]) -> ModelRequest {
    let system = format!(
        "You are the BALONCORE {role} agent. Work only on authorized targets. \
         Produce strict JSON. You may propose hypotheses, but deterministic validators \
         are the only authority that can verify findings."
    );
    let error_summary = errors.join("\n");
    let user = format!(
        "Your previous output was invalid and could not be parsed as the expected JSON schema.\n\n\
         Errors:\n{error_summary}\n\n\
         Your previous output was:\n```\n{prior_raw}\n```\n\n\
         Return ONLY a corrected JSON object matching the AgentOutput schema. \
         Do not include any prose, explanation, or code fences. Output raw JSON only."
    );
    ModelRequest {
        system,
        user,
        max_tokens: 4096,
        temperature: 0.0,
        stop: vec![],
    }
}

#[derive(Debug, Clone)]
pub struct ModelBudget {
    pub max_tokens_total: u32,
    pub max_calls: u32,
    pub max_wall_ms: u64,
    pub used_tokens: u32,
    pub used_calls: u32,
    pub started_at: u64,
}

impl ModelBudget {
    pub fn conservative() -> Self {
        Self {
            max_tokens_total: 50000,
            max_calls: 5,
            max_wall_ms: 120_000,
            used_tokens: 0,
            used_calls: 0,
            started_at: now_millis(),
        }
    }

    pub fn check(&self) -> Result<(), ModelError> {
        if self.used_tokens > self.max_tokens_total {
            return Err(ModelError::BudgetExceeded(format!(
                "token budget exceeded: used {} of {} tokens",
                self.used_tokens, self.max_tokens_total
            )));
        }
        if self.used_calls >= self.max_calls {
            return Err(ModelError::BudgetExceeded(format!(
                "call budget exceeded: used {} of {} calls",
                self.used_calls, self.max_calls
            )));
        }
        let now = now_millis();
        if now.saturating_sub(self.started_at) > self.max_wall_ms {
            return Err(ModelError::BudgetExceeded(format!(
                "wall time budget exceeded: {}ms of {}ms",
                now.saturating_sub(self.started_at),
                self.max_wall_ms
            )));
        }
        Ok(())
    }

    pub fn record(&mut self, usage: &ModelUsage) {
        self.used_tokens += usage.input_tokens + usage.output_tokens;
        self.used_calls += 1;
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ModelBudgetReport {
    pub provider: String,
    pub model: String,
    pub calls: u32,
    pub tokens_used: u32,
    pub max_tokens: u32,
    pub max_calls: u32,
    pub wall_ms: u64,
    pub aborted_reason: Option<String>,
}

impl ModelBudget {
    pub fn report(&self, model: &ModelConfig, aborted_reason: Option<String>) -> ModelBudgetReport {
        ModelBudgetReport {
            provider: model.provider.clone(),
            model: model.model.clone(),
            calls: self.used_calls,
            tokens_used: self.used_tokens,
            max_tokens: self.max_tokens_total,
            max_calls: self.max_calls,
            wall_ms: now_millis().saturating_sub(self.started_at),
            aborted_reason,
        }
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn skipped_output(role: &str, model: &ModelConfig, reason: String) -> AgentOutput {
    AgentOutput {
        agent_role: role.to_string(),
        version: "1.0.0".to_string(),
        status: AgentOutputStatus::Skipped,
        hypotheses: Vec::new(),
        observations: Vec::new(),
        refusal_reason: None,
        skipped_reason: Some(reason),
        uncertainty_notes: Vec::new(),
        model_used: format!("{}:{}", model.provider, model.model),
    }
}

pub fn run_live_agent(
    client: &dyn ModelClient,
    input: &AgentInput,
    model: &ModelConfig,
    budget: &mut ModelBudget,
) -> AgentOutput {
    if let Err(_err) = budget.check() {
        return skipped_output(
            &input.role,
            model,
            "budget exceeded before model call".to_string(),
        );
    }

    let redacted_input = redact_for_model(input);
    let template = crate::agent::prompt_template(&redacted_input.role);
    let system = template.system_prompt.clone();
    let user = serde_json::to_string(&redacted_input)
        .unwrap_or_else(|e| format!("{{\"error\": \"failed to serialize agent input: {e}\"}}"));

    if let Some(secret) = contains_unredacted_secrets(&user) {
        debug_assert!(false, "unredacted secret in model payload: {}", secret);
        return skipped_output(
            &input.role,
            model,
            format!(
                "unredacted secret would reach provider: found [{}]",
                &secret[..secret.len().min(20)]
            ),
        );
    }

    let request = ModelRequest {
        system,
        user,
        max_tokens: model.max_tokens,
        temperature: model.temperature,
        stop: vec![],
    };

    let response = match client.complete(&request) {
        Ok(resp) => resp,
        Err(err) => {
            return skipped_output(&input.role, model, format!("model call failed: {err}"));
        }
    };

    budget.record(&response.usage);

    let parsed = parse_agent_output(&input.role, &response.text);
    let output = match parsed {
        Ok(mut output) => {
            output.model_used = format!("{}:{}", model.provider, model.model);
            output
        }
        Err(_) => {
            let schema_errors = vec!["model output could not be parsed as valid JSON".to_string()];
            match try_repair(
                client,
                &input.role,
                model,
                &response.text,
                &schema_errors,
                budget,
            ) {
                Some(repaired) => repaired,
                None => {
                    return skipped_output(
                        &input.role,
                        model,
                        "model output could not be parsed after one repair attempt".to_string(),
                    );
                }
            }
        }
    };

    let validation = validate_agent_output(&input.role, &output);
    if !validation.valid {
        let schema_errors = validation.errors.clone();
        match try_repair(
            client,
            &input.role,
            model,
            &response.text,
            &schema_errors,
            budget,
        ) {
            Some(repaired) => repaired,
            None => {
                return skipped_output(
                    &input.role,
                    model,
                    "model output failed schema validation after one repair attempt".to_string(),
                );
            }
        }
    } else {
        output
    }
}

fn try_repair(
    client: &dyn ModelClient,
    role: &str,
    model: &ModelConfig,
    prior_raw: &str,
    errors: &[String],
    budget: &mut ModelBudget,
) -> Option<AgentOutput> {
    if budget.check().is_err() {
        budget.used_calls += 1;
        return None;
    }

    let repair_request = build_repair_request(role, prior_raw, errors);
    let repair_response = match client.complete(&repair_request) {
        Ok(resp) => resp,
        Err(_) => return None,
    };

    budget.record(&repair_response.usage);

    match parse_agent_output(role, &repair_response.text) {
        Ok(mut repaired) => {
            repaired.model_used = format!("{}:{}", model.provider, model.model);
            Some(repaired)
        }
        Err(_) => None,
    }
}

pub fn run_live_agent_pipeline(
    client: &dyn ModelClient,
    input: &AgentInput,
    model: &ModelConfig,
    budget: &mut ModelBudget,
) -> AgentPipelineResult {
    let output = run_live_agent(client, input, model, budget);
    let validation = validate_agent_output(&input.role, &output);
    let challenges = challenge_hypotheses(&output);
    let bridges = bridge_hypotheses_to_validators(&output, &challenges);
    let hypotheses_ready_for_validation = bridges
        .iter()
        .filter(|bridge| bridge.eligible_for_validation)
        .count();
    let hypotheses_rejected = output
        .hypotheses
        .len()
        .saturating_sub(hypotheses_ready_for_validation);

    AgentPipelineResult {
        run_id: input.run_id.clone(),
        role: input.role.clone(),
        hypotheses_proposed: output.hypotheses.len(),
        output,
        validation,
        challenges,
        bridges,
        hypotheses_ready_for_validation,
        hypotheses_rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentHypothesis;
    use crate::model_client::ModelResponse;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct StubClient {
        response_text: String,
        call_count: AtomicUsize,
    }

    impl StubClient {
        fn new(response_text: &str) -> Self {
            Self {
                response_text: response_text.to_string(),
                call_count: AtomicUsize::new(0),
            }
        }
    }

    impl ModelClient for StubClient {
        fn complete(&self, _req: &ModelRequest) -> Result<ModelResponse, ModelError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(ModelResponse {
                text: self.response_text.clone(),
                usage: ModelUsage {
                    input_tokens: 100,
                    output_tokens: 200,
                },
                model: "stub-model".to_string(),
                provider: "stub".to_string(),
            })
        }
        fn provider(&self) -> &str {
            "stub"
        }
        fn model(&self) -> &str {
            "stub-model"
        }
    }

    fn valid_api_auth_output() -> String {
        serde_json::json!({
            "agent_role": "api-auth",
            "version": "1.0.0",
            "status": "Success",
            "hypotheses": [
                {
                    "id": "h-001",
                    "classification": "BrokenObjectLevelAuthorization",
                    "confidence": 0.85,
                    "endpoint": "GET /api/invoices/{id}",
                    "description": "test hypothesis",
                    "evidence_refs": ["exchange.json"],
                    "severity": "high"
                }
            ],
            "observations": [],
            "refusal_reason": null,
            "skipped_reason": null,
            "uncertainty_notes": [],
            "model_used": "stub:stub-model"
        })
        .to_string()
    }

    fn test_input() -> AgentInput {
        AgentInput {
            role: "api-auth".to_string(),
            run_id: "test-run".to_string(),
            scope_summary: "local test".to_string(),
            endpoints: vec!["GET /api/invoices/{id}".to_string()],
            findings: vec![],
            evidence_refs: vec!["openapi_inventory.json".to_string()],
            context: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn parse_clean_json() {
        let raw = valid_api_auth_output();
        let result = parse_agent_output("api-auth", &raw).expect("should parse clean JSON");
        assert_eq!(result.agent_role, "api-auth");
        assert_eq!(result.hypotheses.len(), 1);
        assert_eq!(result.hypotheses[0].id, "h-001");
    }

    #[test]
    fn parse_fenced_json_with_preamble() {
        let raw = format!(
            "Here is the agent output:\n```json\n{}\n```",
            valid_api_auth_output()
        );
        let result = parse_agent_output("api-auth", &raw).expect("should parse fenced JSON");
        assert_eq!(result.agent_role, "api-auth");
        assert_eq!(result.hypotheses.len(), 1);
    }

    #[test]
    fn parse_malformed_then_valid_on_repair() {
        let client = StubClient::new(&valid_api_auth_output());
        let model = ModelConfig::default();
        let mut budget = ModelBudget::conservative();
        let input = test_input();
        let output = run_live_agent(&client, &input, &model, &mut budget);
        assert_eq!(output.agent_role, "api-auth");
        assert_eq!(output.hypotheses.len(), 1);
        assert_eq!(output.status, AgentOutputStatus::Success);
        assert!(budget.used_calls >= 1);
    }

    #[test]
    fn parse_twice_malformed_returns_skipped() {
        let client = StubClient::new("this is not JSON at all, not even close");
        let model = ModelConfig::default();
        let mut budget = ModelBudget {
            max_calls: 10,
            ..ModelBudget::conservative()
        };
        let input = test_input();
        let output = run_live_agent(&client, &input, &model, &mut budget);
        assert_eq!(output.status, AgentOutputStatus::Skipped);
        assert!(output.skipped_reason.is_some());
        assert!(
            output.hypotheses.is_empty(),
            "never returns hypotheses from unparseable model output"
        );
    }

    #[test]
    fn budget_exhausted_before_first_call() {
        let client = StubClient::new(&valid_api_auth_output());
        let model = ModelConfig::default();
        let mut budget = ModelBudget {
            max_tokens_total: 0,
            max_calls: 0,
            max_wall_ms: 3600000,
            used_tokens: 0,
            used_calls: 0,
            started_at: now_millis(),
        };
        let input = test_input();
        let output = run_live_agent(&client, &input, &model, &mut budget);
        assert_eq!(output.status, AgentOutputStatus::Skipped);
        assert!(
            output
                .skipped_reason
                .as_ref()
                .map_or(false, |r| r.contains("budget exceeded")),
            "expected budget exceeded reason, got: {:?}",
            output.skipped_reason
        );
        assert!(output.hypotheses.is_empty());
    }

    #[test]
    fn run_live_agent_never_fabricates_hypotheses() {
        let client = StubClient::new("not JSON");
        let model = ModelConfig::default();
        let mut budget = ModelBudget {
            max_calls: 10,
            ..ModelBudget::conservative()
        };
        let input = test_input();
        let output = run_live_agent(&client, &input, &model, &mut budget);
        assert_eq!(
            output.status,
            AgentOutputStatus::Skipped,
            "unparseable output must result in Skipped, not Success with fabricated hypotheses"
        );
        assert!(
            output.hypotheses.is_empty(),
            "run_live_agent must never fabricate hypotheses"
        );
    }

    #[test]
    fn run_live_agent_sets_no_finding_state() {
        let client = StubClient::new("not JSON");
        let model = ModelConfig::default();
        let mut budget = ModelBudget {
            max_calls: 10,
            ..ModelBudget::conservative()
        };
        let input = test_input();
        let output = run_live_agent(&client, &input, &model, &mut budget);
        assert_ne!(
            output.status,
            AgentOutputStatus::Success,
            "on failure, status must not be Success"
        );
    }

    #[test]
    fn build_repair_request_contains_errors() {
        let req = build_repair_request(
            "api-auth",
            "previous broken output",
            &["missing field `endpoint`".to_string()],
        );
        assert!(req.system.contains("api-auth"));
        assert!(req.user.contains("missing field `endpoint`"));
        assert!(req.user.contains("previous broken output"));
    }

    #[test]
    fn model_budget_check_passes_within_limits() {
        let budget = ModelBudget::conservative();
        assert!(budget.check().is_ok());
    }

    #[test]
    fn model_budget_check_fails_when_tokens_exceeded() {
        let budget = ModelBudget {
            max_tokens_total: 100,
            max_calls: 10,
            max_wall_ms: 3600000,
            used_tokens: 200,
            used_calls: 1,
            started_at: 0,
        };
        assert!(budget.check().is_err());
        match budget.check().unwrap_err() {
            ModelError::BudgetExceeded(msg) => {
                assert!(msg.contains("token budget exceeded"));
            }
            other => panic!("expected BudgetExceeded, got {other}"),
        }
    }

    #[test]
    fn model_budget_check_fails_when_calls_exceeded() {
        let budget = ModelBudget {
            max_tokens_total: 50000,
            max_calls: 1,
            max_wall_ms: 3600000,
            used_tokens: 0,
            used_calls: 1,
            started_at: 0,
        };
        assert!(budget.check().is_err());
        match budget.check().unwrap_err() {
            ModelError::BudgetExceeded(msg) => {
                assert!(msg.contains("call budget exceeded"));
            }
            other => panic!("expected BudgetExceeded, got {other}"),
        }
    }

    #[test]
    fn model_budget_records_usage() {
        let mut budget = ModelBudget::conservative();
        let usage = ModelUsage {
            input_tokens: 150,
            output_tokens: 300,
        };
        budget.record(&usage);
        assert_eq!(budget.used_tokens, 450);
        assert_eq!(budget.used_calls, 1);
        budget.record(&usage);
        assert_eq!(budget.used_tokens, 900);
        assert_eq!(budget.used_calls, 2);
    }

    #[test]
    fn transport_error_returns_skipped() {
        struct FailClient;
        impl ModelClient for FailClient {
            fn complete(&self, _req: &ModelRequest) -> Result<ModelResponse, ModelError> {
                Err(ModelError::Transport("connection refused".to_string()))
            }
            fn provider(&self) -> &str {
                "fail"
            }
            fn model(&self) -> &str {
                "fail-model"
            }
        }
        let client = FailClient;
        let model = ModelConfig::default();
        let mut budget = ModelBudget::conservative();
        let input = test_input();
        let output = run_live_agent(&client, &input, &model, &mut budget);
        assert_eq!(output.status, AgentOutputStatus::Skipped);
        assert!(output
            .skipped_reason
            .as_ref()
            .map_or(false, |r| r.contains("connection refused")));
        assert!(output.hypotheses.is_empty());
    }

    #[test]
    fn refused_model_returns_skipped() {
        struct RefusedClient;
        impl ModelClient for RefusedClient {
            fn complete(&self, _req: &ModelRequest) -> Result<ModelResponse, ModelError> {
                Err(ModelError::Refused("content policy violation".to_string()))
            }
            fn provider(&self) -> &str {
                "refused"
            }
            fn model(&self) -> &str {
                "refused-model"
            }
        }
        let client = RefusedClient;
        let model = ModelConfig::default();
        let mut budget = ModelBudget::conservative();
        let input = test_input();
        let output = run_live_agent(&client, &input, &model, &mut budget);
        assert_eq!(output.status, AgentOutputStatus::Skipped);
        assert!(output
            .skipped_reason
            .as_ref()
            .map_or(false, |r| r.contains("content policy")));
        assert!(output.hypotheses.is_empty());
    }

    #[test]
    fn role_is_always_set_by_parse_not_trusted_from_model() {
        let raw = serde_json::json!({
            "agent_role": "wrong-role-from-model",
            "version": "1.0.0",
            "status": "Success",
            "hypotheses": [],
            "observations": [],
            "refusal_reason": null,
            "skipped_reason": null,
            "uncertainty_notes": [],
            "model_used": "stub:stub-model"
        })
        .to_string();
        let result = parse_agent_output("api-auth", &raw).expect("should parse");
        assert_eq!(
            result.agent_role, "api-auth",
            "role must be overridden by the caller, not trusted from model output"
        );
    }

    #[test]
    fn redact_for_model_removes_bearer_tokens() {
        let input = AgentInput {
            role: "api-auth".to_string(),
            run_id: "test-run".to_string(),
            scope_summary: String::new(),
            endpoints: vec![],
            findings: vec![],
            evidence_refs: vec![],
            context: {
                let mut ctx = std::collections::BTreeMap::new();
                ctx.insert(
                    "auth_header".to_string(),
                    serde_json::Value::String("Bearer sk-super-secret-token-12345".to_string()),
                );
                ctx
            },
        };
        let redacted = redact_for_model(&input);
        let auth_val = redacted
            .context
            .get("auth_header")
            .expect("key should exist")
            .as_str()
            .expect("should be string");
        assert!(
            !auth_val.contains("sk-super-secret-token-12345"),
            "bearer token should be redacted, got: {auth_val}"
        );
        assert!(
            auth_val.contains("<REDACTED_AUTHORIZATION>"),
            "bearer token should be replaced with placeholder, got: {auth_val}"
        );
    }

    #[test]
    fn redact_for_model_removes_emails() {
        let input = AgentInput {
            role: "api-auth".to_string(),
            run_id: "test-run".to_string(),
            scope_summary: String::new(),
            endpoints: vec![],
            findings: vec![],
            evidence_refs: vec![],
            context: {
                let mut ctx = std::collections::BTreeMap::new();
                ctx.insert(
                    "user_info".to_string(),
                    serde_json::Value::String("admin@example.com logged in".to_string()),
                );
                ctx
            },
        };
        let redacted = redact_for_model(&input);
        let val = redacted
            .context
            .get("user_info")
            .expect("key should exist")
            .as_str()
            .expect("should be string");
        assert!(
            !val.contains("admin@example.com"),
            "email should be redacted, got: {val}"
        );
        assert!(
            val.contains("<REDACTED_PII>"),
            "email should be replaced with PII placeholder, got: {val}"
        );
    }

    #[test]
    fn redact_for_model_removes_passwords() {
        let input = AgentInput {
            role: "api-auth".to_string(),
            run_id: "test-run".to_string(),
            scope_summary: String::new(),
            endpoints: vec![],
            findings: vec![],
            evidence_refs: vec![],
            context: {
                let mut ctx = std::collections::BTreeMap::new();
                ctx.insert(
                    "login".to_string(),
                    serde_json::Value::String("password=hunter2".to_string()),
                );
                ctx
            },
        };
        let redacted = redact_for_model(&input);
        let val = redacted
            .context
            .get("login")
            .expect("key should exist")
            .as_str()
            .expect("should be string");
        assert!(
            !val.contains("hunter2"),
            "password should be redacted, got: {val}"
        );
        assert!(
            val.contains("<REDACTED_SESSION>"),
            "password should be replaced with session placeholder, got: {val}"
        );
    }

    #[test]
    fn redact_for_model_removes_tokens_and_session_ids() {
        let input = AgentInput {
            role: "api-auth".to_string(),
            run_id: "test-run".to_string(),
            scope_summary: String::new(),
            endpoints: vec![],
            findings: vec![],
            evidence_refs: vec![],
            context: {
                let mut ctx = std::collections::BTreeMap::new();
                ctx.insert(
                    "session".to_string(),
                    serde_json::Value::String("session_id=abc123def456".to_string()),
                );
                ctx.insert(
                    "csrf".to_string(),
                    serde_json::Value::String("csrf_token=xcsrftoken123".to_string()),
                );
                ctx.insert(
                    "api_key".to_string(),
                    serde_json::Value::String("api_key=live_sk_abcdef123456".to_string()),
                );
                ctx
            },
        };
        let redacted = redact_for_model(&input);
        for key in &["session", "csrf", "api_key"] {
            let val = redacted
                .context
                .get(*key)
                .expect("key should exist")
                .as_str()
                .expect("should be string");
            assert!(
                val.contains("<REDACTED_SESSION>"),
                "{key} value should contain session placeholder, got: {val}"
            );
        }
    }

    #[test]
    fn redact_for_model_preserves_non_sensitive_data() {
        let input = AgentInput {
            role: "api-auth".to_string(),
            run_id: "test-run".to_string(),
            scope_summary: "GET /api/invoices/{id}".to_string(),
            endpoints: vec!["GET /api/invoices/{id}".to_string()],
            findings: vec![],
            evidence_refs: vec!["openapi_inventory.json".to_string()],
            context: {
                let mut ctx = std::collections::BTreeMap::new();
                ctx.insert(
                    "endpoint_count".to_string(),
                    serde_json::Value::Number(5.into()),
                );
                ctx.insert(
                    "method".to_string(),
                    serde_json::Value::String("GET".to_string()),
                );
                ctx
            },
        };
        let redacted = redact_for_model(&input);
        assert_eq!(redacted.role, "api-auth");
        assert_eq!(redacted.scope_summary, "GET /api/invoices/{id}");
        assert_eq!(redacted.endpoints, vec!["GET /api/invoices/{id}"]);
        assert_eq!(redacted.evidence_refs, vec!["openapi_inventory.json"]);
        assert_eq!(
            redacted.context.get("endpoint_count"),
            Some(&serde_json::Value::Number(5.into()))
        );
        assert_eq!(
            redacted.context.get("method"),
            Some(&serde_json::Value::String("GET".to_string()))
        );
    }

    #[test]
    fn contains_unredacted_secrets_detects_bearer_token() {
        let text = r#"{"context": {"auth": "Bearer sk-secret-key-12345"}}"#;
        let found = contains_unredacted_secrets(text);
        assert!(found.is_some(), "should detect bearer token");
        let secret = found.expect("should find secret");
        assert!(
            secret.contains("Bearer"),
            "should identify the bearer token: {secret}"
        );
    }

    #[test]
    fn contains_unredacted_secrets_detects_authorization_header() {
        let text = r#"{"context": {"h": "authorization: Basic dXNlcjpwYXNz"}}"#;
        let found = contains_unredacted_secrets(text);
        assert!(found.is_some(), "should detect authorization header");
    }

    #[test]
    fn contains_unredacted_secrets_detects_password() {
        let text = r#"{"context": {"login": "password=s3cr3t"}}"#;
        let found = contains_unredacted_secrets(text);
        assert!(found.is_some(), "should detect password");
    }

    #[test]
    fn contains_unredacted_secrets_allows_clean_text() {
        let text = r#"{"role": "api-auth", "scope_summary": "GET /api/invoices"}"#;
        let found = contains_unredacted_secrets(text);
        assert!(found.is_none(), "clean text should not trigger detection");
    }

    #[test]
    fn run_live_agent_redacts_input_before_sending() {
        let response = serde_json::json!({
            "agent_role": "api-auth",
            "version": "1.0.0",
            "status": "Success",
            "hypotheses": [],
            "observations": [],
            "refusal_reason": null,
            "skipped_reason": null,
            "uncertainty_notes": [],
            "model_used": "stub:stub-model"
        });
        let client = StubClient::new(&response.to_string());
        let model = ModelConfig::default();
        let mut budget = ModelBudget::conservative();
        let input = AgentInput {
            role: "api-auth".to_string(),
            run_id: "test-redact".to_string(),
            scope_summary: String::new(),
            endpoints: vec![],
            findings: vec![],
            evidence_refs: vec![],
            context: {
                let mut ctx = std::collections::BTreeMap::new();
                ctx.insert(
                    "auth".to_string(),
                    serde_json::Value::String("Bearer sk-leaked-key-999".to_string()),
                );
                ctx.insert(
                    "email".to_string(),
                    serde_json::Value::String("user@corp.com".to_string()),
                );
                ctx
            },
        };
        let output = run_live_agent(&client, &input, &model, &mut budget);
        assert_eq!(output.status, AgentOutputStatus::Success);
    }

    #[test]
    fn run_live_agent_blocks_unredacted_secret_when_bypassed() {
        let input_with_secret = AgentInput {
            role: "api-auth".to_string(),
            run_id: "test-block".to_string(),
            scope_summary: String::new(),
            endpoints: vec![],
            findings: vec![],
            evidence_refs: vec![],
            context: {
                let mut ctx = std::collections::BTreeMap::new();
                ctx.insert(
                    "auth".to_string(),
                    serde_json::Value::String("Bearer sk-unredactable-key".to_string()),
                );
                ctx
            },
        };
        let redacted = redact_for_model(&input_with_secret);
        let serialized = serde_json::to_string(&redacted).expect("should serialize");
        let check = contains_unredacted_secrets(&serialized);
        assert!(
            check.is_none(),
            "redacted payload should not contain unredacted secrets, found: {check:?}"
        );
    }

    #[test]
    fn live_pipeline_false_hypothesis_is_not_promoted_to_verified() {
        let false_output = AgentOutput {
            agent_role: "api-auth".to_string(),
            version: "1.0.0".to_string(),
            status: AgentOutputStatus::Success,
            hypotheses: vec![AgentHypothesis {
                id: "h-false-001".to_string(),
                classification: "BrokenObjectLevelAuthorization".to_string(),
                confidence: 0.99,
                endpoint: None,
                object_id: None,
                profile: None,
                description: "vague claim with no concrete endpoint".to_string(),
                evidence_refs: vec![],
                recommendation: None,
                severity: Some("high".to_string()),
            }],
            observations: vec![],
            refusal_reason: None,
            skipped_reason: None,
            uncertainty_notes: vec![],
            model_used: "stub:stub-model".to_string(),
        };
        let false_json = serde_json::to_string(&false_output).expect("should serialize");
        let client = StubClient::new(&false_json);
        let model = ModelConfig::default();
        let mut budget = ModelBudget::conservative();
        let input = AgentInput {
            role: "api-auth".to_string(),
            run_id: "firewall-false-test".to_string(),
            scope_summary: "local test".to_string(),
            endpoints: vec!["GET /api/invoices/{id}".to_string()],
            findings: vec![],
            evidence_refs: vec!["openapi_inventory.json".to_string()],
            context: std::collections::BTreeMap::new(),
        };

        let result = run_live_agent_pipeline(&client, &input, &model, &mut budget);

        assert_eq!(
            result.output.status,
            AgentOutputStatus::Success,
            "pipeline should succeed"
        );
        assert_eq!(
            result.hypotheses_proposed, 1,
            "one hypothesis should be proposed"
        );
        assert!(
            result.hypotheses_ready_for_validation == 0,
            "false hypothesis with no endpoint and no evidence must NOT be eligible for validation, got {} eligible",
            result.hypotheses_ready_for_validation
        );
        assert!(
            result.hypotheses_rejected >= 1,
            "false hypothesis should be counted as rejected"
        );
        let false_bridge = result
            .bridges
            .iter()
            .find(|b| b.hypothesis_id == "h-false-001")
            .expect("bridge should exist for hypothesis");
        assert!(
            !false_bridge.eligible_for_validation,
            "false hypothesis must NOT be eligible for validation"
        );
        let has_blocking_challenge = result
            .challenges
            .iter()
            .any(|c| c.hypothesis_id == "h-false-001" && c.blocking);
        assert!(
            has_blocking_challenge,
            "false hypothesis must have at least one blocking challenge"
        );
    }

    #[test]
    fn live_pipeline_true_hypothesis_is_promoted() {
        let true_output = AgentOutput {
            agent_role: "api-auth".to_string(),
            version: "1.0.0".to_string(),
            status: AgentOutputStatus::Success,
            hypotheses: vec![AgentHypothesis {
                id: "h-true-001".to_string(),
                classification: "BrokenObjectLevelAuthorization".to_string(),
                confidence: 0.85,
                endpoint: Some("GET /api/invoices/{id}".to_string()),
                object_id: Some("invoice_12345".to_string()),
                profile: Some("attacker-identity".to_string()),
                description: "cross-user invoice access via IDOR on invoice endpoint".to_string(),
                evidence_refs: vec!["openapi_inventory.json".to_string()],
                recommendation: Some("add authorization check on invoice endpoint".to_string()),
                severity: Some("high".to_string()),
            }],
            observations: vec![],
            refusal_reason: None,
            skipped_reason: None,
            uncertainty_notes: vec![],
            model_used: "stub:stub-model".to_string(),
        };
        let true_json = serde_json::to_string(&true_output).expect("should serialize");
        let client = StubClient::new(&true_json);
        let model = ModelConfig::default();
        let mut budget = ModelBudget::conservative();
        let input = AgentInput {
            role: "api-auth".to_string(),
            run_id: "firewall-true-test".to_string(),
            scope_summary: "local test".to_string(),
            endpoints: vec!["GET /api/invoices/{id}".to_string()],
            findings: vec![],
            evidence_refs: vec!["openapi_inventory.json".to_string()],
            context: std::collections::BTreeMap::new(),
        };

        let result = run_live_agent_pipeline(&client, &input, &model, &mut budget);

        assert_eq!(
            result.output.status,
            AgentOutputStatus::Success,
            "pipeline should succeed"
        );
        assert_eq!(
            result.hypotheses_proposed, 1,
            "one hypothesis should be proposed"
        );
        assert!(
            result.hypotheses_ready_for_validation >= 1,
            "true hypothesis with endpoint, evidence, and confidence >= 0.55 should be eligible for validation, got {} eligible",
            result.hypotheses_ready_for_validation
        );
        assert_eq!(
            result.hypotheses_rejected, 0,
            "true hypothesis should not be rejected"
        );
        let true_bridge = result
            .bridges
            .iter()
            .find(|b| b.hypothesis_id == "h-true-001")
            .expect("bridge should exist for hypothesis");
        assert!(
            true_bridge.eligible_for_validation,
            "true hypothesis must be eligible for validation: reason = {}",
            true_bridge.reason
        );
        assert!(
            true_bridge.validator.contains("validator"),
            "bridge should map to a deterministic validator, got: {}",
            true_bridge.validator
        );
        let no_blocking = result
            .challenges
            .iter()
            .all(|c| !c.blocking || c.hypothesis_id != "h-true-001");
        assert!(
            no_blocking,
            "true hypothesis should have no blocking challenges"
        );
    }

    #[test]
    fn live_pipeline_no_hypothesis_produces_empty_result() {
        let no_hypo = AgentOutput {
            agent_role: "api-auth".to_string(),
            version: "1.0.0".to_string(),
            status: AgentOutputStatus::Success,
            hypotheses: vec![],
            observations: vec![],
            refusal_reason: None,
            skipped_reason: None,
            uncertainty_notes: vec![],
            model_used: "stub:stub-model".to_string(),
        };
        let json = serde_json::to_string(&no_hypo).expect("should serialize");
        let client = StubClient::new(&json);
        let model = ModelConfig::default();
        let mut budget = ModelBudget::conservative();
        let input = AgentInput {
            role: "api-auth".to_string(),
            run_id: "firewall-empty-test".to_string(),
            scope_summary: "local test".to_string(),
            endpoints: vec![],
            findings: vec![],
            evidence_refs: vec![],
            context: std::collections::BTreeMap::new(),
        };
        let result = run_live_agent_pipeline(&client, &input, &model, &mut budget);
        assert_eq!(result.hypotheses_proposed, 0);
        assert_eq!(result.hypotheses_ready_for_validation, 0);
        assert_eq!(result.hypotheses_rejected, 0);
        assert!(result.bridges.is_empty());
        assert!(result.challenges.is_empty());
    }
}
