use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::agents::{builtin_agents, AgentSpec};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelConfig {
    pub provider: String,
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

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            provider: "fixture".to_string(),
            model: "baloncore-local-fixture".to_string(),
            api_base: None,
            api_key_env: None,
            max_tokens: default_max_tokens(),
            temperature: 0.0,
        }
    }
}

fn default_max_tokens() -> u32 {
    4096
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentInput {
    pub role: String,
    pub run_id: String,
    #[serde(default)]
    pub scope_summary: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub findings: Vec<AgentFindingSummary>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub context: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentFindingSummary {
    pub finding_id: String,
    pub classification: String,
    pub endpoint: String,
    pub severity: String,
    pub state: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentOutputStatus {
    Success,
    Refused,
    Skipped,
    NeedsMoreEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentOutput {
    pub agent_role: String,
    pub version: String,
    pub status: AgentOutputStatus,
    #[serde(default)]
    pub hypotheses: Vec<AgentHypothesis>,
    #[serde(default)]
    pub observations: Vec<AgentObservation>,
    #[serde(default)]
    pub refusal_reason: Option<String>,
    #[serde(default)]
    pub skipped_reason: Option<String>,
    #[serde(default)]
    pub uncertainty_notes: Vec<String>,
    pub model_used: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentHypothesis {
    pub id: String,
    pub classification: String,
    pub confidence: f32,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub object_id: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    pub description: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub recommendation: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentObservation {
    pub category: String,
    pub description: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentRun {
    pub run_id: String,
    pub started_at: u64,
    pub finished_at: u64,
    pub input: AgentInput,
    pub output: AgentOutput,
    pub validation: AgentOutputValidation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentOutputValidation {
    pub valid: bool,
    pub role_match: bool,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PromptTemplate {
    pub role: String,
    pub version: String,
    pub system_prompt: String,
    pub output_schema: String,
    #[serde(default)]
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifierChallenge {
    pub hypothesis_id: String,
    pub challenge_type: String,
    pub reason: String,
    pub blocking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorBridge {
    pub hypothesis_id: String,
    pub validator: String,
    pub eligible_for_validation: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentPipelineResult {
    pub run_id: String,
    pub role: String,
    pub output: AgentOutput,
    pub validation: AgentOutputValidation,
    pub challenges: Vec<VerifierChallenge>,
    pub bridges: Vec<ValidatorBridge>,
    pub hypotheses_proposed: usize,
    pub hypotheses_ready_for_validation: usize,
    pub hypotheses_rejected: usize,
}

pub fn agent_spec(role: &str) -> Option<AgentSpec> {
    builtin_agents().into_iter().find(|spec| spec.name == role)
}

pub fn prompt_template(role: &str) -> PromptTemplate {
    let pv = crate::agents::latest_prompt_template(role);
    let spec = agent_spec(role);
    let _mission = spec
        .as_ref()
        .map(|s| s.mission)
        .unwrap_or("Assist BALONCORE with authorized security validation.");
    let output_schema = spec
        .as_ref()
        .map(|s| s.output_schema)
        .unwrap_or("AgentOutput");
    PromptTemplate {
        role: role.to_string(),
        version: pv.version.clone(),
        system_prompt: format!(
            "{}\n\nAgentOutput JSON schema:\n{}",
            pv.system_prompt, pv.output_schema
        ),
        output_schema: output_schema.to_string(),
        examples: vec![
            format!("GOOD example (accepted):\n{}", pv.good_example),
            format!(
                "BAD example (rejected — vague, no endpoint, no evidence):\n{}",
                pv.bad_example
            ),
        ],
    }
}

pub fn run_fixture_agent(input: &AgentInput, model: &ModelConfig) -> AgentOutput {
    match input.role.as_str() {
        "recon" => recon_output(input, model),
        "api-auth" => api_auth_output(input, model),
        "schema-discovery" => schema_discovery_output(input, model),
        "business-logic" => business_logic_output(input, model),
        "attack-chain" => attack_chain_output(input, model),
        "evidence-hygiene" => evidence_hygiene_output(input, model),
        "verifier" => verifier_output(input, model),
        "reporter" => reporter_output(input, model),
        "detection-engineer" => detection_engineer_output(input, model),
        _ => generic_output(input, model),
    }
}

pub fn run_fixture_agent_pipeline(input: &AgentInput, model: &ModelConfig) -> AgentPipelineResult {
    let output = run_fixture_agent(input, model);
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

pub fn validate_agent_output(expected_role: &str, output: &AgentOutput) -> AgentOutputValidation {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let role_match = output.agent_role == expected_role;
    if !role_match {
        errors.push(format!(
            "role mismatch: expected `{expected_role}`, got `{}`",
            output.agent_role
        ));
    }
    if output.status == AgentOutputStatus::Refused && output.refusal_reason.is_none() {
        errors.push("refused output must include refusal_reason".to_string());
    }
    if output.status == AgentOutputStatus::Skipped && output.skipped_reason.is_none() {
        errors.push("skipped output must include skipped_reason".to_string());
    }
    if agent_spec(expected_role).is_some_and(|spec| spec.must_validate) {
        for hypothesis in &output.hypotheses {
            if hypothesis.endpoint.is_none() {
                errors.push(format!("hypothesis `{}` has no endpoint", hypothesis.id));
            }
            if hypothesis.evidence_refs.is_empty() {
                warnings.push(format!(
                    "hypothesis `{}` has no evidence_refs and cannot be promoted",
                    hypothesis.id
                ));
            }
            if !(0.0..=1.0).contains(&hypothesis.confidence) {
                errors.push(format!(
                    "hypothesis `{}` confidence must be between 0 and 1",
                    hypothesis.id
                ));
            }
        }
    }

    AgentOutputValidation {
        valid: errors.is_empty(),
        role_match,
        errors,
        warnings,
    }
}

pub fn challenge_hypotheses(output: &AgentOutput) -> Vec<VerifierChallenge> {
    let mut challenges = Vec::new();
    for hypothesis in &output.hypotheses {
        if hypothesis.endpoint.is_none() {
            challenges.push(VerifierChallenge {
                hypothesis_id: hypothesis.id.clone(),
                challenge_type: "missing_endpoint".to_string(),
                reason: "hypothesis has no endpoint or asset target".to_string(),
                blocking: true,
            });
        }
        if hypothesis.evidence_refs.is_empty() {
            challenges.push(VerifierChallenge {
                hypothesis_id: hypothesis.id.clone(),
                challenge_type: "missing_evidence".to_string(),
                reason: "hypothesis has no evidence references".to_string(),
                blocking: true,
            });
        }
        if hypothesis.confidence < 0.55 {
            challenges.push(VerifierChallenge {
                hypothesis_id: hypothesis.id.clone(),
                challenge_type: "low_confidence".to_string(),
                reason: "confidence is below promotion threshold".to_string(),
                blocking: true,
            });
        }
        if hypothesis.confidence < 0.75 {
            challenges.push(VerifierChallenge {
                hypothesis_id: hypothesis.id.clone(),
                challenge_type: "needs_more_evidence".to_string(),
                reason: "confidence is moderate; prioritize reproducibility checks".to_string(),
                blocking: false,
            });
        }
    }
    challenges
}

pub fn bridge_hypotheses_to_validators(
    output: &AgentOutput,
    challenges: &[VerifierChallenge],
) -> Vec<ValidatorBridge> {
    output
        .hypotheses
        .iter()
        .map(|hypothesis| {
            let blocked = challenges
                .iter()
                .any(|challenge| challenge.hypothesis_id == hypothesis.id && challenge.blocking);
            let validator = validator_for_classification(&hypothesis.classification);
            ValidatorBridge {
                hypothesis_id: hypothesis.id.clone(),
                validator: validator.to_string(),
                eligible_for_validation: !blocked && validator != "manual-review",
                reason: if blocked {
                    "blocked by verifier challenge".to_string()
                } else if validator == "manual-review" {
                    "no deterministic validator is registered for this classification".to_string()
                } else {
                    "ready for deterministic validation, not verified by agent".to_string()
                },
            }
        })
        .collect()
}

pub fn validator_for_classification(classification: &str) -> &'static str {
    let normalized = classification
        .to_ascii_lowercase()
        .replace([' ', '-', '_'], "");
    match normalized.as_str() {
        "brokenobjectlevelauthorization" | "idor" => "bola-validator",
        "brokenfunctionlevelauthorization" | "bfla" => "authorization-matrix-validator",
        "missingauthentication" => "anonymous-exposure-validator",
        "graphqlfieldauthorization" => "graphql-auth-validator",
        "businesslogicworkflowbypass" => "workflow-invariant-validator",
        "publicresourceexposure" | "overprivilegedpolicy" => "cloud-iam-validator",
        "reentrancy" | "accesscontrol" | "oraclemanipulation" => "web3-validator",
        _ => "manual-review",
    }
}

fn base_output(input: &AgentInput, model: &ModelConfig) -> AgentOutput {
    AgentOutput {
        agent_role: input.role.clone(),
        version: "1.0.0".to_string(),
        status: AgentOutputStatus::Success,
        hypotheses: Vec::new(),
        observations: Vec::new(),
        refusal_reason: None,
        skipped_reason: None,
        uncertainty_notes: Vec::new(),
        model_used: format!("{}:{}", model.provider, model.model),
    }
}

fn recon_output(input: &AgentInput, model: &ModelConfig) -> AgentOutput {
    let mut output = base_output(input, model);
    output.observations.push(AgentObservation {
        category: "attack_surface".to_string(),
        description: format!(
            "{} endpoint(s), {} finding(s), {} evidence reference(s) available for reasoning",
            input.endpoints.len(),
            input.findings.len(),
            input.evidence_refs.len()
        ),
        evidence_refs: input.evidence_refs.clone(),
        severity: Some("info".to_string()),
    });
    output
}

fn api_auth_output(input: &AgentInput, model: &ModelConfig) -> AgentOutput {
    let mut output = base_output(input, model);
    for (index, endpoint) in input
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.contains("{id}") || endpoint.contains(":id"))
        .take(5)
        .enumerate()
    {
        output.hypotheses.push(AgentHypothesis {
            id: format!("api-auth-hypothesis-{index:03}"),
            classification: "BrokenObjectLevelAuthorization".to_string(),
            confidence: 0.78,
            endpoint: Some(endpoint.clone()),
            object_id: None,
            profile: None,
            description:
                "Object-shaped endpoint should be tested across owner and non-owner profiles"
                    .to_string(),
            evidence_refs: input.evidence_refs.clone(),
            recommendation: Some("run deterministic authorization matrix validation".to_string()),
            severity: Some("high".to_string()),
        });
    }
    if output.hypotheses.is_empty() {
        output.status = AgentOutputStatus::NeedsMoreEvidence;
        output
            .uncertainty_notes
            .push("no object-shaped endpoints were present in the agent input".to_string());
    }
    output
}

fn schema_discovery_output(input: &AgentInput, model: &ModelConfig) -> AgentOutput {
    let mut output = base_output(input, model);
    output.observations.push(AgentObservation {
        category: "schema_prioritization".to_string(),
        description: format!(
            "Prioritize schemas that describe authenticated object endpoints; {} endpoint(s) are currently indexed",
            input.endpoints.len()
        ),
        evidence_refs: input.evidence_refs.clone(),
        severity: Some("info".to_string()),
    });
    output
}

fn business_logic_output(input: &AgentInput, model: &ModelConfig) -> AgentOutput {
    let mut output = base_output(input, model);
    let mut sequence_endpoints: Vec<_> = input
        .endpoints
        .iter()
        .filter(|endpoint| {
            endpoint.starts_with("POST ")
                || endpoint.starts_with("PATCH ")
                || endpoint.starts_with("DELETE ")
        })
        .take(3)
        .cloned()
        .collect();
    if sequence_endpoints.is_empty() {
        sequence_endpoints = input.endpoints.iter().take(2).cloned().collect();
    }
    for (index, endpoint) in sequence_endpoints.iter().enumerate() {
        output.hypotheses.push(AgentHypothesis {
            id: format!("business-logic-hypothesis-{index:03}"),
            classification: "BusinessLogicWorkflowBypass".to_string(),
            confidence: 0.58,
            endpoint: Some(endpoint.clone()),
            object_id: None,
            profile: None,
            description: "State-changing workflow should be checked for missing prerequisite or ownership controls".to_string(),
            evidence_refs: input.evidence_refs.clone(),
            recommendation: Some("build a safe workflow-order validation plan before execution".to_string()),
            severity: Some("medium".to_string()),
        });
    }
    output
}

fn attack_chain_output(input: &AgentInput, model: &ModelConfig) -> AgentOutput {
    let mut output = base_output(input, model);
    if input.findings.len() >= 2 {
        output.hypotheses.push(AgentHypothesis {
            id: "attack-chain-hypothesis-000".to_string(),
            classification: "AttackChain".to_string(),
            confidence: 0.62,
            endpoint: input.findings.first().map(|finding| finding.endpoint.clone()),
            object_id: None,
            profile: None,
            description: "Multiple verified findings may compose into a higher-impact chain; require graph validation".to_string(),
            evidence_refs: input.evidence_refs.clone(),
            recommendation: Some("connect only evidence-backed edges in the attack graph".to_string()),
            severity: Some("high".to_string()),
        });
    } else {
        output.status = AgentOutputStatus::Skipped;
        output.skipped_reason =
            Some("attack-chain reasoning requires at least two findings".to_string());
    }
    output
}

fn evidence_hygiene_output(input: &AgentInput, model: &ModelConfig) -> AgentOutput {
    let mut output = base_output(input, model);
    let sensitive_refs: Vec<String> = input
        .evidence_refs
        .iter()
        .filter(|reference| {
            let lower = reference.to_ascii_lowercase();
            lower.contains("exchange") || lower.contains("authorization") || lower.contains("token")
        })
        .cloned()
        .collect();
    output.observations.push(AgentObservation {
        category: "redaction_review".to_string(),
        description: format!(
            "{} evidence reference(s) should be checked for sensitive request/response data before export",
            sensitive_refs.len()
        ),
        evidence_refs: sensitive_refs,
        severity: Some("medium".to_string()),
    });
    output
}

fn verifier_output(input: &AgentInput, model: &ModelConfig) -> AgentOutput {
    let mut output = base_output(input, model);
    output.observations.push(AgentObservation {
        category: "verification_rule".to_string(),
        description: "Require deterministic validator evidence before report inclusion".to_string(),
        evidence_refs: input.evidence_refs.clone(),
        severity: Some("info".to_string()),
    });
    output
}

fn reporter_output(input: &AgentInput, model: &ModelConfig) -> AgentOutput {
    let mut output = base_output(input, model);
    output.observations.push(AgentObservation {
        category: "reporting".to_string(),
        description: format!(
            "Report {} verified/reportable finding(s) with reproduction, impact, remediation, and evidence integrity",
            input.findings.len()
        ),
        evidence_refs: input.evidence_refs.clone(),
        severity: Some("info".to_string()),
    });
    output
}

fn detection_engineer_output(input: &AgentInput, model: &ModelConfig) -> AgentOutput {
    let mut output = base_output(input, model);
    output.observations.push(AgentObservation {
        category: "detection".to_string(),
        description:
            "Generate detection rules from verified behavior, not from unvalidated hypotheses"
                .to_string(),
        evidence_refs: input.evidence_refs.clone(),
        severity: Some("info".to_string()),
    });
    output
}

fn generic_output(input: &AgentInput, model: &ModelConfig) -> AgentOutput {
    let mut output = base_output(input, model);
    output.observations.push(AgentObservation {
        category: "general".to_string(),
        description: "No specialized fixture runner exists for this role yet".to_string(),
        evidence_refs: input.evidence_refs.clone(),
        severity: Some("info".to_string()),
    });
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(role: &str) -> AgentInput {
        AgentInput {
            role: role.to_string(),
            run_id: "run-1".to_string(),
            scope_summary: "local lab".to_string(),
            endpoints: vec![
                "GET /api/invoices/{id}".to_string(),
                "POST /api/invoices".to_string(),
            ],
            findings: vec![],
            evidence_refs: vec!["openapi_inventory.json".to_string()],
            context: BTreeMap::new(),
        }
    }

    #[test]
    fn api_auth_fixture_generates_validator_ready_hypothesis() {
        let output = run_fixture_agent(&input("api-auth"), &ModelConfig::default());
        let validation = validate_agent_output("api-auth", &output);
        assert!(validation.valid);
        assert_eq!(output.hypotheses.len(), 1);
        let challenges = challenge_hypotheses(&output);
        assert!(challenges.iter().all(|challenge| !challenge.blocking));
        let bridges = bridge_hypotheses_to_validators(&output, &challenges);
        assert!(bridges[0].eligible_for_validation);
        assert_eq!(bridges[0].validator, "bola-validator");
    }

    #[test]
    fn missing_evidence_blocks_promotion() {
        let mut output = run_fixture_agent(&input("api-auth"), &ModelConfig::default());
        output.hypotheses[0].evidence_refs.clear();
        let challenges = challenge_hypotheses(&output);
        assert!(challenges.iter().any(|challenge| challenge.blocking));
        let bridges = bridge_hypotheses_to_validators(&output, &challenges);
        assert!(!bridges[0].eligible_for_validation);
    }

    #[test]
    fn validation_rejects_role_mismatch() {
        let output = run_fixture_agent(&input("api-auth"), &ModelConfig::default());
        let validation = validate_agent_output("recon", &output);
        assert!(!validation.valid);
        assert!(!validation.role_match);
    }

    #[test]
    fn prompt_template_enforces_validator_boundary() {
        let template = prompt_template("api-auth");
        assert!(template.system_prompt.contains("deterministic validators"));
        assert_eq!(template.role, "api-auth");
    }

    #[test]
    fn versioned_prompts_embed_schema_for_all_roles() {
        let execution_roles = [
            "recon",
            "api-auth",
            "schema-discovery",
            "business-logic",
            "attack-chain",
            "triage",
            "evidence-hygiene",
            "detection-engineer",
            "verifier",
            "reporter",
        ];
        for role in execution_roles {
            let template = prompt_template(role);
            assert!(
                template.system_prompt.contains("agent_role"),
                "{role}: prompt must embed the AgentOutput JSON schema (missing agent_role)",
            );
            assert!(
                template.system_prompt.contains("hypotheses"),
                "{role}: prompt must embed the AgentOutput JSON schema (missing hypotheses)",
            );
            assert!(
                template.system_prompt.contains("confidence"),
                "{role}: prompt must embed the AgentOutput JSON schema (missing confidence)",
            );
            assert!(
                template.system_prompt.contains("endpoint"),
                "{role}: prompt must mention endpoint requirement",
            );
        }
    }

    #[test]
    fn versioned_prompts_contain_scope_and_firewall_rules() {
        let roles = ["recon", "api-auth", "business-logic", "verifier"];
        for role in roles {
            let template = prompt_template(role);
            assert!(
                template.system_prompt.contains("authorize")
                    || template.system_prompt.contains("authorized scope"),
                "{role}: prompt must contain scope rule about authorized targets",
            );
            assert!(
                template.system_prompt.contains("deterministic validators")
                    || template.system_prompt.contains("validators"),
                "{role}: prompt must contain firewall rule about validators",
            );
        }
    }

    #[test]
    fn versioned_prompts_have_good_and_bad_examples() {
        let roles = ["api-auth", "business-logic", "verifier"];
        for role in roles {
            let template = prompt_template(role);
            assert!(
                !template.examples.is_empty(),
                "{role}: prompt must have at least one example",
            );
            let has_good = template.examples.iter().any(|e| e.contains("GOOD"));
            let has_bad = template.examples.iter().any(|e| e.contains("BAD"));
            assert!(
                has_good,
                "{role}: prompt examples must include a GOOD example"
            );
            assert!(
                has_bad,
                "{role}: prompt examples must include a BAD example"
            );
        }
    }

    #[test]
    fn api_auth_prompt_requires_concrete_endpoint_and_object() {
        let template = prompt_template("api-auth");
        assert!(
            template.system_prompt.contains("concrete")
                || template.system_prompt.contains("specific"),
            "api-auth prompt must instruct model to produce concrete hypotheses",
        );
        assert!(
            template.system_prompt.contains("alternate-user")
                || template.system_prompt.contains("object_id"),
            "api-auth prompt must instruct model to specify alternate user or object",
        );
    }

    #[test]
    fn verifier_prompt_requires_active_challenge() {
        let template = prompt_template("verifier");
        assert!(
            template.system_prompt.contains("argue AGAINST")
                || template.system_prompt.contains("challenge"),
            "verifier prompt must instruct model to actively challenge hypotheses",
        );
        assert!(
            template.system_prompt.contains("skeptical")
                || template.system_prompt.contains("reproducible"),
            "verifier prompt must emphasize skepticism and reproducibility",
        );
    }

    #[test]
    fn prompt_version_is_v2() {
        let template = prompt_template("api-auth");
        assert_eq!(template.version, "2.0.0");
    }

    #[test]
    fn versioned_prompt_template_lookup_works() {
        let pv = crate::agents::versioned_prompt_template("api-auth", "2.0.0");
        assert!(pv.is_some(), "should find api-auth v2.0.0");
        let pv = pv.unwrap();
        assert_eq!(pv.role, "api-auth");
        assert_eq!(pv.version, "2.0.0");
    }

    #[test]
    fn versioned_prompt_template_returns_none_for_unknown_version() {
        let pv = crate::agents::versioned_prompt_template("api-auth", "0.0.1");
        assert!(pv.is_none(), "unknown version should return None");
    }

    #[test]
    fn bad_examples_have_null_endpoint_or_empty_evidence() {
        let roles = ["api-auth", "business-logic", "verifier", "recon"];
        for role in roles {
            let pv = crate::agents::latest_prompt_template(role);
            assert!(
                pv.bad_example.contains("null")
                    || pv.bad_example.contains("\"null\"")
                    || pv.bad_example.contains("no endpoint"),
                "{role}: bad example must have null endpoint or vague description",
            );
        }
    }
}
