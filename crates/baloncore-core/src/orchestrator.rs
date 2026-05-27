use serde::{Deserialize, Serialize};

use crate::agent::{
    bridge_hypotheses_to_validators, challenge_hypotheses, run_fixture_agent,
    run_fixture_agent_pipeline, validate_agent_output, AgentInput, AgentRun, ModelConfig,
    ValidatorBridge,
};
use crate::research_engine::{run_research_engine, ResearchEngineReport};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutonomousBudget {
    pub max_steps: usize,
    pub max_active_requests: usize,
    pub max_depth: usize,
    pub allowed_noise_mode: String,
    pub allowed_tools: Vec<String>,
}

impl Default for AutonomousBudget {
    fn default() -> Self {
        Self {
            max_steps: 8,
            max_active_requests: 100,
            max_depth: 3,
            allowed_noise_mode: "moderate".to_string(),
            allowed_tools: vec![
                "agent".to_string(),
                "research-graph".to_string(),
                "hypothesis-forge".to_string(),
                "false-positive-killer".to_string(),
                "validator-bridge".to_string(),
                "scan-openapi-bola".to_string(),
                "authorization-matrix-validator".to_string(),
                "anonymous-exposure-validator".to_string(),
                "repo-exposure-validator".to_string(),
                "reporter".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AutonomousStepStatus {
    Planned,
    Completed,
    Blocked,
    Abandoned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCallRequest {
    pub tool: String,
    pub purpose: String,
    pub target: String,
    pub estimated_requests: usize,
    pub noise_mode: String,
    pub requires_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCallResult {
    pub status: String,
    pub summary: String,
    pub artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalGate {
    pub gate_id: String,
    pub required: bool,
    pub approved: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutonomousStep {
    pub id: String,
    pub role: String,
    pub action: String,
    pub status: AutonomousStepStatus,
    pub abandon_reason: Option<String>,
    pub tool_request: Option<ToolCallRequest>,
    pub tool_result: Option<ToolCallResult>,
    pub approval_gate: Option<ApprovalGate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AgentMemory {
    pub recon_nodes: usize,
    pub research_hypotheses: usize,
    pub proof_plans: usize,
    pub false_positive_challenges: usize,
    pub hypotheses_seen: usize,
    pub hypotheses_ready_for_validation: usize,
    pub validator_bridges: usize,
    pub verified_findings: usize,
    pub abandoned_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutonomousRun {
    pub run_id: String,
    pub scope_summary: String,
    pub budget: AutonomousBudget,
    pub steps: Vec<AutonomousStep>,
    pub agent_runs: Vec<AgentRun>,
    pub validator_bridges: Vec<ValidatorBridge>,
    pub research_engine: ResearchEngineReport,
    pub memory: AgentMemory,
    pub passed_safety: bool,
    pub summary: String,
}

pub fn run_autonomous_fixture(
    input: &AgentInput,
    budget: AutonomousBudget,
    model: &ModelConfig,
) -> AutonomousRun {
    let run_id = input.run_id.clone();
    let mut steps = Vec::new();
    let mut agent_runs = Vec::new();
    let mut bridges = Vec::new();
    let mut memory = AgentMemory::default();
    let mut passed_safety = true;

    let recon_input = AgentInput {
        role: "recon".to_string(),
        ..input.clone()
    };
    let recon_output = run_fixture_agent(&recon_input, model);
    let recon_validation = validate_agent_output("recon", &recon_output);
    agent_runs.push(AgentRun {
        run_id: format!("{}-recon", input.run_id),
        started_at: 0,
        finished_at: 0,
        input: recon_input,
        output: recon_output,
        validation: recon_validation,
    });
    steps.push(AutonomousStep {
        id: "step-001-recon".to_string(),
        role: "recon".to_string(),
        action: "summarize attack surface and available evidence".to_string(),
        status: AutonomousStepStatus::Completed,
        abandon_reason: None,
        tool_request: None,
        tool_result: Some(ToolCallResult {
            status: "completed".to_string(),
            summary: "attack surface summarized from local artifacts".to_string(),
            artifact_refs: input.evidence_refs.clone(),
        }),
        approval_gate: None,
    });

    let research_engine = run_research_engine(input, &budget);
    memory.recon_nodes = research_engine.graph.nodes.len();
    memory.research_hypotheses = research_engine.hypotheses.len();
    memory.proof_plans = research_engine.proof_plans.len();
    memory.false_positive_challenges = research_engine.challenges.len();
    memory.hypotheses_seen += research_engine.hypotheses.len();
    let blocking_challenge_ids = research_engine
        .challenges
        .iter()
        .filter(|challenge| challenge.blocking)
        .map(|challenge| challenge.hypothesis_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let research_ready = research_engine
        .hypotheses
        .iter()
        .filter(|hypothesis| !blocking_challenge_ids.contains(hypothesis.id.as_str()))
        .count();
    memory.hypotheses_ready_for_validation += research_ready;
    memory.validator_bridges += research_engine.proof_plans.len();
    steps.push(AutonomousStep {
        id: "step-002-research-graph".to_string(),
        role: "research-graph".to_string(),
        action: "build a multi-surface recon graph from scoped evidence".to_string(),
        status: AutonomousStepStatus::Completed,
        abandon_reason: None,
        tool_request: None,
        tool_result: Some(ToolCallResult {
            status: "completed".to_string(),
            summary: format!(
                "{} node(s), {} edge(s), {} coverage gap(s)",
                research_engine.graph.nodes.len(),
                research_engine.graph.edges.len(),
                research_engine.graph.coverage_gaps.len()
            ),
            artifact_refs: input.evidence_refs.clone(),
        }),
        approval_gate: None,
    });
    steps.push(AutonomousStep {
        id: "step-003-hypothesis-forge".to_string(),
        role: "hypothesis-forge".to_string(),
        action: "generate validator-bound vulnerability hypotheses across web, repo, cloud, and Web3 surfaces".to_string(),
        status: AutonomousStepStatus::Completed,
        abandon_reason: None,
        tool_request: None,
        tool_result: Some(ToolCallResult {
            status: "completed".to_string(),
            summary: format!(
                "{} hypothesis/hypotheses forged; {} ready after blocking challenges",
                research_engine.hypotheses.len(),
                research_ready
            ),
            artifact_refs: input.evidence_refs.clone(),
        }),
        approval_gate: None,
    });
    let planned_requests = research_engine
        .proof_plans
        .iter()
        .map(|plan| plan.active_requests_budget)
        .sum::<usize>();
    steps.push(AutonomousStep {
        id: "step-004-proof-plans".to_string(),
        role: "proof-executor".to_string(),
        action: "convert hypotheses into scoped deterministic proof plans".to_string(),
        status: AutonomousStepStatus::Completed,
        abandon_reason: None,
        tool_request: Some(ToolCallRequest {
            tool: "research-proof-planner".to_string(),
            purpose: "plan proof execution without promoting AI-only claims".to_string(),
            target: input.scope_summary.clone(),
            estimated_requests: planned_requests,
            noise_mode: budget.allowed_noise_mode.clone(),
            requires_approval: planned_requests > budget.max_active_requests,
        }),
        tool_result: Some(ToolCallResult {
            status: "planned".to_string(),
            summary: format!(
                "{} proof plan(s) generated inside active request budget {}",
                research_engine.proof_plans.len(),
                budget.max_active_requests
            ),
            artifact_refs: input.evidence_refs.clone(),
        }),
        approval_gate: None,
    });
    let blocking_challenges = research_engine
        .challenges
        .iter()
        .filter(|challenge| challenge.blocking)
        .count();
    steps.push(AutonomousStep {
        id: "step-005-false-positive-kill".to_string(),
        role: "verifier".to_string(),
        action: "block weak or unproven hypotheses before report promotion".to_string(),
        status: AutonomousStepStatus::Completed,
        abandon_reason: None,
        tool_request: None,
        tool_result: Some(ToolCallResult {
            status: "completed".to_string(),
            summary: format!(
                "{} challenge(s), {} blocking false-positive guard(s)",
                research_engine.challenges.len(),
                blocking_challenges
            ),
            artifact_refs: input.evidence_refs.clone(),
        }),
        approval_gate: None,
    });

    let api_input = AgentInput {
        role: "api-auth".to_string(),
        ..input.clone()
    };
    let pipeline = run_fixture_agent_pipeline(&api_input, model);
    memory.hypotheses_seen += pipeline.hypotheses_proposed;
    memory.hypotheses_ready_for_validation += pipeline.hypotheses_ready_for_validation;
    memory.validator_bridges += pipeline.bridges.len();
    bridges.extend(pipeline.bridges.clone());
    let challenges = challenge_hypotheses(&pipeline.output);
    let bridge_check = bridge_hypotheses_to_validators(&pipeline.output, &challenges);
    let ready = bridge_check
        .iter()
        .filter(|bridge| bridge.eligible_for_validation)
        .count();
    agent_runs.push(AgentRun {
        run_id: format!("{}-api-auth", input.run_id),
        started_at: 0,
        finished_at: 0,
        input: api_input,
        output: pipeline.output.clone(),
        validation: pipeline.validation.clone(),
    });
    steps.push(AutonomousStep {
        id: "step-006-api-auth".to_string(),
        role: "api-auth".to_string(),
        action: "propose authorization hypotheses and challenge false positives".to_string(),
        status: AutonomousStepStatus::Completed,
        abandon_reason: None,
        tool_request: None,
        tool_result: Some(ToolCallResult {
            status: "completed".to_string(),
            summary: format!("{ready} hypothesis/hypotheses ready for deterministic validation"),
            artifact_refs: input.evidence_refs.clone(),
        }),
        approval_gate: None,
    });

    let estimated_requests = ready.saturating_mul(3);
    let requires_approval = estimated_requests > budget.max_active_requests
        || budget.allowed_noise_mode == "loud"
        || !budget
            .allowed_tools
            .iter()
            .any(|tool| tool == "scan-openapi-bola");
    let gate = ApprovalGate {
        gate_id: "gate-active-validation".to_string(),
        required: requires_approval,
        approved: !requires_approval,
        reason: if requires_approval {
            "active validation exceeds budget, uses loud noise, or tool is not allowed".to_string()
        } else {
            "active validation is within configured budget".to_string()
        },
    };
    let validation_status = if gate.required && !gate.approved {
        passed_safety = false;
        memory
            .abandoned_paths
            .push("active validation blocked by approval gate".to_string());
        AutonomousStepStatus::Blocked
    } else {
        AutonomousStepStatus::Completed
    };
    steps.push(AutonomousStep {
        id: "step-007-validate".to_string(),
        role: "validator".to_string(),
        action: "map ready hypotheses to deterministic validators".to_string(),
        status: validation_status,
        abandon_reason: if gate.required && !gate.approved {
            Some("approval required before active validation".to_string())
        } else {
            None
        },
        tool_request: Some(ToolCallRequest {
            tool: "scan-openapi-bola".to_string(),
            purpose: "validate authorization hypotheses with owner/tested/anonymous matrix"
                .to_string(),
            target: input.scope_summary.clone(),
            estimated_requests,
            noise_mode: budget.allowed_noise_mode.clone(),
            requires_approval,
        }),
        tool_result: (!requires_approval).then(|| ToolCallResult {
            status: "ready".to_string(),
            summary: "deterministic validators selected; agents did not mark findings verified"
                .to_string(),
            artifact_refs: input.evidence_refs.clone(),
        }),
        approval_gate: Some(gate),
    });

    if steps.len() < budget.max_steps {
        let reporter_input = AgentInput {
            role: "reporter".to_string(),
            ..input.clone()
        };
        let reporter_output = run_fixture_agent(&reporter_input, model);
        let reporter_validation = validate_agent_output("reporter", &reporter_output);
        agent_runs.push(AgentRun {
            run_id: format!("{}-reporter", input.run_id),
            started_at: 0,
            finished_at: 0,
            input: reporter_input,
            output: reporter_output,
            validation: reporter_validation,
        });
        steps.push(AutonomousStep {
            id: "step-008-report".to_string(),
            role: "reporter".to_string(),
            action: "summarize validated evidence and remaining hypotheses".to_string(),
            status: AutonomousStepStatus::Completed,
            abandon_reason: None,
            tool_request: None,
            tool_result: Some(ToolCallResult {
                status: "completed".to_string(),
                summary: "reporter output generated from evidence-backed inputs".to_string(),
                artifact_refs: input.evidence_refs.clone(),
            }),
            approval_gate: None,
        });
    }

    if steps.len() > budget.max_steps {
        steps.truncate(budget.max_steps);
        passed_safety = false;
        memory
            .abandoned_paths
            .push("plan truncated by max_steps budget".to_string());
    }

    let summary = format!(
        "Autonomous run planned {} step(s), mapped {} recon node(s), generated {} hypothesis/hypotheses, bridged {} validator/proof candidate(s), safety passed: {}.",
        steps.len(),
        memory.recon_nodes,
        memory.hypotheses_seen,
        memory.validator_bridges,
        passed_safety
    );

    AutonomousRun {
        run_id,
        scope_summary: input.scope_summary.clone(),
        budget,
        steps,
        agent_runs,
        validator_bridges: bridges,
        research_engine,
        memory,
        passed_safety,
        summary,
    }
}

pub fn render_autonomous_run_report(run: &AutonomousRun) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Autonomous Run Report\n\n");
    md.push_str(&format!("{}\n\n", run.summary));
    md.push_str("## Budget\n\n");
    md.push_str(&format!(
        "- Max steps: `{}`\n- Max active requests: `{}`\n- Max depth: `{}`\n- Noise mode: `{}`\n- Allowed tools: `{}`\n\n",
        run.budget.max_steps,
        run.budget.max_active_requests,
        run.budget.max_depth,
        run.budget.allowed_noise_mode,
        run.budget.allowed_tools.join(", ")
    ));
    md.push_str("## Steps\n\n");
    for step in &run.steps {
        md.push_str(&format!(
            "### {} - {:?}\n\n- Role: `{}`\n- Action: {}\n",
            step.id, step.status, step.role, step.action
        ));
        if let Some(gate) = &step.approval_gate {
            md.push_str(&format!(
                "- Approval required: `{}`\n- Approved: `{}`\n- Reason: {}\n",
                gate.required, gate.approved, gate.reason
            ));
        }
        if let Some(request) = &step.tool_request {
            md.push_str(&format!(
                "- Tool: `{}`\n- Estimated requests: `{}`\n",
                request.tool, request.estimated_requests
            ));
        }
        if let Some(reason) = &step.abandon_reason {
            md.push_str(&format!("- Abandon reason: {}\n", reason));
        }
        md.push('\n');
    }
    md.push_str("## Validator Bridge\n\n");
    if run.validator_bridges.is_empty() {
        md.push_str("No validator bridge candidates were produced.\n");
    } else {
        for bridge in &run.validator_bridges {
            md.push_str(&format!(
                "- `{}` -> `{}` eligible=`{}`: {}\n",
                bridge.hypothesis_id,
                bridge.validator,
                bridge.eligible_for_validation,
                bridge.reason
            ));
        }
    }
    md.push_str("\n## Autonomous Research Engine\n\n");
    md.push_str(&format!(
        "- Readiness score: `{}`\n- Recon nodes: `{}`\n- Hypotheses: `{}`\n- Proof plans: `{}`\n- False-positive challenges: `{}`\n\n",
        run.research_engine.readiness_score,
        run.research_engine.graph.nodes.len(),
        run.research_engine.hypotheses.len(),
        run.research_engine.proof_plans.len(),
        run.research_engine.challenges.len()
    ));
    for hypothesis in run.research_engine.hypotheses.iter().take(8) {
        md.push_str(&format!(
            "- `{}` `{}` target=`{}` validator=`{}` confidence=`{}`\n",
            hypothesis.id,
            hypothesis.class,
            hypothesis.target,
            hypothesis.expected_validator,
            hypothesis.confidence
        ));
    }
    if !run.research_engine.next_actions.is_empty() {
        md.push_str("\n### Research Next Actions\n\n");
        for action in &run.research_engine.next_actions {
            md.push_str(&format!("- {action}\n"));
        }
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn input() -> AgentInput {
        AgentInput {
            role: "autonomous".to_string(),
            run_id: "auto-1".to_string(),
            scope_summary: "local lab".to_string(),
            endpoints: vec!["GET /api/invoices/{id}".to_string()],
            findings: vec![],
            evidence_refs: vec!["openapi_inventory.json".to_string()],
            context: BTreeMap::new(),
        }
    }

    #[test]
    fn autonomous_fixture_bridges_hypotheses_to_validators() {
        let run = run_autonomous_fixture(
            &input(),
            AutonomousBudget::default(),
            &ModelConfig::default(),
        );
        assert!(run.passed_safety);
        assert!(run.memory.hypotheses_seen > 0);
        assert!(run
            .validator_bridges
            .iter()
            .any(|bridge| bridge.validator == "bola-validator"));
        assert!(run
            .research_engine
            .hypotheses
            .iter()
            .any(|hypothesis| { hypothesis.class == "BrokenObjectLevelAuthorization" }));
        assert!(run.steps.iter().any(|step| step.role == "validator"));
    }

    #[test]
    fn autonomous_fixture_blocks_over_budget_validation() {
        let budget = AutonomousBudget {
            max_active_requests: 1,
            ..AutonomousBudget::default()
        };
        let run = run_autonomous_fixture(&input(), budget, &ModelConfig::default());
        assert!(!run.passed_safety);
        assert!(run
            .steps
            .iter()
            .any(|step| step.status == AutonomousStepStatus::Blocked));
        assert!(!run.memory.abandoned_paths.is_empty());
    }

    #[test]
    fn autonomous_report_lists_steps_and_bridge() {
        let run = run_autonomous_fixture(
            &input(),
            AutonomousBudget::default(),
            &ModelConfig::default(),
        );
        let report = render_autonomous_run_report(&run);
        assert!(report.contains("Autonomous Run Report"));
        assert!(report.contains("Validator Bridge"));
        assert!(report.contains("Autonomous Research Engine"));
    }
}
