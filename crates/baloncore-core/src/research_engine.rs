use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{agent::AgentInput, orchestrator::AutonomousBudget};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResearchSurfaceKind {
    WebApi,
    WebApp,
    CloudIam,
    Web3,
    Repository,
    CiCd,
    Finding,
    Evidence,
    Unknown,
}

impl ResearchSurfaceKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::WebApi => "web_api",
            Self::WebApp => "web_app",
            Self::CloudIam => "cloud_iam",
            Self::Web3 => "web3",
            Self::Repository => "repository",
            Self::CiCd => "ci_cd",
            Self::Finding => "finding",
            Self::Evidence => "evidence",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconNode {
    pub id: String,
    pub kind: ResearchSurfaceKind,
    pub label: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub risk_tags: Vec<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
    #[serde(default)]
    pub evidence_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconGraph {
    pub nodes: Vec<ReconNode>,
    pub edges: Vec<ReconEdge>,
    #[serde(default)]
    pub coverage_gaps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResearchHypothesis {
    pub id: String,
    pub surface: ResearchSurfaceKind,
    pub class: String,
    pub title: String,
    pub target: String,
    pub why: String,
    #[serde(default)]
    pub preconditions: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub confidence: u8,
    pub expected_validator: String,
    pub safety_boundary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofExecutionPlan {
    pub id: String,
    pub hypothesis_id: String,
    pub validator: String,
    pub mode: String,
    pub active_requests_budget: usize,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub required_artifacts: Vec<String>,
    #[serde(default)]
    pub safety_gates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FalsePositiveChallenge {
    pub hypothesis_id: String,
    pub challenge_type: String,
    pub blocking: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResearchFindingMemoryRecord {
    pub fingerprint: String,
    pub class: String,
    pub surface: ResearchSurfaceKind,
    pub first_seen: String,
    pub last_seen: String,
    pub seen_count: u64,
    pub outcome: String,
    pub defense: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResearchEngineReport {
    pub run_id: String,
    pub graph: ReconGraph,
    pub hypotheses: Vec<ResearchHypothesis>,
    pub proof_plans: Vec<ProofExecutionPlan>,
    pub challenges: Vec<FalsePositiveChallenge>,
    pub memory_records: Vec<ResearchFindingMemoryRecord>,
    pub readiness_score: u8,
    #[serde(default)]
    pub next_actions: Vec<String>,
}

pub fn run_research_engine(input: &AgentInput, budget: &AutonomousBudget) -> ResearchEngineReport {
    let graph = build_research_graph(input);
    let hypotheses = forge_research_hypotheses(&graph, input);
    let proof_plans = build_proof_plans(&hypotheses, budget);
    let challenges = challenge_research_hypotheses(&hypotheses, &proof_plans);
    let memory_records = build_research_memory(&hypotheses, &challenges, &input.run_id);
    let readiness_score =
        research_readiness_score(&graph, &hypotheses, &proof_plans, &challenges, input);
    let next_actions = next_actions(&graph, &hypotheses, &proof_plans, &challenges);

    ResearchEngineReport {
        run_id: input.run_id.clone(),
        graph,
        hypotheses,
        proof_plans,
        challenges,
        memory_records,
        readiness_score,
        next_actions,
    }
}

pub fn build_research_graph(input: &AgentInput) -> ReconGraph {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut seen = BTreeSet::new();

    push_node(
        &mut nodes,
        &mut seen,
        ReconNode {
            id: "scope".to_string(),
            kind: ResearchSurfaceKind::Unknown,
            label: if input.scope_summary.trim().is_empty() {
                "authorized scope".to_string()
            } else {
                input.scope_summary.clone()
            },
            evidence_refs: input.evidence_refs.iter().take(8).cloned().collect(),
            risk_tags: vec!["scope_boundary".to_string()],
            confidence: 80,
        },
    );

    for (index, endpoint) in input.endpoints.iter().take(120).enumerate() {
        let tags = endpoint_risk_tags(endpoint);
        let kind = endpoint_surface(endpoint);
        let id = format!("endpoint-{index:03}");
        push_node(
            &mut nodes,
            &mut seen,
            ReconNode {
                id: id.clone(),
                kind,
                label: endpoint.clone(),
                evidence_refs: input.evidence_refs.iter().take(6).cloned().collect(),
                risk_tags: tags,
                confidence: 86,
            },
        );
        edges.push(ReconEdge {
            from: "scope".to_string(),
            to: id,
            relation: "exposes_endpoint".to_string(),
            evidence_ref: input.evidence_refs.first().cloned(),
        });
    }

    for (index, finding) in input.findings.iter().take(60).enumerate() {
        let id = format!("finding-{index:03}");
        push_node(
            &mut nodes,
            &mut seen,
            ReconNode {
                id: id.clone(),
                kind: ResearchSurfaceKind::Finding,
                label: format!(
                    "{} {} {}",
                    finding.severity, finding.classification, finding.endpoint
                ),
                evidence_refs: finding.evidence_refs.clone(),
                risk_tags: vec![
                    normalize_token(&finding.classification),
                    normalize_token(&finding.severity),
                    normalize_token(&finding.state),
                ],
                confidence: if finding.state.to_ascii_lowercase().contains("verified") {
                    95
                } else {
                    72
                },
            },
        );
        if let Some(endpoint_index) = input
            .endpoints
            .iter()
            .position(|endpoint| endpoint == &finding.endpoint)
        {
            edges.push(ReconEdge {
                from: format!("endpoint-{endpoint_index:03}"),
                to: id,
                relation: "has_finding_signal".to_string(),
                evidence_ref: finding.evidence_refs.first().cloned(),
            });
        } else {
            edges.push(ReconEdge {
                from: "scope".to_string(),
                to: id,
                relation: "has_finding_signal".to_string(),
                evidence_ref: finding.evidence_refs.first().cloned(),
            });
        }
    }

    for (index, reference) in input.evidence_refs.iter().take(80).enumerate() {
        let id = format!("evidence-{index:03}");
        let kind = evidence_surface(reference);
        push_node(
            &mut nodes,
            &mut seen,
            ReconNode {
                id: id.clone(),
                kind,
                label: reference.clone(),
                evidence_refs: vec![reference.clone()],
                risk_tags: evidence_tags(reference),
                confidence: 90,
            },
        );
        edges.push(ReconEdge {
            from: id,
            to: "scope".to_string(),
            relation: "supports_scope_reasoning".to_string(),
            evidence_ref: Some(reference.clone()),
        });
    }

    for key in input.context.keys().take(40) {
        let id = format!("context-{}", normalize_token(key));
        push_node(
            &mut nodes,
            &mut seen,
            ReconNode {
                id: id.clone(),
                kind: ResearchSurfaceKind::Unknown,
                label: key.clone(),
                evidence_refs: input.evidence_refs.iter().take(3).cloned().collect(),
                risk_tags: vec!["context".to_string()],
                confidence: 65,
            },
        );
        edges.push(ReconEdge {
            from: "scope".to_string(),
            to: id,
            relation: "has_context".to_string(),
            evidence_ref: None,
        });
    }

    let mut coverage_gaps = Vec::new();
    if input.endpoints.is_empty() {
        coverage_gaps.push(
            "No endpoints were indexed; add OpenAPI, route inventory, or crawler evidence."
                .to_string(),
        );
    }
    if input.evidence_refs.is_empty() {
        coverage_gaps.push(
            "No evidence references were supplied; hypotheses cannot be promoted.".to_string(),
        );
    }
    if !nodes
        .iter()
        .any(|node| node.kind == ResearchSurfaceKind::Web3)
    {
        coverage_gaps.push("No Web3 proof surface indexed yet.".to_string());
    }
    if !nodes
        .iter()
        .any(|node| node.kind == ResearchSurfaceKind::CloudIam)
    {
        coverage_gaps.push("No Cloud/IAM proof surface indexed yet.".to_string());
    }
    if !nodes.iter().any(|node| {
        node.risk_tags
            .iter()
            .any(|tag| tag == "state_changing" || tag == "workflow")
    }) {
        coverage_gaps.push("No state-changing workflow candidates were indexed.".to_string());
    }

    ReconGraph {
        nodes,
        edges,
        coverage_gaps,
    }
}

pub fn forge_research_hypotheses(
    graph: &ReconGraph,
    input: &AgentInput,
) -> Vec<ResearchHypothesis> {
    let mut hypotheses = Vec::new();
    let mut seen = BTreeSet::new();

    for node in graph.nodes.iter().filter(|node| {
        matches!(
            node.kind,
            ResearchSurfaceKind::WebApi | ResearchSurfaceKind::WebApp
        )
    }) {
        let lower = node.label.to_ascii_lowercase();
        if looks_object_scoped(&lower) {
            push_hypothesis(
                &mut hypotheses,
                &mut seen,
                hypothesis(
                    ResearchSurfaceKind::WebApi,
                    "BrokenObjectLevelAuthorization",
                    "Object endpoint may leak another tenant or user's record",
                    &node.label,
                    "Object-shaped routes require owner, non-owner, admin, and anonymous matrix proof.",
                    vec![
                        "at least two auth profiles or a seeded owner/non-owner fixture".to_string(),
                        "baseline owner response evidence".to_string(),
                    ],
                    node.evidence_refs.clone(),
                    84,
                    "scan-openapi-bola",
                    "authorized scope, quiet request budget, no destructive payloads",
                ),
            );
        }
        if lower.contains("/admin")
            || lower.contains(" admin")
            || lower.contains("/internal")
            || lower.contains("/manage")
        {
            push_hypothesis(
                &mut hypotheses,
                &mut seen,
                hypothesis(
                    ResearchSurfaceKind::WebApi,
                    "BrokenFunctionLevelAuthorization",
                    "Privileged function may be reachable by a weaker profile",
                    &node.label,
                    "Privileged routes need user/admin/anonymous comparison and intended-access proof.",
                    vec![
                        "admin and non-admin profiles".to_string(),
                        "explicit intended privileged-access model".to_string(),
                    ],
                    node.evidence_refs.clone(),
                    82,
                    "authorization-matrix-validator",
                    "authorized scope, profile matrix only, no unsafe state mutation",
                ),
            );
        }
        if lower.contains("graphql") {
            push_hypothesis(
                &mut hypotheses,
                &mut seen,
                hypothesis(
                    ResearchSurfaceKind::WebApi,
                    "GraphQLFieldAuthorization",
                    "GraphQL field or introspection boundary may expose unauthorized data",
                    &node.label,
                    "GraphQL surfaces often hide object authorization failures below a single endpoint.",
                    vec![
                        "schema or operation inventory".to_string(),
                        "owner/non-owner variables for object fields".to_string(),
                    ],
                    node.evidence_refs.clone(),
                    76,
                    "graphql-auth-validator",
                    "schema-safe introspection only when authorized; no brute force",
                ),
            );
        }
        if lower.starts_with("post ")
            || lower.starts_with("patch ")
            || lower.starts_with("put ")
            || lower.starts_with("delete ")
        {
            push_hypothesis(
                &mut hypotheses,
                &mut seen,
                hypothesis(
                    ResearchSurfaceKind::WebApp,
                    "BusinessLogicWorkflowBypass",
                    "State-changing workflow may miss prerequisite or ownership checks",
                    &node.label,
                    "State-changing routes create cross-step invariants that scanners usually miss.",
                    vec![
                        "safe replay fixture or dry-run environment".to_string(),
                        "pre/post-state observation without destructive effects".to_string(),
                    ],
                    node.evidence_refs.clone(),
                    70,
                    "workflow-invariant-validator",
                    "non-production or fixture-only active checks; destructive payloads blocked",
                ),
            );
        }
        if lower.contains("upload") || lower.contains("import") || lower.contains("file") {
            push_hypothesis(
                &mut hypotheses,
                &mut seen,
                hypothesis(
                    ResearchSurfaceKind::WebApp,
                    "UnsafeFileUploadOrParserBoundary",
                    "Upload or import boundary may accept dangerous content or trust metadata",
                    &node.label,
                    "Parser and upload boundaries deserve content-type, extension, storage, and access proof.",
                    vec![
                        "benign fixture files only".to_string(),
                        "storage/access artifact capture".to_string(),
                    ],
                    node.evidence_refs.clone(),
                    68,
                    "parser-boundary-validator",
                    "benign files only; no malware payloads; no external callbacks",
                ),
            );
        }
        if lower.contains("webhook") || lower.contains("callback") {
            push_hypothesis(
                &mut hypotheses,
                &mut seen,
                hypothesis(
                    ResearchSurfaceKind::WebApi,
                    "WebhookSignatureReplay",
                    "Webhook or callback may lack signature, timestamp, or replay validation",
                    &node.label,
                    "Webhook bugs often become payment, account, and integration compromise chains.",
                    vec![
                        "documented signing scheme or test secret".to_string(),
                        "replay-safe local event fixture".to_string(),
                    ],
                    node.evidence_refs.clone(),
                    72,
                    "webhook-replay-validator",
                    "authorized fixture events only; no third-party delivery attempts",
                ),
            );
        }
        if lower.contains("url")
            || lower.contains("fetch")
            || lower.contains("redirect")
            || lower.contains("proxy")
        {
            push_hypothesis(
                &mut hypotheses,
                &mut seen,
                hypothesis(
                    ResearchSurfaceKind::WebApi,
                    "SafeEgressBoundary",
                    "URL-handling endpoint may allow unsafe egress, redirect, or metadata access",
                    &node.label,
                    "Egress and redirect paths need proof against strictly local/synthetic endpoints.",
                    vec![
                        "local-only callback fixture".to_string(),
                        "egress denylist/allowlist evidence".to_string(),
                    ],
                    node.evidence_refs.clone(),
                    66,
                    "safe-egress-validator",
                    "local callback targets only; metadata and third-party targets blocked",
                ),
            );
        }
        if lower.contains("reset") || lower.contains("token") || lower.contains("invite") {
            push_hypothesis(
                &mut hypotheses,
                &mut seen,
                hypothesis(
                    ResearchSurfaceKind::WebApp,
                    "AccountWorkflowAbuse",
                    "Account workflow may allow token reuse, weak expiry, or cross-profile action",
                    &node.label,
                    "Identity workflows need sequence-aware proof, not only endpoint status checks.",
                    vec![
                        "fixture account profiles".to_string(),
                        "token lifecycle evidence without real secrets".to_string(),
                    ],
                    node.evidence_refs.clone(),
                    69,
                    "identity-workflow-validator",
                    "fixture accounts only; no credential guessing; no account takeover attempts",
                ),
            );
        }
    }

    for node in &graph.nodes {
        match node.kind {
            ResearchSurfaceKind::Web3 => push_hypothesis(
                &mut hypotheses,
                &mut seen,
                hypothesis(
                    ResearchSurfaceKind::Web3,
                    "Web3AccessControlInvariant",
                    "Protocol privilege or accounting invariant needs deterministic proof",
                    &node.label,
                    "Solidity and protocol artifacts should become invariant tests before claims.",
                    vec![
                        "local test chain or fork fixture".to_string(),
                        "generated invariant or proof test artifact".to_string(),
                    ],
                    node.evidence_refs.clone(),
                    74,
                    "web3-invariant-validator",
                    "local deterministic chain only; no mainnet transaction broadcast",
                ),
            ),
            ResearchSurfaceKind::CloudIam => push_hypothesis(
                &mut hypotheses,
                &mut seen,
                hypothesis(
                    ResearchSurfaceKind::CloudIam,
                    "CloudIamPrivilegePath",
                    "Cloud principal may reach sensitive resource through policy or trust chain",
                    &node.label,
                    "IAM graphs uncover privilege chains humans miss when policies are reviewed one by one.",
                    vec![
                        "offline policy/config snapshot".to_string(),
                        "principal, action, and resource evidence".to_string(),
                    ],
                    node.evidence_refs.clone(),
                    75,
                    "cloud-iam-graph-validator",
                    "offline graph analysis only unless explicit cloud connector scope exists",
                ),
            ),
            ResearchSurfaceKind::CiCd => push_hypothesis(
                &mut hypotheses,
                &mut seen,
                hypothesis(
                    ResearchSurfaceKind::CiCd,
                    "CiTrustBoundary",
                    "CI workflow may expose privileged token, untrusted input, or deployment path",
                    &node.label,
                    "CI/CD is where repository findings become cloud or production compromise paths.",
                    vec![
                        "workflow file evidence".to_string(),
                        "token permission model or branch protection context".to_string(),
                    ],
                    node.evidence_refs.clone(),
                    71,
                    "ci-evidence-gate",
                    "offline workflow analysis; no external pipeline mutation",
                ),
            ),
            ResearchSurfaceKind::Repository => push_hypothesis(
                &mut hypotheses,
                &mut seen,
                hypothesis(
                    ResearchSurfaceKind::Repository,
                    "RepositoryExposure",
                    "Repository evidence may reveal secret, dependency, IaC, or framework risk",
                    &node.label,
                    "Repo signals need redacted evidence, owner review, and CI prevention gates.",
                    vec![
                        "local repository authorization".to_string(),
                        "redacted evidence capture".to_string(),
                    ],
                    node.evidence_refs.clone(),
                    70,
                    "repo-exposure-validator",
                    "local files only; redaction required before export",
                ),
            ),
            _ => {}
        }
    }

    for finding in &input.findings {
        if finding.state.to_ascii_lowercase().contains("verified") {
            push_hypothesis(
                &mut hypotheses,
                &mut seen,
                ResearchHypothesis {
                    id: String::new(),
                    surface: ResearchSurfaceKind::Finding,
                    class: "RegressionReplay".to_string(),
                    title: format!("Verified {} should be locked into regression", finding.classification),
                    target: finding.endpoint.clone(),
                    why: "A verified finding is not done until a patched app can prove the behavior is gone.".to_string(),
                    preconditions: vec![
                        "reproduction artifact".to_string(),
                        "patched target or branch".to_string(),
                        "CI policy threshold".to_string(),
                    ],
                    evidence_refs: finding.evidence_refs.clone(),
                    confidence: 92,
                    expected_validator: "run-regression".to_string(),
                    safety_boundary: "replay only the captured authorized proof case".to_string(),
                },
            );
        }
    }

    for (index, hypothesis) in hypotheses.iter_mut().enumerate() {
        hypothesis.id = format!("research-hypothesis-{index:03}");
    }
    hypotheses
}

pub fn build_proof_plans(
    hypotheses: &[ResearchHypothesis],
    budget: &AutonomousBudget,
) -> Vec<ProofExecutionPlan> {
    let mut plans = Vec::new();
    let mut remaining_requests = budget.max_active_requests;
    for (index, hypothesis) in hypotheses.iter().enumerate().take(budget.max_steps * 8) {
        let mut active_budget = active_budget_for(hypothesis);
        if active_budget > remaining_requests {
            active_budget = 0;
        } else {
            remaining_requests = remaining_requests.saturating_sub(active_budget);
        }
        let allowed = budget
            .allowed_tools
            .iter()
            .any(|tool| tool == &hypothesis.expected_validator)
            || planned_validator(&hypothesis.expected_validator);
        let mode = if active_budget == 0
            && matches!(
                hypothesis.surface,
                ResearchSurfaceKind::WebApi | ResearchSurfaceKind::WebApp
            ) {
            "blocked_by_request_budget"
        } else if !allowed {
            "validator_not_allowed"
        } else if active_budget == 0 {
            "offline_deterministic_analysis"
        } else {
            "scoped_active_validation"
        };
        plans.push(ProofExecutionPlan {
            id: format!("proof-plan-{index:03}"),
            hypothesis_id: hypothesis.id.clone(),
            validator: hypothesis.expected_validator.clone(),
            mode: mode.to_string(),
            active_requests_budget: active_budget,
            commands: proof_commands(hypothesis),
            required_artifacts: required_artifacts(hypothesis),
            safety_gates: safety_gates(hypothesis),
        });
    }
    plans
}

pub fn challenge_research_hypotheses(
    hypotheses: &[ResearchHypothesis],
    proof_plans: &[ProofExecutionPlan],
) -> Vec<FalsePositiveChallenge> {
    let plans_by_hypothesis = proof_plans
        .iter()
        .map(|plan| (plan.hypothesis_id.as_str(), plan))
        .collect::<BTreeMap<_, _>>();
    let mut challenges = Vec::new();
    for hypothesis in hypotheses {
        if hypothesis.evidence_refs.is_empty() {
            challenges.push(FalsePositiveChallenge {
                hypothesis_id: hypothesis.id.clone(),
                challenge_type: "missing_evidence".to_string(),
                blocking: true,
                reason: "candidate has no evidence reference and cannot be promoted".to_string(),
            });
        }
        if hypothesis.confidence < 70 {
            challenges.push(FalsePositiveChallenge {
                hypothesis_id: hypothesis.id.clone(),
                challenge_type: "low_confidence".to_string(),
                blocking: false,
                reason: "candidate should be queued after higher-confidence proof work".to_string(),
            });
        }
        if !registered_validator(&hypothesis.expected_validator) {
            challenges.push(FalsePositiveChallenge {
                hypothesis_id: hypothesis.id.clone(),
                challenge_type: "validator_gap".to_string(),
                blocking: true,
                reason: format!(
                    "deterministic validator `{}` is planned but not promoted to verified-report authority",
                    hypothesis.expected_validator
                ),
            });
        }
        if let Some(plan) = plans_by_hypothesis.get(hypothesis.id.as_str()) {
            if plan.mode == "blocked_by_request_budget" || plan.mode == "validator_not_allowed" {
                challenges.push(FalsePositiveChallenge {
                    hypothesis_id: hypothesis.id.clone(),
                    challenge_type: plan.mode.clone(),
                    blocking: true,
                    reason: "proof plan cannot execute inside the current autonomous budget"
                        .to_string(),
                });
            }
        } else {
            challenges.push(FalsePositiveChallenge {
                hypothesis_id: hypothesis.id.clone(),
                challenge_type: "missing_proof_plan".to_string(),
                blocking: true,
                reason: "candidate has no proof execution plan".to_string(),
            });
        }
        if hypothesis.class == "BrokenObjectLevelAuthorization" {
            challenges.push(FalsePositiveChallenge {
                hypothesis_id: hypothesis.id.clone(),
                challenge_type: "owner_baseline_required".to_string(),
                blocking: false,
                reason: "must compare owner baseline, non-owner profile, anonymous profile, and intended admin access".to_string(),
            });
        }
        if hypothesis.class == "BrokenFunctionLevelAuthorization" {
            challenges.push(FalsePositiveChallenge {
                hypothesis_id: hypothesis.id.clone(),
                challenge_type: "intended_privilege_model_required".to_string(),
                blocking: false,
                reason: "admin success is not a vulnerability unless weaker profiles also reach the function".to_string(),
            });
        }
        if hypothesis.surface == ResearchSurfaceKind::Web3 {
            challenges.push(FalsePositiveChallenge {
                hypothesis_id: hypothesis.id.clone(),
                challenge_type: "proof_test_required".to_string(),
                blocking: false,
                reason:
                    "protocol risk needs deterministic local invariant/fuzz proof before promotion"
                        .to_string(),
            });
        }
        if hypothesis.surface == ResearchSurfaceKind::CloudIam {
            challenges.push(FalsePositiveChallenge {
                hypothesis_id: hypothesis.id.clone(),
                challenge_type: "principal_resource_edge_required".to_string(),
                blocking: false,
                reason: "IAM risk must include principal, action, resource, and policy-source edge"
                    .to_string(),
            });
        }
    }
    challenges
}

pub fn build_research_memory(
    hypotheses: &[ResearchHypothesis],
    challenges: &[FalsePositiveChallenge],
    run_id: &str,
) -> Vec<ResearchFindingMemoryRecord> {
    hypotheses
        .iter()
        .map(|hypothesis| {
            let blocked = challenges
                .iter()
                .any(|challenge| challenge.hypothesis_id == hypothesis.id && challenge.blocking);
            let outcome = if blocked {
                "candidate_blocked_until_proven"
            } else if registered_validator(&hypothesis.expected_validator) {
                "ready_for_deterministic_validation"
            } else {
                "needs_validator_implementation"
            };
            ResearchFindingMemoryRecord {
                fingerprint: fingerprint(hypothesis),
                class: hypothesis.class.clone(),
                surface: hypothesis.surface.clone(),
                first_seen: run_id.to_string(),
                last_seen: run_id.to_string(),
                seen_count: 1,
                outcome: outcome.to_string(),
                defense: defense_for(hypothesis),
            }
        })
        .collect()
}

pub fn render_research_engine_report(report: &ResearchEngineReport) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Autonomous Research Engine\n\n");
    md.push_str(&format!(
        "- Readiness score: `{}`\n- Recon nodes: `{}`\n- Recon edges: `{}`\n- Hypotheses: `{}`\n- Proof plans: `{}`\n- False-positive challenges: `{}`\n\n",
        report.readiness_score,
        report.graph.nodes.len(),
        report.graph.edges.len(),
        report.hypotheses.len(),
        report.proof_plans.len(),
        report.challenges.len()
    ));
    if !report.graph.coverage_gaps.is_empty() {
        md.push_str("## Coverage Gaps\n\n");
        for gap in &report.graph.coverage_gaps {
            md.push_str(&format!("- {gap}\n"));
        }
        md.push('\n');
    }
    md.push_str("## Top Hypotheses\n\n");
    for hypothesis in report.hypotheses.iter().take(12) {
        md.push_str(&format!(
            "- `{}` `{}` on `{}` confidence=`{}` validator=`{}`\n",
            hypothesis.id,
            hypothesis.class,
            hypothesis.target,
            hypothesis.confidence,
            hypothesis.expected_validator
        ));
    }
    md.push_str("\n## Proof Plans\n\n");
    for plan in report.proof_plans.iter().take(12) {
        md.push_str(&format!(
            "- `{}` uses `{}` mode=`{}` requests=`{}`\n",
            plan.hypothesis_id, plan.validator, plan.mode, plan.active_requests_budget
        ));
    }
    md.push_str("\n## Next Actions\n\n");
    for action in &report.next_actions {
        md.push_str(&format!("- {action}\n"));
    }
    md
}

fn push_node(nodes: &mut Vec<ReconNode>, seen: &mut BTreeSet<String>, node: ReconNode) {
    if seen.insert(node.id.clone()) {
        nodes.push(node);
    }
}

fn push_hypothesis(
    hypotheses: &mut Vec<ResearchHypothesis>,
    seen: &mut BTreeSet<String>,
    hypothesis: ResearchHypothesis,
) {
    let key = format!(
        "{}:{}:{}",
        hypothesis.surface.as_str(),
        normalize_token(&hypothesis.class),
        normalize_token(&hypothesis.target)
    );
    if seen.insert(key) {
        hypotheses.push(hypothesis);
    }
}

fn hypothesis(
    surface: ResearchSurfaceKind,
    class: &str,
    title: &str,
    target: &str,
    why: &str,
    preconditions: Vec<String>,
    evidence_refs: Vec<String>,
    confidence: u8,
    expected_validator: &str,
    safety_boundary: &str,
) -> ResearchHypothesis {
    ResearchHypothesis {
        id: String::new(),
        surface,
        class: class.to_string(),
        title: title.to_string(),
        target: target.to_string(),
        why: why.to_string(),
        preconditions,
        evidence_refs: evidence_refs.into_iter().take(8).collect(),
        confidence,
        expected_validator: expected_validator.to_string(),
        safety_boundary: safety_boundary.to_string(),
    }
}

fn endpoint_surface(endpoint: &str) -> ResearchSurfaceKind {
    let lower = endpoint.to_ascii_lowercase();
    if lower.contains("graphql") || lower.contains("/api/") || lower.starts_with("get ") {
        ResearchSurfaceKind::WebApi
    } else {
        ResearchSurfaceKind::WebApp
    }
}

fn evidence_surface(reference: &str) -> ResearchSurfaceKind {
    let lower = reference.to_ascii_lowercase();
    if lower.contains("web3") || lower.ends_with(".sol") || lower.contains("foundry") {
        ResearchSurfaceKind::Web3
    } else if lower.contains("cloud")
        || lower.contains("iam")
        || lower.contains("terraform")
        || lower.contains("kubernetes")
        || lower.contains("cloudformation")
    {
        ResearchSurfaceKind::CloudIam
    } else if lower.contains("workflow") || lower.contains("github") || lower.contains("gitlab") {
        ResearchSurfaceKind::CiCd
    } else if lower.contains("repo") || lower.contains("package") || lower.contains("inventory") {
        ResearchSurfaceKind::Repository
    } else {
        ResearchSurfaceKind::Evidence
    }
}

fn endpoint_risk_tags(endpoint: &str) -> Vec<String> {
    let lower = endpoint.to_ascii_lowercase();
    let mut tags = Vec::new();
    if looks_object_scoped(&lower) {
        tags.push("object_scoped".to_string());
    }
    if lower.contains("/admin") || lower.contains("/internal") || lower.contains("/manage") {
        tags.push("privileged".to_string());
    }
    if lower.starts_with("post ")
        || lower.starts_with("patch ")
        || lower.starts_with("put ")
        || lower.starts_with("delete ")
    {
        tags.push("state_changing".to_string());
        tags.push("workflow".to_string());
    }
    if lower.contains("upload") || lower.contains("import") || lower.contains("file") {
        tags.push("parser_boundary".to_string());
    }
    if lower.contains("webhook") || lower.contains("callback") {
        tags.push("integration_boundary".to_string());
    }
    if lower.contains("url") || lower.contains("fetch") || lower.contains("redirect") {
        tags.push("egress_boundary".to_string());
    }
    if tags.is_empty() {
        tags.push("observable".to_string());
    }
    tags
}

fn evidence_tags(reference: &str) -> Vec<String> {
    let lower = reference.to_ascii_lowercase();
    let mut tags = Vec::new();
    for (needle, tag) in [
        ("matrix_summary", "auth_matrix"),
        ("evidence_manifest", "trusted_evidence"),
        ("proof_package", "proof_package"),
        ("web3", "web3"),
        ("repo_inventory", "repo_inventory"),
        ("cloud", "cloud"),
        ("iam", "iam"),
        ("workflow", "ci_cd"),
        ("secret", "secret_review"),
    ] {
        if lower.contains(needle) {
            tags.push(tag.to_string());
        }
    }
    if tags.is_empty() {
        tags.push("evidence".to_string());
    }
    tags
}

fn looks_object_scoped(value: &str) -> bool {
    value.contains("{id}")
        || value.contains(":id")
        || value.contains("/{")
        || value.contains("/id")
        || value.contains("_id")
        || value.contains("{address}")
        || value.contains("{account}")
}

fn active_budget_for(hypothesis: &ResearchHypothesis) -> usize {
    match hypothesis.class.as_str() {
        "BrokenObjectLevelAuthorization" => 8,
        "BrokenFunctionLevelAuthorization" => 6,
        "GraphQLFieldAuthorization" => 5,
        "BusinessLogicWorkflowBypass" => 4,
        "WebhookSignatureReplay" => 3,
        "SafeEgressBoundary" => 3,
        "UnsafeFileUploadOrParserBoundary" => 2,
        "AccountWorkflowAbuse" => 4,
        _ => 0,
    }
}

fn proof_commands(hypothesis: &ResearchHypothesis) -> Vec<String> {
    match hypothesis.expected_validator.as_str() {
        "scan-openapi-bola" => vec![
            "scan-openapi-bola --authorized --quiet --capture-evidence".to_string(),
            "run-regression --from-proof-package".to_string(),
        ],
        "authorization-matrix-validator" => {
            vec!["scan-openapi-bola --auth-matrix --include-admin --include-anonymous".to_string()]
        }
        "cloud-iam-graph-validator" => vec![
            "analyze-cloud-iam --offline-policy-snapshot".to_string(),
            "generate-least-privilege-guidance".to_string(),
        ],
        "web3-invariant-validator" => vec![
            "analyze-web3 --generate-invariants".to_string(),
            "run-local-proof-tests --no-broadcast".to_string(),
        ],
        "ci-evidence-gate" => vec!["scan-repo --ci-trust-boundary".to_string()],
        "run-regression" => vec!["run-regression --ci --fail-on-unfixed".to_string()],
        validator => vec![format!("{validator} --scoped --evidence-required")],
    }
}

fn required_artifacts(hypothesis: &ResearchHypothesis) -> Vec<String> {
    let mut artifacts = vec![
        "scope_contract.json".to_string(),
        "evidence_manifest.json".to_string(),
        "false_positive_challenge.json".to_string(),
    ];
    match hypothesis.surface {
        ResearchSurfaceKind::WebApi | ResearchSurfaceKind::WebApp => {
            artifacts.extend([
                "request_response_capture.json".to_string(),
                "auth_profile_matrix.json".to_string(),
                "remediation.md".to_string(),
            ]);
        }
        ResearchSurfaceKind::Web3 => {
            artifacts.extend([
                "web3_analysis.json".to_string(),
                "generated_invariant_test.sol".to_string(),
                "proof_manifest.json".to_string(),
            ]);
        }
        ResearchSurfaceKind::CloudIam => {
            artifacts.extend([
                "iam_graph.json".to_string(),
                "privilege_path.json".to_string(),
                "least_privilege_guidance.md".to_string(),
            ]);
        }
        ResearchSurfaceKind::Repository | ResearchSurfaceKind::CiCd => {
            artifacts.extend([
                "repo_inventory.json".to_string(),
                "redaction_review.json".to_string(),
                "ci_policy_gate.json".to_string(),
            ]);
        }
        _ => {}
    }
    artifacts
}

fn safety_gates(hypothesis: &ResearchHypothesis) -> Vec<String> {
    let mut gates = vec![
        "authorized_scope_required".to_string(),
        "request_budget_enforced".to_string(),
        "no_destructive_payloads".to_string(),
        "proof_before_report".to_string(),
        "false_positive_challenge_required".to_string(),
        "sensitive_evidence_redaction_required".to_string(),
    ];
    match hypothesis.surface {
        ResearchSurfaceKind::CloudIam => gates.push("offline_policy_snapshot_required".to_string()),
        ResearchSurfaceKind::Web3 => gates.push("no_transaction_broadcast".to_string()),
        ResearchSurfaceKind::Repository | ResearchSurfaceKind::CiCd => {
            gates.push("local_files_only".to_string())
        }
        _ => {}
    }
    gates
}

fn registered_validator(validator: &str) -> bool {
    matches!(
        validator,
        "scan-openapi-bola"
            | "authorization-matrix-validator"
            | "anonymous-exposure-validator"
            | "graphql-auth-validator"
            | "workflow-invariant-validator"
            | "run-regression"
            | "repo-exposure-validator"
    )
}

fn planned_validator(validator: &str) -> bool {
    registered_validator(validator)
        || matches!(
            validator,
            "graphql-auth-validator"
                | "workflow-invariant-validator"
                | "parser-boundary-validator"
                | "webhook-replay-validator"
                | "safe-egress-validator"
                | "identity-workflow-validator"
                | "cloud-iam-graph-validator"
                | "web3-invariant-validator"
                | "ci-evidence-gate"
        )
}

fn research_readiness_score(
    graph: &ReconGraph,
    hypotheses: &[ResearchHypothesis],
    proof_plans: &[ProofExecutionPlan],
    challenges: &[FalsePositiveChallenge],
    input: &AgentInput,
) -> u8 {
    let mut score = 0_u16;
    score += (graph.nodes.len() as u16).min(30);
    score += ((hypotheses.len() as u16) * 3).min(25);
    score += ((proof_plans.len() as u16) * 2).min(20);
    if !input.evidence_refs.is_empty() {
        score += 10;
    }
    if input
        .findings
        .iter()
        .any(|finding| finding.state.to_ascii_lowercase().contains("verified"))
    {
        score += 10;
    }
    let blockers = challenges
        .iter()
        .filter(|challenge| challenge.blocking)
        .count() as u16;
    score = score.saturating_sub((blockers * 3).min(25));
    score.min(100) as u8
}

fn next_actions(
    graph: &ReconGraph,
    hypotheses: &[ResearchHypothesis],
    proof_plans: &[ProofExecutionPlan],
    challenges: &[FalsePositiveChallenge],
) -> Vec<String> {
    let mut actions = Vec::new();
    let registered_ready = hypotheses
        .iter()
        .filter(|hypothesis| registered_validator(&hypothesis.expected_validator))
        .count();
    if registered_ready > 0 {
        actions.push(format!(
            "Execute {registered_ready} registered validator-backed hypothesis/hypotheses before reporting."
        ));
    }
    let validator_gaps = challenges
        .iter()
        .filter(|challenge| challenge.challenge_type == "validator_gap")
        .count();
    if validator_gaps > 0 {
        actions.push(format!(
            "Promote {validator_gaps} planned validator(s) into deterministic Rust proof modules."
        ));
    }
    let budget_blocked = proof_plans
        .iter()
        .filter(|plan| plan.mode == "blocked_by_request_budget")
        .count();
    if budget_blocked > 0 {
        actions.push(format!(
            "Increase the authorized request budget or split {budget_blocked} proof plan(s) into separate runs."
        ));
    }
    for gap in graph.coverage_gaps.iter().take(3) {
        actions.push(format!("Close coverage gap: {gap}"));
    }
    actions.push(
        "Persist confirmed outcomes into finding memory so future runs learn recurrence and suppressions."
            .to_string(),
    );
    actions
}

fn defense_for(hypothesis: &ResearchHypothesis) -> String {
    match hypothesis.class.as_str() {
        "BrokenObjectLevelAuthorization" => {
            "object ownership guard, auth matrix regression, sensitive field minimizer".to_string()
        }
        "BrokenFunctionLevelAuthorization" => {
            "role policy guard, admin action audit, privilege regression".to_string()
        }
        "CloudIamPrivilegePath" => {
            "least privilege policy, public exposure gate, trust relationship review".to_string()
        }
        "Web3AccessControlInvariant" => {
            "invariant proof tests, privilege review, deployment gate".to_string()
        }
        "CiTrustBoundary" => {
            "minimum token permissions, branch protection, workflow input hardening".to_string()
        }
        "RepositoryExposure" => {
            "redaction review, rotation workflow, secret scanning gate".to_string()
        }
        "RegressionReplay" => "CI replay gate and patch verification".to_string(),
        _ => "validator-specific remediation and regression replay".to_string(),
    }
}

fn fingerprint(hypothesis: &ResearchHypothesis) -> String {
    format!(
        "{}-{}-{}",
        hypothesis.surface.as_str(),
        normalize_token(&hypothesis.class),
        normalize_token(&hypothesis.target)
    )
}

fn normalize_token(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in value.to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentFindingSummary;

    fn input() -> AgentInput {
        AgentInput {
            role: "autonomous".to_string(),
            run_id: "research-1".to_string(),
            scope_summary: "local lab".to_string(),
            endpoints: vec![
                "GET /api/invoices/{id}".to_string(),
                "GET /api/admin/reports/{id}".to_string(),
                "POST /api/import".to_string(),
            ],
            findings: vec![AgentFindingSummary {
                finding_id: "finding-1".to_string(),
                classification: "BrokenObjectLevelAuthorization".to_string(),
                endpoint: "GET /api/invoices/{id}".to_string(),
                severity: "High".to_string(),
                state: "verified".to_string(),
                evidence_refs: vec!["evidence_manifest.json".to_string()],
            }],
            evidence_refs: vec![
                "openapi_inventory.json".to_string(),
                "matrix_summary.json".to_string(),
                "repo_inventory.json".to_string(),
                "web3/web3_analysis.json".to_string(),
            ],
            context: BTreeMap::new(),
        }
    }

    #[test]
    fn graph_indexes_endpoints_evidence_and_findings() {
        let graph = build_research_graph(&input());
        assert!(graph.nodes.iter().any(|node| node.id == "scope"));
        assert!(graph
            .nodes
            .iter()
            .any(|node| node.risk_tags.contains(&"object_scoped".to_string())));
        assert!(graph
            .nodes
            .iter()
            .any(|node| node.kind == ResearchSurfaceKind::Web3));
        assert!(!graph.edges.is_empty());
    }

    #[test]
    fn hypothesis_forge_prioritizes_auth_and_parser_boundaries() {
        let input = input();
        let graph = build_research_graph(&input);
        let hypotheses = forge_research_hypotheses(&graph, &input);
        assert!(hypotheses
            .iter()
            .any(|hypothesis| hypothesis.class == "BrokenObjectLevelAuthorization"));
        assert!(hypotheses
            .iter()
            .any(|hypothesis| hypothesis.class == "BrokenFunctionLevelAuthorization"));
        assert!(hypotheses
            .iter()
            .any(|hypothesis| hypothesis.class == "UnsafeFileUploadOrParserBoundary"));
        assert!(hypotheses
            .iter()
            .any(|hypothesis| hypothesis.class == "Web3AccessControlInvariant"));
    }

    #[test]
    fn proof_plans_enforce_request_budget_and_safety_gates() {
        let report = run_research_engine(
            &input(),
            &AutonomousBudget {
                max_active_requests: 1,
                ..AutonomousBudget::default()
            },
        );
        assert!(report
            .proof_plans
            .iter()
            .any(|plan| plan.mode == "blocked_by_request_budget"));
        assert!(report.proof_plans.iter().all(|plan| plan
            .safety_gates
            .contains(&"authorized_scope_required".to_string())));
        assert!(report.challenges.iter().any(|challenge| challenge.blocking));
    }

    #[test]
    fn registered_validators_can_be_ready_for_validation() {
        let report = run_research_engine(&input(), &AutonomousBudget::default());
        assert!(report.memory_records.iter().any(|record| {
            record.outcome == "ready_for_deterministic_validation"
                && record.class == "BrokenObjectLevelAuthorization"
        }));
        let rendered = render_research_engine_report(&report);
        assert!(rendered.contains("Autonomous Research Engine"));
        assert!(rendered.contains("Proof Plans"));
    }
}
