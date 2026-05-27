pub mod agent;
pub mod agent_runtime;
pub mod agents;
pub mod attack_graph;
pub mod business_logic;
pub mod ci;
pub mod ci_analytics;
pub mod ci_pipeline;
pub mod ci_revalidation;
pub mod ci_runtime;
pub mod cloud_iam;
pub mod cloud_providers;
pub mod config;
pub mod defense;
pub mod diligence;
pub mod discovery;
pub mod evaluation;
pub mod evidence;
pub mod finding;
pub mod flagship_report;
pub mod github;
pub mod lifecycle;
pub mod matcher;
pub mod metrics;
pub mod model_client;
pub mod orchestrator;
pub mod pipeline;
pub mod platform;
pub mod proof;
pub mod research_engine;
pub mod rigor;
pub mod safety;
pub mod sarif;
pub mod scope;
pub mod triage;
pub mod web3;
pub mod web3_parsers;
pub mod web_api;

pub use agent::{
    agent_spec, bridge_hypotheses_to_validators, challenge_hypotheses, prompt_template,
    run_fixture_agent, run_fixture_agent_pipeline, validate_agent_output,
    validator_for_classification, AgentFindingSummary, AgentHypothesis, AgentInput,
    AgentObservation, AgentOutput, AgentOutputStatus, AgentOutputValidation, AgentPipelineResult,
    AgentRun, ModelConfig, PromptTemplate, ValidatorBridge, VerifierChallenge,
};
pub use agent_runtime::{
    build_repair_request, contains_unredacted_secrets, parse_agent_output, redact_for_model,
    run_live_agent, run_live_agent_pipeline, AgentParseError, ModelBudget, ModelBudgetReport,
};
pub use business_logic::{
    BusinessLogicAbuse, BusinessLogicDecision, BusinessLogicValidationCase, BusinessLogicValidator,
    RejectedBusinessLogicHypothesis, VerifiedBusinessLogicFinding, WorkflowExchange,
    WorkflowInvariant, WorkflowState, WorkflowStep,
};
pub use ci::{
    evaluate_ci_gate, BaselineFile, BaselineFinding, BlockingFinding, CIGateResult, DiffEndpoint,
    DiffResult, PolicyConfig,
};
pub use ci_analytics::{
    compute_ci_analytics, render_ci_dashboard, render_ci_dashboard_compact, BlockingClassCount,
    CIAnalytics, CIPipelineHistory, CIPipelineRunRecord, RunTrendPoint, StagePassRate,
    StageRecord as CIAnalyticsStageRecord,
};
pub use ci_pipeline::{
    deliver_notification, generate_github_actions_workflow, render_ci_pipeline_summary,
    CIPipelineConfig, CIPipelineResult, CIPipelineRunner, CIPipelineStage, GitHubActionsConfig,
    NotificationResult, NotificationTarget, StageResult,
};
pub use ci_revalidation::{
    generate_fix_lifecycle_transitions, render_revalidation_report, CIPreset, FixTransition,
    RegressionVerdictSummary, RevalidationReport, RevalidationResult, RevalidationRunner,
    RevalidationStatus,
};
pub use ci_runtime::{
    build_check_run_from_gate, create_github_check_run, render_ci_status_markdown, AnnotationLevel,
    CICheckAnnotation, CICheckRun, CIProvider, CIRuntime, CheckRunConclusion, CheckRunStatus,
};
pub use cloud_iam::{
    cloud_reachability_proofs, render_cloud_reachability_proofs, AmazonResourceType,
    CloudAnalysisResult, CloudAnalysisSummary, CloudEvidence, CloudEvidenceKind, CloudFinding,
    CloudProofEvidenceStep, CloudProofStep, CloudProvider, CloudReachabilityProof, CloudResource,
    CloudSeverity, Effect, IAMCondition, IAMEdge, IAMEdgeKind, IAMGraph, IAMPolicy, IAMPrincipal,
    IAMStatement, IdentityChainEntry, PolicySourceType, PrincipalKind, PrivilegeLevel,
    PrivilegePath, TrustRelationship,
};
pub use cloud_providers::{aws_iam, azure_arm, cloudformation, gcp_iam, kubernetes, terraform};
pub use config::{
    ApiKeyHeaderRef, AuthCredentialRef, AuthProfile, BaloncoreConfig, CookieSessionRef, ModelTable,
    OAuth2GrantType, OAuth2Ref, ProjectConfig, ScopeConfig, SuppressionRule, TemplateCookie,
    TemplateHeader,
};
pub use defense::{
    defense_maturity_for_finding, generate_defense_report, generate_least_privilege_guidance,
    generate_regression_tests, generate_sigma_rule, recommend, recommend_for_findings,
    render_defense_report, DefenseMaturityScore, DefenseRecommendation, DetectionRule,
    DetectionRuleType, FixTemplate, GuidanceCategory, GuidanceItem, GuidancePriority,
    LeastPrivilegeGuidance, LogField, LoggingSuggestion, RegressionTest, RegressionTestType,
    StrideCategory, ThreatModelSnippet, WafAction, WafRule, WafRuleType,
};
pub use diligence::{
    compute_diligence_trend, render_diligence_trend, ComplianceCoverageReport,
    DiligenceFindingSummary, DiligenceHistory, DiligenceHistoryEntry, DiligenceRecommendation,
    DiligenceTrend, EvidenceQualityAssessment, FrameworkControlStatus, FrameworkCoverage,
    FrameworkSpecificReport, InvestmentReadinessScore, QuestionnaireAnswer, QuestionnaireSection,
    RiskCategory, RiskHeatmap, SecurityDiligenceReport, SecurityPosture, SecurityQuestionnaire,
};
pub use evaluation::{
    all_benchmark_suites, append_to_history, benchmark_ci_gate, benchmark_suite_by_id,
    cloud_iam_benchmark_suite, compare_runs, compute_cross_domain_correlation,
    compute_difficulty_breakdown, compute_evaluation_metrics, compute_repetition_stats,
    compute_tag_breakdown, create_benchmark_run_from_results, detect_drift, eval_gate,
    evaluate_cloud_iam_findings, evaluate_evidence_integrity, evaluate_web3_findings,
    evaluate_web_api_run, evidence_lifecycle_benchmark_suite, generate_benchmark_doc,
    generate_golden_baseline, generate_leaderboard, generate_methodology_doc,
    generate_recommendations, generate_scorecard, load_benchmark_run, load_benchmark_suite,
    load_determinism_check, load_eval_gate_result, load_golden_baseline, load_history,
    load_leaderboard, load_repetition_result, load_scorecard, render_ci_gate_result,
    render_determinism_check, render_drift_report, render_eval_gate_result, render_history,
    render_leaderboard, render_repetition_result, render_run_diff, render_scorecard,
    save_benchmark_run, save_benchmark_suite, save_determinism_check, save_eval_gate_result,
    save_golden_baseline, save_history, save_leaderboard, save_repetition_result, save_scorecard,
    verify_determinism, web3_benchmark_suite, web_api_benchmark_suite, BenchmarkCIGateResult,
    BenchmarkCase, BenchmarkConfig, BenchmarkDifficulty, BenchmarkDomain, BenchmarkHistory,
    BenchmarkRepetitionResult, BenchmarkResult, BenchmarkRun, BenchmarkSuite, CaseComparison,
    ComparisonResult, CrossDomainCorrelation, DeterminismCheckResult, DifficultyMetrics,
    DomainPairCorrelation, DriftReport, EvalGateResult, EvaluationGrade, EvaluationMetrics,
    EvaluationScorecard, GroundTruthLabel, HistoryEntry, LeaderboardAttribution, LeaderboardReport,
    LeaderboardRunEntry, MetricStatistics, PerCaseResult, TagMetrics, ThresholdCheck,
    VulnClassMetrics,
};
pub use flagship_report::{
    EvidenceEntry, FixGuidance, FlagshipFinding, FlagshipReport, ReproductionStep,
};
pub use github::{
    analyze_pr_diff, build_revalidation_plan, get_pr, get_pr_files, list_open_prs,
    parse_github_webhook, post_pr_comment, post_pr_review, render_pr_review_comment, AuthChange,
    EndpointChange, GitHubClient, GitHubPR, GitHubPRComment, GitHubPRFile, GitHubReview,
    GitHubWebhookEvent, GitHubWebhookResponse, PRComparison, PRDiffAnalysis, RevalidationPlan,
    RevalidationTarget, SecurityRelevantFile,
};
pub use lifecycle::{FindingRecord, FindingState, FindingStore, FindingTransition, ScanRecord};
pub use metrics::{
    ci_blocked_criticals, compute_metrics_summary, compute_metrics_trend,
    false_positive_reduction_rate, false_positive_reduction_rate_from_store, load_metrics_rollup,
    model_calls_per_verified, render_metrics_rollup, render_metrics_summary, render_metrics_trend,
    retest_success_rate, retest_success_rate_simple, save_metrics_rollup, scan_volume_over_time,
    time_to_fix, time_to_proof, tokens_per_verified, verified_findings_per_scan,
    vuln_class_breakdown, MetricPoint, MetricsRollup, MetricsSummary, MetricsTrendPoint,
    ScanMetricsEntry, ScanVolumePoint, TimeToFixMetrics, TimeToProofMetrics,
    VulnClassMetricsSummary,
};
pub use model_client::{
    client_for, ModelClient, ModelError, ModelRequest, ModelResponse, ModelUsage,
};
pub use orchestrator::{
    render_autonomous_run_report, run_autonomous_fixture, AgentMemory, ApprovalGate,
    AutonomousBudget, AutonomousRun, AutonomousStep, AutonomousStepStatus, ToolCallRequest,
    ToolCallResult,
};
pub use platform::{
    bootstrap_platform_state, compliance_mapping, deobfuscate_evidence, obfuscate_evidence,
    render_platform_audit_log, render_platform_onboarding, AuditEvent, BillingAccount,
    ComplianceControl, ComplianceMapping, EvidenceBundleRef, InvestorMetrics, ObfuscationConfig,
    OnboardingStep, OnboardingTracker, Organization, PlanLimits, PlatformFinding,
    PlatformPermission, PlatformPlan, PlatformRole, PlatformScan, PlatformState, PlatformUser,
    Project, RoleAssignment, UsageMetrics, Workspace,
};
pub use research_engine::{
    build_proof_plans, build_research_graph, build_research_memory, challenge_research_hypotheses,
    forge_research_hypotheses, render_research_engine_report, run_research_engine,
    FalsePositiveChallenge, ProofExecutionPlan, ReconEdge, ReconGraph, ReconNode,
    ResearchEngineReport, ResearchFindingMemoryRecord, ResearchHypothesis, ResearchSurfaceKind,
};
pub use rigor::{
    AuditIntegrityRecord, ComplianceProof, CustodyChain, CustodyStep, DecoyResult,
    DecoyVerification, DefenseLineageEntry, RegressionCheckpoint, RegressionProvenanceEntry,
    ReportIntegrityCheck, ScopeAuditProof, TamperEvidentEvent,
};
pub use sarif::{findings_to_sarif, sarif_to_file, sarif_to_string, SarifReport};
pub use scope::{ScopeDecision, ScopeGuard};
pub use web3::{
    analyze_web3_project, apply_fuzz_results, detect_project_kind, generate_foundry_proof_tests,
    generate_invariants_for_project, ingest_slither_output, render_web3_proof_manifest,
    render_web3_report, run_forge_fuzz, run_fuzz_and_update, ContractKind, ContractSummary,
    ExploitProof, FoundryConfig, FunctionVisibility, FuzzConfig, FuzzResult, FuzzRunResult,
    HardhatConfig, InheritanceRelation, InvariantKind, InvariantSpec, InvariantStatus,
    InvariantTemplate, SlitherElement, SlitherFinding, SlitherOutput, SolidityContract,
    SolidityEvent, SolidityFunction, SolidityParameter, SolidityType, SourceLocation,
    StateMutability, StorageLayout, StorageVariable, VulnerabilityClass, Web3AnalysisResult,
    Web3AnalysisSummary, Web3Evidence, Web3EvidenceKind, Web3Finding, Web3GeneratedTest,
    Web3Project, Web3ProjectKind, Web3Severity,
};
pub use web3_parsers::{parse_foundry_config, parse_solidity_file, parse_solidity_project};
