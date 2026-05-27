"use client";

export const API_BASE =
  process.env.NEXT_PUBLIC_BALONCORE_API?.replace(/\/$/, "") ??
  "http://127.0.0.1:8788";

export type StatusPayload = {
  name?: string;
  mode?: string;
  kernel?: string;
  control_plane?: string;
  jobs?: {
    recent_count?: number;
    status_counts?: Record<string, number>;
  };
  workbench_root?: string;
};

export type JobRecord = {
  job_id: string;
  type: string;
  status: string;
  created_at?: string;
  updated_at?: string;
  error?: string | null;
  result?: {
    ok?: boolean;
    run_dir?: string;
    artifact_count?: number;
    run_intelligence?: {
      score?: number;
      readiness?: string;
      executive_summary?: string;
      enterprise_scorecard?: string;
      artifact_index?: string;
      signals?: Record<string, number>;
    };
  } | null;
};

export type Artifact = {
  path: string;
  relative_path: string;
  kind: string;
  bytes: number;
  modified_at?: string;
};

export type ArtifactPreview = {
  relative_path?: string;
  kind?: string;
  bytes?: number;
  truncated?: boolean;
  text?: string | null;
  json?: unknown;
};

export type CustomerRecord = {
  id: string;
  company_name: string;
  contact_email: string;
  sector: string;
  plan: string;
  status: string;
  asset_count: number;
  risk_posture: string;
  scope_contract: string;
  assets?: string[];
};

export type SaasOverview = {
  name: string;
  mode: string;
  summary: {
    organizations: number;
    active_organizations: number;
    jobs: number;
    artifacts: number;
    latest_score: number;
    verified_findings: number;
    signed_evidence_bundles: number;
    proof_readiness: string;
  };
  customers: CustomerRecord[];
  audit_events?: AuditEvent[];
  plans: Array<{ name: string; price: string; fit: string; limits: string }>;
  admin_queues: Array<{ name: string; count: number; sla: string }>;
  modules: Array<{ name: string; status: string; signal: string }>;
};

export type AuditEvent = {
  id: string;
  created_at: string;
  event_type: string;
  actor: string;
  target: string;
  detail?: Record<string, unknown>;
};

export type CommandCenter = {
  proof_twin: {
    score: number;
    readiness: string;
    policy: string;
    signals?: Record<string, number>;
  };
  attack_graph?: AttackGraph;
  policy_gates?: PolicyGates;
  defense_plan?: DefensePlan;
  risk_register?: RiskRegister;
  executive_brief?: ExecutiveBrief;
  defense_rules?: DefenseRules;
  sector_threat_model?: SectorThreatModel;
  research_engine?: ResearchEngine;
  autonomous_lanes: Array<{
    lane: string;
    state: string;
    role: string;
    confidence: number;
  }>;
  standout_capabilities: Array<{ name: string; why_it_matters: string }>;
  coverage_matrix: Array<{ surface: string; status: string; proof: string }>;
};

export type ResearchEngine = {
  created_at: string;
  input: {
    run_id: string;
    scope_summary: string;
    endpoints: number;
    findings: number;
    evidence_refs: number;
  };
  summary: {
    readiness_score: number;
    recon_nodes: number;
    recon_edges: number;
    coverage_gaps: number;
    hypotheses: number;
    proof_plans: number;
    false_positive_challenges: number;
    blocking_challenges: number;
    memory_records: number;
    surface_counts?: Record<string, number>;
  };
  graph: {
    nodes: Array<{
      id: string;
      kind: string;
      label: string;
      evidence_refs?: string[];
      risk_tags?: string[];
      confidence: number;
    }>;
    edges: Array<{ from: string; to: string; relation: string; evidence_ref?: string | null }>;
    coverage_gaps: string[];
  };
  hypotheses: Array<{
    id: string;
    surface: string;
    class: string;
    title: string;
    target: string;
    why: string;
    preconditions?: string[];
    evidence_refs?: string[];
    confidence: number;
    expected_validator: string;
    safety_boundary: string;
  }>;
  proof_plans: Array<{
    id: string;
    hypothesis_id: string;
    validator: string;
    mode: string;
    active_requests_budget: number;
    commands?: string[];
    required_artifacts?: string[];
    safety_gates?: string[];
  }>;
  challenges: Array<{
    hypothesis_id: string;
    challenge_type: string;
    blocking: boolean;
    reason: string;
  }>;
  memory_records: Array<{
    fingerprint: string;
    class: string;
    surface: string;
    first_seen: string;
    last_seen: string;
    seen_count: number;
    outcome: string;
    defense: string;
  }>;
  next_actions: string[];
};

export type BackboneStatus = {
  name: string;
  created_at: string;
  storage_mode: string;
  postgres_schema: {
    path: string;
    required_for_hosted_saas: boolean;
    migrations: Array<{
      file: string;
      bytes: number;
      sha256: string;
      tables_declared: number;
    }>;
  };
  domain_model: {
    organizations: number;
    projects: number;
    assets: number;
    audit_events: number;
  };
  queue_model: {
    jobs?: {
      total?: number;
      states?: Record<string, number>;
      pools?: Record<string, number>;
      attempt_records?: number;
      registered_workers?: number;
    };
    worker_pools: Array<{
      id: string;
      job_types: string[];
      isolation: string;
      status: string;
    }>;
    registered_workers: number;
    attempt_records: number;
  };
  hardening_gates: Array<{ name: string; status: string; proof: string }>;
  production_next: string[];
};

export type WorkerRecord = {
  worker_id: string;
  pool: string;
  status: string;
  capacity: number;
  last_heartbeat: string;
  metadata?: Record<string, unknown>;
};

export type WorkerQueue = {
  created_at: string;
  summary: {
    total: number;
    states?: Record<string, number>;
    pools?: Record<string, number>;
    attempt_records?: number;
    registered_workers?: number;
  };
  workers: WorkerRecord[];
  recent_attempts: Array<Record<string, unknown>>;
  jobs: Array<{
    queue_id?: string;
    job_id: string;
    type: string;
    status: string;
    queue_state: string;
    worker_pool: string;
    priority: number;
    attempts: number;
    max_attempts: number;
    lease_owner?: string | null;
    org_id?: string | null;
    project_id?: string | null;
    asset_id?: string | null;
    created_at?: string;
    updated_at?: string;
  }>;
};

export type RiskRegister = {
  created_at: string;
  count: number;
  risks: Array<{
    id: string;
    title: string;
    surface: string;
    severity: string;
    state: string;
    score: number;
    readiness: string;
    job_id: string;
    recurrence_count?: number;
    sample_job_ids?: string[];
    evidence: string;
    owner: string;
    next_action: string;
  }>;
};

export type DefensePlan = {
  created_at: string;
  name: string;
  actions: Array<{
    id: string;
    priority: string;
    title: string;
    owner: string;
    status: string;
    impact: string;
  }>;
  playbooks: Array<{ name: string; outputs: string[] }>;
};

export type AttackGraph = {
  created_at: string;
  nodes: Array<{ id: string; label: string; kind: string; state: string }>;
  edges: Array<{ from: string; to: string; label: string }>;
  risk_pressure: number;
  moat: string;
};

export type PolicyGates = {
  created_at: string;
  gates: Array<{
    name: string;
    status: string;
    severity: string;
    detail: string;
  }>;
};

export type ExecutiveBrief = {
  created_at: string;
  verdict: string;
  headline: string;
  board_metrics: Array<{ label: string; value: number; unit: string }>;
  top_risk: {
    severity?: string;
    title?: string;
    surface?: string;
  };
  assurance_statement: string;
  next_72_hours: string[];
  why_it_stands_out: string[];
};

export type DefenseRules = {
  created_at: string;
  count: number;
  packs: Array<{
    id: string;
    name: string;
    surface: string;
    priority: string;
    status: string;
    summary: string;
    outputs: string[];
    snippet: string;
  }>;
};

export type SectorThreatModel = {
  created_at: string;
  observed_customer_sectors: Record<string, number>;
  positioning: string;
  packs: Array<{
    sector: string;
    focus: string;
    primary_controls: string[];
    baloncore_edge: string;
  }>;
};

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  const data = (await response.json()) as T;
  if (!response.ok) {
    throw new Error(JSON.stringify(data, null, 2));
  }
  return data;
}

export function readinessLabel(value?: string) {
  if (!value) return "No proof yet";
  return value.replaceAll("_", " ");
}

export function compactPath(value?: string) {
  if (!value) return "";
  return value.replace("/Users/simdia/Documents/youtube explanation/", "");
}

export type MetricsSummary = {
  total_scans: number;
  total_findings: number;
  verified_findings: number;
  verified_findings_per_scan: number;
  rejected_hypotheses: number;
  false_positive_reduction_rate: number;
  retest_success_rate: number;
  ci_blocked_criticals: number;
  model_calls_per_verified: number;
  tokens_per_verified: number;
  per_vuln_class: Array<{
    vuln_class: string;
    verified: number;
    rejected: number;
    suppressed: number;
    fp_reduction_rate: number;
    time_to_proof_ms: number;
  }>;
  time_to_proof: {
    mean_ms: number;
    median_ms: number;
    p90_ms: number;
    min_ms: number;
    max_ms: number;
    sample_count: number;
  };
  time_to_fix: {
    mean_ms: number;
    median_ms: number;
    p90_ms: number;
    min_ms: number;
    max_ms: number;
    sample_count: number;
  };
};

export type MetricsTrendPoint = {
  period: string;
  metric: string;
  value: number;
  sample_count: number;
};

export type MetricsTrend = {
  metric: string;
  bucket: string;
  points: MetricsTrendPoint[];
};

export type MetricsDrilldownEntry = {
  scan_id: string;
  metric: string;
  value: number;
  started_at: number;
  computed_at: number;
  findings_count: number;
  findings: Array<Record<string, unknown>>;
};

export type MetricsDrilldown = {
  metric: string;
  period_filter: string | null;
  total_entries: number;
  entries: MetricsDrilldownEntry[];
};

/// T3.d — typed fetchers for the /api/metrics/* endpoints.
/// The dashboard's Program Health view consumes these and links every figure
/// back to its source via `fetchMetricsDrilldown`.
export async function fetchMetricsSummary(): Promise<MetricsSummary> {
  return api<MetricsSummary>("/api/metrics/summary");
}

export async function fetchMetricsTrend(
  metric: string,
  bucket: string = "day"
): Promise<MetricsTrend> {
  const qs = new URLSearchParams({ metric, bucket }).toString();
  return api<MetricsTrend>(`/api/metrics/trend?${qs}`);
}

export async function fetchMetricsDrilldown(
  metric: string,
  period?: string
): Promise<MetricsDrilldown> {
  const params = new URLSearchParams({ metric });
  if (period) params.set("period", period);
  return api<MetricsDrilldown>(`/api/metrics/drilldown?${params.toString()}`);
}
