use anyhow::{anyhow, bail, Context, Result};
use baloncore_core::{
    platform::{OnboardingStep, PlatformRole, PlatformState},
    run_research_engine, AgentFindingSummary, AgentInput, AutonomousBudget, MetricsRollup,
    ResearchSurfaceKind,
};
use regex_lite::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_SCAN_FILES: usize = 6000;
const MAX_TEXT_FILE_BYTES: u64 = 1_000_000;
const MAX_PREVIEW_BYTES: u64 = 200_000;
static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct ApiConfig {
    host: String,
    port: u16,
    repo_root: PathBuf,
    workbench_root: PathBuf,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn main() -> Result<()> {
    let mut host = "127.0.0.1".to_string();
    let mut port = 8788_u16;
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--host" => {
                index += 1;
                host = args
                    .get(index)
                    .cloned()
                    .context("--host requires a value")?;
            }
            "--port" => {
                index += 1;
                port = args
                    .get(index)
                    .context("--port requires a value")?
                    .parse()
                    .context("port must be a number")?;
            }
            _ => bail!("unknown argument: {}", args[index]),
        }
        index += 1;
    }

    if host != "127.0.0.1" && host != "localhost" {
        bail!("Refusing to bind non-local host. Use 127.0.0.1 for local development.");
    }

    let repo_root = env::current_dir().context("resolve current directory")?;
    let workbench_root = repo_root.join(".baloncore").join("workbench");
    fs::create_dir_all(workbench_root.join("jobs")).context("create workbench dirs")?;

    let config = ApiConfig {
        host,
        port,
        repo_root,
        workbench_root,
    };
    serve(config)
}

fn serve(config: ApiConfig) -> Result<()> {
    let listener = TcpListener::bind((config.host.as_str(), config.port))
        .with_context(|| format!("bind {}:{}", config.host, config.port))?;
    println!(
        "BALONCORE Rust API running at http://{}:{}",
        config.host, config.port
    );
    println!("Artifacts: {}", config.workbench_root.display());

    for stream in listener.incoming() {
        let stream = stream.context("accept connection")?;
        let config = ApiConfig {
            host: config.host.clone(),
            port: config.port,
            repo_root: config.repo_root.clone(),
            workbench_root: config.workbench_root.clone(),
        };
        thread::spawn(move || {
            if let Err(err) = handle_connection(stream, &config) {
                eprintln!("request failed: {err:#}");
            }
        });
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, config: &ApiConfig) -> Result<()> {
    let request = parse_request(&mut stream)?;
    let response = route_request(config, request);
    match response {
        Ok((status, body)) => write_json_response(&mut stream, status, &body),
        Err(err) => write_json_response(
            &mut stream,
            500,
            &json!({
                "ok": false,
                "error": err.to_string()
            }),
        ),
    }
}

fn route_request(config: &ApiConfig, request: HttpRequest) -> Result<(u16, Value)> {
    if request.method == "OPTIONS" {
        return Ok((204, json!({})));
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/status") => Ok((200, status_payload(config)?)),
        ("GET", "/api/jobs") => Ok((200, json!({ "jobs": list_jobs(config)? }))),
        ("GET", "/api/saas/overview") => Ok((200, saas_overview(config)?)),
        ("GET", "/api/saas/backbone") => Ok((200, saas_backbone(config)?)),
        ("GET", "/api/saas/projects") => Ok((200, json!({ "projects": load_projects(config)? }))),
        ("GET", "/api/saas/assets") => Ok((200, json!({ "assets": load_assets(config)? }))),
        ("GET", "/api/saas/audit-log") => {
            Ok((200, json!({ "events": load_audit_events(config)? })))
        }
        ("GET", "/api/workers") => Ok((200, json!({ "workers": load_workers(config)? }))),
        ("GET", "/api/workers/queue") => Ok((200, worker_queue(config)?)),
        ("GET", "/api/security/command-center") => Ok((200, security_command_center(config)?)),
        ("GET", "/api/security/research-engine") => Ok((200, security_research_engine(config)?)),
        ("GET", "/api/security/risk-register") => Ok((200, risk_register(config)?)),
        ("GET", "/api/security/defense-plan") => Ok((200, defense_plan(config)?)),
        ("GET", "/api/security/attack-graph") => Ok((200, attack_graph(config)?)),
        ("GET", "/api/security/policy-gates") => Ok((200, policy_gates(config)?)),
        ("GET", "/api/security/executive-brief") => Ok((200, executive_brief(config)?)),
        ("GET", "/api/security/defense-rules") => Ok((200, defense_rules(config)?)),
        ("GET", "/api/security/sector-threat-model") => Ok((200, sector_threat_model(config)?)),
        ("GET", "/api/artifacts") => {
            Ok((200, json!({ "artifacts": list_artifacts(config, None)? })))
        }
        ("GET", "/api/artifact") => {
            let path = request
                .query
                .get("path")
                .ok_or_else(|| anyhow!("path query parameter is required"))?;
            Ok((200, preview_artifact(config, path)?))
        }
        ("GET", "/api/run-intelligence") => {
            let run_dir = request
                .query
                .get("run_dir")
                .ok_or_else(|| anyhow!("run_dir query parameter is required"))?;
            Ok((200, run_intelligence(config, run_dir)?))
        }
        ("POST", "/api/jobs") => {
            let body = parse_json_body(&request)?;
            let record = create_job(config, body)?;
            Ok((202, record))
        }
        ("POST", "/api/saas/onboard") => {
            let body = parse_json_body(&request)?;
            let record = onboard_customer(config, body)?;
            Ok((201, record))
        }
        ("POST", "/api/saas/projects") => {
            let body = parse_json_body(&request)?;
            let record = create_project(config, body)?;
            Ok((201, record))
        }
        ("POST", "/api/saas/assets") => {
            let body = parse_json_body(&request)?;
            let record = create_asset(config, body)?;
            Ok((201, record))
        }
        ("POST", "/api/saas/scope-contract") => {
            let body = parse_json_body(&request)?;
            let record = update_scope_contract(config, body)?;
            Ok((200, record))
        }
        ("POST", "/api/workers/register") => {
            let body = parse_json_body(&request)?;
            let record = register_worker(config, body)?;
            Ok((201, record))
        }
        ("POST", "/api/workers/reconcile") => {
            let body = parse_json_body(&request)?;
            Ok((200, reconcile_worker_queue(config, body)?))
        }
        ("POST", "/api/scan/repo") => {
            let body = parse_json_body(&request)?;
            require_authorized(&body)?;
            Ok((200, scan_repo(config, &body)?))
        }
        ("POST", "/api/scan/webapp") => {
            let body = parse_json_body(&request)?;
            require_authorized(&body)?;
            Ok((200, scan_webapp(config, &body)?))
        }
        ("POST", "/api/tenant/orgs") => {
            let body = parse_json_body(&request)?;
            Ok((201, tenant_create_org(config, body)?))
        }
        ("GET", "/api/tenant/orgs") => Ok((200, tenant_list_orgs(config)?)),
        _ if request.method == "GET" && request.path.starts_with("/api/tenant/orgs/") => {
            let org_id = request.path.trim_start_matches("/api/tenant/orgs/");
            Ok((200, tenant_get_org(config, org_id)?))
        }
        ("POST", "/api/tenant/workspaces") => {
            let body = parse_json_body(&request)?;
            Ok((201, tenant_create_workspace(config, body)?))
        }
        ("POST", "/api/tenant/users") => {
            let body = parse_json_body(&request)?;
            Ok((201, tenant_add_user(config, body)?))
        }
        ("POST", "/api/tenant/members") => {
            let body = parse_json_body(&request)?;
            Ok((201, tenant_add_member(config, body)?))
        }
        ("GET", "/api/tenant/audit") => {
            let org_id = request
                .query
                .get("org_id")
                .map(|s| s.as_str())
                .unwrap_or("");
            Ok((200, tenant_audit_log(config, org_id)?))
        }
        ("GET", "/api/tenant/metrics") => {
            let org_id = request
                .query
                .get("org_id")
                .map(|s| s.as_str())
                .unwrap_or("");
            Ok((200, tenant_metrics(config, org_id)?))
        }
        ("GET", "/api/tenant/compliance") => {
            let classification = request
                .query
                .get("classification")
                .map(|s| s.as_str())
                .unwrap_or("idor");
            Ok((
                200,
                json!({ "controls": baloncore_core::platform::ComplianceMapping::for_classification(classification) }),
            ))
        }
        ("GET", "/api/metrics/summary") => Ok((200, metrics_summary(config)?)),
        ("GET", "/api/metrics/trend") => {
            let metric = request
                .query
                .get("metric")
                .map(|s| s.as_str())
                .unwrap_or("verified_findings");
            let bucket = request
                .query
                .get("bucket")
                .map(|s| s.as_str())
                .unwrap_or("day");
            Ok((200, metrics_trend(config, metric, bucket)?))
        }
        ("GET", "/api/metrics/drilldown") => {
            let metric = request
                .query
                .get("metric")
                .map(|s| s.as_str())
                .unwrap_or("verified_findings");
            let period = request.query.get("period").map(|s| s.as_str());
            Ok((200, metrics_drilldown(config, metric, period)?))
        }
        ("POST", "/api/tenant/onboard") => {
            let body = parse_json_body(&request)?;
            Ok((201, tenant_onboard(config, body)?))
        }
        ("POST", "/api/tenant/onboard-step") => {
            let body = parse_json_body(&request)?;
            Ok((200, tenant_onboard_step(config, body)?))
        }
        ("GET", "/api/tenant/onboarding") => {
            let org_id = request
                .query
                .get("org_id")
                .map(|s| s.as_str())
                .unwrap_or("");
            Ok((200, tenant_onboarding_status(config, org_id)?))
        }
        ("POST", "/api/tenant/api-keys") => {
            let body = parse_json_body(&request)?;
            Ok((201, tenant_create_api_key(config, body)?))
        }
        _ if request.method == "GET" && request.path.starts_with("/api/jobs/") => {
            let job_id = request.path.trim_start_matches("/api/jobs/");
            Ok((200, read_job(config, job_id)?))
        }
        _ => Ok((404, json!({ "ok": false, "error": "not found" }))),
    }
}

fn parse_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 4096];
    let header_end;
    loop {
        let read = stream.read(&mut temp).context("read request")?;
        if read == 0 {
            bail!("empty request");
        }
        buffer.extend_from_slice(&temp[..read]);
        if let Some(pos) = find_header_end(&buffer) {
            header_end = pos;
            break;
        }
        if buffer.len() > 1024 * 1024 {
            bail!("request headers too large");
        }
    }

    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = headers.lines();
    let request_line = lines.next().context("missing request line")?;
    let parts = request_line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        bail!("malformed request line");
    }

    let method = parts[0].to_string();
    let target = parts[1];
    let (path, query) = parse_target(target);

    let mut content_length = 0_usize;
    for line in lines {
        if let Some(value) = line.strip_prefix("Content-Length:") {
            content_length = value.trim().parse().context("invalid Content-Length")?;
        } else if let Some(value) = line.strip_prefix("content-length:") {
            content_length = value.trim().parse().context("invalid content-length")?;
        }
    }

    let body_start = header_end + 4;
    while buffer.len() < body_start + content_length {
        let read = stream.read(&mut temp).context("read request body")?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..read]);
    }
    let body = buffer[body_start..buffer.len().min(body_start + content_length)].to_vec();
    Ok(HttpRequest {
        method,
        path,
        query,
        body,
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_target(target: &str) -> (String, BTreeMap<String, String>) {
    let mut split = target.splitn(2, '?');
    let path = split.next().unwrap_or("/").to_string();
    let mut query = BTreeMap::new();
    if let Some(raw_query) = split.next() {
        for pair in raw_query.split('&') {
            let mut kv = pair.splitn(2, '=');
            if let Some(key) = kv.next() {
                let value = kv.next().unwrap_or("");
                query.insert(percent_decode(key), percent_decode(value));
            }
        }
    }
    (path, query)
}

fn percent_decode(input: &str) -> String {
    let mut output = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = &input[index + 1..index + 3];
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                output.push(value);
                index += 3;
                continue;
            }
        }
        output.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn parse_json_body(request: &HttpRequest) -> Result<Value> {
    if request.body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&request.body).context("invalid JSON body")
}

fn write_json_response(stream: &mut TcpStream, status: u16, body: &Value) -> Result<()> {
    let body = if status == 204 {
        Vec::new()
    } else {
        serde_json::to_vec_pretty(body).context("serialize response")?
    };
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .context("write response headers")?;
    stream.write_all(&body).context("write response body")?;
    Ok(())
}

fn status_payload(config: &ApiConfig) -> Result<Value> {
    let jobs = list_jobs(config)?;
    let mut status_counts = BTreeMap::<String, u64>::new();
    for job in jobs.as_array().unwrap_or(&vec![]) {
        let status = job
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        *status_counts.entry(status).or_default() += 1;
    }
    Ok(json!({
        "name": "BALONCORE Rust API",
        "mode": "rust-enterprise-api",
        "created_at": utc_now(),
        "repo_root": config.repo_root,
        "workbench_root": config.workbench_root,
        "jobs_root": jobs_root(config),
        "network_posture": "binds to 127.0.0.1 by default; active scans require authorized=true",
        "kernel": "Rust validator/proof engine",
        "control_plane": "Rust HTTP API",
        "frontend": "Next.js app in apps/web",
        "storage": "Postgres-ready schema with local durable adapter",
        "worker_runtime": "durable queue metadata plus local worker abstraction",
        "jobs": {
            "recent_count": jobs.as_array().map(|j| j.len()).unwrap_or_default(),
            "status_counts": status_counts
        },
        "capabilities": [
            "authorized OpenAPI BOLA/BFLA/missing-auth scan orchestration",
            "local repo inventory with redacted secret detection",
            "Solidity/Web3 project handoff to BALONCORE invariant analysis",
            "tenant/org/project/asset control-plane model",
            "durable queue records with worker pools and attempt tracking",
            "durable local job ledger",
            "artifact index, enterprise scorecard, executive summary, and safe artifact preview"
        ]
    }))
}

fn require_authorized(payload: &Value) -> Result<()> {
    if payload.get("authorized").and_then(Value::as_bool) != Some(true) {
        bail!("BALONCORE requires authorized=true for active scans and local repo review.");
    }
    Ok(())
}

fn saas_overview(config: &ApiConfig) -> Result<Value> {
    let customers = load_customers(config)?;
    let jobs = list_jobs(config)?;
    let artifacts = list_artifacts(config, None)?;
    let job_records = jobs.as_array().cloned().unwrap_or_default();
    let artifact_records = artifacts.as_array().cloned().unwrap_or_default();
    let latest_score = job_records
        .iter()
        .filter_map(|job| {
            job.pointer("/result/run_intelligence/score")
                .and_then(Value::as_u64)
        })
        .max()
        .unwrap_or_default();
    let verified_findings = job_records
        .iter()
        .filter_map(|job| {
            job.pointer("/result/run_intelligence/signals/verified_webapi_findings")
                .and_then(Value::as_u64)
        })
        .sum::<u64>();
    let evidence_manifests = job_records
        .iter()
        .filter_map(|job| {
            job.pointer("/result/run_intelligence/signals/evidence_manifests")
                .and_then(Value::as_u64)
        })
        .sum::<u64>();
    let active_customers = customers
        .iter()
        .filter(|customer| {
            customer
                .get("status")
                .and_then(Value::as_str)
                .map(|status| matches!(status, "active" | "pilot" | "trial"))
                .unwrap_or(false)
        })
        .count();

    Ok(json!({
        "name": "BALONCORE SaaS Control Plane",
        "mode": "local-hosted-saas-foundation",
        "created_at": utc_now(),
        "summary": {
            "organizations": customers.len(),
            "active_organizations": active_customers,
            "jobs": job_records.len(),
            "artifacts": artifact_records.len(),
            "latest_score": latest_score,
            "verified_findings": verified_findings,
            "signed_evidence_bundles": evidence_manifests,
            "proof_readiness": if latest_score >= 85 { "investor_demo_ready_local" } else { "needs_more_verified_runs" }
        },
        "customers": customers,
        "audit_events": load_audit_events(config)?.into_iter().rev().take(8).collect::<Vec<_>>(),
        "plans": [
            {
                "name": "Team",
                "price": "$799/mo",
                "fit": "startups shipping APIs weekly",
                "limits": "3 projects, CI replay, signed evidence"
            },
            {
                "name": "Growth",
                "price": "$4,000/mo",
                "fit": "funded teams with cloud, API, and repo attack surface",
                "limits": "10 projects, scheduled retests, Jira/Slack export"
            },
            {
                "name": "Enterprise",
                "price": "$30k+/yr",
                "fit": "security teams needing SSO, audit, private deployment",
                "limits": "custom projects, RBAC, tenant audit, policy packs"
            }
        ],
        "admin_queues": [
            { "name": "Onboarding review", "count": customers.iter().filter(|c| c.get("status").and_then(Value::as_str) == Some("trial")).count(), "sla": "4h" },
            { "name": "Evidence trust review", "count": evidence_manifests, "sla": "continuous" },
            { "name": "Critical proof triage", "count": verified_findings, "sla": "same day" }
        ],
        "modules": security_modules()
    }))
}

fn security_command_center(config: &ApiConfig) -> Result<Value> {
    let jobs = list_jobs(config)?;
    let job_records = jobs.as_array().cloned().unwrap_or_default();
    let strongest = job_records
        .iter()
        .max_by_key(|job| {
            job.pointer("/result/run_intelligence/score")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        })
        .cloned()
        .unwrap_or_else(|| json!({}));
    let score = strongest
        .pointer("/result/run_intelligence/score")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let readiness = strongest
        .pointer("/result/run_intelligence/readiness")
        .and_then(Value::as_str)
        .unwrap_or("no_verified_runs");
    let signals = strongest
        .pointer("/result/run_intelligence/signals")
        .cloned()
        .unwrap_or_else(|| json!({}));

    Ok(json!({
        "created_at": utc_now(),
        "strongest_proof_job": strongest,
        "proof_twin": {
            "score": score,
            "readiness": readiness,
            "policy": "AI may propose; deterministic validators must prove; defense artifacts must replay.",
            "signals": signals
        },
        "autonomous_lanes": [
            { "lane": "Recon Graph", "state": "ready", "role": "maps API, repo, cloud, and Web3 evidence into attack paths", "confidence": 91 },
            { "lane": "Hypothesis Forge", "state": "bounded", "role": "generates authorized candidate chains without sending unsafe traffic", "confidence": 87 },
            { "lane": "Proof Kernel", "state": "online", "role": "validates exploitability with request/response evidence and false-positive kill checks", "confidence": 94 },
            { "lane": "Defense Fabric", "state": "online", "role": "converts proof into remediation, CI replay, detections, and policy gates", "confidence": 92 },
            { "lane": "Verifier Council", "state": "strict", "role": "blocks claims without scope, impact, reproduction, and evidence integrity", "confidence": 95 }
        ],
        "standout_capabilities": [
            {
                "name": "Proof-to-Defense Autopilot",
                "why_it_matters": "Verified findings automatically become fix guidance, regression checks, evidence manifests, and defense rules."
            },
            {
                "name": "Exploitability Twin",
                "why_it_matters": "Each asset gets a living model of what is actually reachable, exploitable, fixed, recurring, or suppressed."
            },
            {
                "name": "ScopeGuard",
                "why_it_matters": "Every active validation requires explicit authorization, request budgets, local-only defaults, and audit records."
            },
            {
                "name": "Sector Defense Packs",
                "why_it_matters": "Findings map into SaaS, fintech, health, cloud, Web3, education, and compliance control language."
            },
            {
                "name": "Evidence Trust Ledger",
                "why_it_matters": "Signed evidence, lifecycle state, redaction gates, and CI enforcement make results fundable and auditable."
            }
        ],
        "coverage_matrix": [
            { "surface": "Web/API", "status": "deepest", "proof": "BOLA/BFLA/missing-auth validation with live HTTP evidence" },
            { "surface": "Repositories", "status": "active", "proof": "inventory, redacted secret signals, dependency/IaC/Web3 detection" },
            { "surface": "Cloud/IAM", "status": "foundation", "proof": "offline graph analysis and attack-path reports" },
            { "surface": "Web3", "status": "foundation", "proof": "Solidity analysis, invariant suggestions, generated proof tests" },
            { "surface": "Defense", "status": "active", "proof": "regression replay, signed evidence, SARIF, detection/control mappings" }
        ],
        "attack_graph": attack_graph(config)?,
        "policy_gates": policy_gates(config)?,
        "defense_plan": defense_plan(config)?,
        "risk_register": risk_register(config)?,
        "executive_brief": executive_brief(config)?,
        "defense_rules": defense_rules(config)?,
        "sector_threat_model": sector_threat_model(config)?,
        "research_engine": security_research_engine(config)?
    }))
}

fn security_research_engine(config: &ApiConfig) -> Result<Value> {
    let input = research_agent_input(config)?;
    let mut budget = AutonomousBudget::default();
    budget.max_steps = 12;
    budget.max_active_requests = 250;
    for tool in [
        "graphql-auth-validator",
        "workflow-invariant-validator",
        "parser-boundary-validator",
        "webhook-replay-validator",
        "safe-egress-validator",
        "identity-workflow-validator",
        "cloud-iam-graph-validator",
        "web3-invariant-validator",
        "ci-evidence-gate",
    ] {
        if !budget.allowed_tools.iter().any(|item| item == tool) {
            budget.allowed_tools.push(tool.to_string());
        }
    }
    let report = run_research_engine(&input, &budget);
    let mut surface_counts = BTreeMap::<String, usize>::new();
    for hypothesis in &report.hypotheses {
        *surface_counts
            .entry(research_surface_label(&hypothesis.surface).to_string())
            .or_default() += 1;
    }
    Ok(json!({
        "created_at": utc_now(),
        "input": {
            "run_id": input.run_id,
            "scope_summary": input.scope_summary,
            "endpoints": input.endpoints.len(),
            "findings": input.findings.len(),
            "evidence_refs": input.evidence_refs.len()
        },
        "summary": {
            "readiness_score": report.readiness_score,
            "recon_nodes": report.graph.nodes.len(),
            "recon_edges": report.graph.edges.len(),
            "coverage_gaps": report.graph.coverage_gaps.len(),
            "hypotheses": report.hypotheses.len(),
            "proof_plans": report.proof_plans.len(),
            "false_positive_challenges": report.challenges.len(),
            "blocking_challenges": report.challenges.iter().filter(|challenge| challenge.blocking).count(),
            "memory_records": report.memory_records.len(),
            "surface_counts": surface_counts
        },
        "graph": report.graph,
        "hypotheses": report.hypotheses,
        "proof_plans": report.proof_plans,
        "challenges": report.challenges,
        "memory_records": report.memory_records,
        "next_actions": report.next_actions
    }))
}

fn research_agent_input(config: &ApiConfig) -> Result<AgentInput> {
    let endpoints = collect_research_endpoints(config)?;
    let findings = collect_research_findings(config)?;
    let evidence_refs = collect_research_evidence_refs(config)?;
    let mut context = BTreeMap::new();
    context.insert(
        "control_plane".to_string(),
        json!("local BALONCORE SaaS workbench"),
    );
    context.insert(
        "authorization_policy".to_string(),
        json!("active validation requires authorized=true and request budgets"),
    );
    Ok(AgentInput {
        role: "autonomous-research-engine".to_string(),
        run_id: format!("research-{}", utc_now().replace([':', '-'], "")),
        scope_summary: "authorized local BALONCORE workbench evidence".to_string(),
        endpoints,
        findings,
        evidence_refs,
        context,
    })
}

fn collect_research_endpoints(config: &ApiConfig) -> Result<Vec<String>> {
    let mut endpoints = BTreeSet::<String>::new();
    if config.workbench_root.exists() {
        for path in collect_files(&config.workbench_root, "matrix_summary.json")? {
            let matrix = read_json(&path)?;
            for validation in matrix
                .get("validations")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
            {
                if let Some(endpoint) = validation.get("endpoint").and_then(Value::as_str) {
                    endpoints.insert(endpoint.to_string());
                }
            }
            for endpoint in matrix
                .pointer("/coverage/endpoints")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
            {
                if let Some(id) = endpoint.get("id").and_then(Value::as_str) {
                    endpoints.insert(id.to_string());
                }
            }
        }
        for path in collect_files(&config.workbench_root, "openapi_inventory.json")? {
            let inventory = read_json(&path)?;
            for endpoint in inventory
                .get("endpoints")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
            {
                if let Some(id) = endpoint.get("id").and_then(Value::as_str) {
                    endpoints.insert(id.to_string());
                } else {
                    let method = endpoint
                        .get("method")
                        .and_then(Value::as_str)
                        .unwrap_or("GET");
                    let path = endpoint
                        .get("path")
                        .or_else(|| endpoint.get("url_template"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if !path.is_empty() {
                        endpoints.insert(format!("{} {}", method.to_ascii_uppercase(), path));
                    }
                }
            }
        }
    }
    if endpoints.is_empty() {
        endpoints.extend([
            "GET /api/invoices/{id}".to_string(),
            "GET /api/admin/reports/{id}".to_string(),
            "POST /api/import".to_string(),
            "POST /api/webhooks/provider".to_string(),
            "POST /api/fetch-url".to_string(),
            "POST /graphql".to_string(),
        ]);
    }
    Ok(endpoints.into_iter().take(150).collect())
}

fn collect_research_findings(config: &ApiConfig) -> Result<Vec<AgentFindingSummary>> {
    let mut findings = Vec::new();
    if config.workbench_root.exists() {
        for path in collect_files(&config.workbench_root, "matrix_summary.json")? {
            let matrix = read_json(&path)?;
            for validation in matrix
                .get("validations")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
            {
                let is_verified = validation.pointer("/decision/Verified").is_some();
                if !is_verified {
                    continue;
                }
                let class = validation
                    .get("classification")
                    .and_then(Value::as_str)
                    .unwrap_or("VerifiedBehavior");
                if matches!(
                    class,
                    "IntendedPrivilegedAccess" | "IntendedOwnerAccess" | "BlockedAsExpected"
                ) {
                    continue;
                }
                let endpoint = validation
                    .get("endpoint")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let severity = validation
                    .pointer("/impact/severity")
                    .and_then(Value::as_str)
                    .unwrap_or("High");
                let evidence_refs = validation
                    .get("artifacts")
                    .and_then(Value::as_str)
                    .map(|artifact| vec![artifact.to_string()])
                    .unwrap_or_else(|| vec![relative_to_repo(config, &path)]);
                findings.push(AgentFindingSummary {
                    finding_id: format!(
                        "finding-{}",
                        sha256_hex(format!("{class}:{endpoint}:{path:?}").as_bytes())[..12]
                            .to_string()
                    ),
                    classification: class.to_string(),
                    endpoint: endpoint.to_string(),
                    severity: severity.to_string(),
                    state: "verified".to_string(),
                    evidence_refs,
                });
            }
        }
    }
    Ok(findings.into_iter().take(100).collect())
}

fn collect_research_evidence_refs(config: &ApiConfig) -> Result<Vec<String>> {
    let mut refs = BTreeSet::<String>::new();
    if config.workbench_root.exists() {
        for file_name in [
            "openapi_inventory.json",
            "matrix_summary.json",
            "evidence_manifest.json",
            "proof_package.json",
            "repo_inventory.json",
            "web3_analysis.json",
            "cloud_iam_analysis.json",
            "artifact_index.json",
            "enterprise_scorecard.json",
        ] {
            for path in collect_files(&config.workbench_root, file_name)? {
                refs.insert(relative_to_repo(config, &path));
            }
        }
    }
    if refs.is_empty() {
        refs.extend([
            "openapi_inventory.json".to_string(),
            "matrix_summary.json".to_string(),
            "repo_inventory.json".to_string(),
            "web3_analysis.json".to_string(),
        ]);
    }
    Ok(refs.into_iter().take(160).collect())
}

fn research_surface_label(surface: &ResearchSurfaceKind) -> &'static str {
    match surface {
        ResearchSurfaceKind::WebApi => "Web/API",
        ResearchSurfaceKind::WebApp => "Web App",
        ResearchSurfaceKind::CloudIam => "Cloud/IAM",
        ResearchSurfaceKind::Web3 => "Web3",
        ResearchSurfaceKind::Repository => "Repository",
        ResearchSurfaceKind::CiCd => "CI/CD",
        ResearchSurfaceKind::Finding => "Finding",
        ResearchSurfaceKind::Evidence => "Evidence",
        ResearchSurfaceKind::Unknown => "Unknown",
    }
}

fn risk_register(config: &ApiConfig) -> Result<Value> {
    let jobs = list_jobs(config)?;
    let mut risks = Vec::new();
    for job in jobs.as_array().cloned().unwrap_or_default() {
        let job_id = job
            .get("job_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let job_type = job.get("type").and_then(Value::as_str).unwrap_or("unknown");
        let status = job
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let score = job
            .pointer("/result/run_intelligence/score")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let readiness = job
            .pointer("/result/run_intelligence/readiness")
            .and_then(Value::as_str)
            .unwrap_or("no_readiness");
        let signals = job
            .pointer("/result/run_intelligence/signals")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let verified = signals
            .get("verified_webapi_findings")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let repo_secret_hits = signals
            .get("repo_secret_hits")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let web3_findings = signals
            .get("web3_findings")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        if verified > 0 {
            risks.push(json!({
                "id": format!("risk-{job_id}-webapi"),
                "title": "Verified exploitable web/API authorization weakness",
                "surface": "Web/API",
                "severity": "Critical",
                "state": if status == "succeeded" { "verified" } else { "needs_review" },
                "score": score,
                "readiness": readiness,
                "job_id": job_id,
                "evidence": "live request/response proof, proof package, remediation, regression replay",
                "owner": "Application Security",
                "next_action": "Patch authorization guard and run BALONCORE regression in CI."
            }));
        }
        if repo_secret_hits > 0 {
            risks.push(json!({
                "id": format!("risk-{job_id}-secrets"),
                "title": "Repository exposure signal requires credential review",
                "surface": "Repository",
                "severity": "High",
                "state": "triage",
                "score": score,
                "readiness": readiness,
                "job_id": job_id,
                "evidence": "redacted secret pattern with local-only storage",
                "owner": "Platform Security",
                "next_action": "Review redacted hit, rotate real credentials, enforce secret scanning."
            }));
        }
        if web3_findings > 0 {
            risks.push(json!({
                "id": format!("risk-{job_id}-web3"),
                "title": "Web3 invariant candidates require protocol proof execution",
                "surface": "Web3",
                "severity": "Medium",
                "state": "candidate",
                "score": score,
                "readiness": readiness,
                "job_id": job_id,
                "evidence": "Solidity analysis and generated invariant proof-test handoff",
                "owner": "Protocol Security",
                "next_action": "Run generated Foundry/Hardhat proof tests and promote confirmed violations."
            }));
        }
        if score == 0 && job_type != "unknown" {
            risks.push(json!({
                "id": format!("risk-{job_id}-coverage"),
                "title": "Security run has no scored proof yet",
                "surface": title_case(job_type),
                "severity": "Informational",
                "state": "coverage_gap",
                "score": score,
                "readiness": readiness,
                "job_id": job_id,
                "evidence": "job exists without proof score",
                "owner": "Security Operations",
                "next_action": "Add scope seeds, credentials, or provider fixture to increase validation depth."
            }));
        }
    }
    let mut grouped = BTreeMap::<String, Value>::new();
    for mut risk in risks {
        let key = format!(
            "{}:{}",
            risk.get("surface").and_then(Value::as_str).unwrap_or(""),
            risk.get("title").and_then(Value::as_str).unwrap_or("")
        );
        if let Some(existing) = grouped.get_mut(&key) {
            let recurrence = existing
                .get("recurrence_count")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                + 1;
            existing["recurrence_count"] = json!(recurrence);
            let mut samples = existing
                .get("sample_job_ids")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if samples.len() < 5 {
                if let Some(job_id) = risk.get("job_id").and_then(Value::as_str) {
                    samples.push(json!(job_id));
                }
            }
            existing["sample_job_ids"] = Value::Array(samples);
        } else {
            risk["recurrence_count"] = json!(1);
            risk["sample_job_ids"] = json!(risk
                .get("job_id")
                .and_then(Value::as_str)
                .map(|job_id| vec![job_id.to_string()])
                .unwrap_or_default());
            grouped.insert(key, risk);
        }
    }
    let mut risks = grouped.into_values().collect::<Vec<_>>();
    risks.sort_by(|a, b| {
        let severity = severity_rank(a.get("severity").and_then(Value::as_str).unwrap_or("")).cmp(
            &severity_rank(b.get("severity").and_then(Value::as_str).unwrap_or("")),
        );
        if severity == std::cmp::Ordering::Equal {
            b.get("recurrence_count")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                .cmp(
                    &a.get("recurrence_count")
                        .and_then(Value::as_u64)
                        .unwrap_or(1),
                )
        } else {
            severity
        }
    });
    Ok(json!({
        "created_at": utc_now(),
        "count": risks.len(),
        "risks": risks.into_iter().take(30).collect::<Vec<_>>()
    }))
}

fn defense_plan(config: &ApiConfig) -> Result<Value> {
    let command = security_command_center_without_expansions(config)?;
    let signals = command
        .pointer("/proof_twin/signals")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let verified = signals
        .get("verified_webapi_findings")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let secret_hits = signals
        .get("repo_secret_hits")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let evidence = signals
        .get("evidence_manifests")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let mut actions = Vec::new();
    actions.push(json!({
        "id": "defense-scopeguard",
        "priority": "P0",
        "title": "Keep ScopeGuard enabled before every active validation",
        "owner": "Security Operations",
        "status": "enforced",
        "impact": "Prevents unsafe, unauthorized, or noisy validation traffic."
    }));
    if verified > 0 {
        actions.push(json!({
            "id": "defense-authz-regression",
            "priority": "P0",
            "title": "Promote verified authorization proof into CI regression",
            "owner": "Application Engineering",
            "status": "ready",
            "impact": "Stops BOLA/BFLA/missing-auth regressions from shipping again."
        }));
        actions.push(json!({
            "id": "defense-sensitive-fields",
            "priority": "P1",
            "title": "Add response-level sensitive field guards",
            "owner": "AppSec",
            "status": "ready",
            "impact": "Reduces blast radius when authorization controls fail."
        }));
    }
    if secret_hits > 0 {
        actions.push(json!({
            "id": "defense-secret-rotation",
            "priority": "P0",
            "title": "Review and rotate redacted repository secret hits",
            "owner": "Platform Security",
            "status": "triage",
            "impact": "Prevents credential reuse turning code exposure into infrastructure compromise."
        }));
    }
    if evidence > 0 {
        actions.push(json!({
            "id": "defense-evidence-trust",
            "priority": "P1",
            "title": "Require signed evidence bundles before customer export",
            "owner": "Security Governance",
            "status": "ready",
            "impact": "Makes findings attributable, tamper-evident, and board/audit friendly."
        }));
    }
    actions.push(json!({
        "id": "defense-sector-pack",
        "priority": "P2",
        "title": "Map each verified risk to sector controls and detection rules",
        "owner": "Customer Success Security",
        "status": "planned",
        "impact": "Turns offensive proof into compliance-ready prevention language."
    }));
    Ok(json!({
        "created_at": utc_now(),
        "name": "BALONCORE Defense Fabric Plan",
        "actions": actions,
        "playbooks": [
            { "name": "API Authorization Hardening", "outputs": ["policy check", "regression replay", "remediation note"] },
            { "name": "Evidence Trust", "outputs": ["manifest", "signature", "trusted signer check"] },
            { "name": "Exposure Response", "outputs": ["rotation", "redaction", "CI gate"] }
        ]
    }))
}

fn attack_graph(config: &ApiConfig) -> Result<Value> {
    let risk = risk_register(config)?;
    let risk_count = risk
        .get("count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    Ok(json!({
        "created_at": utc_now(),
        "nodes": [
            { "id": "asset-api", "label": "Customer API", "kind": "asset", "state": "in_scope" },
            { "id": "auth-matrix", "label": "Auth Matrix", "kind": "validator", "state": "active" },
            { "id": "proof-kernel", "label": "Proof Kernel", "kind": "proof", "state": "verified" },
            { "id": "evidence-ledger", "label": "Evidence Ledger", "kind": "trust", "state": "signed" },
            { "id": "ci-defense", "label": "CI Defense", "kind": "defense", "state": "replayable" },
            { "id": "repo-surface", "label": "Repo Surface", "kind": "asset", "state": "observed" },
            { "id": "cloud-iam", "label": "Cloud/IAM", "kind": "asset", "state": "foundation" }
        ],
        "edges": [
            { "from": "asset-api", "to": "auth-matrix", "label": "authorized traffic budget" },
            { "from": "auth-matrix", "to": "proof-kernel", "label": "candidate promoted only with evidence" },
            { "from": "proof-kernel", "to": "evidence-ledger", "label": "manifest + signature" },
            { "from": "evidence-ledger", "to": "ci-defense", "label": "regression and policy gate" },
            { "from": "repo-surface", "to": "proof-kernel", "label": "secret/IaC/Web3 signals" },
            { "from": "cloud-iam", "to": "ci-defense", "label": "least privilege hardening" }
        ],
        "risk_pressure": risk_count,
        "moat": "The same graph carries hypothesis, proof, evidence trust, regression, and defense."
    }))
}

fn policy_gates(config: &ApiConfig) -> Result<Value> {
    let overview = saas_overview(config)?;
    let summary = overview
        .get("summary")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let latest_score = summary
        .get("latest_score")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let evidence_bundles = summary
        .get("signed_evidence_bundles")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let verified = summary
        .get("verified_findings")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    Ok(json!({
        "created_at": utc_now(),
        "gates": [
            {
                "name": "Authorization required",
                "status": "pass",
                "severity": "blocking",
                "detail": "Active scan endpoints require authorized=true and local-safe defaults."
            },
            {
                "name": "Exploitability proof exists",
                "status": if latest_score >= 85 { "pass" } else { "warn" },
                "severity": "blocking",
                "detail": format!("Strongest proof score is {latest_score}.")
            },
            {
                "name": "Evidence trust available",
                "status": if evidence_bundles > 0 { "pass" } else { "warn" },
                "severity": "high",
                "detail": format!("{evidence_bundles} evidence manifest signal(s) observed.")
            },
            {
                "name": "Verified risk is actionable",
                "status": if verified > 0 { "pass" } else { "watch" },
                "severity": "medium",
                "detail": format!("{verified} verified finding signal(s) available for remediation.")
            },
            {
                "name": "Tenant audit trail",
                "status": if load_audit_events(config)?.is_empty() { "warn" } else { "pass" },
                "severity": "medium",
                "detail": "Customer onboarding and scan activity emit local audit events."
            }
        ]
    }))
}

fn executive_brief(config: &ApiConfig) -> Result<Value> {
    let overview = saas_overview(config)?;
    let summary = overview
        .get("summary")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let risk = risk_register(config)?;
    let gates = policy_gates(config)?;
    let command = security_command_center_without_expansions(config)?;
    let latest_score = summary
        .get("latest_score")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let verified = summary
        .get("verified_findings")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let evidence_bundles = summary
        .get("signed_evidence_bundles")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let risk_count = risk
        .get("count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let watch_gates = gates
        .get("gates")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|gate| {
                    gate.get("status")
                        .and_then(Value::as_str)
                        .map(|status| status != "pass")
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or_default();
    let top_risk = risk
        .get("risks")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "severity": "Informational",
                "title": "No verified risk has been promoted yet",
                "surface": "Coverage"
            })
        });
    let verdict = if latest_score >= 85 && verified > 0 && evidence_bundles > 0 {
        "board_ready_verified_proof"
    } else if latest_score >= 60 || verified > 0 {
        "operator_review_needed"
    } else {
        "needs_more_scope_and_evidence"
    };
    Ok(json!({
        "created_at": utc_now(),
        "verdict": verdict,
        "headline": if verified > 0 {
            "BALONCORE has converted an authorized security test into verified exploitability evidence and replayable defense work."
        } else {
            "BALONCORE is ready to run authorized validation, but needs more scoped evidence before making strong claims."
        },
        "board_metrics": [
            { "label": "Proof confidence", "value": latest_score, "unit": "score" },
            { "label": "Verified finding signals", "value": verified, "unit": "signals" },
            { "label": "Signed evidence bundles", "value": evidence_bundles, "unit": "bundles" },
            { "label": "Tracked risk themes", "value": risk_count, "unit": "risks" },
            { "label": "Policy gates needing review", "value": watch_gates, "unit": "gates" }
        ],
        "top_risk": top_risk,
        "assurance_statement": command
            .pointer("/proof_twin/policy")
            .and_then(Value::as_str)
            .unwrap_or("Deterministic validators must prove every claim."),
        "next_72_hours": [
            "Patch verified authorization failures and rerun BALONCORE regression checks.",
            "Require signed evidence and policy gates before customer-facing export.",
            "Promote defense rule packs into application middleware, CI, and detection backlogs.",
            "Add the next scoped asset class, then compare new proof against this baseline."
        ],
        "why_it_stands_out": [
            "Proof-first: findings require scoped evidence, response capture, and false-positive kill checks.",
            "Defense-first: every verified issue has regression and control output.",
            "Enterprise-ready: tenant audit records, scope contracts, and evidence trust are part of the workflow.",
            "Sector-aware: proof language maps into SaaS, fintech, health, Web3, and cloud control language."
        ]
    }))
}

fn defense_rules(config: &ApiConfig) -> Result<Value> {
    let risk = risk_register(config)?;
    let risks = risk
        .get("risks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let has_verified_api = risks.iter().any(|risk| {
        risk.get("surface").and_then(Value::as_str) == Some("Web/API")
            && risk.get("severity").and_then(Value::as_str) == Some("Critical")
    });
    let has_repo_secret = risks.iter().any(|risk| {
        risk.get("surface").and_then(Value::as_str) == Some("Repository")
            && risk.get("severity").and_then(Value::as_str) == Some("High")
    });
    let has_web3 = risks
        .iter()
        .any(|risk| risk.get("surface").and_then(Value::as_str) == Some("Web3"));
    let mut packs = Vec::new();
    packs.push(json!({
        "id": "rule-scopeguard",
        "name": "ScopeGuard active-validation policy",
        "surface": "Platform",
        "priority": "P0",
        "status": "enforced",
        "summary": "Require explicit authorization, local-safe defaults, and request budgets before active validation.",
        "outputs": ["tenant audit event", "scope contract", "scan admission gate"],
        "snippet": "deny scan unless authorized=true and target is inside the signed scope contract"
    }));
    if has_verified_api {
        packs.push(json!({
            "id": "rule-tenant-object-guard",
            "name": "Tenant object authorization guard",
            "surface": "Web/API",
            "priority": "P0",
            "status": "ready",
            "summary": "Block cross-tenant object access unless the subject owns the resource or has an explicit privileged grant.",
            "outputs": ["middleware policy", "OPA/Rego sketch", "CI regression replay"],
            "snippet": "default allow=false; allow when subject.tenant_id == resource.tenant_id; allow when privileged role is explicitly granted for the action"
        }));
        packs.push(json!({
            "id": "rule-sensitive-response-minimizer",
            "name": "Sensitive response minimizer",
            "surface": "Web/API",
            "priority": "P1",
            "status": "ready",
            "summary": "Redact sensitive fields when authorization context is weak, anonymous, or cross-tenant.",
            "outputs": ["response policy", "field allowlist", "negative regression check"],
            "snippet": "if subject is anonymous or tenant mismatch then remove owner_email, owner_id, financial identifiers, internal notes"
        }));
    }
    if has_repo_secret {
        packs.push(json!({
            "id": "rule-secret-rotation-gate",
            "name": "Credential exposure response gate",
            "surface": "Repository",
            "priority": "P0",
            "status": "triage",
            "summary": "Convert redacted secret hits into owner review, rotation tracking, and CI prevention.",
            "outputs": ["rotation ticket", "secret-scan CI check", "redaction audit"],
            "snippet": "block merge when new high-confidence credential pattern appears outside an approved suppression"
        }));
    }
    if has_web3 {
        packs.push(json!({
            "id": "rule-web3-invariant-runner",
            "name": "Protocol invariant proof runner",
            "surface": "Web3",
            "priority": "P1",
            "status": "candidate",
            "summary": "Promote invariant candidates into local Foundry/Hardhat proof runs before reporting protocol risk.",
            "outputs": ["generated tests", "proof manifest", "confirmed/falsified status"],
            "snippet": "candidate invariant remains informational until a deterministic local proof run confirms it"
        }));
    }
    packs.push(json!({
        "id": "rule-evidence-trust-gate",
        "name": "Evidence trust release gate",
        "surface": "Governance",
        "priority": "P1",
        "status": "ready",
        "summary": "Require intact, signed, trusted evidence before report export or CI pass.",
        "outputs": ["manifest verification", "trusted signer check", "SARIF export gate"],
        "snippet": "release report only when evidence manifest verifies and signer is trusted"
    }));
    Ok(json!({
        "created_at": utc_now(),
        "count": packs.len(),
        "packs": packs
    }))
}

fn sector_threat_model(config: &ApiConfig) -> Result<Value> {
    let overview = saas_overview(config)?;
    let customers = overview
        .get("customers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut sectors = BTreeMap::<String, u64>::new();
    for customer in customers {
        if let Some(sector) = customer.get("sector").and_then(Value::as_str) {
            *sectors.entry(sector.to_string()).or_insert(0) += 1;
        }
    }
    let packs = vec![
        json!({
            "sector": "SaaS",
            "focus": "tenant isolation, BOLA/BFLA, data export controls, admin impersonation paths",
            "primary_controls": ["object ownership checks", "admin action audit", "response minimization", "CI auth regression"],
            "baloncore_edge": "maps each proof to tenant-impact language and regression checks"
        }),
        json!({
            "sector": "Fintech",
            "focus": "financial object exposure, payment metadata, authorization drift, evidence integrity",
            "primary_controls": ["strong object authorization", "sensitive field gating", "trusted evidence export", "change-control CI gates"],
            "baloncore_edge": "turns verified data exposure into board-grade evidence and prevention controls"
        }),
        json!({
            "sector": "Health",
            "focus": "patient data minimization, access auditability, privacy-impact proof, export redaction",
            "primary_controls": ["least data response", "role-aware access checks", "redaction blockers", "audit trail review"],
            "baloncore_edge": "keeps sensitive evidence local and forces redaction review before export"
        }),
        json!({
            "sector": "Web3",
            "focus": "protocol invariants, privileged contract paths, accounting drift, oracle/trust assumptions",
            "primary_controls": ["generated invariant tests", "protocol proof manifest", "privilege path review", "economic impact triage"],
            "baloncore_edge": "connects source analysis to deterministic local proof tests"
        }),
        json!({
            "sector": "Cloud",
            "focus": "public exposure, IAM privilege chains, trust relationships, deployment drift",
            "primary_controls": ["offline graph analysis", "least privilege fixes", "exposure policy gates", "terraform drift review"],
            "baloncore_edge": "models attack paths without needing unsafe live exploitation"
        }),
    ];
    Ok(json!({
        "created_at": utc_now(),
        "observed_customer_sectors": sectors,
        "packs": packs,
        "positioning": "Sector packs keep BALONCORE from being a generic scanner: the same proof is translated into controls that buyers, auditors, and engineering teams understand."
    }))
}

fn metrics_path(config: &ApiConfig) -> PathBuf {
    config
        .repo_root
        .join(".baloncore")
        .join("evidence")
        .join("metrics.json")
}

fn evidence_store_path(config: &ApiConfig) -> PathBuf {
    config
        .repo_root
        .join(".baloncore")
        .join("evidence")
        .join("index.json")
}

fn metrics_summary(config: &ApiConfig) -> Result<Value> {
    let path = metrics_path(config);
    let rollup = if path.exists() {
        baloncore_core::load_metrics_rollup(&path)
            .map_err(|e| anyhow!("failed to load metrics rollup: {}", e))?
    } else {
        MetricsRollup::new()
    };
    let summary = &rollup.cumulative;
    Ok(json!({
        "total_scans": summary.total_scans,
        "total_findings": summary.total_findings,
        "verified_findings": summary.verified_findings,
        "verified_findings_per_scan": summary.verified_findings_per_scan,
        "rejected_hypotheses": summary.rejected_hypotheses,
        "false_positive_reduction_rate": summary.false_positive_reduction_rate,
        "retest_success_rate": summary.retest_success_rate,
        "ci_blocked_criticals": summary.ci_blocked_criticals,
        "model_calls_per_verified": summary.model_calls_per_verified,
        "tokens_per_verified": summary.tokens_per_verified,
        "per_vuln_class": summary.per_vuln_class,
        "time_to_proof": summary.time_to_proof,
        "time_to_fix": summary.time_to_fix,
    }))
}

fn metrics_trend(config: &ApiConfig, metric: &str, bucket: &str) -> Result<Value> {
    let path = metrics_path(config);
    let rollup = if path.exists() {
        baloncore_core::load_metrics_rollup(&path)
            .map_err(|e| anyhow!("failed to load metrics rollup: {}", e))?
    } else {
        MetricsRollup::new()
    };
    let trend = baloncore_core::compute_metrics_trend(&rollup, metric, bucket);
    let points: Vec<Value> = trend
        .iter()
        .map(|point| {
            json!({
                "period": point.period,
                "metric": point.metric,
                "value": point.value,
                "sample_count": point.sample_count,
            })
        })
        .collect();
    Ok(json!({
        "metric": metric,
        "bucket": bucket,
        "points": points,
    }))
}

fn metrics_drilldown(config: &ApiConfig, metric: &str, period: Option<&str>) -> Result<Value> {
    let metrics_path = metrics_path(config);
    let rollup = if metrics_path.exists() {
        baloncore_core::load_metrics_rollup(&metrics_path)
            .map_err(|e| anyhow!("failed to load metrics rollup: {}", e))?
    } else {
        MetricsRollup::new()
    };

    let store_path = evidence_store_path(config);
    let store_data = std::fs::read_to_string(&store_path).unwrap_or_else(|_| "{}".to_string());
    let store: Value = serde_json::from_str(&store_data).unwrap_or_else(|_| json!({}));
    let scans = store
        .get("scans")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut matching_entries: Vec<Value> = Vec::new();
    for scan_entry in &rollup.per_scan {
        let scan_id = &scan_entry.scan_id;
        let scan_record = scans
            .iter()
            .find(|s| s.get("scan_id").and_then(Value::as_str) == Some(scan_id.as_str()));

        let mut findings_list: Vec<Value> = Vec::new();
        if let Some(record) = scan_record {
            findings_list = record
                .get("findings")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
        }

        let value = match metric {
            "verified_findings" => scan_entry.verified_findings as f64,
            "rejected_hypotheses" => scan_entry.rejected_hypotheses as f64,
            "suppressed_findings" => scan_entry.suppressed_findings as f64,
            "total_candidates" => scan_entry.total_candidates as f64,
            _ => scan_entry.verified_findings as f64,
        };

        matching_entries.push(json!({
            "scan_id": scan_id,
            "metric": metric,
            "value": value,
            "started_at": scan_entry.started_at,
            "computed_at": scan_entry.computed_at,
            "findings_count": findings_list.len(),
            "findings": findings_list,
        }));
    }

    if let Some(p) = period {
        matching_entries.retain(|entry| {
            entry
                .get("period")
                .and_then(Value::as_str)
                .map(|s| s.starts_with(p))
                .unwrap_or(true)
        });
    }

    Ok(json!({
        "metric": metric,
        "period_filter": period,
        "total_entries": matching_entries.len(),
        "entries": matching_entries,
    }))
}

fn security_command_center_without_expansions(config: &ApiConfig) -> Result<Value> {
    let jobs = list_jobs(config)?;
    let job_records = jobs.as_array().cloned().unwrap_or_default();
    let strongest = job_records
        .iter()
        .max_by_key(|job| {
            job.pointer("/result/run_intelligence/score")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        })
        .cloned()
        .unwrap_or_else(|| json!({}));
    let score = strongest
        .pointer("/result/run_intelligence/score")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let readiness = strongest
        .pointer("/result/run_intelligence/readiness")
        .and_then(Value::as_str)
        .unwrap_or("no_verified_runs");
    let signals = strongest
        .pointer("/result/run_intelligence/signals")
        .cloned()
        .unwrap_or_else(|| json!({}));

    Ok(json!({
        "created_at": utc_now(),
        "strongest_proof_job": strongest,
        "proof_twin": {
            "score": score,
            "readiness": readiness,
            "policy": "AI may propose; deterministic validators must prove; defense artifacts must replay.",
            "signals": signals
        }
    }))
}

fn onboard_customer(config: &ApiConfig, body: Value) -> Result<Value> {
    let company_name = required_string(&body, "company_name")?;
    let contact_email = required_string(&body, "contact_email")?;
    let sector = optional_string(&body, "sector", "SaaS");
    let plan = optional_string(&body, "plan", "Growth");
    let asset_count = body
        .get("asset_count")
        .and_then(Value::as_u64)
        .unwrap_or(12);
    let assets = body
        .get("assets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| {
            vec![
                json!("api"),
                json!("web_app"),
                json!("repository"),
                json!("cloud_iam"),
            ]
        });
    let mut customers = load_customers(config)?;
    let record = json!({
        "id": new_id("org"),
        "company_name": company_name.clone(),
        "contact_email": contact_email,
        "sector": sector.clone(),
        "plan": plan.clone(),
        "status": "trial",
        "asset_count": asset_count,
        "assets": assets,
        "created_at": utc_now(),
        "risk_posture": "pending_first_proof_run",
        "scope_contract": "pending_customer_authorization",
        "admin_notes": "New organization created through BALONCORE SaaS onboarding."
    });
    customers.push(record.clone());
    write_json(&customers_path(config), &Value::Array(customers))?;
    append_audit_event(
        config,
        "tenant.onboarded",
        "baloncore-admin",
        company_name.as_str(),
        json!({
            "company_name": company_name,
            "plan": plan,
            "sector": sector,
            "scope_contract": "pending_customer_authorization"
        }),
    )?;
    Ok(record)
}

fn update_scope_contract(config: &ApiConfig, body: Value) -> Result<Value> {
    let org_id = required_string(&body, "org_id")?;
    let scope_contract = optional_string(&body, "scope_contract", "signed");
    let mut customers = load_customers(config)?;
    let mut updated = None;
    for customer in &mut customers {
        if customer.get("id").and_then(Value::as_str) == Some(org_id.as_str()) {
            customer["scope_contract"] = json!(scope_contract);
            customer["scope_updated_at"] = json!(utc_now());
            if let Some(assets) = body.get("authorized_assets") {
                customer["authorized_assets"] = assets.clone();
            }
            updated = Some(customer.clone());
            break;
        }
    }
    let record = updated.with_context(|| format!("unknown organization: {org_id}"))?;
    write_json(&customers_path(config), &Value::Array(customers))?;
    append_audit_event(
        config,
        "tenant.scope_contract_updated",
        "baloncore-admin",
        org_id.as_str(),
        json!({
            "scope_contract": record.get("scope_contract").cloned().unwrap_or(Value::Null),
            "authorized_assets": record.get("authorized_assets").cloned().unwrap_or(Value::Null)
        }),
    )?;
    Ok(record)
}

fn load_audit_events(config: &ApiConfig) -> Result<Vec<Value>> {
    let path = audit_log_path(config);
    if !path.exists() {
        let defaults = vec![json!({
            "id": "audit-bootstrap",
            "created_at": utc_now(),
            "event_type": "system.bootstrap",
            "actor": "baloncore-system",
            "target": "local-saas-foundation",
            "detail": {
                "message": "BALONCORE local SaaS audit trail initialized."
            }
        })];
        write_json(&path, &Value::Array(defaults.clone()))?;
        return Ok(defaults);
    }
    Ok(read_json(&path)?.as_array().cloned().unwrap_or_default())
}

fn append_audit_event(
    config: &ApiConfig,
    event_type: &str,
    actor: &str,
    target: &str,
    detail: Value,
) -> Result<()> {
    let mut events = load_audit_events(config)?;
    events.push(json!({
        "id": new_id("audit"),
        "created_at": utc_now(),
        "event_type": event_type,
        "actor": actor,
        "target": target,
        "detail": detail
    }));
    write_json(&audit_log_path(config), &Value::Array(events))
}

fn security_modules() -> Value {
    json!([
        { "name": "API/Web Proof", "status": "live", "signal": "authorization flaws, sensitive response shape, missing-auth exposure" },
        { "name": "Repo Exposure", "status": "live", "signal": "secrets, CI, dependency manifests, IaC, Web3 projects" },
        { "name": "Cloud/IAM Graph", "status": "foundation", "signal": "privilege paths, public resources, risky trust edges" },
        { "name": "Web3 Forge", "status": "foundation", "signal": "Solidity patterns, generated invariants, proof-test handoff" },
        { "name": "Defense Fabric", "status": "live", "signal": "regression, signed evidence, SARIF, controls, detections" },
        { "name": "Admin Trust", "status": "live", "signal": "tenants, plans, queues, scope contracts, readiness" }
    ])
}

fn saas_backbone(config: &ApiConfig) -> Result<Value> {
    let organizations = load_customers(config)?;
    let projects = load_projects(config)?;
    let assets = load_assets(config)?;
    let workers = load_workers(config)?;
    let queue = worker_queue(config)?;
    let migrations = postgres_migrations(config)?;
    let audit_events = load_audit_events(config)?;
    Ok(json!({
        "name": "BALONCORE SaaS Control Plane Backbone",
        "created_at": utc_now(),
        "storage_mode": "postgres_ready_local_adapter",
        "postgres_schema": {
            "path": "crates/baloncore-api/migrations/0001_saas_control_plane.sql",
            "migrations": migrations,
            "required_for_hosted_saas": true
        },
        "domain_model": {
            "organizations": organizations.len(),
            "projects": projects.len(),
            "assets": assets.len(),
            "audit_events": audit_events.len()
        },
        "queue_model": {
            "jobs": queue.get("summary").cloned().unwrap_or_else(|| json!({})),
            "worker_pools": worker_pools(),
            "registered_workers": workers.len(),
            "attempt_records": load_job_attempts(config)?.len()
        },
        "hardening_gates": [
            { "name": "Tenant isolation model", "status": "implemented", "proof": "org/project/asset records with scope state" },
            { "name": "Durable job queue", "status": "implemented", "proof": "queue metadata persists with each job record" },
            { "name": "Worker abstraction", "status": "implemented", "proof": "worker pools, registered workers, and job attempts are exposed" },
            { "name": "Postgres migration", "status": if migrations.is_empty() { "missing" } else { "implemented" }, "proof": "SQL schema is versioned under crates/baloncore-api/migrations" },
            { "name": "Audit trail", "status": "implemented", "proof": "tenant, scope, job, and worker events are append-only local records" }
        ],
        "production_next": [
            "Run this migration in managed Postgres and swap the local JSON adapter for a sqlx repository.",
            "Move workers into isolated queue consumers with per-tenant network egress policies.",
            "Add SSO/RBAC session enforcement before exposing this beyond localhost.",
            "Move artifacts and evidence bundles into tenant-scoped object storage."
        ]
    }))
}

fn postgres_migrations(config: &ApiConfig) -> Result<Vec<Value>> {
    let migration_root = config.repo_root.join("crates/baloncore-api/migrations");
    if !migration_root.exists() {
        return Ok(Vec::new());
    }
    let mut entries = fs::read_dir(&migration_root)
        .with_context(|| format!("read migration dir {}", migration_root.display()))?
        .flatten()
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("sql"))
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    let mut migrations = Vec::new();
    for entry in entries {
        let path = entry.path();
        let sql = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        migrations.push(json!({
            "file": relative_to_repo(config, &path),
            "bytes": sql.len(),
            "sha256": sha256_hex(sql.as_bytes()),
            "tables_declared": sql.matches("CREATE TABLE").count()
        }));
    }
    Ok(migrations)
}

fn load_projects(config: &ApiConfig) -> Result<Vec<Value>> {
    let path = projects_path(config);
    if !path.exists() {
        let defaults = default_projects(config)?;
        write_json(&path, &Value::Array(defaults.clone()))?;
        return Ok(defaults);
    }
    Ok(read_json(&path)?.as_array().cloned().unwrap_or_default())
}

fn default_projects(config: &ApiConfig) -> Result<Vec<Value>> {
    let mut projects = Vec::new();
    for customer in load_customers(config)? {
        let org_id = customer
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("org-local");
        let company = customer
            .get("company_name")
            .and_then(Value::as_str)
            .unwrap_or("Local Organization");
        let sector = customer
            .get("sector")
            .and_then(Value::as_str)
            .unwrap_or("SaaS");
        projects.push(json!({
            "id": format!("project-{}", sanitize_slug(org_id.trim_start_matches("org-"))),
            "org_id": org_id,
            "name": format!("{company} Core Surface"),
            "kind": match sector {
                "Web3" => "protocol_security",
                "Healthcare" => "regulated_web_platform",
                "Fintech" => "financial_api_platform",
                _ => "web_api_platform"
            },
            "status": "active",
            "created_at": utc_now(),
            "risk_objective": "continuously prove exploitable risk and turn it into defense"
        }));
    }
    Ok(projects)
}

fn load_assets(config: &ApiConfig) -> Result<Vec<Value>> {
    let path = assets_path(config);
    if !path.exists() {
        let defaults = default_assets(config)?;
        write_json(&path, &Value::Array(defaults.clone()))?;
        return Ok(defaults);
    }
    Ok(read_json(&path)?.as_array().cloned().unwrap_or_default())
}

fn default_assets(config: &ApiConfig) -> Result<Vec<Value>> {
    let projects = load_projects(config)?;
    let mut project_by_org = BTreeMap::<String, String>::new();
    for project in projects {
        if let (Some(org_id), Some(project_id)) = (
            project.get("org_id").and_then(Value::as_str),
            project.get("id").and_then(Value::as_str),
        ) {
            project_by_org.insert(org_id.to_string(), project_id.to_string());
        }
    }
    let mut assets = Vec::new();
    for customer in load_customers(config)? {
        let org_id = customer
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("org-local");
        let project_id = project_by_org
            .get(org_id)
            .cloned()
            .unwrap_or_else(|| "project-local".to_string());
        let company_slug = sanitize_slug(
            customer
                .get("company_name")
                .and_then(Value::as_str)
                .unwrap_or("customer")
                .to_lowercase()
                .replace(' ', "-")
                .as_str(),
        );
        let scope_status =
            if customer.get("scope_contract").and_then(Value::as_str) == Some("signed") {
                "in_scope"
            } else {
                "pending_scope_contract"
            };
        for asset in customer
            .get("assets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let asset_type = asset.as_str().unwrap_or("web_app");
            assets.push(json!({
                "id": format!("asset-{}-{}", sanitize_slug(org_id.trim_start_matches("org-")), sanitize_slug(asset_type)),
                "org_id": org_id,
                "project_id": project_id,
                "asset_type": asset_type,
                "locator": default_asset_locator(&company_slug, asset_type),
                "scope_status": scope_status,
                "validation_mode": if scope_status == "in_scope" { "authorized_active_or_offline" } else { "offline_only_until_scope_signed" },
                "created_at": utc_now()
            }));
        }
    }
    Ok(assets)
}

fn default_asset_locator(company_slug: &str, asset_type: &str) -> String {
    match asset_type {
        "api" => format!("https://api.{company_slug}.example/openapi.json"),
        "web_app" => format!("https://app.{company_slug}.example"),
        "repository" => format!("git@example.com:{company_slug}/core.git"),
        "cloud_iam" => format!("aws://{company_slug}/organization"),
        "web3" => format!("protocol://{company_slug}/contracts"),
        other => format!("{other}://{company_slug}"),
    }
}

fn create_project(config: &ApiConfig, body: Value) -> Result<Value> {
    let org_id = required_string(&body, "org_id")?;
    let name = required_string(&body, "name")?;
    if !load_customers(config)?
        .iter()
        .any(|customer| customer.get("id").and_then(Value::as_str) == Some(org_id.as_str()))
    {
        bail!("unknown organization: {org_id}");
    }
    let record = json!({
        "id": new_id("project"),
        "org_id": org_id,
        "name": name,
        "kind": optional_string(&body, "kind", "web_api_platform"),
        "status": optional_string(&body, "status", "active"),
        "risk_objective": optional_string(&body, "risk_objective", "prove exploitability and prevent regressions"),
        "created_at": utc_now()
    });
    let mut projects = load_projects(config)?;
    projects.push(record.clone());
    write_json(&projects_path(config), &Value::Array(projects))?;
    append_audit_event(
        config,
        "project.created",
        "baloncore-admin",
        record
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
        json!({
            "org_id": record.get("org_id").cloned().unwrap_or(Value::Null),
            "kind": record.get("kind").cloned().unwrap_or(Value::Null)
        }),
    )?;
    Ok(record)
}

fn create_asset(config: &ApiConfig, body: Value) -> Result<Value> {
    let org_id = required_string(&body, "org_id")?;
    let project_id = required_string(&body, "project_id")?;
    let asset_type = optional_string(&body, "asset_type", "web_app");
    let locator = required_string(&body, "locator")?;
    if !load_projects(config)?.iter().any(|project| {
        project.get("id").and_then(Value::as_str) == Some(project_id.as_str())
            && project.get("org_id").and_then(Value::as_str) == Some(org_id.as_str())
    }) {
        bail!("project does not belong to organization");
    }
    let record = json!({
        "id": new_id("asset"),
        "org_id": org_id,
        "project_id": project_id,
        "asset_type": asset_type,
        "locator": locator,
        "scope_status": optional_string(&body, "scope_status", "pending_scope_contract"),
        "validation_mode": optional_string(&body, "validation_mode", "offline_only_until_scope_signed"),
        "created_at": utc_now()
    });
    let mut assets = load_assets(config)?;
    assets.push(record.clone());
    write_json(&assets_path(config), &Value::Array(assets))?;
    append_audit_event(
        config,
        "asset.created",
        "baloncore-admin",
        record
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
        json!({
            "org_id": record.get("org_id").cloned().unwrap_or(Value::Null),
            "project_id": record.get("project_id").cloned().unwrap_or(Value::Null),
            "asset_type": record.get("asset_type").cloned().unwrap_or(Value::Null),
            "scope_status": record.get("scope_status").cloned().unwrap_or(Value::Null)
        }),
    )?;
    Ok(record)
}

fn tenant_metadata(body: &Value, payload: &Value) -> Value {
    json!({
        "org_id": value_string(body, payload, "org_id", "org-atlas-fintech"),
        "project_id": value_string(body, payload, "project_id", "project-atlas-fintech"),
        "asset_id": value_string(body, payload, "asset_id", "asset-atlas-fintech-api")
    })
}

fn queue_metadata(job_id: &str, job_type: &str, body: &Value, payload: &Value) -> Value {
    let priority = body
        .get("priority")
        .or_else(|| payload.get("priority"))
        .and_then(Value::as_u64)
        .unwrap_or(50);
    let max_attempts = body
        .get("max_attempts")
        .or_else(|| payload.get("max_attempts"))
        .and_then(Value::as_u64)
        .unwrap_or(3);
    json!({
        "queue_id": format!("queue-{job_id}"),
        "state": "queued",
        "worker_pool": worker_pool_for_job_type(job_type),
        "priority": priority,
        "attempts": 0,
        "max_attempts": max_attempts,
        "available_at": utc_now(),
        "lease_owner": null,
        "lease_started_at": null,
        "lease_finished_at": null,
        "idempotency_key": value_string(body, payload, "idempotency_key", job_id)
    })
}

fn value_string(body: &Value, payload: &Value, key: &str, default: &str) -> String {
    body.get(key)
        .or_else(|| payload.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default)
        .chars()
        .take(160)
        .collect()
}

fn worker_pool_for_job_type(job_type: &str) -> &'static str {
    match job_type {
        "webapi_scan" => "webapi-validator",
        "repo_scan" => "repo-intelligence",
        "cloud_iam_analysis" => "cloud-iam",
        "web3_analysis" => "web3-proof",
        "evidence_gate" | "defense_bundle" => "evidence-defense",
        _ => "general-purpose",
    }
}

fn queue_state_from_job_status(status: Option<&str>) -> String {
    match status.unwrap_or("unknown") {
        "queued" => "queued",
        "running" => "running",
        "succeeded" => "succeeded",
        "failed" => "failed",
        _ => "unknown",
    }
    .to_string()
}

fn worker_queue(config: &ApiConfig) -> Result<Value> {
    let jobs = list_jobs(config)?;
    let attempts = load_job_attempts(config)?;
    let workers = load_workers(config)?;
    let mut states = BTreeMap::<String, u64>::new();
    let mut pools = BTreeMap::<String, u64>::new();
    let entries = jobs
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|job| {
            let job_type = job.get("type").and_then(Value::as_str).unwrap_or("unknown");
            let pool = job
                .pointer("/queue/worker_pool")
                .and_then(Value::as_str)
                .unwrap_or_else(|| worker_pool_for_job_type(job_type));
            let state = job
                .pointer("/queue/state")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| queue_state_from_job_status(job.get("status").and_then(Value::as_str)));
            *states.entry(state.clone()).or_default() += 1;
            *pools.entry(pool.to_string()).or_default() += 1;
            json!({
                "queue_id": job.pointer("/queue/queue_id").cloned().unwrap_or(Value::Null),
                "job_id": job.get("job_id").cloned().unwrap_or(Value::Null),
                "type": job.get("type").cloned().unwrap_or(Value::Null),
                "status": job.get("status").cloned().unwrap_or(Value::Null),
                "queue_state": state,
                "worker_pool": pool,
                "priority": job.pointer("/queue/priority").cloned().unwrap_or_else(|| json!(50)),
                "attempts": job.pointer("/queue/attempts").cloned().unwrap_or_else(|| json!(0)),
                "max_attempts": job.pointer("/queue/max_attempts").cloned().unwrap_or_else(|| json!(3)),
                "lease_owner": job.pointer("/queue/lease_owner").cloned().unwrap_or(Value::Null),
                "org_id": job.pointer("/tenant/org_id").cloned().unwrap_or(Value::Null),
                "project_id": job.pointer("/tenant/project_id").cloned().unwrap_or(Value::Null),
                "asset_id": job.pointer("/tenant/asset_id").cloned().unwrap_or(Value::Null),
                "created_at": job.get("created_at").cloned().unwrap_or(Value::Null),
                "updated_at": job.get("updated_at").cloned().unwrap_or(Value::Null)
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "created_at": utc_now(),
        "summary": {
            "total": entries.len(),
            "states": states,
            "pools": pools,
            "attempt_records": attempts.len(),
            "registered_workers": workers.len()
        },
        "worker_pools": worker_pools(),
        "workers": workers,
        "recent_attempts": attempts.into_iter().rev().take(12).collect::<Vec<_>>(),
        "jobs": entries
    }))
}

fn worker_pools() -> Value {
    json!([
        { "id": "webapi-validator", "job_types": ["webapi_scan"], "isolation": "scoped HTTP runner with request budget", "status": "local_ready" },
        { "id": "repo-intelligence", "job_types": ["repo_scan"], "isolation": "local filesystem allowlist and redacted secret handling", "status": "local_ready" },
        { "id": "cloud-iam", "job_types": ["cloud_iam_analysis"], "isolation": "offline provider export analysis", "status": "schema_ready" },
        { "id": "web3-proof", "job_types": ["web3_analysis"], "isolation": "local protocol proof-test runner", "status": "schema_ready" },
        { "id": "evidence-defense", "job_types": ["evidence_gate", "defense_bundle"], "isolation": "signed evidence and CI policy worker", "status": "schema_ready" }
    ])
}

fn register_worker(config: &ApiConfig, body: Value) -> Result<Value> {
    let worker_id = optional_string(&body, "worker_id", &new_id("worker"));
    let pool = optional_string(&body, "pool", "webapi-validator");
    let status = optional_string(&body, "status", "online");
    let capacity = body.get("capacity").and_then(Value::as_u64).unwrap_or(1);
    let record = upsert_worker_state(
        config,
        worker_id.as_str(),
        pool.as_str(),
        status.as_str(),
        capacity,
        json!({
            "registered_via": "api",
            "host": optional_string(&body, "host", "local")
        }),
    )?;
    append_audit_event(
        config,
        "worker.registered",
        "baloncore-admin",
        worker_id.as_str(),
        json!({
            "pool": pool,
            "status": status,
            "capacity": capacity
        }),
    )?;
    Ok(record)
}

fn reconcile_worker_queue(config: &ApiConfig, body: Value) -> Result<Value> {
    let force_job_id = body
        .get("job_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let max_runtime_seconds = body
        .get("max_runtime_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(900);
    let mut reconciled = Vec::new();
    for job in list_jobs(config)?.as_array().cloned().unwrap_or_default() {
        let job_id = job
            .get("job_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let is_forced = force_job_id.as_deref() == Some(job_id.as_str());
        let is_running = job.get("status").and_then(Value::as_str) == Some("running")
            || job.pointer("/queue/state").and_then(Value::as_str) == Some("running");
        if !is_running || (!is_forced && max_runtime_seconds != 0) {
            continue;
        }
        let mut record = read_job(config, job_id.as_str())?;
        let worker_id = record
            .pointer("/queue/lease_owner")
            .and_then(Value::as_str)
            .unwrap_or("unknown-worker")
            .to_string();
        record["status"] = json!("failed");
        record["error"] = json!("worker lease reconciled as stale");
        if !record.get("queue").map(Value::is_object).unwrap_or(false) {
            let job_type = record
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            record["queue"] = queue_metadata(
                job_id.as_str(),
                job_type.as_str(),
                &json!({}),
                &record["payload"],
            );
        }
        record["queue"]["state"] = json!("failed");
        record["queue"]["lease_owner"] = Value::Null;
        record["queue"]["lease_finished_at"] = json!(utc_now());
        record["finished_at"] = json!(utc_now());
        record["updated_at"] = json!(utc_now());
        write_job(config, &record)?;
        append_job_attempt(
            config,
            job_id.as_str(),
            worker_id.as_str(),
            "reconciled_stale",
            json!({
                "reason": "worker lease exceeded reconciliation policy or was manually forced",
                "max_runtime_seconds": max_runtime_seconds
            }),
        )?;
        reconciled.push(json!({
            "job_id": job_id,
            "worker_id": worker_id,
            "status": "failed",
            "reason": "stale_worker_lease"
        }));
    }
    if !reconciled.is_empty() {
        append_audit_event(
            config,
            "worker.queue_reconciled",
            "baloncore-admin",
            "worker-queue",
            json!({
                "reconciled": reconciled.clone()
            }),
        )?;
    }
    Ok(json!({
        "created_at": utc_now(),
        "reconciled_count": reconciled.len(),
        "reconciled": reconciled
    }))
}

fn load_workers(config: &ApiConfig) -> Result<Vec<Value>> {
    let path = workers_path(config);
    if !path.exists() {
        let defaults = vec![
            json!({
                "worker_id": "local-webapi-validator",
                "pool": "webapi-validator",
                "status": "online",
                "capacity": 1,
                "last_heartbeat": utc_now(),
                "metadata": { "runtime": "local-thread", "scope": "authorized web/api validation" }
            }),
            json!({
                "worker_id": "local-repo-intelligence",
                "pool": "repo-intelligence",
                "status": "online",
                "capacity": 1,
                "last_heartbeat": utc_now(),
                "metadata": { "runtime": "local-thread", "scope": "authorized repo inventory" }
            }),
        ];
        write_json(&path, &Value::Array(defaults.clone()))?;
        return Ok(defaults);
    }
    Ok(read_json(&path)?.as_array().cloned().unwrap_or_default())
}

fn upsert_worker_state(
    config: &ApiConfig,
    worker_id: &str,
    pool: &str,
    status: &str,
    capacity: u64,
    metadata: Value,
) -> Result<Value> {
    let mut workers = load_workers(config)?;
    let record = json!({
        "worker_id": worker_id,
        "pool": pool,
        "status": status,
        "capacity": capacity,
        "last_heartbeat": utc_now(),
        "metadata": metadata
    });
    if let Some(existing) = workers
        .iter_mut()
        .find(|worker| worker.get("worker_id").and_then(Value::as_str) == Some(worker_id))
    {
        *existing = record.clone();
    } else {
        workers.push(record.clone());
    }
    write_json(&workers_path(config), &Value::Array(workers))?;
    Ok(record)
}

fn load_job_attempts(config: &ApiConfig) -> Result<Vec<Value>> {
    let path = job_attempts_path(config);
    if !path.exists() {
        write_json(&path, &json!([]))?;
    }
    Ok(read_json(&path)?.as_array().cloned().unwrap_or_default())
}

fn append_job_attempt(
    config: &ApiConfig,
    job_id: &str,
    worker_id: &str,
    status: &str,
    detail: Value,
) -> Result<()> {
    let mut attempts = load_job_attempts(config)?;
    attempts.push(json!({
        "id": new_id("attempt"),
        "job_id": job_id,
        "worker_id": worker_id,
        "status": status,
        "created_at": utc_now(),
        "detail": detail
    }));
    write_json(&job_attempts_path(config), &Value::Array(attempts))
}

fn load_customers(config: &ApiConfig) -> Result<Vec<Value>> {
    let path = customers_path(config);
    if !path.exists() {
        let defaults = default_customers();
        write_json(&path, &Value::Array(defaults.clone()))?;
        return Ok(defaults);
    }
    Ok(read_json(&path)?.as_array().cloned().unwrap_or_default())
}

fn default_customers() -> Vec<Value> {
    vec![
        json!({
            "id": "org-atlas-fintech",
            "company_name": "Atlas Fintech",
            "contact_email": "security@atlas.example",
            "sector": "Fintech",
            "plan": "Enterprise",
            "status": "active",
            "asset_count": 68,
            "assets": ["api", "web_app", "cloud_iam", "repository"],
            "created_at": "2026-05-20T09:00:00Z",
            "risk_posture": "proof_ready",
            "scope_contract": "signed"
        }),
        json!({
            "id": "org-northstar-health",
            "company_name": "Northstar Health",
            "contact_email": "appsec@northstar.example",
            "sector": "Healthcare",
            "plan": "Growth",
            "status": "pilot",
            "asset_count": 31,
            "assets": ["api", "web_app", "repository"],
            "created_at": "2026-05-21T15:30:00Z",
            "risk_posture": "active_validation",
            "scope_contract": "signed"
        }),
        json!({
            "id": "org-protocol-forge",
            "company_name": "Protocol Forge",
            "contact_email": "audit@protocolforge.example",
            "sector": "Web3",
            "plan": "Protocol Pack",
            "status": "trial",
            "asset_count": 14,
            "assets": ["web3", "repository", "api"],
            "created_at": "2026-05-23T11:15:00Z",
            "risk_posture": "needs_first_signed_bundle",
            "scope_contract": "pending"
        }),
    ]
}

fn required_string(body: &Value, key: &str) -> Result<String> {
    let value = body
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{key} is required"))?;
    Ok(value.chars().take(160).collect())
}

fn optional_string(body: &Value, key: &str, default: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default)
        .chars()
        .take(160)
        .collect()
}

fn scan_repo(config: &ApiConfig, payload: &Value) -> Result<Value> {
    let target_path = payload
        .get("path")
        .and_then(Value::as_str)
        .context("path is required")?;
    let target_path = resolve_local_path(config, target_path)?;
    let out_dir = make_run_dir(config, "repo-scan")?;
    let inventory = scan_repository(config, &target_path, &out_dir)?;
    let mut commands = Vec::new();
    for (index, web3_root) in web3_project_roots(&target_path, &inventory)
        .into_iter()
        .enumerate()
    {
        let slug = sanitize_slug(
            web3_root
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("project"),
        );
        let web3_out = out_dir
            .join("web3")
            .join(format!("{:02}_{}", index + 1, slug));
        fs::create_dir_all(&web3_out).context("create web3 output dir")?;
        commands.push(run_command(
            config,
            vec![
                "cargo".to_string(),
                "run".to_string(),
                "-p".to_string(),
                "baloncore".to_string(),
                "--".to_string(),
                "analyze-web3".to_string(),
                web3_root.display().to_string(),
                "--out-dir".to_string(),
                web3_out.display().to_string(),
                "--json".to_string(),
            ],
            &out_dir,
            payload
                .get("timeout_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(300),
        )?);
    }

    let ok = commands
        .iter()
        .all(|command| command.get("ok").and_then(Value::as_bool) == Some(true));
    let mut result = json!({
        "ok": ok,
        "run_dir": out_dir,
        "inventory": inventory,
        "commands": commands
    });
    write_json(&out_dir.join("repo_scan_result.json"), &result)?;
    let intelligence = write_run_intelligence(config, &out_dir, "repo_scan")?;
    result["run_intelligence"] = intelligence;
    result["artifact_paths"] = list_artifacts(config, Some(&out_dir))?;
    write_json(&out_dir.join("repo_scan_result.json"), &result)?;
    Ok(result)
}

fn scan_webapp(config: &ApiConfig, payload: &Value) -> Result<Value> {
    let base_url = payload
        .get("base_url")
        .and_then(Value::as_str)
        .context("base_url is required")?;
    let openapi_url = payload
        .get("openapi_url")
        .and_then(Value::as_str)
        .context("openapi_url is required")?;
    let owner_profile = payload
        .get("owner_profile")
        .and_then(Value::as_str)
        .unwrap_or("user_b");
    let config_path = payload
        .get("config")
        .and_then(Value::as_str)
        .unwrap_or("baloncore.toml");
    let noise_mode = payload
        .get("noise_mode")
        .and_then(Value::as_str)
        .unwrap_or("quiet");
    let max_active_requests = payload
        .get("max_active_requests")
        .and_then(Value::as_u64)
        .unwrap_or(250);
    let out_dir = make_run_dir(config, "webapi-scan")?;

    let mut args = vec![
        "cargo".to_string(),
        "run".to_string(),
        "-p".to_string(),
        "baloncore".to_string(),
        "--".to_string(),
        "scan-openapi-bola".to_string(),
        "--base-url".to_string(),
        base_url.to_string(),
        "--openapi-url".to_string(),
        openapi_url.to_string(),
        "--config".to_string(),
        config_path.to_string(),
        "--owner-profile".to_string(),
        owner_profile.to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
        "--noise-mode".to_string(),
        noise_mode.to_string(),
        "--max-active-requests".to_string(),
        max_active_requests.to_string(),
        "--json".to_string(),
    ];
    if let Some(profiles) = payload.get("attacker_profiles").and_then(Value::as_array) {
        for profile in profiles {
            if let Some(profile) = profile.as_str() {
                args.push("--attacker-profile".to_string());
                args.push(profile.to_string());
            }
        }
    }
    if payload
        .get("ci_anonymous_exposure")
        .and_then(Value::as_bool)
        == Some(true)
    {
        args.push("--ci-anonymous-exposure".to_string());
    }

    let command = run_command(
        config,
        args,
        &out_dir,
        payload
            .get("timeout_seconds")
            .and_then(Value::as_u64)
            .unwrap_or(300),
    )?;
    let mut result = json!({
        "ok": command.get("ok").and_then(Value::as_bool) == Some(true),
        "run_dir": out_dir,
        "command": command
    });
    write_json(&out_dir.join("webapi_scan_result.json"), &result)?;
    let intelligence = write_run_intelligence(config, &out_dir, "webapi_scan")?;
    result["run_intelligence"] = intelligence;
    result["artifact_paths"] = list_artifacts(config, Some(&out_dir))?;
    write_json(&out_dir.join("webapi_scan_result.json"), &result)?;
    Ok(result)
}

fn run_command(
    config: &ApiConfig,
    args: Vec<String>,
    out_dir: &Path,
    timeout_seconds: u64,
) -> Result<Value> {
    let started = Instant::now();
    let mut child = Command::new(&args[0])
        .args(&args[1..])
        .current_dir(&config.repo_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn command {}", args.join(" ")))?;
    let timeout = Duration::from_secs(timeout_seconds.max(1));
    let mut timed_out = false;
    loop {
        if child
            .try_wait()
            .with_context(|| format!("poll command {}", args.join(" ")))?
            .is_some()
        {
            break;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let output = child
        .wait_with_output()
        .with_context(|| format!("collect command {}", args.join(" ")))?;
    let duration_ms = started.elapsed().as_millis();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let record = json!({
        "command": args,
        "cwd": config.repo_root,
        "started_at": utc_now(),
        "timeout_seconds": timeout_seconds,
        "duration_seconds": (duration_ms as f64) / 1000.0,
        "exit_code": output.status.code(),
        "timed_out": timed_out,
        "ok": output.status.success() && !timed_out,
        "stdout": tail_chars(&stdout, 16_000),
        "stderr": tail_chars(&stderr, 16_000)
    });
    append_command_log(out_dir, &record)?;
    Ok(record)
}

fn scan_repository(config: &ApiConfig, target_path: &Path, out_dir: &Path) -> Result<Value> {
    let root = if target_path.is_file() {
        target_path.parent().unwrap_or(target_path).to_path_buf()
    } else {
        target_path.to_path_buf()
    };
    let mut files_seen = 0_usize;
    let mut files_skipped = 0_usize;
    let mut extensions = BTreeMap::<String, u64>::new();
    let mut tagged = Vec::<Value>::new();
    let mut dependency_manifests = Vec::<String>::new();
    let mut ci_workflows = Vec::<String>::new();
    let mut iac = Vec::<String>::new();
    let mut web3 = Vec::<String>::new();
    let mut containers = Vec::<String>::new();
    let mut secret_hits = Vec::<Value>::new();
    let secret_patterns = secret_patterns()?;

    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                files_skipped += 1;
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_dir() {
                if should_skip_dir(name) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            files_seen += 1;
            if files_seen > MAX_SCAN_FILES {
                files_skipped += 1;
                continue;
            }

            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let metadata = match fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => {
                    files_skipped += 1;
                    continue;
                }
            };
            let extension = path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| format!(".{}", ext.to_ascii_lowercase()))
                .unwrap_or_else(|| "<none>".to_string());
            *extensions.entry(extension.clone()).or_default() += 1;

            let tags = classify_file(&root, &path, &rel);
            if !tags.is_empty() {
                tagged.push(json!({
                    "path": rel,
                    "extension": extension,
                    "tags": tags
                }));
            }
            if tags.iter().any(|tag| tag == "dependency_manifest") {
                dependency_manifests.push(rel.clone());
            }
            if tags.iter().any(|tag| tag == "ci_workflow") {
                ci_workflows.push(rel.clone());
            }
            if tags.iter().any(|tag| {
                matches!(
                    tag.as_str(),
                    "terraform" | "kubernetes_yaml" | "cloudformation"
                )
            }) {
                iac.push(rel.clone());
            }
            if tags.iter().any(|tag| tag == "web3") {
                web3.push(rel.clone());
            }
            if tags.iter().any(|tag| tag == "container") {
                containers.push(rel.clone());
            }

            if metadata.len() > MAX_TEXT_FILE_BYTES || !should_read_text(&path) {
                continue;
            }
            let text = match fs::read_to_string(&path) {
                Ok(text) => text,
                Err(_) => continue,
            };
            for (line_index, line) in text.lines().enumerate() {
                for (name, pattern) in &secret_patterns {
                    for hit in pattern.find_iter(line) {
                        let value = hit.as_str();
                        secret_hits.push(json!({
                            "type": name,
                            "path": rel,
                            "line": line_index + 1,
                            "redacted": redact_secret(value),
                            "action": "Rotate if real; BALONCORE did not validate or transmit this secret."
                        }));
                    }
                }
            }
        }
    }

    let risk_score = [
        (secret_hits.len() as u64 * 20).min(60),
        if iac.is_empty() { 0 } else { 10 },
        if ci_workflows.is_empty() { 0 } else { 10 },
        if web3.is_empty() { 0 } else { 10 },
        if containers.is_empty() { 0 } else { 5 },
    ]
    .iter()
    .sum::<u64>()
    .min(100);

    let mut next_actions = Vec::new();
    if !secret_hits.is_empty() {
        next_actions.push("Review redacted secret hits, rotate real credentials, and add pre-commit secret scanning.");
    }
    if !iac.is_empty() {
        next_actions.push("Run authorized cloud/IAM analysis on exported Terraform, CloudFormation, or provider JSON.");
    }
    if !web3.is_empty() {
        next_actions.push(
            "Run BALONCORE Web3 analysis and generated invariant tests for Solidity projects.",
        );
    }
    if !ci_workflows.is_empty() {
        next_actions.push("Add BALONCORE CI evidence gates and regression replay to the pipeline.");
    }
    if next_actions.is_empty() {
        next_actions.push(
            "No high-signal repo indicators found; add dependency, SAST, and IaC adapters next.",
        );
    }

    let inventory = json!({
        "kind": "baloncore_repo_inventory",
        "created_at": utc_now(),
        "root": root,
        "output_dir": out_dir,
        "summary": {
            "files_seen": files_seen,
            "files_skipped": files_skipped,
            "extensions": extensions,
            "dependency_manifests": dependency_manifests.len(),
            "ci_workflows": ci_workflows.len(),
            "iac_files": iac.len(),
            "web3_files": web3.len(),
            "container_files": containers.len(),
            "secret_hits": secret_hits.len(),
            "risk_score": risk_score
        },
        "files": {
            "dependency_manifests": truncate_vec(dependency_manifests, 200),
            "ci_workflows": truncate_vec(ci_workflows, 200),
            "iac": truncate_vec(iac, 200),
            "web3": truncate_vec(web3, 200),
            "containers": truncate_vec(containers, 200),
            "tagged": tagged.into_iter().take(500).collect::<Vec<_>>()
        },
        "secret_hits": secret_hits.into_iter().take(500).collect::<Vec<_>>(),
        "next_actions": next_actions,
        "policy": {
            "network_validation": "disabled",
            "secret_values_stored": "redacted_only",
            "max_scan_files": MAX_SCAN_FILES,
            "max_text_file_bytes": MAX_TEXT_FILE_BYTES
        },
        "engine": "rust"
    });
    write_json(&out_dir.join("repo_inventory.json"), &inventory)?;
    let _ = config;
    Ok(inventory)
}

fn classify_file(root: &Path, path: &Path, rel: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let suffix = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext.to_ascii_lowercase()))
        .unwrap_or_default();
    if dependency_manifests().contains(&name) {
        tags.push("dependency_manifest".to_string());
    }
    if rel.contains(".github/workflows/") && matches!(suffix.as_str(), ".yml" | ".yaml") {
        tags.push("ci_workflow".to_string());
    }
    if name == "Dockerfile" || name.starts_with("Dockerfile.") || name == "docker-compose.yml" {
        tags.push("container".to_string());
    }
    if suffix == ".tf" || name.ends_with(".tfstate") || name.ends_with(".tfplan.json") {
        tags.push("terraform".to_string());
    }
    if matches!(suffix.as_str(), ".yml" | ".yaml") {
        if let Ok(body) = fs::read_to_string(path) {
            let body = &body[..body.len().min(4000)];
            if body.contains("apiVersion:") && body.contains("kind:") {
                tags.push("kubernetes_yaml".to_string());
            }
            if body.contains("AWSTemplateFormatVersion") || body.contains("AWS::") {
                tags.push("cloudformation".to_string());
            }
        }
    }
    if suffix == ".sol"
        || matches!(
            name,
            "foundry.toml" | "hardhat.config.js" | "hardhat.config.ts"
        )
    {
        tags.push("web3".to_string());
    }
    if name.starts_with(".env") {
        tags.push("environment_file".to_string());
    }
    let _ = root;
    tags
}

fn web3_project_roots(target_path: &Path, inventory: &Value) -> Vec<PathBuf> {
    let root = if target_path.is_file() {
        target_path.parent().unwrap_or(target_path).to_path_buf()
    } else {
        target_path.to_path_buf()
    };
    let markers = ["foundry.toml", "hardhat.config.js", "hardhat.config.ts"];
    let mut roots = Vec::<PathBuf>::new();
    let files = inventory
        .get("files")
        .and_then(|files| files.get("web3"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for rel in files {
        let Some(rel) = rel.as_str() else { continue };
        let absolute = root.join(rel);
        let selected = if markers.iter().any(|marker| absolute.ends_with(marker)) {
            absolute.parent().unwrap_or(&root).to_path_buf()
        } else {
            find_marker_parent(&root, absolute.parent().unwrap_or(&root), &markers)
        };
        if !roots.contains(&selected) {
            roots.push(selected);
        }
    }
    roots.sort();
    roots.truncate(5);
    roots
}

fn find_marker_parent(root: &Path, start: &Path, markers: &[&str]) -> PathBuf {
    let mut cursor = start.to_path_buf();
    loop {
        if markers.iter().any(|marker| cursor.join(marker).exists()) {
            return cursor;
        }
        if cursor == root {
            return start.to_path_buf();
        }
        if !cursor.pop() {
            return start.to_path_buf();
        }
    }
}

fn create_job(config: &ApiConfig, body: Value) -> Result<Value> {
    let job_type = body
        .get("type")
        .and_then(Value::as_str)
        .context("type is required")?
        .to_string();
    if job_type != "repo_scan" && job_type != "webapi_scan" {
        bail!("job type must be repo_scan or webapi_scan");
    }
    let payload = body.get("payload").cloned().unwrap_or_else(|| json!({}));
    require_authorized(&payload)?;
    let job_id = new_id("job");
    let tenant = tenant_metadata(&body, &payload);
    let queue = queue_metadata(&job_id, &job_type, &body, &payload);
    let record = json!({
        "job_id": job_id,
        "type": job_type,
        "status": "queued",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "tenant": tenant,
        "queue": queue,
        "payload": payload,
        "result": null,
        "error": null
    });
    write_job(config, &record)?;
    append_audit_event(
        config,
        "scan.job_queued",
        "baloncore-user",
        record["job_id"].as_str().unwrap_or("unknown"),
        json!({
            "type": record.get("type").cloned().unwrap_or(Value::Null),
            "authorization": "authorized_true_required"
        }),
    )?;

    let config = ApiConfig {
        host: config.host.clone(),
        port: config.port,
        repo_root: config.repo_root.clone(),
        workbench_root: config.workbench_root.clone(),
    };
    let job_id = record["job_id"].as_str().unwrap().to_string();
    thread::spawn(move || {
        if let Err(err) = run_job(&config, &job_id) {
            eprintln!("job {job_id} failed: {err:#}");
        }
    });
    Ok(record)
}

fn run_job(config: &ApiConfig, job_id: &str) -> Result<()> {
    let mut record = read_job(config, job_id)?;
    let job_type = record
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    if !record.get("queue").map(Value::is_object).unwrap_or(false) {
        record["queue"] = queue_metadata(job_id, job_type.as_str(), &json!({}), &record["payload"]);
    }
    let worker_pool = record
        .pointer("/queue/worker_pool")
        .and_then(Value::as_str)
        .unwrap_or_else(|| worker_pool_for_job_type(job_type.as_str()))
        .to_string();
    let worker_id = format!("local-{worker_pool}");
    let attempts = record
        .pointer("/queue/attempts")
        .and_then(Value::as_u64)
        .unwrap_or_default()
        + 1;
    record["status"] = json!("running");
    record["queue"]["state"] = json!("running");
    record["queue"]["attempts"] = json!(attempts);
    record["queue"]["lease_owner"] = json!(worker_id.clone());
    record["queue"]["lease_started_at"] = json!(utc_now());
    record["started_at"] = json!(utc_now());
    record["updated_at"] = json!(utc_now());
    write_job(config, &record)?;
    upsert_worker_state(
        config,
        worker_id.as_str(),
        worker_pool.as_str(),
        "busy",
        1,
        json!({
            "runtime": "local-thread",
            "current_job_id": job_id
        }),
    )?;
    append_job_attempt(
        config,
        job_id,
        worker_id.as_str(),
        "started",
        json!({
            "worker_pool": worker_pool.clone(),
            "attempt": attempts
        }),
    )?;

    let result = match record["type"].as_str().unwrap_or("") {
        "repo_scan" => scan_repo(config, &record["payload"]),
        "webapi_scan" => scan_webapp(config, &record["payload"]),
        other => Err(anyhow!("unsupported job type: {other}")),
    };

    match result {
        Ok(result) => {
            let ok = result.get("ok").and_then(Value::as_bool).unwrap_or(false);
            record["status"] = json!(if ok { "succeeded" } else { "failed" });
            record["queue"]["state"] = json!(if ok { "succeeded" } else { "failed" });
            record["queue"]["lease_owner"] = Value::Null;
            record["queue"]["lease_finished_at"] = json!(utc_now());
            record["result"] = json!({
                "ok": ok,
                "run_dir": result.get("run_dir").cloned().unwrap_or(Value::Null),
                "run_intelligence": result.get("run_intelligence").cloned().unwrap_or(Value::Null),
                "artifact_count": result.get("artifact_paths").and_then(Value::as_array).map(|a| a.len()).unwrap_or_default()
            });
            if !ok {
                record["error"] = json!("scan completed with failing command status");
            }
            append_audit_event(
                config,
                if ok {
                    "scan.job_succeeded"
                } else {
                    "scan.job_failed"
                },
                "baloncore-worker",
                job_id,
                json!({
                    "type": record.get("type").cloned().unwrap_or(Value::Null),
                    "run_dir": record.pointer("/result/run_dir").cloned().unwrap_or(Value::Null),
                    "score": record.pointer("/result/run_intelligence/score").cloned().unwrap_or(Value::Null)
                }),
            )?;
            append_job_attempt(
                config,
                job_id,
                worker_id.as_str(),
                if ok { "succeeded" } else { "failed" },
                json!({
                    "run_dir": record.pointer("/result/run_dir").cloned().unwrap_or(Value::Null),
                    "score": record.pointer("/result/run_intelligence/score").cloned().unwrap_or(Value::Null)
                }),
            )?;
        }
        Err(err) => {
            record["status"] = json!("failed");
            record["queue"]["state"] = json!("failed");
            record["queue"]["lease_owner"] = Value::Null;
            record["queue"]["lease_finished_at"] = json!(utc_now());
            record["error"] = json!(err.to_string());
            append_audit_event(
                config,
                "scan.job_failed",
                "baloncore-worker",
                job_id,
                json!({
                    "type": record.get("type").cloned().unwrap_or(Value::Null),
                    "error": record.get("error").cloned().unwrap_or(Value::Null)
                }),
            )?;
            append_job_attempt(
                config,
                job_id,
                worker_id.as_str(),
                "failed",
                json!({
                    "error": record.get("error").cloned().unwrap_or(Value::Null)
                }),
            )?;
        }
    }
    upsert_worker_state(
        config,
        worker_id.as_str(),
        worker_pool.as_str(),
        "idle",
        1,
        json!({
            "runtime": "local-thread",
            "last_job_id": job_id,
            "last_status": record.get("status").cloned().unwrap_or(Value::Null)
        }),
    )?;
    record["finished_at"] = json!(utc_now());
    record["updated_at"] = json!(utc_now());
    write_job(config, &record)?;
    Ok(())
}

fn list_jobs(config: &ApiConfig) -> Result<Value> {
    let root = jobs_root(config);
    fs::create_dir_all(&root).context("create jobs dir")?;
    let mut entries = fs::read_dir(root)
        .context("read jobs dir")?
        .flatten()
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or_default()
    });
    entries.reverse();
    let mut jobs = Vec::new();
    for entry in entries.into_iter().take(50) {
        if let Ok(value) = read_json(&entry.path()) {
            jobs.push(value);
        }
    }
    Ok(Value::Array(jobs))
}

fn read_job(config: &ApiConfig, job_id: &str) -> Result<Value> {
    validate_id(job_id)?;
    read_json(&jobs_root(config).join(format!("{job_id}.json")))
}

fn write_job(config: &ApiConfig, record: &Value) -> Result<()> {
    let job_id = record
        .get("job_id")
        .and_then(Value::as_str)
        .context("job_id missing")?;
    validate_id(job_id)?;
    write_json(&jobs_root(config).join(format!("{job_id}.json")), record)
}

fn write_run_intelligence(config: &ApiConfig, run_dir: &Path, run_type: &str) -> Result<Value> {
    let artifact_index = build_artifact_index(config, run_dir)?;
    let matrix_summary = summarize_matrix_run(run_dir)?;
    let repo_summary = summarize_repo_run(run_dir)?;
    let web3_summaries = summarize_web3_outputs(config, run_dir)?;
    let scorecard = enterprise_scorecard(
        run_dir,
        run_type,
        &artifact_index,
        &matrix_summary,
        &repo_summary,
        &web3_summaries,
    );
    write_json(&run_dir.join("enterprise_scorecard.json"), &scorecard)?;
    fs::write(run_dir.join("executive_summary.md"), "").context("seed summary")?;
    let artifact_index = build_artifact_index(config, run_dir)?;
    let executive = render_executive_summary(
        run_dir,
        run_type,
        &artifact_index,
        &matrix_summary,
        &repo_summary,
        &web3_summaries,
        &scorecard,
    );
    fs::write(run_dir.join("executive_summary.md"), executive).context("write summary")?;
    let artifact_index = build_artifact_index(config, run_dir)?;
    Ok(json!({
        "artifact_index": run_dir.join("artifact_index.json"),
        "enterprise_scorecard": run_dir.join("enterprise_scorecard.json"),
        "executive_summary": run_dir.join("executive_summary.md"),
        "score": scorecard["score"],
        "readiness": scorecard["readiness"],
        "signals": scorecard["signals"],
        "artifact_count": artifact_index["artifact_count"]
    }))
}

fn build_artifact_index(config: &ApiConfig, run_dir: &Path) -> Result<Value> {
    let artifacts = list_artifacts(config, Some(run_dir))?;
    let mut counts = BTreeMap::<String, u64>::new();
    if let Some(items) = artifacts.as_array() {
        for item in items {
            let kind = item
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("artifact");
            *counts.entry(kind.to_string()).or_default() += 1;
        }
    }
    let index = json!({
        "kind": "baloncore_artifact_index",
        "created_at": utc_now(),
        "run_dir": run_dir,
        "artifact_count": artifacts.as_array().map(|a| a.len()).unwrap_or_default(),
        "artifact_counts": counts,
        "artifacts": artifacts
    });
    write_json(&run_dir.join("artifact_index.json"), &index)?;
    Ok(index)
}

fn summarize_matrix_run(run_dir: &Path) -> Result<Value> {
    let path = run_dir.join("matrix_summary.json");
    if !path.exists() {
        return Ok(json!({}));
    }
    let matrix = read_json(&path)?;
    let mut verified = Vec::new();
    let mut rejected = 0_u64;
    let mut skipped = 0_u64;
    let mut suppressed = 0_u64;
    let mut sensitive_fields = 0_u64;
    let mut remediation_paths = Vec::new();
    let mut severity_counts = BTreeMap::<String, u64>::new();
    let mut classification_counts = BTreeMap::<String, u64>::new();

    for validation in matrix
        .get("validations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let class = validation
            .get("classification")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        *classification_counts.entry(class.clone()).or_default() += 1;
        if validation.get("suppressed").and_then(Value::as_bool) == Some(true) {
            suppressed += 1;
        }
        if validation.get("status").and_then(Value::as_str) == Some("skipped") {
            skipped += 1;
            continue;
        }
        let decision = validation
            .get("decision")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if decision.get("Rejected").is_some() {
            rejected += 1;
        }
        let is_verified = decision.get("Verified").is_some();
        if is_verified
            && !matches!(
                class.as_str(),
                "IntendedPrivilegedAccess" | "IntendedOwnerAccess" | "BlockedAsExpected"
            )
        {
            let impact = validation
                .get("impact")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let severity = impact
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("Unknown")
                .to_string();
            *severity_counts.entry(severity.clone()).or_default() += 1;
            let sensitive = impact
                .get("sensitive_fields")
                .and_then(Value::as_array)
                .map(|items| items.len() as u64)
                .unwrap_or_default();
            sensitive_fields += sensitive;
            if let Some(remediation) = validation.get("remediation").and_then(Value::as_str) {
                remediation_paths.push(remediation.to_string());
            }
            verified.push(json!({
                "classification": class,
                "endpoint": validation.get("endpoint").cloned().unwrap_or(Value::Null),
                "profile": validation.get("profile").cloned().unwrap_or(Value::Null),
                "target": validation.get("target").cloned().unwrap_or(Value::Null),
                "severity": severity,
                "score": impact.get("score").cloned().unwrap_or(Value::Null),
                "artifact_dir": validation.get("artifacts").cloned().unwrap_or(Value::Null)
            }));
        }
    }

    Ok(json!({
        "kind": "webapi_auth_matrix",
        "base_url": matrix.get("base_url").cloned().unwrap_or(Value::Null),
        "openapi_url": matrix.get("openapi_url").cloned().unwrap_or(Value::Null),
        "owner_profile": matrix.get("owner_profile").cloned().unwrap_or(Value::Null),
        "matrix_profiles": matrix.get("matrix_profiles").cloned().unwrap_or_else(|| json!([])),
        "verified_findings": verified.len(),
        "rejected_validations": rejected,
        "skipped_validations": skipped,
        "suppressed_findings": suppressed,
        "classification_counts": classification_counts,
        "severity_counts": severity_counts,
        "sensitive_fields_exposed": sensitive_fields,
        "remediation_count": remediation_paths.len(),
        "remediation_paths": remediation_paths,
        "findings": verified,
        "coverage": matrix.pointer("/coverage/summary").cloned().unwrap_or_else(|| json!({})),
        "active_requests": matrix.get("active_request_policy").cloned().unwrap_or_else(|| json!({})),
        "hypotheses": matrix.get("hypothesis_ledger").cloned().unwrap_or_else(|| json!({}))
    }))
}

fn summarize_repo_run(run_dir: &Path) -> Result<Value> {
    let path = run_dir.join("repo_inventory.json");
    if !path.exists() {
        return Ok(json!({}));
    }
    let inventory = read_json(&path)?;
    Ok(json!({
        "kind": "repo_inventory",
        "root": inventory.get("root").cloned().unwrap_or(Value::Null),
        "summary": inventory.get("summary").cloned().unwrap_or_else(|| json!({})),
        "secret_hits": inventory.get("secret_hits").cloned().unwrap_or_else(|| json!([])),
        "dependency_manifests": inventory.pointer("/files/dependency_manifests").cloned().unwrap_or_else(|| json!([])),
        "ci_workflows": inventory.pointer("/files/ci_workflows").cloned().unwrap_or_else(|| json!([])),
        "iac_files": inventory.pointer("/files/iac").cloned().unwrap_or_else(|| json!([])),
        "web3_files": inventory.pointer("/files/web3").cloned().unwrap_or_else(|| json!([])),
        "next_actions": inventory.get("next_actions").cloned().unwrap_or_else(|| json!([]))
    }))
}

fn summarize_web3_outputs(config: &ApiConfig, run_dir: &Path) -> Result<Vec<Value>> {
    let mut output = Vec::new();
    for path in collect_files(run_dir, "web3_analysis.json")? {
        let analysis = read_json(&path)?;
        let summary = analysis
            .get("summary")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let project = analysis
            .get("project")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let generated_tests = collect_extension(path.parent().unwrap_or(run_dir), ".sol")?
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.ends_with(".t.sol"))
                    .unwrap_or(false)
            })
            .count();
        output.push(json!({
            "kind": "web3_analysis",
            "path": path,
            "relative_path": relative_to_repo(config, &path),
            "project_name": project.get("name").cloned().unwrap_or(Value::Null),
            "project_kind": summary.get("project_kind").cloned().unwrap_or(Value::Null),
            "finding_count": summary.get("finding_count").cloned().unwrap_or(Value::Null),
            "critical_count": summary.get("critical_count").cloned().unwrap_or(Value::Null),
            "high_count": summary.get("high_count").cloned().unwrap_or(Value::Null),
            "invariant_count": summary.get("invariant_count").cloned().unwrap_or(Value::Null),
            "generated_tests": generated_tests
        }));
    }
    Ok(output)
}

fn enterprise_scorecard(
    run_dir: &Path,
    run_type: &str,
    artifact_index: &Value,
    matrix_summary: &Value,
    repo_summary: &Value,
    web3_summaries: &[Value],
) -> Value {
    let counts = artifact_index
        .get("artifact_counts")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let count = |key: &str| counts.get(key).and_then(Value::as_u64).unwrap_or_default();
    let verified = matrix_summary
        .get("verified_findings")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let repo_secret_hits = repo_summary
        .pointer("/summary/secret_hits")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let web3_findings = web3_summaries
        .iter()
        .map(|item| {
            item.get("finding_count")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        })
        .sum::<u64>();
    let generated_tests = web3_summaries
        .iter()
        .map(|item| {
            item.get("generated_tests")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        })
        .sum::<u64>();

    let mut score = 0_u64;
    score += 20;
    score += (verified * 20).min(30);
    score += (count("evidence_manifest") * 15).min(20);
    score += (count("remediation") * 10).min(15);
    score += (count("proof_package") * 10).min(10);
    score += (count("report") * 5).min(10);
    score += (generated_tests * 2).min(10);
    if repo_summary
        .as_object()
        .map(|o| !o.is_empty())
        .unwrap_or(false)
        && repo_secret_hits == 0
    {
        score += 5;
    }
    score = score.min(100);
    let readiness = if score >= 80 {
        "investor_demo_ready_local"
    } else if score >= 55 {
        "operator_ready_local"
    } else {
        "foundation_needs_more_proof"
    };
    let mut gaps = Vec::new();
    if verified > 0 && count("evidence_manifest") == 0 {
        gaps.push("Verified findings need sealed evidence manifests.");
    }
    if verified > 0 && count("remediation") == 0 {
        gaps.push("Verified findings need remediation artifacts.");
    }
    if web3_findings > 0 && generated_tests == 0 {
        gaps.push("Web3 findings need generated proof tests.");
    }
    if verified == 0 && web3_findings == 0 && repo_secret_hits == 0 {
        gaps.push("Run did not produce high-impact proof signals.");
    }

    json!({
        "kind": "baloncore_enterprise_scorecard",
        "created_at": utc_now(),
        "run_dir": run_dir,
        "run_type": run_type,
        "score": score,
        "readiness": readiness,
        "signals": {
            "verified_webapi_findings": verified,
            "evidence_manifests": count("evidence_manifest"),
            "proof_packages": count("proof_package"),
            "remediation_artifacts": count("remediation"),
            "reports": count("report"),
            "repo_secret_hits": repo_secret_hits,
            "web3_findings": web3_findings,
            "web3_generated_tests": generated_tests
        },
        "gaps": gaps
    })
}

fn render_executive_summary(
    run_dir: &Path,
    run_type: &str,
    artifact_index: &Value,
    matrix_summary: &Value,
    repo_summary: &Value,
    web3_summaries: &[Value],
    scorecard: &Value,
) -> String {
    let mut lines = vec![
        "# BALONCORE Run Intelligence".to_string(),
        String::new(),
        format!("- Run type: `{run_type}`"),
        format!("- Run directory: `{}`", run_dir.display()),
        format!("- Enterprise score: `{}`", scorecard["score"]),
        format!(
            "- Readiness: `{}`",
            scorecard["readiness"].as_str().unwrap_or("unknown")
        ),
        format!(
            "- Artifacts indexed: `{}`",
            artifact_index["artifact_count"]
        ),
        String::new(),
        "## Proof Signals".to_string(),
        String::new(),
    ];
    if let Some(signals) = scorecard.get("signals").and_then(Value::as_object) {
        for (key, value) in signals {
            lines.push(format!("- {}: `{}`", title_case(key), value));
        }
    }
    if matrix_summary
        .as_object()
        .map(|o| !o.is_empty())
        .unwrap_or(false)
    {
        lines.extend([
            String::new(),
            "## Web/API Authorization".to_string(),
            String::new(),
            format!(
                "- Verified findings: `{}`",
                matrix_summary["verified_findings"]
            ),
            format!(
                "- Sensitive fields exposed: `{}`",
                matrix_summary["sensitive_fields_exposed"]
            ),
            format!(
                "- Remediation plans: `{}`",
                matrix_summary["remediation_count"]
            ),
        ]);
        for finding in matrix_summary
            .get("findings")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            lines.push(format!(
                "- `{}` `{}` on `{}` as `{}`",
                finding["severity"].as_str().unwrap_or("Unknown"),
                finding["classification"].as_str().unwrap_or("unknown"),
                finding["endpoint"].as_str().unwrap_or("unknown"),
                finding["profile"].as_str().unwrap_or("unknown")
            ));
        }
    }
    if repo_summary
        .as_object()
        .map(|o| !o.is_empty())
        .unwrap_or(false)
    {
        let summary = repo_summary
            .get("summary")
            .cloned()
            .unwrap_or_else(|| json!({}));
        lines.extend([
            String::new(),
            "## Repository Inventory".to_string(),
            String::new(),
            format!("- Files seen: `{}`", summary["files_seen"]),
            format!(
                "- Dependency manifests: `{}`",
                summary["dependency_manifests"]
            ),
            format!("- CI workflows: `{}`", summary["ci_workflows"]),
            format!("- IaC files: `{}`", summary["iac_files"]),
            format!("- Web3 files: `{}`", summary["web3_files"]),
            format!("- Redacted secret hits: `{}`", summary["secret_hits"]),
        ]);
    }
    if !web3_summaries.is_empty() {
        lines.extend([String::new(), "## Web3 Analysis".to_string(), String::new()]);
        for item in web3_summaries {
            lines.push(format!(
                "- `{}` findings=`{}` critical=`{}` high=`{}` generated_tests=`{}`",
                item["project_name"].as_str().unwrap_or("unknown"),
                item["finding_count"],
                item["critical_count"],
                item["high_count"],
                item["generated_tests"]
            ));
        }
    }
    if let Some(gaps) = scorecard.get("gaps").and_then(Value::as_array) {
        if !gaps.is_empty() {
            lines.extend([
                String::new(),
                "## Remaining Gaps".to_string(),
                String::new(),
            ]);
            for gap in gaps {
                if let Some(gap) = gap.as_str() {
                    lines.push(format!("- {gap}"));
                }
            }
        }
    }
    lines.push(String::new());
    lines.join("\n")
}

fn run_intelligence(config: &ApiConfig, run_dir: &str) -> Result<Value> {
    let run_dir = resolve_local_path(config, run_dir)?;
    if !run_dir.starts_with(&config.workbench_root) {
        bail!("run intelligence is restricted to .baloncore/workbench");
    }
    let summary = run_dir.join("executive_summary.md");
    Ok(json!({
        "artifact_index": read_optional_json(&run_dir.join("artifact_index.json"))?,
        "enterprise_scorecard": read_optional_json(&run_dir.join("enterprise_scorecard.json"))?,
        "executive_summary": if summary.exists() { Some(fs::read_to_string(summary).context("read executive summary")?) } else { None }
    }))
}

fn preview_artifact(config: &ApiConfig, path: &str) -> Result<Value> {
    let path = resolve_artifact_path(config, path)?;
    let metadata = fs::metadata(&path).context("artifact metadata")?;
    let mut output = json!({
        "path": path,
        "relative_path": relative_to_repo(config, &path),
        "kind": artifact_kind(&path),
        "bytes": metadata.len(),
        "modified_at": metadata.modified().ok().map(system_time_string),
        "truncated": metadata.len() > MAX_PREVIEW_BYTES,
        "text": null,
        "json": null
    });
    if metadata.len() > MAX_PREVIEW_BYTES || !is_previewable(&path) {
        return Ok(output);
    }
    let text = fs::read_to_string(&path).context("read artifact")?;
    output["text"] = json!(text);
    if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
        output["json"] =
            serde_json::from_str(output["text"].as_str().unwrap()).unwrap_or(Value::Null);
    }
    Ok(output)
}

fn list_artifacts(config: &ApiConfig, root: Option<&Path>) -> Result<Value> {
    let base = root.unwrap_or(&config.workbench_root);
    if !base.exists() {
        return Ok(json!([]));
    }
    let mut files = collect_all_files(base)?;
    files.sort_by_key(|path| {
        fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or_default()
    });
    files.reverse();
    let artifacts = files
        .into_iter()
        .take(300)
        .filter_map(|path| {
            let metadata = fs::metadata(&path).ok()?;
            Some(json!({
                "path": path,
                "relative_path": relative_to_repo(config, &path),
                "kind": artifact_kind(&path),
                "bytes": metadata.len(),
                "modified_at": metadata.modified().ok().map(system_time_string)
            }))
        })
        .collect::<Vec<_>>();
    Ok(Value::Array(artifacts))
}

fn artifact_kind(path: &Path) -> &'static str {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let parent = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let suffix = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    match name {
        "repo_inventory.json" | "openapi_inventory.json" | "schema_discovery.json" => "inventory",
        "matrix_summary.json" | "webapi_scan_result.json" | "repo_scan_result.json" => "run_result",
        "artifact_index.json" | "enterprise_scorecard.json" => "run_intelligence",
        "executive_summary.md" => "executive_summary",
        "evidence_manifest.json" => "evidence_manifest",
        "evidence_signature.json" => "evidence_signature",
        "proof_package.json" => "proof_package",
        "regression_result.json" | "regression_result.md" => "regression_result",
        "command_log.json" => "command_log",
        "report.md" | "run_report.md" => "report",
        _ if name.starts_with("remediation.") => "remediation",
        _ if name.starts_with("web3_") || parent == "foundry-tests" || suffix == "sol" => "web3",
        _ if name.ends_with("_exchange.json") => "http_evidence",
        _ => "artifact",
    }
}

fn resolve_local_path(config: &ApiConfig, value: &str) -> Result<PathBuf> {
    if value.trim().is_empty() {
        bail!("path is required");
    }
    let path = PathBuf::from(value);
    let path = if path.is_absolute() {
        path
    } else {
        config.repo_root.join(path)
    };
    let path = path
        .canonicalize()
        .with_context(|| format!("resolve path {value}"))?;
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    Ok(path)
}

fn resolve_artifact_path(config: &ApiConfig, value: &str) -> Result<PathBuf> {
    let path = resolve_local_path(config, value)?;
    let workbench = config
        .workbench_root
        .canonicalize()
        .unwrap_or_else(|_| config.workbench_root.clone());
    if !path.starts_with(workbench) {
        bail!("artifact preview is restricted to .baloncore/workbench artifacts");
    }
    if !path.is_file() {
        bail!("artifact does not exist: {}", path.display());
    }
    Ok(path)
}

fn make_run_dir(config: &ApiConfig, prefix: &str) -> Result<PathBuf> {
    let dir = config.workbench_root.join(new_id(prefix));
    fs::create_dir_all(&dir).context("create run dir")?;
    Ok(dir)
}

fn jobs_root(config: &ApiConfig) -> PathBuf {
    config.workbench_root.join("jobs")
}

fn saas_root(config: &ApiConfig) -> PathBuf {
    config.workbench_root.join("saas")
}

fn customers_path(config: &ApiConfig) -> PathBuf {
    saas_root(config).join("customers.json")
}

fn projects_path(config: &ApiConfig) -> PathBuf {
    saas_root(config).join("projects.json")
}

fn assets_path(config: &ApiConfig) -> PathBuf {
    saas_root(config).join("assets.json")
}

fn audit_log_path(config: &ApiConfig) -> PathBuf {
    saas_root(config).join("audit_log.json")
}

fn workers_path(config: &ApiConfig) -> PathBuf {
    saas_root(config).join("workers.json")
}

fn job_attempts_path(config: &ApiConfig) -> PathBuf {
    saas_root(config).join("job_attempts.json")
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create json parent")?;
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(value).context("serialize json")?,
    )
    .with_context(|| format!("write {}", path.display()))
}

fn read_json(path: &Path) -> Result<Value> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn read_optional_json(path: &Path) -> Result<Option<Value>> {
    if path.exists() {
        Ok(Some(read_json(path)?))
    } else {
        Ok(None)
    }
}

fn append_command_log(out_dir: &Path, record: &Value) -> Result<()> {
    let path = out_dir.join("command_log.json");
    let mut records = if path.exists() {
        read_json(&path)?.as_array().cloned().unwrap_or_default()
    } else {
        Vec::new()
    };
    records.push(record.clone());
    write_json(&path, &Value::Array(records))
}

fn collect_files(root: &Path, file_name: &str) -> Result<Vec<PathBuf>> {
    Ok(collect_all_files(root)?
        .into_iter()
        .filter(|path| path.file_name().and_then(|n| n.to_str()) == Some(file_name))
        .collect())
}

fn collect_extension(root: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    Ok(collect_all_files(root)?
        .into_iter()
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| format!(".{ext}") == extension)
                .unwrap_or(false)
        })
        .collect())
}

fn collect_all_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).with_context(|| format!("read dir {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn secret_patterns() -> Result<Vec<(&'static str, Regex)>> {
    Ok(vec![
        ("aws_access_key_id", Regex::new(r"\bAKIA[0-9A-Z]{16}\b")?),
        (
            "aws_temp_access_key_id",
            Regex::new(r"\bASIA[0-9A-Z]{16}\b")?,
        ),
        (
            "github_token",
            Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")?,
        ),
        (
            "openai_api_key",
            Regex::new(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")?,
        ),
        (
            "stripe_live_secret",
            Regex::new(r"\bsk_live_[A-Za-z0-9]{16,}\b")?,
        ),
        (
            "slack_token",
            Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")?,
        ),
        (
            "jwt",
            Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")?,
        ),
        (
            "private_key_block",
            Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")?,
        ),
    ])
}

fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".baloncore"
            | ".git"
            | ".hg"
            | ".svn"
            | "dist"
            | "node_modules"
            | "target"
            | "vendor"
            | "venv"
    ) || name.starts_with(".terraform")
}

fn should_read_text(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if dependency_manifests().contains(&name) || name.starts_with(".env") {
        return true;
    }
    matches!(
        path.extension().and_then(|ext| ext.to_str()).unwrap_or(""),
        "bash"
            | "c"
            | "conf"
            | "cpp"
            | "cs"
            | "css"
            | "csv"
            | "env"
            | "go"
            | "graphql"
            | "h"
            | "html"
            | "java"
            | "js"
            | "json"
            | "jsx"
            | "kt"
            | "lock"
            | "md"
            | "php"
            | "py"
            | "rb"
            | "rs"
            | "sh"
            | "sol"
            | "sql"
            | "tf"
            | "toml"
            | "ts"
            | "tsx"
            | "txt"
            | "xml"
            | "yaml"
            | "yml"
    )
}

fn dependency_manifests() -> Vec<&'static str> {
    vec![
        "Cargo.toml",
        "Cargo.lock",
        "Gemfile",
        "Gemfile.lock",
        "go.mod",
        "go.sum",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pom.xml",
        "pyproject.toml",
        "requirements.txt",
        "yarn.lock",
    ]
}

fn truncate_vec<T>(items: Vec<T>, limit: usize) -> Vec<T> {
    items.into_iter().take(limit).collect()
}

fn redact_secret(value: &str) -> String {
    if value.len() <= 8 {
        "*".repeat(value.len())
    } else {
        format!("{}...{}", &value[..4], &value[value.len() - 4..])
    }
}

fn tail_chars(value: &str, limit: usize) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    let start = chars.len().saturating_sub(limit);
    chars[start..].iter().collect()
}

fn relative_to_repo(config: &ApiConfig, path: &Path) -> String {
    path.strip_prefix(&config.repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn sanitize_slug(value: &str) -> String {
    let slug = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if slug.is_empty() {
        "project".to_string()
    } else {
        slug
    }
}

fn validate_id(value: &str) -> Result<()> {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        Ok(())
    } else {
        bail!("invalid id")
    }
}

fn new_id(prefix: &str) -> String {
    let timestamp = compact_system_time(SystemTime::now());
    let counter = JOB_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{prefix}-{timestamp}-{counter:06}")
}

fn utc_now() -> String {
    system_time_string(SystemTime::now())
}

fn utc_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn system_time_string(time: SystemTime) -> String {
    let (year, month, day, hour, minute, second) = system_time_parts(time);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn compact_system_time(time: SystemTime) -> String {
    let (year, month, day, hour, minute, second) = system_time_parts(time);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

fn system_time_parts(time: SystemTime) -> (i64, u32, u32, u32, u32, u32) {
    let total_seconds = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = total_seconds / 86_400;
    let seconds_of_day = total_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = (seconds_of_day / 3_600) as u32;
    let minute = ((seconds_of_day % 3_600) / 60) as u32;
    let second = (seconds_of_day % 60) as u32;
    (year, month, day, hour, minute, second)
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    (year, month as u32, day as u32)
}

fn title_case(value: &str) -> String {
    value
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn severity_rank(value: &str) -> u8 {
    match value {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        "Low" => 3,
        "Informational" => 4,
        _ => 5,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_previewable(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()).unwrap_or(""),
        "json" | "md" | "txt" | "log" | "html" | "toml" | "yaml" | "yml"
    )
}

fn tenant_create_org(config: &ApiConfig, body: Value) -> Result<Value> {
    let name = required_string(&body, "name")?;
    let slug = required_string(&body, "slug")?;
    let _plan_str = body
        .get("plan")
        .and_then(Value::as_str)
        .unwrap_or("starter");
    let now = utc_now_unix();
    let org = baloncore_core::platform::Organization {
        id: format!("org_{}", slug),
        name: name.clone(),
        created_at_unix_seconds: now,
    };
    let mut state = load_platform_state(config);
    state.organizations.push(org.clone());
    state.record_audit_event(baloncore_core::platform::AuditEvent {
        id: format!("audit_org_{}", now),
        at_unix_seconds: now,
        organization_id: org.id.clone(),
        workspace_id: None,
        actor_user_id: "system".to_string(),
        action: "org_created".to_string(),
        resource_type: "organization".to_string(),
        resource_id: org.id.clone(),
        outcome: "success".to_string(),
    });
    save_platform_state(config, &state)?;
    Ok(serde_json::to_value(&org)?)
}

fn tenant_list_orgs(config: &ApiConfig) -> Result<Value> {
    let state = load_platform_state(config);
    Ok(json!({ "organizations": state.organizations }))
}

fn tenant_get_org(config: &ApiConfig, org_id: &str) -> Result<Value> {
    let state = load_platform_state(config);
    match state.organizations.iter().find(|o| o.id == org_id) {
        Some(org) => Ok(serde_json::to_value(org)?),
        None => Ok(json!({ "error": "Organization not found" })),
    }
}

fn tenant_create_workspace(config: &ApiConfig, body: Value) -> Result<Value> {
    let org_id = required_string(&body, "org_id")?;
    let name = required_string(&body, "name")?;
    let environment = body
        .get("environment")
        .and_then(Value::as_str)
        .unwrap_or("production");
    let mut state = load_platform_state(config);
    let ws = state.add_workspace(&org_id, &name, environment);
    save_platform_state(config, &state)?;
    Ok(serde_json::to_value(&ws)?)
}

fn tenant_add_user(config: &ApiConfig, body: Value) -> Result<Value> {
    let org_id = required_string(&body, "org_id")?;
    let email = required_string(&body, "email")?;
    let display_name = required_string(&body, "display_name")?;
    let role_str = body.get("role").and_then(Value::as_str).unwrap_or("viewer");
    let role = match role_str {
        "owner" => PlatformRole::Owner,
        "admin" => PlatformRole::Admin,
        "analyst" => PlatformRole::Analyst,
        "billing" => PlatformRole::Billing,
        _ => PlatformRole::Viewer,
    };
    let mut state = load_platform_state(config);
    let user = state.add_platform_user(&email, &display_name, &org_id, role);
    save_platform_state(config, &state)?;
    Ok(serde_json::to_value(&user)?)
}

fn tenant_add_member(config: &ApiConfig, body: Value) -> Result<Value> {
    let org_id = required_string(&body, "org_id")?;
    let workspace_id = required_string(&body, "workspace_id")?;
    let user_id = required_string(&body, "user_id")?;
    let role_str = body
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("analyst");
    let role = match role_str {
        "owner" => PlatformRole::Owner,
        "admin" => PlatformRole::Admin,
        "viewer" => PlatformRole::Viewer,
        "billing" => PlatformRole::Billing,
        _ => PlatformRole::Analyst,
    };
    let mut state = load_platform_state(config);
    state
        .add_user_to_workspace(&user_id, &org_id, &workspace_id, role)
        .map_err(|e| anyhow::anyhow!(e))?;
    save_platform_state(config, &state)?;
    Ok(json!({ "ok": true, "user_id": user_id, "workspace_id": workspace_id, "role": role_str }))
}

fn tenant_audit_log(config: &ApiConfig, org_id: &str) -> Result<Value> {
    let events = load_audit_events(config)?;
    Ok(json!({ "org_id": org_id, "events": events }))
}

fn tenant_metrics(config: &ApiConfig, _org_id: &str) -> Result<Value> {
    let state = load_platform_state(config);
    let metrics = state.investor_metrics();
    Ok(serde_json::to_value(&metrics)?)
}

fn tenant_onboard(_config: &ApiConfig, body: Value) -> Result<Value> {
    let org_id = required_string(&body, "org_id")?;
    let now = utc_now_unix();
    let tracker = baloncore_core::platform::OnboardingTracker::start(&org_id, now);
    Ok(serde_json::to_value(&tracker)?)
}

fn tenant_onboard_step(_config: &ApiConfig, body: Value) -> Result<Value> {
    let step_str = required_string(&body, "step")?;
    let step = match step_str.as_str() {
        "create_org" => OnboardingStep::CreateOrg,
        "configure_scope" => OnboardingStep::ConfigureScope,
        "add_auth_profile" => OnboardingStep::AddAuthProfile,
        "run_lab_scan" => OnboardingStep::RunLabScan,
        "export_report" => OnboardingStep::ExportReport,
        _ => bail!("Unknown onboarding step: {}", step_str),
    };
    Ok(json!({ "ok": true, "step": format!("{:?}", step) }))
}

fn tenant_onboarding_status(_config: &ApiConfig, org_id: &str) -> Result<Value> {
    Ok(json!({ "org_id": org_id, "status": "pending" }))
}

fn tenant_create_api_key(config: &ApiConfig, body: Value) -> Result<Value> {
    let org_id = required_string(&body, "org_id")?;
    let workspace_id = required_string(&body, "workspace_id")?;
    let name = required_string(&body, "name")?;
    let role_str = body
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("api_user");
    let role = match role_str {
        "owner" => PlatformRole::Owner,
        "admin" => PlatformRole::Admin,
        "analyst" => PlatformRole::Analyst,
        "viewer" => PlatformRole::Viewer,
        _ => PlatformRole::Analyst,
    };
    let mut state = load_platform_state(config);
    let api_key = state.create_api_key(&org_id, &workspace_id, &name, role, utc_now_unix());
    save_platform_state(config, &state)?;
    Ok(serde_json::to_value(&api_key)?)
}

fn load_platform_state(config: &ApiConfig) -> PlatformState {
    let path = saas_root(config).join("platform_state.json");
    if path.exists() {
        let data = std::fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        PlatformState::new()
    }
}

fn save_platform_state(config: &ApiConfig, state: &PlatformState) -> Result<()> {
    let path = saas_root(config).join("platform_state.json");
    let dir = path.parent().unwrap();
    std::fs::create_dir_all(dir)?;
    let json = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query_with_percent_decoding() {
        let (path, query) = parse_target("/api/artifact?path=.baloncore%2Fdemo.json");
        assert_eq!(path, "/api/artifact");
        assert_eq!(query.get("path").unwrap(), ".baloncore/demo.json");
    }

    #[test]
    fn classifies_artifacts() {
        assert_eq!(
            artifact_kind(Path::new("evidence_manifest.json")),
            "evidence_manifest"
        );
        assert_eq!(artifact_kind(Path::new("remediation.md")), "remediation");
        assert_eq!(artifact_kind(Path::new("web3_analysis.json")), "web3");
    }

    #[test]
    fn redacts_secret_edges() {
        assert_eq!(redact_secret("AKIA1234567890ABCDEF"), "AKIA...CDEF");
    }

    #[test]
    fn rejects_bad_job_id() {
        assert!(validate_id("../escape").is_err());
        assert!(validate_id("job-123_ok").is_ok());
    }

    #[test]
    fn formats_rfc3339_utc_timestamps() {
        assert_eq!(system_time_string(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(compact_system_time(UNIX_EPOCH), "19700101T000000Z");
        assert_eq!(
            system_time_string(UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    fn maps_job_types_to_worker_pools() {
        assert_eq!(worker_pool_for_job_type("webapi_scan"), "webapi-validator");
        assert_eq!(worker_pool_for_job_type("repo_scan"), "repo-intelligence");
        assert_eq!(worker_pool_for_job_type("web3_analysis"), "web3-proof");
        assert_eq!(worker_pool_for_job_type("unknown"), "general-purpose");
    }

    #[test]
    fn queue_metadata_carries_tenant_and_worker_contract() {
        let body = json!({
            "org_id": "org-demo",
            "project_id": "project-demo",
            "asset_id": "asset-demo",
            "priority": 90
        });
        let payload = json!({});
        let tenant = tenant_metadata(&body, &payload);
        let queue = queue_metadata("job-demo", "webapi_scan", &body, &payload);
        assert_eq!(tenant["org_id"], "org-demo");
        assert_eq!(tenant["project_id"], "project-demo");
        assert_eq!(queue["worker_pool"], "webapi-validator");
        assert_eq!(queue["priority"], 90);
        assert_eq!(queue["state"], "queued");
    }

    #[test]
    #[cfg(unix)]
    fn run_command_enforces_timeout() {
        let root = std::env::temp_dir().join(format!(
            "baloncore-api-test-{}",
            compact_system_time(SystemTime::now())
        ));
        let out_dir = root.join("out");
        fs::create_dir_all(&out_dir).unwrap();
        let config = ApiConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            repo_root: root.clone(),
            workbench_root: root.join("workbench"),
        };
        let result = run_command(
            &config,
            vec!["/bin/sleep".to_string(), "2".to_string()],
            &out_dir,
            1,
        )
        .unwrap();
        assert_eq!(result["timed_out"], true);
        assert_eq!(result["ok"], false);
    }

    fn make_test_config() -> (ApiConfig, PathBuf) {
        let id = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("baloncore-p3s2-{}-{}", id, ts));
        let workbench = root.join("workbench");
        let evidence = root.join(".baloncore").join("evidence");
        fs::create_dir_all(&workbench).unwrap();
        fs::create_dir_all(&evidence).unwrap();
        let config = ApiConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            repo_root: root.clone(),
            workbench_root: workbench,
        };
        (config, root)
    }

    fn write_test_rollup(config: &ApiConfig) {
        let path = metrics_path(config);
        let mut rollup = MetricsRollup::new();
        let scan = baloncore_core::ScanRecord {
            scan_id: "scan-test-1".to_string(),
            started_at: 1000000,
            finished_at: Some(1003600),
            scan_type: "web_api".to_string(),
            base_url: "http://localhost:3000".to_string(),
            owner_profile: "user_a".to_string(),
            matrix_profiles: vec!["user_a".to_string()],
            endpoints_imported: 10,
            candidates_considered: 20,
            validated_count: 15,
            verified_findings: 5,
            rejected_hypotheses: 3,
            suppressed_findings: 1,
            noise_mode: "moderate".to_string(),
            run_dir: "/tmp".to_string(),
            findings: vec![],
        };
        let finding = baloncore_core::FindingRecord {
            finding_id: "f1".to_string(),
            scan_id: "scan-test-1".to_string(),
            fingerprint: "fp-1".to_string(),
            classification: "BOLA".to_string(),
            vulnerability_class: "BOLA".to_string(),
            endpoint: "/api/test".to_string(),
            object_id: "obj-1".to_string(),
            owner_profile: "user_a".to_string(),
            tested_profile: "user_b".to_string(),
            severity: "high".to_string(),
            score: 8,
            state: baloncore_core::FindingState::Verified,
            first_seen_run: "scan-test-1".to_string(),
            last_seen_run: "scan-test-1".to_string(),
            first_seen_at: 1000000,
            last_seen_at: 1003600,
            seen_count: 1,
            latest_artifacts: "/tmp".to_string(),
            latest_evidence_dir: "/tmp".to_string(),
            transitions: vec![],
            defense_classifications: vec![],
        };
        rollup.add_scan(&scan, &[finding], 100, 5000);
        baloncore_core::save_metrics_rollup(&rollup, &path).unwrap();
    }

    #[test]
    fn metrics_summary_returns_rollup_data() {
        let (config, root) = make_test_config();
        write_test_rollup(&config);
        let result = metrics_summary(&config).unwrap();
        assert_eq!(result["total_scans"], 1);
        assert_eq!(result["verified_findings"], 1);
        assert_eq!(result["rejected_hypotheses"], 0);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn metrics_summary_returns_empty_when_no_data() {
        let (config, root) = make_test_config();
        let result = metrics_summary(&config).unwrap();
        assert_eq!(result["total_scans"], 0);
        assert_eq!(result["verified_findings"], 0);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn metrics_trend_returns_series() {
        let (config, root) = make_test_config();
        write_test_rollup(&config);
        let result = metrics_trend(&config, "verified_findings", "day").unwrap();
        assert_eq!(result["metric"], "verified_findings");
        assert_eq!(result["bucket"], "day");
        let points = result["points"].as_array().unwrap();
        assert!(!points.is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn metrics_trend_returns_empty_series_for_no_data() {
        let (config, root) = make_test_config();
        let result = metrics_trend(&config, "verified_findings", "day").unwrap();
        let points = result["points"].as_array().unwrap();
        assert!(points.is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn metrics_drilldown_returns_entries() {
        let (config, root) = make_test_config();
        write_test_rollup(&config);
        let result = metrics_drilldown(&config, "verified_findings", None).unwrap();
        assert_eq!(result["metric"], "verified_findings");
        let entries = result["entries"].as_array().unwrap();
        assert!(!entries.is_empty());
        assert_eq!(result["total_entries"], entries.len() as u64);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn metrics_drilldown_returns_empty_for_no_data() {
        let (config, root) = make_test_config();
        let result = metrics_drilldown(&config, "verified_findings", None).unwrap();
        let entries = result["entries"].as_array().unwrap();
        assert!(entries.is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn metrics_endpoints_wired_in_router() {
        let (config, _root) = make_test_config();
        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/metrics/summary".to_string(),
            query: BTreeMap::new(),
            body: vec![],
        };
        let response = route_request(&config, request).unwrap();
        assert_eq!(response.0, 200);

        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/metrics/trend".to_string(),
            query: {
                let mut q = BTreeMap::new();
                q.insert("metric".to_string(), "verified_findings".to_string());
                q.insert("bucket".to_string(), "day".to_string());
                q
            },
            body: vec![],
        };
        let response = route_request(&config, request).unwrap();
        assert_eq!(response.0, 200);

        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/metrics/drilldown".to_string(),
            query: {
                let mut q = BTreeMap::new();
                q.insert("metric".to_string(), "verified_findings".to_string());
                q
            },
            body: vec![],
        };
        let response = route_request(&config, request).unwrap();
        assert_eq!(response.0, 200);
    }
}
