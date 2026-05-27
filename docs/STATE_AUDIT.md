# BALONCORE State Audit — P0.S0

Date: 2025-05-25  
Auditor: P0.S0 automated honest audit  
Invariant reminder: Models propose, validators promote. No shortcutting.

---

## 1. Capability Classification by Roadmap Stage

Legend:
- **REAL**: Runs real work on real/external input, has positive AND negative tests, produces durable evidence.
- **FIXTURE**: Only deterministic/canned output, or only runs against a self-authored lab.
- **STUB**: Type/CLI/schema surface exists but behavior is a placeholder.

### Stage 0 — Foundation

| Capability | Classification | Evidence |
|---|---|---|
| Rust workspace | **REAL** | Cargo workspace with 3 crates, `cargo build` and `cargo test` pass. |
| Config format (baloncore.toml) | **REAL** | `config.rs` full TOML parsing, `BaloncoreConfig::load_from_path`, `example()`. CLI `init` and `check-config` work. |
| Scope model (ScopeGuard) | **REAL** | `scope.rs` with allow/deny URL/host rules. CLI `check-scope` evaluates real URLs. `scan_openapi_bola` enforces scope on every request (CLI main.rs:1489). |
| Evidence model | **REAL** | `evidence.rs` defines `EvidenceRecord`, `EvidenceKind`, `RedactionStatus`, `RedactionRule`, `default_redaction_rules()`. CLI `seal-evidence`, `sign-evidence`, `verify-evidence` all write and verify real SHA-256 + Ed25519 signatures. |
| Finding model | **REAL** | `lifecycle.rs` defines `FindingState` through `Hypothesis→Rejected→NeedsMoreEvidence→Verified→Reported→Fixed→Retested→Closed` with `can_transition_to` enforcement. `FindingStore` persists to JSON disk. CLI `record-finding-lifecycle` enforces valid transitions. |
| Safety documentation | **REAL** | `docs/SAFETY.md` exists, scope guard works. |

### Stage 1 — Web/API Validation MVP

| Capability | Classification | Evidence |
|---|---|---|
| Endpoint inventory (OpenAPI) | **REAL** | `OpenApiInventory::from_json` in `web_api.rs:527-593`. CLI `scan-openapi-bola` fetches real OpenAPI URLs. |
| HTTP request runner (live) | **REAL** | `HttpRequestRunner` in `web_api.rs:934-983` uses `reqwest::blocking::Client` to make real outbound HTTP requests. `live_exchange` in CLI main.rs. |
| Auth profiles (bearer tokens) | **REAL** | `AuthProfile` + `AuthCredentialRef` in `config.rs:39-58`. `bearer_token_env` reads from env vars. CLI resolves tokens at scan time. Only supports bearer-token auth; no OAuth2/cookie/session yet. |
| Auth matrix validation | **REAL** | `scan_openapi_bola` in CLI main.rs runs real owner/attacker/anonymous exchanges against live endpoints. `BolaValidator::validate` makes real classification decisions from real HTTP responses. |
| BOLA validator | **REAL** | `web_api.rs:1037-1101` — validates real `BolaValidationCase` with owner/attacker/anonymous exchange comparison. Produces `VerifiedBolaFinding` or `RejectedHypothesis`. Tested with unit tests in `web_api.rs` (body similarity, evidence markers, classification). |
| Anonymous exposure classification | **REAL** | `AuthorizationClass::MissingAuthentication` path in `web_api.rs:808-810` — when anonymous gets 200 with similar body or evidence markers, classified as missing auth. |
| BFLA classification | **REAL** | `web_api.rs:822-830` — admin tests on privileged endpoints and admin-owned objects. |
| Resource-aware seed/candidate matching | **REAL** | `BolaCandidate::matches_seed` in `web_api.rs:699-729` filters out resource-mismatched pairs. CLI skips mismatched candidates with explicit `skip_class: resource_mismatch`. |
| Sensitive field detection | **REAL** | `sensitive_fields_from_value` in `web_api.rs:1180-1186` detects email, financial, credential, PII, ownership, privileged data categories. `ResponseImpactAnalysis` uses them for real severity scoring. |
| Impact severity scoring | **REAL** | `base_impact_score` + `sensitive_category_weight` + shape similarity bonus in `web_api.rs:345-400`. Produces real severity classifications. |
| Noise policy/budget enforcement | **REAL** | CLI `--noise-mode quiet/moderate/loud` + `--max-active-requests` hard budget. Skips validation with `skip_class: noise_policy_budget` when exceeded. `web_api.rs:1518-1519`. |
| Remediation plans | **REAL** | `RemediationPlan::for_authorization_finding` generates real fix steps and `RegressionCheck`s with expected statuses. CLI `run-regression` sends real HTTP requests. |
| Regression runner (live) | **REAL** | CLI `run-regression` reads a `remediation.json`, sends real HTTP requests for each check, classifies `Fixed`/`StillFailing`. |
| Evidence sealing/signing | **REAL** | CLI `seal-evidence` writes SHA-256 manifest, `init-signing-key` generates Ed25519 keys, `sign-evidence` creates signatures, `verify-evidence` + `verify-evidence-run` verify both. Has tamper-negative tests. |
| Evidence indexing | **REAL** | CLI `index-evidence-run` normalizes run artifacts into `.baloncore/evidence/index.json` and per-scan records. |
| Schema discovery | **FIXTURE** | `discovery.rs` defines probe types and orchestration, but no real non-OpenAPI schema fetcher makes live requests. OpenAPI inventory works. GraphQL, Postman, WSDL, gRPC probes are type stubs — they define `SchemaType` variants but don't make live discovery requests. |
| Local vulnerable API lab | **REAL** | `labs/vulnerable-api/server.js` — planted BOLA at `/api/invoices/inv_2002`. `stage1_e2e_demo.sh` runs a full scan, remediation, and regression check against it. |
| Response-shape comparison | **REAL** | `shape_similarity` in `web_api.rs:1144-1158` compares token-based Jaccard similarity. |

### Stage 2 — Evidence and Reporting

| Capability | Classification | Evidence |
|---|---|---|
| Durable evidence store | **REAL** | `.baloncore/evidence/index.json` + per-scan records under `.baloncore/evidence/scans/`. CLI `index-evidence-run` creates them. |
| Finding lifecycle | **REAL** | `FindingStore` with transition enforcement in `lifecycle.rs`. CLI `record-finding-lifecycle`. |
| Evidence redaction | **REAL** | `default_redaction_rules()` in `evidence.rs` replaces auth headers, session tokens, PII. CLI `redact-evidence-file` and `check-evidence-export` enforce export blockers on unredacted evidence. |
| HTML report export | **REAL** | CLI `export-evidence-report --format html` produces a self-contained HTML report. |
| Markdown/JSON report | **REAL** | `run_report.md` and JSON artifacts written per scan. |
| Evidence sensitivity labels | **REAL** | `RedactionStatus` enum: NotReviewed, RedactionRequired, Redacted, SafeToShare in `evidence.rs:36-42`. |
| SARIF export | **REAL** | `sarif.rs` implements `findings_to_sarif`. CLI `export-evidence-sarif`. |

### Stage 3 — AI Agent Layer

| Capability | Classification | Evidence |
|---|---|---|
| Model configuration | **STUB** | `ModelConfig` in `agent.rs:8-19` defines `provider`, `model`, `api_base`, `api_key_env`, `max_tokens`, `temperature`. Default is `"fixture"`. No network call to any LLM provider exists. |
| Agent input/output schemas | **REAL** | `AgentInput`, `AgentOutput`, `AgentHypothesis`, `AgentObservation`, `AgentRun` are well-defined in `agent.rs`. CLI `show-agent`, `run-agent-dry-run`, `validate-agent-output`, `agent-pipeline` all work with real I/O. |
| Fixture agent runner | **FIXTURE** | `run_fixture_agent` in `agent.rs:211-224` returns canned/hardcoded output per role. No actual model reasoning. It patterns on input endpoints but does not invoke any intelligence. |
| Fixture agent pipeline | **FIXTURE** | `run_fixture_agent_pipeline` in `agent.rs:226-251` chains fixture output through the validation/challenge/bridge logic. The pipeline plumbing is real; the model call is canned. |
| Validation/challenge of agent output | **REAL** | `validate_agent_output` checks role match, refusal reasons, schema constraints. `challenge_hypotheses` blocks missing endpoints, missing evidence, low confidence. `bridge_hypotheses_to_validators` routes to deterministic validators by classification. All real logic in `agent.rs:253-376`. |
| Validator classification bridge | **REAL** | `validator_for_classification` maps BOLA→bola-validator, BFLA→authorization-matrix-validator, missing-auth→anonymous-exposure-validator, etc. `"manual-review"` for unknowns. |
| Prompt templates | **STUB** | `prompt_template` in `agent.rs:184-209` generates a template string but it is never sent to a model. Version is `"1.0.0"`, no version registry. |
| Agent specs | **REAL** | `agents.rs` defines 9 agent specs with name, mission, output_schema, must_validate. |
| Model provider: fixture | **FIXTURE** | The only provider. No Anthropic, no OpenAI, no other provider exists. |

### Stage 4 — Dashboard

| Capability | Classification | Evidence |
|---|---|---|
| Dashboard page | **STUB** | `apps/web/app/dashboard/page.tsx` exists. Next.js app present. Reads from baloncore.ts client that calls the Rust API. Shows scan history and findings but is a static/semi-static artifact display, not a live product-quality dashboard. |
| Login page | **STUB** | `apps/web/app/login/page.tsx` exists. No real auth. |
| Admin page | **STUB** | `apps/web/app/admin/page.tsx` exists. |
| API service | **FIXTURE** | `baloncore-api/src/main.rs` is a raw TCP HTTP server (no framework like actix/axum). Reads/writes JSON files in `.baloncore/workbench/`. No real database. No auth. Binds to 127.0.0.1 only. Has 30+ endpoints but they read JSON files from disk and return hardcoded/template data. |

### Stage 5 — CI/CD

| Capability | Classification | Evidence |
|---|---|---|
| SARIF export | **REAL** | `sarif.rs` + CLI `export-evidence-sarif`. |
| CI evidence gate | **REAL** | CLI `ci-evidence-gate` and `ci-run` evaluate real evidence policies against indexed findings. |
| Baseline comparison | **REAL** | CLI `baseline-evidence` writes baseline files. CI gate compares against baseline. |
| OpenAPI diff | **REAL** | CLI `diff-openapi` compares two OpenAPI specs and emits auth-relevant changed endpoints. |
| Notification dry-run | **REAL** | `export-notification-dry-run` renders Slack/Linear/Jira payloads without sending. No real webhook delivery. |
| PR summary | **REAL** | `ci-run` writes `pr_summary.md` from real run data. |
| GitHub Actions integration | **STUB** | `export-regression-ci` generates a workflow YAML. No real GitHub API integration. |

### Stage 6 — Cloud/IAM

| Capability | Classification | Evidence |
|---|---|---|
| Cloud IAM graph model | **REAL** | `cloud_iam.rs` defines `IAMGraph`, `IAMPrincipal`, `IAMPolicy`, `IAMStatement`, `TrustRelationship`, `PrivilegePath`, `CloudReachabilityProof`. Full graph analysis. |
| AWS IAM parser | **REAL** | `aws_iam.rs` parses IAM policy documents. CLI `analyze-cloud-iam aws labs/cloud-iam/aws-risky.json`. |
| Terraform adapter | **REAL** | `terraform.rs` parses HCL-like Terraform state to extract IAM resources and trust relationships. |
| Other cloud IaC parsers | **REAL** | `gcp_iam.rs`, `azure_arm.rs`, `cloudformation.rs`, `kubernetes.rs` all parse their respective config formats. |
| Reachability proofs | **REAL** | `cloud_reachability_proofs` computes privilege paths from parsed config. CLI outputs `cloud_reachability_proofs.json` + `.md`. |
| Live cloud validation | **FIXTURE** | All cloud analysis operates on local config files. No live AWS/GCP/Azure API calls. The `labs/cloud-iam/aws-risky.json` is a hand-authored fixture. |

### Stage 7 — Web3

| Capability | Classification | Evidence |
|---|---|---|
| Solidity parser | **REAL** | `web3_parsers.rs` parses Solidity files for contracts, functions, events, storage. |
| Slither JSON ingestion | **REAL** | `web3.rs` `ingest_slither_output` parses Slither's SARIF-like JSON output. |
| Invariant generation | **REAL** | `generate_invariants_for_project` creates template invariants (conservation, access-control, reentrancy, etc.). |
| Foundry proof-test generation | **REAL** | `generate_foundry_proof_tests` creates `.t.sol` test files. CLI `analyze-web3` outputs them. |
| Fuzz runner | **STUB** | `run_forge_fuzz` and `run_fuzz_and_update` are defined but call out to `forge test` — this requires a real Foundry installation. No unit test exercises the fuzz path without Foundry. |
| Foundry config parsing | **REAL** | `parse_foundry_config` reads `foundry.toml`. |
| Live Web3 validation | **FIXTURE** | All analysis runs on local files in `labs/vulnerable-protocol/`. No on-chain interaction. |

### Stage 8 — Autonomous Pentest

| Capability | Classification | Evidence |
|---|---|---|
| Orchestrator | **FIXTURE** | `orchestrator.rs` defines `AutonomousBudget`, `AutonomousStep`, `AutonomousRun`, `AutonomousStepStatus`, `ToolCallRequest`, `ToolCallResult`, `ApprovalGate`, `AgentMemory`. CLI `autonomous-run` runs `run_autonomous_fixture` which produces canned steps. No real multi-agent coordination. |
| Research engine | **FIXTURE** | `research_engine.rs` defines `ReconGraph`, `ReconNode`, `ResearchHypothesis`, `ProofExecutionPlan`, `FalsePositiveChallenge`. API `/api/security/research-engine` calls `run_research_engine` which generates hypotheses from canned templates based on local file artifacts. Not a real autonomous research agent. |
| Attack graph | **STUB** | `attack_graph.rs` defines types but the API `/api/security/attack-graph` returns mostly hardcoded/template data. |
| Human approval gates | **STUB** | `ApprovalGate` type exists with `gate_type: String` but CLI `autonomous-run` does not pause for approval — it checks `passed_safety` at the end. No real interactive approval. |

### Stage 9 — Defense

| Capability | Classification | Evidence |
|---|---|---|
| Defense recommendation engine | **REAL** | `defense.rs` `recommend` + `recommend_for_findings` generates remediation, detection, regression, WAF, least-privilege guidance based on classification. CLI `defense-report` and `export-defense-bundle` work. |
| Sigma rule generation | **REAL** | `generate_sigma_rule` produces real Sigma-style detection rules. |
| WAF rule generation | **REAL** | `WafRule` and `WafRuleType` provide real WAF guidance. |
| Least-privilege guidance | **REAL** | `generate_least_privilege_guidance` produces real IAM least-privilege suggestions. |
| Regression test templates | **REAL** | `generate_regression_tests` creates real regression test templates. |
| Threat model snippets | **REAL** | `ThreatModelSnippet` and `StrideCategory` classification work. |
| Defense maturity scoring | **REAL** | `DefenseMaturityScore` computes maturity from findings. |

### Stage 10 — Company-Grade Platform

| Capability | Classification | Evidence |
|---|---|---|
| Organizations/WS/RBAC model | **STUB** | `platform.rs` defines `Organization`, `Workspace`, `PlatformUser`, `PlatformRole`, `PlatformPermission`, `RoleAssignment`. CLI `platform-bootstrap` creates a local `platform_state.json`. No real auth, no real RBAC enforcement at API layer, no real multi-tenant isolation. |
| Billing model | **STUB** | `BillingAccount` and `UsageMetrics` are type definitions in `platform.rs`. No real billing integration, no real metering. |
| Audit event model | **STUB** | `AuditEvent` is a struct in `platform.rs`. CLI `platform-bootstrap` creates a sample. API `/api/saas/audit-log` reads from JSON. No append-only, no real immutability, no real audit pipeline. |
| Compliance mapping | **STUB** | `compliance_mapping()` in `platform.rs` returns hardcoded OWASP API Security Top 10 mappings. Not dynamically computed from findings. |
| SaaS control plane | **FIXTURE** | API is a raw TCP server reading JSON files. Postgres schema in `migrations/0001_saas_control_plane.sql` exists (161 lines) but is not connected to the application. All data flows through `.baloncore/workbench/` JSON files. No real database. No real auth. No real tenant isolation. |
| Encrypted evidence at rest | **STUB** | No encryption anywhere. Evidence JSON is stored plaintext on disk. |
| Metrics computation | **STUB** | No `metrics.rs` module exists. Investor metrics (verified findings per scan, FP reduction rate, time to proof, etc.) are not computed anywhere in the codebase. The API computes ad-hoc counts from JSON files for display but has no proper metric functions. |

---

## 2. Specific Findings

### 2.1 Is there ANY real LLM provider network call?

**No.** The only HTTP client in the codebase is `reqwest::blocking::Client` in `web_api.rs` (used by `HttpRequestRunner` for live validation requests to target APIs). There is no Anthropic client, no OpenAI client, no model client trait, no `live-models` feature flag, and no code that POSTs to any LLM API. The `openai_api_key` string in the API server is a regex pattern for secret detection (`crates/baloncore-api/src/main.rs:3643`), not a credential used to call OpenAI.

The only "model" is `ModelConfig::default()` with `provider: "fixture"` (`agent.rs:24`). All agent output comes from `run_fixture_agent` (`agent.rs:211-224`) which returns hardcoded/pattern-matched responses per role. No network call to any AI service.

### 2.2 Which validators send live HTTP vs operate on fixtures?

| Validator | Live HTTP? | Evidence |
|---|---|---|
| BOLA validator (`BolaValidator::validate`) | No — operates on pre-fetched `BolaValidationCase` structs | `web_api.rs:1037-1101`. The validation logic is deterministic given the exchanges. But `HttpRequestRunner` sends live HTTP to fetch those exchanges in the first place (CLI main.rs scan_openapi_bola). |
| Authorization matrix classification (`AuthorizationMatrixObservation::classify`) | No — deterministic classification from exchange data | `web_api.rs:777-862`. Given owner/attacker/anonymous exchanges, produces classification deterministically. |
| Cloud IAM graph analysis | No — offline analysis of local config files | `cloud_iam.rs` + CLI `analyze-cloud-iam`. |
| Web3 analysis | No — offline static analysis | `web3.rs` + CLI `analyze-web3`. |
| Schema discovery probes | Partially — OpenAPI fetch is live; other probes are stubs | `discovery.rs` defines probe types but only OpenAPI inventory fetch via `HttpRequestRunner` works live. |
| Agent pipeline → validator bridge | No — fixture output bridges to deterministic validators | `agent.rs:226-251`. The bridge logic is real but the agent output is canned. |

### 2.3 Which findings have ever been produced against a target NOT written by us?

**None confirmed.** All documented proof runs are against `labs/vulnerable-api/server.js` (written by this project). The `labs/cloud-iam/aws-risky.json` is hand-authored fixture data. No external target (OWASP crAPI, VAmPI, DVGA, etc.) has been validated against. The P2 benchmark corpus does not exist yet.

### 2.4 Which investor metrics in the roadmap are actually computed and stored today?

| Metric | Computed? | Stored? | Where |
|---|---|---|---|
| Verified findings per scan | Partially — `verified_findings` count exists in `ScanRecord` | Yes — in `.baloncore/evidence/index.json` per scan | `lifecycle.rs:166` |
| False-positive reduction rate | **No** | No | — |
| Time to proof | **No** | No timestamps computed for this in code | — |
| Time to fix | **No** | `FindingTransition` has `at: u64` but no code computes fix-time delta | — |
| Retest success rate | **No** | `RegressionRunReport` has `Fixed`/`StillFailing` but no aggregation computes rate | — |
| CI-blocked criticals | **No** — CI gate evaluates real evidence but doesn't compute a metric | No | — |
| Scan volume over time | **No** | No time-series bucketing | — |
| Model calls per verified finding | **No** — no model calls exist | No | — |

### 2.5 Where are JSON files standing in for a real database?

**Everywhere.** The entire data layer is JSON files on disk:

- `.baloncore/evidence/index.json` — evidence store
- `.baloncore/evidence/scans/*.json` — per-scan records
- `.baloncore/findings/index.json` — finding store
- `.baloncore/hypotheses/index.json` — hypothesis store
- `.baloncore/workbench/*.json` — API workbench data (jobs, organizations, projects, assets, audit events, workers, queue, scorecards, artifacts)
- `.baloncore/platform/platform_state.json` — platform/RBAC model
- `.baloncore/keys/trusted_signers.json` — signer trust
- `.baloncore/agents/*.json` — agent run artifacts
- `.baloncore/ci/*.json` — CI artifacts
- `.baloncore/defense/bundle/*.json` — defense bundles

The `baloncore-api` server reads/writes these JSON files directly. The Postgres schema in `migrations/0001_saas_control_plane.sql` is not connected. There is no real database anywhere.

---

## 3. Honest Classification Table

| Roadmap Stage | Capability Area | Classification |
|---|---|---|
| 0 — Foundation | Workspace, config, scope, evidence model | **REAL** |
| 1 — Web/API | BOLA/BFLA/missing-auth validation | **REAL** (against self-authored lab) |
| 1 — Web/API | Auth matrix, resource matching, sensitivity | **REAL** |
| 1 — Web/API | Live HTTP runner + scoped requests | **REAL** |
| 1 — Web/API | Schema discovery (non-OpenAPI) | **FIXTURE** |
| 1 — Web/API | Workflow/state-transition mapping | **STUB** — `schema_workflow_inventory.json` is generated but contains structural data, not semantic workflow analysis |
| 2 — Evidence | Evidence store, finding lifecycle, sealing/signing | **REAL** |
| 2 — Evidence | Redaction, SARIF, reports | **REAL** |
| 3 — AI Agent | Agent I/O schemas, validation, bridge | **REAL** |
| 3 — AI Agent | Model calls / LLM integration | **STUB** — fixture only |
| 3 — AI Agent | Prompt version registry | **STUB** — single version, no registry |
| 4 — Dashboard | Web UI | **FIXTURE** — reads JSON workbench files |
| 4 — Dashboard | API server with real DB | **STUB** — raw TCP, JSON files, no auth |
| 5 — CI/CD | SARIF, baseline, evidence gate, PR summary | **REAL** |
| 5 — CI/CD | GitHub integration / real CI delivery | **STUB** — YAML templates only |
| 6 — Cloud/IAM | Offline graph analysis from config files | **REAL** |
| 6 — Cloud/IAM | Live cloud validation | **FIXTURE** — local files only |
| 7 — Web3 | Solidity parsing, invariant generation, Slither ingestion | **REAL** |
| 7 — Web3 | Live fuzz/test execution | **STUB** — requires external Foundry |
| 8 — Autonomous | Orchestrator | **FIXTURE** — canned steps |
| 8 — Autonomous | Research engine | **FIXTURE** — template generation |
| 9 — Defense | Remediation, detection, regression templates | **REAL** |
| 9 — Defense | WAF rules, least-privilege guidance | **REAL** |
| 10 — Platform | Org/WS/RBAC/billing/audit | **STUB** — type definitions, JSON bootstraps |
| 10 — Platform | Encrypted evidence at rest | **STUB** |
| 10 — Platform | Real metrics pipeline | **STUB** — does not exist |

---

## 4. What a technical diligence reviewer concludes in 30 minutes

This project has a **real, working Web/API authorization validator** that can prove BOLA, BFLA, and missing-auth findings against a local lab with live HTTP requests, deterministic classification, evidence capture, sealing, and regression. That is the genuine core product, and it works.

Everything beyond Stage 1-2's evidence pipeline is progressively less real. The "AI agent layer" is a **structure without intelligence** — schemas, validation, and bridge logic are correct, but the only model is a fixture that returns canned output. No LLM has ever been called. The cloud/IAM and Web3 modules are **offline static analyzers** that produce useful output from local config files but do no live validation. The autonomous orchestrator, research engine, and "command center" in the API are **demonstration scaffolding** backed by JSON files. The SaaS platform has types and templates but no real database, no real auth, no real tenant isolation, and no real metrics.

The strongest real artifact is the BOLA validator + live lab + evidence lifecycle. The weakest claim is the "AI-native" label — there is no AI in the loop today. The P1 (real model-in-the-loop) gap is the single most important gap because it means the "AI proposes, validators prove" firewall has never been tested with an actual model. The investor metrics (FP reduction rate, time to proof, retest success rate) are not computed at all, which means the "data-driven" pitch relies on counts that exist but rates that do not.

---

## 5. Top 5 Gaps Ranked by Funding Impact

| Rank | Gap | Impact | Closed By |
|---|---|---|---|
| 1 | **No real LLM provider call exists** — the "AI-native" claim and the entire firewall test have never run with real model output. A model could produce subtly wrong schemas, hallucinated endpoints, or adversarial text that the current fixture never exercises. | **Critical** — this is the difference between a security tool with AI and a deterministic scanner with a demo. | P1.S0–S8 |
| 2 | **No benchmark corpus or external target validation** — all proof runs are against the project's own lab. No independent target has ever validated a finding. This means "verified findings per scan" is a number from a self-authored test, not from an independent corpus. | **High** — a diligence reviewer will immediately ask "what has this actually found that you didn't plant?" | P2.S2–S3 |
| 3 | **JSON files standing in for a database** — the entire API and platform layer reads/writes flat JSON. No real multi-tenant store, no real query capability, no durability guarantee, no concurrency. This is the "is it a prototype or a product?" question. | **High** — blocks enterprise deployment and any real SaaS narrative. | P5.S0 |
| 4 | **No real metrics computation** — the roadmap's investor metrics (FP reduction rate, time to proof, time to fix, model calls per verified finding) have no implementation. The API returns hardcoded/template scorecards. | **Medium-High** — the numbers that would support a pitch deck don't exist as computed values. | P3.S0–S1 |
| 5 | **Schema discovery (non-OpenAPI) and workflow mapping are stubs** — the roadmap claims GraphQL, Postman, WSDL, gRPC discovery but only OpenAPI actually fetches live schemas. Business-logic validation (the "scanners miss this" selling point) has no implementation beyond the `business-logic` fixture agent that pattern-matches on `POST`/`PATCH`/`DELETE`. | **Medium** — reduces the addressable surface for a paying customer to REST/OpenAPI APIs only. | P4.S0–S3 |

---

## 6. Known Breakage — Build/Test Ground Truth (P0.S1)

Ran: 2025-05-25

### cargo build — exit code 0

```
Compiling baloncore-api v0.1.0
Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.43s
```

**Result: PASS. Clean build, no errors.**

### cargo test — exit code 0

```
running 17 tests  ... test result: ok. 17 passed; 0 failed   (baloncore-cli)
running 8 tests   ... test result: ok. 8 passed; 0 failed    (baloncore-api)
running 185 tests ... test result: ok. 185 passed; 0 failed   (baloncore-core)
running 0 doc-tests ... test result: ok. 0 passed; 0 failed
```

**Result: PASS. 210 tests total, all green, no failures.**

### cargo fmt --check — exit code 0

```
(no output — no formatting errors)
```

**Result: PASS. Code is formatted.**

### cargo clippy --all-targets — exit code 0, 48 warnings (0 errors)

Warnings by category:

| Category | Count | Files |
|---|---|---|
| `unnecessary_map_or` / `is_none_or` | 6 | `ci.rs`, `platform.rs` |
| `collapsible_str_replace` | 4 | `gcp_iam.rs`, `sarif.rs` |
| `single_char_add_str` | 7 | `cloud_iam.rs`, `defense.rs`, `web3.rs` |
| `too_many_arguments` | 4 | `research_engine.rs`, `main.rs` (CLI) |
| `len_zero` | 5 | `cloud_iam.rs`, `web3.rs`, `web3_parsers.rs` |
| `field_reassign_with_default` | 2 | `main.rs` (API), `main.rs` (CLI) |
| `match_like_matches_macro` | 1 | `lifecycle.rs` |
| `wildcard_in_or_patterns` | 1 | `aws_iam.rs` |
| `redundant_closure` | 1 | `aws_iam.rs` |
| `unnecessary_filter_map` | 1 | `aws_iam.rs` |
| `map_identity` | 1 | `aws_iam.rs` |
| `for_kv_map` | 3 | `cloud_iam.rs` |
| `collapsible_else_if` | 1 | `cloud_iam.rs` |
| `useless_format` | 2 | `cloud_iam.rs` |
| `bool_comparison` | 1 | `web3.rs` |
| `manual_contains` | 1 | `web3_parsers.rs` |
| `type_complexity` | 1 | `web3_parsers.rs` |
| `trim_split_whitespace` | 1 | `web3_parsers.rs` |
| `manual_pattern_char_comparison` | 1 | `web3.rs` |
| `option_map_unit_fn` | 1 | `web3.rs` |
| `to_string_in_format_args` | 1 | `main.rs` (API) |
| `bind_instead_of_map` | 1 | `ci.rs` |

**Result: PASS with 48 warnings, 0 errors. All warnings are style/suggestion level, not correctness issues. No clippy errors block the build.**

### Frontend build (apps/web) — `npx next build` — exit code 0

```
Next.js 16.2.6 (Turbopack)
✓ Compiled successfully in 915ms
Generating static pages (6/6) in 220ms
Routes: /, /_not-found, /admin, /dashboard, /login
```

**Result: PASS. Frontend builds and type-checks cleanly.**

### Frontend typecheck (`tsc --noEmit`) — exit code 0

**Result: PASS. No TypeScript errors.**

### Summary: No known breakage. All builds, tests, formatting, lint, and type checks pass clean.

---

*End of P0.S0 + P0.S1 state audit. P0.S1 risk register follows in docs/RISK_REGISTER.md.*