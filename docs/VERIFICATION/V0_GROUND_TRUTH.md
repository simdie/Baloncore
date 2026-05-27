# V0 — BALONCORE Independent Ground-Truth Audit

> Auditor: Claude Opus 4.7, executing V0 of `BALONCORE_VERIFICATION_FINALIZATION.md`.
> Method: trust nothing self-reported. Every claim is reduced to a file, a line, or a runnable command. Where the evidence shows a feature is a façade, the verdict is **STUB / FAKE** regardless of the README's checkmark.
> Mode: audit only — no fixes applied in this pass.

---

## 1. Build, test, clippy, lint — verbatim

| Command | Exit | Notes |
|---|---|---|
| `cargo build` | **0** | `warning: unused import: CIAnalytics` in [crates/baloncore-cli/src/main.rs:29](crates/baloncore-cli/src/main.rs#L29); otherwise clean. |
| `cargo test --workspace` | **0** | `baloncore` 17 passed, `baloncore-api` 15 passed, `baloncore-core` 502 passed, doc-tests 0. **Zero failures, zero ignored**. |
| `cargo test --features live-models` | **0** | `baloncore-core` rises to **511 passed** (gate-flagged Anthropic/OpenAI mock-server tests). |
| `cargo fmt --check` | **1** | One diff: [crates/baloncore-cli/src/main.rs:10995](crates/baloncore-cli/src/main.rs#L10995) — `let finding_ids: Vec<String> = ...` reformatting. **Trivial; not a code defect.** |
| `cargo clippy --all-targets` | **0** | **163 warnings**, 0 errors. Categories: `unused_imports`, `clippy::too_many_arguments`, `clippy::redundant_closure`, `clippy::collapsible_if`, `clippy::needless_borrow`, unused mut, dead-code `make_finding_with_transition`. None are errors but the count is high. |
| `corepack pnpm --dir apps/web typecheck` | **0** | `tsc --noEmit` clean. |
| `corepack pnpm --dir apps/web build` | **0** | Next 16.2.6 / Turbopack: 7 static pages (`/`, `/admin`, `/dashboard`, `/health`, `/login`, `/_not-found`). Compile + TS in ~2.3 s. |

**Headline:** the workspace compiles and *every* test passes. That is necessary but not sufficient — the rest of this document shows that several "passing" tests pass against stubs.

---

## 2. The single most important finding (read this before anything else)

The **benchmark scoreboard that the diligence documentation tells investors to reproduce is a 100 %-by-construction tautology.** It does **not** run BALONCORE against any target. Concretely:

- [docs/DILIGENCE/BENCHMARK.md:7-15](docs/DILIGENCE/BENCHMARK.md#L7-L15) and [benchmarks/METHODOLOGY.md:9-11](benchmarks/METHODOLOGY.md#L9-L11) both promote `./scripts/run_benchmarks.sh` / `cargo run -p baloncore -- benchmark-ci --suite baloncore-web-api-v1 --save-golden --json` as the *one-command reproduction*.
- That command lands in `benchmark_ci` at [crates/baloncore-cli/src/main.rs:9213-9326](crates/baloncore-cli/src/main.rs#L9213-L9326). When the golden file is absent (or `--save-golden` is passed) it calls `baloncore_core::generate_golden_baseline(&suite)`.
- `generate_golden_baseline` ([crates/baloncore-core/src/evaluation.rs:4127-4180](crates/baloncore-core/src/evaluation.rs#L4127-L4180)) constructs a `BenchmarkRun` whose every `BenchmarkResult.prediction = case.ground_truth` and `evidence_found = case.expected_evidence_keys`.
- The same suite is then handed to `benchmark_ci_gate` and `generate_scorecard`, which compare predictions to ground truth. They match by construction.

I ran the exact CLI command the docs prescribe in a clean directory:

```
$ baloncore benchmark-ci --suite baloncore-web-api-v1 --save-golden --json ...
{ "accuracy":1.0, "f1_score":1.0, "fpr":0.0, "grade":"A+",
  "passed":true, "precision":1.0, "recall":1.0, ... }
```

No BALONCORE scan ran. No target was started. The numbers are not measurements — they are a copy of the ground-truth labels printed back as `prediction`. **A technical diligence reviewer who runs the documented command will be shown a tautology.**

---

## 3. Stage-by-stage verdict table

Legend — **REAL**: runs real work, exercised by tests that genuinely fail if the feature breaks. **FIXTURE**: only canned / self-authored input, deterministic. **STUB / FAKE**: placeholder, hardcoded output masquerading as computed, or a test that passes against broken code.

| Stage | Claim | Verdict | Evidence |
|---|---|---|---|
| **P0.S0** capability ledger | `docs/STATE_AUDIT.md` exists with REAL/FIXTURE/STUB table | REAL (artifact present) | [docs/STATE_AUDIT.md](docs/STATE_AUDIT.md) |
| **P0.S1** build/test ground truth | risk register exists | REAL (artifact) | [docs/RISK_REGISTER.md](docs/RISK_REGISTER.md) — content not re-verified in V0 |
| **P1.S0** provider abstraction skeleton | `ModelClient` trait + `FixtureModelClient` + `client_for` factory | **REAL** | [crates/baloncore-core/src/model_client.rs:57-61](crates/baloncore-core/src/model_client.rs#L57-L61), [crates/baloncore-core/src/model_client.rs:429-446](crates/baloncore-core/src/model_client.rs#L429-L446); tests `client_for_default_returns_fixture`, `client_for_unknown_provider_is_refused`, `fixture_client_returns_valid_json` ([model_client.rs:452-514](crates/baloncore-core/src/model_client.rs#L452-L514)). |
| **P1.S1** strict JSON + repair + budget | `parse_agent_output`, `build_repair_request`, `run_live_agent`, `ModelBudget` | **REAL** | [crates/baloncore-core/src/agent_runtime.rs:124-207](crates/baloncore-core/src/agent_runtime.rs#L124-L207), [agent_runtime.rs:209-293](crates/baloncore-core/src/agent_runtime.rs#L209-L293), [agent_runtime.rs:309-409](crates/baloncore-core/src/agent_runtime.rs#L309-L409); positive + negative tests `parse_clean_json`, `parse_fenced_json_with_preamble`, `parse_malformed_then_valid_on_repair`, `parse_twice_malformed_returns_skipped`, `budget_exhausted_before_first_call`, `role_is_always_set_by_parse_not_trusted_from_model`, `transport_error_returns_skipped` ([agent_runtime.rs:553-790](crates/baloncore-core/src/agent_runtime.rs#L553-L790)). |
| **P1.S2** Anthropic client | `AnthropicClient` gated behind `feature = "live-models"` | **REAL but never hit a real Anthropic host in tests** | [model_client.rs:127-277](crates/baloncore-core/src/model_client.rs#L127-L277); `anthropic_client_missing_key_returns_error`, `anthropic_client_sends_correct_request_shape`, `anthropic_client_handles_non_200_status` ([model_client.rs:591-700](crates/baloncore-core/src/model_client.rs#L591-L700)) use a tiny `TcpListener` mock — correct discipline, no production traffic. **No real Anthropic call ever made by the test suite.** |
| **P1.S3** OpenAI client + parity | `OpenAIClient` + cross-provider parity test | **REAL** | [model_client.rs:279-427](crates/baloncore-core/src/model_client.rs#L279-L427); `openai_client_*`, `provider_parity_fixture_anthropic_openai_produce_schema_valid_output` ([model_client.rs:724-1004](crates/baloncore-core/src/model_client.rs#L724-L1004)). |
| **P1.S4** redaction-before-send | `redact_for_model`, `contains_unredacted_secrets`, fail-closed in `run_live_agent` | **REAL** | [agent_runtime.rs:7-109](crates/baloncore-core/src/agent_runtime.rs#L7-L109), fail-closed guard at [agent_runtime.rs:329-339](crates/baloncore-core/src/agent_runtime.rs#L329-L339); tests `redact_for_model_removes_bearer_tokens`, `_removes_emails`, `_removes_passwords` (agent_runtime.rs ~814-900). |
| **P1.S5** firewall test (false claim cannot be promoted) | adversarial test refutes false confident hypothesis | **PARTIAL / FIXTURE** | [agent_runtime.rs:1097-1170](crates/baloncore-core/src/agent_runtime.rs#L1097-L1170) only proves the *structural pre-filter* (`challenge_hypotheses` + `bridge_hypotheses_to_validators`) blocks a hypothesis with no endpoint and no evidence_refs. There is **no test that feeds a confident, schema-clean false claim (with endpoint + evidence_refs + confidence ≥ 0.55) through `run_live_agent_pipeline` and the real `HttpRequestRunner` against `labs/vulnerable-api`** to prove that even a well-formed false hypothesis is refused by the live validator. The plan's explicit P1.S5 acceptance criterion is therefore not met. |
| **P1.S6** CLI provider + budgets | `--provider`, `--model`, `--token-budget`, `--call-budget`, `--time-budget-ms` flags | **REAL (CLI wiring)** | [crates/baloncore-cli/src/main.rs:95-117](crates/baloncore-cli/src/main.rs#L95-L117) (`AgentPipeline`), [main.rs:1780-1834](crates/baloncore-cli/src/main.rs#L1780-L1834) (`run_live_agent_pipeline` dispatch under `cfg(feature = "live-models")`). Live mode is gated by the cargo feature, fixture is the default. |
| **P1.S7** versioned per-role prompts | `prompt_template(role)` reads from a registry | REAL (registry present) | [crates/baloncore-core/src/agent.rs:184-211](crates/baloncore-core/src/agent.rs#L184-L211), test `versioned_prompts_contain_scope_and_firewall_rules` ([agent.rs:680-692](crates/baloncore-core/src/agent.rs#L680-L692)). |
| **P1.S8** hallucination + cost regression gate | committed transcripts under `tests/transcripts/`, replayed in CI | **STUB / MISSING** | No `tests/transcripts/` directory exists in the repo (`find` confirms). The "hallucination harness" specified in P1.S8 has not been built. |
| **P2.S0** new `baloncore-eval` crate + `benchmarks/cases/<id>/{case.toml, scope.toml, ground_truth.json}` corpus | dedicated workspace member with file-per-case corpus | **STUB / RESHAPED** | The workspace has only three members ([Cargo.toml:2-6](Cargo.toml#L2-L6)). There is no `crates/baloncore-eval`. The "corpus" is hardcoded as Rust constants in `web_api_benchmark_suite()` / `cloud_iam_benchmark_suite()` / `web3_benchmark_suite()` / `evidence_lifecycle_benchmark_suite()` inside [crates/baloncore-core/src/evaluation.rs:2703-3115](crates/baloncore-core/src/evaluation.rs#L2703-L3115). `benchmarks/cases/` does not exist. |
| **P2.S1** pure scoring functions with TP/FP/FN/decoy math | precision/recall/F1/FPR derivable from `(ground_truth, produced_findings)` | **REAL** for the math, **NOT INTEGRATED** with real scans | Pure functions exist in [evaluation.rs:409-…](crates/baloncore-core/src/evaluation.rs#L409) (`compute_evaluation_metrics`) and tests assert literal values across multiple suites. The math itself is correctly implemented and unit-tested. |
| **P2.S2** runner that boots targets, executes BALONCORE end-to-end, tears them down | one command brings target up, scans it, scores | **STUB / FAKE** | The `benchmark-ci` command bypasses target execution entirely (see §2). The `evaluate-benchmark` command at [main.rs:8768-8915](crates/baloncore-cli/src/main.rs#L8768-L8915) does read pre-existing `matrix_summary.json` / `cloud_iam_analysis.json` / `web3_analysis.json` if they happen to be there, but it never starts a Docker target, runs the scan, or tears anything down — that responsibility is shoved onto the operator. When the artifact is absent it silently falls back to `run_ground_truth_baseline` ([main.rs:8917-8944](crates/baloncore-cli/src/main.rs#L8917-L8944)) which, like `generate_golden_baseline`, copies ground truth as the prediction. |
| **P2.S3** ≥ 5 license-clear vendored targets (crAPI, VAmPI, DVGA, Damn Vulnerable DeFi, IAM mis-config) | each as `benchmarks/cases/<id>/` with pinned commit + ground_truth.json | **STUB / MISSING** | `benchmarks/` contains only `METHODOLOGY.md`. Zero vendored cases, zero `case.toml`, zero `ground_truth.json` files. The only labs in-tree are `labs/vulnerable-api`, `labs/vulnerable-saas`, `labs/vulnerable-protocol`, `labs/cloud-iam` — all self-authored. |
| **P2.S4** leaderboard + run-over-run diff | `LEADERBOARD.md`, `compare <a.json> <b.json>` | **PARTIAL / GENERATED** | `compare-benchmark` CLI exists ([main.rs:8698-8766](crates/baloncore-cli/src/main.rs#L8698-L8766)) and rendering helpers exist (`render_leaderboard`, `render_run_diff`). No committed `LEADERBOARD.md` was found. |
| **P2.S5** determinism lock + live K-sample mean/stddev | byte-identical fixture eval over repeated runs | PARTIAL | `verify_determinism`, `BenchmarkRepetitionResult`, `compute_repetition_stats` exist in `evaluation.rs`. They operate on the same canned-prediction baseline; "determinism" trivially holds when the prediction is `case.ground_truth`. |
| **P2.S6** CI gate + GHA workflow | gate exits nonzero on regression | **FAKE** for the headline number | The gate at [main.rs:9279-9325](crates/baloncore-cli/src/main.rs#L9279-L9325) compares a self-generated golden baseline against itself — it can only fail if the *gate thresholds* are set higher than 1.0. A deliberately-broken validator would not change the run (because the run never invokes a validator) and so could not fail the gate. |
| **P2.S7** diligence-facing benchmark doc | numbers auto-quoted from real artifacts | **MISLEADING** | [docs/DILIGENCE/BENCHMARK.md](docs/DILIGENCE/BENCHMARK.md) and [benchmarks/METHODOLOGY.md](benchmarks/METHODOLOGY.md) describe the gate as if it measured capability. They tell the reviewer to run a command that does not measure capability (see §2). |
| **P3.S0** pure metric functions | `verified_findings_per_scan`, `false_positive_reduction_rate*`, `time_to_proof`, `time_to_fix`, `retest_success_rate`, `ci_blocked_criticals`, `model_calls_per_verified`, `tokens_per_verified`, `vuln_class_breakdown`, `compute_metrics_summary` | **REAL** | [crates/baloncore-core/src/metrics.rs:104-498](crates/baloncore-core/src/metrics.rs#L104-L498) operate purely on `ScanRecord` / `FindingRecord`. Tests are extensive (lines 742-984 + `p3s4_traceability_anti_gaming` mod at line 1426). |
| **P3.S0a** caveat: `ci_blocked_criticals` semantics | metric should count *blocked critical findings* | **MISLEADING IMPL** | [metrics.rs:291-293](crates/baloncore-core/src/metrics.rs#L291-L293) `ci_blocked_criticals` returns `sum(s.verified_findings for s in scans)`. This is the total verified-finding count, **not** the count of CI-blocked criticals. The name oversells the math. |
| **P3.S1** evidence-store rollup | `MetricsRollup` + `index-evidence-run` updates it | REAL (saving/loading present) | Re-exported in [lib.rs:144-152](crates/baloncore-core/src/lib.rs#L144-L152). Unit tests (`rollup_*`) live around metrics.rs:1061+. Not re-verified end-to-end against a real run in V0. |
| **P3.S2** API endpoints `/api/metrics/{summary,trend,drilldown}` | each returns real values per scope | PARTIAL — endpoints exist, no auth/tenant scope | [crates/baloncore-api/src/main.rs:264-285](crates/baloncore-api/src/main.rs#L264-L285) wire the three endpoints; `metrics_drilldown` is at [main.rs:1543](crates/baloncore-api/src/main.rs#L1543). They read from local workbench JSON and are **not scoped to a caller** — there is no auth check (see P5 row below). Drilldown smoke tests at [main.rs:4503-4520](crates/baloncore-api/src/main.rs#L4503-L4520). |
| **P3.S3** dashboard "Program Health" with clickable drill-down | every figure links to its source runs/findings | **STUB / MISSING** | Only one dashboard page exists ([apps/web/app/dashboard/page.tsx](apps/web/app/dashboard/page.tsx)). It displays `command?.executive_brief?.board_metrics` (line 213-214) and never calls `/api/metrics/summary`, `/api/metrics/trend`, or `/api/metrics/drilldown`. There is no drill-down route. |
| **P3.S4** anti-gaming test | rejected/suppressed/hypothesis records excluded from verified counts | **REAL** | Tests `anti_gaming_hypothesis_not_counted_as_verified`, `anti_gaming_rejected_not_counted_as_verified`, `anti_gaming_suppressed_not_counted_as_verified`, `anti_gaming_mixed_states_only_verified_counted`, `anti_gaming_rollup_excludes_unverified_from_cumulative`, `anti_gaming_no_false_positive_inflation` ([metrics.rs:1696-1880](crates/baloncore-core/src/metrics.rs#L1696-L1880)). |
| **P4.S0** auth scheme expansion (cookie/session, API key, OAuth2) | profiles configurable, evidence redacts tokens | REAL (bearer, API key, cookie) — OAuth2 **NOT IMPLEMENTED** | `AuthProfile` + `apply_credential_to_spec_*` tests at [web_api.rs ~3500+]; tests `apply_credential_to_spec_bearer/api_key/cookie_session` and `resolve_credential_*` pass (see test list). `OAuth2Ref`, `OAuth2GrantType` exist in [config.rs](crates/baloncore-core/src/config.rs) but there is no implementation that actually performs a token-endpoint exchange — no `reqwest::post` to a token URL anywhere. |
| **P4.S1** multi-tenant SaaS lab with cross-tenant BOLA + decoy | `labs/vulnerable-saas` planted bug + decoy | REAL (lab exists) | [labs/vulnerable-saas/server.js](labs/vulnerable-saas/server.js); README lists cross-tenant BOLA `org-a member → /api/orgs/org-b/projects/proj-b-001` and decoy `proj-b-secret`. The matrix/runner can be pointed at port 3010 — but a benchmark integration that *automatically* runs this lab and verifies the planted finding does not exist. |
| **P4.S2** GraphQL **active** validation parity | enumerate, replay across profiles, capture evidence | **PARTIAL** | Introspection + candidate generation + a deterministic "graphql-bola validator" exist in `web_api.rs` (tests `graphql_introspection_*`, `graphql_bola_validator_*` pass). The vulnerable-saas lab has a `/graphql` endpoint with an intentional cross-tenant BOLA ([labs/vulnerable-saas/server.js:236-368](labs/vulnerable-saas/server.js#L236-L368)). The unit tests use synthetic fixtures; **no CLI flow chains "introspect GraphQL → enumerate → replay → produce proof package" against the lab end-to-end** (no `scan-graphql-bola` command surfaced in the CLI). |
| **P4.S3** business-logic validator (price tamper / state skip / replay / quantity bypass) | proven by replayable before/after evidence | **REAL** math, **NOT WIRED** into a scan command | Validator + decision types in [crates/baloncore-core/src/business_logic.rs:160-470](crates/baloncore-core/src/business_logic.rs#L160-L470); rich tests for each abuse type. But no CLI command actually runs the validator against the SaaS lab: grep for `BusinessLogicValidator|business-logic` in `baloncore-cli/src/main.rs` returns only the `business_logic_case.json` fallback consumed by `export-flagship-report` ([main.rs:9762-9881](crates/baloncore-cli/src/main.rs#L9762-L9881)). The validator is a library function awaiting a caller. |
| **P4.S4** flagship customer report HTML + PDF | HTML and PDF, every claim links to evidence, secrets redacted, reproducible in CI | **PARTIAL — HTML only** | [crates/baloncore-core/src/flagship_report.rs:469-944](crates/baloncore-core/src/flagship_report.rs#L469-L944) renders HTML and Markdown. There is **no PDF renderer**: no headless-Chrome step, no PDF crate dependency in `Cargo.toml`, no `--format pdf` branch that does anything other than emit HTML/markdown. `export-flagship-report` CLI exists ([main.rs:9762](crates/baloncore-cli/src/main.rs#L9762)). |
| **P5.S0** Postgres adapter via `ControlPlaneStore` trait + sqlx | trait + JSON adapter + Postgres adapter + `BALONCORE_STORE` env switch | **STUB / FAKE** | `crates/baloncore-api/Cargo.toml` has **no `sqlx`, no `tokio`, no Postgres driver**. The API is synchronous: `serve` uses raw `TcpListener` + `thread::spawn` ([baloncore-api/src/main.rs:87-110](crates/baloncore-api/src/main.rs#L87-L110)), and every read/write is `serde_json::from_str` on a file under `.baloncore/workbench/`. The migration SQL file exists ([crates/baloncore-api/migrations/0001_saas_control_plane.sql](crates/baloncore-api/migrations/0001_saas_control_plane.sql)) but is never executed by any code in the repo. The README ([README.md:96-201](README.md#L96-L201)) calls the schema "Postgres-ready" — true literally (it's a `.sql` file), false operationally (nothing in this repo can connect to Postgres). |
| **P5.S1** RBAC + tenant isolation enforced at handler boundary | every handler resolves caller → org → permission; cross-org access returns 403 | **STUB / FAKE** | The API has no authentication. Routes match on `(method, path)` and dispatch with `config: &ApiConfig` only — there is no `Authorization:` header parsing, no session cookie, no caller identity ([baloncore-api/src/main.rs:113-300](crates/baloncore-api/src/main.rs#L113-L300)). The only "authorization" check is `require_authorized(&body)` ([main.rs:488-490](crates/baloncore-api/src/main.rs#L488-L490)) which just demands the request body include `"authorized": true` — a self-declared flag, not access control. The `platform_check_access` CLI command ([crates/baloncore-cli/src/main.rs:4352-4383](crates/baloncore-cli/src/main.rs#L4352-L4383)) calls `state.authorize_workspace(user, ws, perm)` as a stand-alone tool but **the running HTTP API never invokes it.** There are zero "Org A cannot read Org B" tests. The acceptance criterion for V0 ("isolation proven by a test that fails when isolation is removed") cannot be met because there is no isolation to remove. |
| **P5.S2** evidence encrypted at rest (AES-256-GCM, KMS-style provider) | bundles ciphertext on disk; authorized export decrypts + audits | **FAKE ENCRYPTION** | `encrypt_evidence` ([crates/baloncore-core/src/platform.rs:474-491](crates/baloncore-core/src/platform.rs#L474-L491)) derives a key by repeating the literal string `"baloncore-evidence-v1-key-{key_id}"`, a 12-byte nonce by repeating `"baloncore-evidence-v1-nonce-{key_id}"`, and XORs each input byte with `key[i % 32] ^ nonce[i % 12]`. `decrypt_evidence` is the same call. The `EncryptionConfig.algorithm = "AES-256-GCM"` field ([platform.rs:467](crates/baloncore-core/src/platform.rs#L467)) is decorative; no `aes-gcm` crate is in `Cargo.lock`. **Anyone with the source code can decrypt any "encrypted" bundle.** This is not encryption; it is obfuscation, mislabeled. |
| **P5.S3** real background worker with lease/heartbeat/reclaim, exactly-once execution | worker process leases jobs, heartbeats, abandoned leases are reclaimed once | **STUB / FAKE** | No separate worker binary, no background thread that polls for jobs. `reconcile_worker_queue` ([baloncore-api/src/main.rs:2222-2305](crates/baloncore-api/src/main.rs#L2222-L2305)) is a `POST /api/workers/reconcile` endpoint that scans the JSON job log and marks any `running` job `failed` with `"worker lease reconciled as stale"` — there is no heartbeat, no second worker that picks the work back up, no exactly-once execution guarantee, no `job_attempts` retry semantics beyond appending the string `"reconciled_stale"`. The `register_worker` endpoint records a worker row but nothing leases jobs to it. |
| **P5.S4** complete audit coverage | every sensitive action emits an immutable, attributable `audit_event` | PARTIAL | Many handlers call `append_audit_event` (~12 sites in `baloncore-api/src/main.rs`). The events are written to a JSON file (append-only at the FS level only if no one rewrites the file). No test enumerates sensitive endpoints and asserts an audit entry per action; no immutability/tenant-scope test exists because there is no tenant identity to scope by (see P5.S1). |
| **P6.S0** auto-generated diligence docs | BENCHMARK.md / ARCHITECTURE_ONE_PAGER.md / SAFETY.md / METRICS.md generated from real outputs | **PARTIAL** | `docs/DILIGENCE/` contains **only `BENCHMARK.md`**. `ARCHITECTURE_ONE_PAGER.md`, `SAFETY.md`, and `METRICS.md` (as P6 specs them) are missing from `docs/DILIGENCE/`. `docs/SAFETY.md` exists at the top level. The numbers in BENCHMARK.md are not auto-quoted from a real artifact; they reference the tautological gate. |
| **P6.S1** scripted reproducible demo + `scripts/diligence_repro.sh` | clean clone + one script reproduces flagship finding + headline numbers; exits nonzero on drift | **STUB / MISSING** | `scripts/` has `run_benchmarks.sh`, `stage1_e2e_demo.sh`, `start_web.sh`, `start_workbench.sh`, `generate_roadmap_pdf.py`. **No `diligence_repro.sh`, no `DEMO.md`.** `stage1_e2e_demo.sh` is a real end-to-end demo of the openapi-bola matrix → seal/sign/verify pipeline (this part is legitimate) but it does not exercise the benchmark, the metrics, or the flagship report and does not enforce drift tolerance. |

---

## 4. Specific questions V0 must answer

### 4.1 Is there a real LLM provider network call?

**Yes — but only under `--features live-models`, and never executed against a real host by the test suite.** Files: [crates/baloncore-core/src/model_client.rs:127-277](crates/baloncore-core/src/model_client.rs#L127-L277) (Anthropic) and [model_client.rs:279-427](crates/baloncore-core/src/model_client.rs#L279-L427) (OpenAI). The shape of the request is correct (Anthropic `/v1/messages` with `x-api-key`, `anthropic-version: 2023-06-01`; OpenAI `/v1/chat/completions` with `Authorization: Bearer …`). The CLI plumbs `--provider`, `--model`, `--api-base`, `--api-key-env`, `--token-budget`, `--call-budget`, `--time-budget-ms` ([crates/baloncore-cli/src/main.rs:95-117](crates/baloncore-cli/src/main.rs#L95-L117)). Default build is fixture-only; `cargo test` does not require keys or network. **Verdict: REAL provider code, but no recorded transcript suite (P1.S8 is missing) — so we have correctness-by-mock, not correctness-by-replay.**

### 4.2 Which validators send real traffic vs operate on fixtures?

| Validator | Mode |
|---|---|
| OpenAPI BOLA/BFLA matrix (`scan-openapi-bola`) | **REAL** HTTP via `reqwest::blocking::Client` in `HttpRequestRunner` ([crates/baloncore-core/src/web_api.rs:128-129, 1770-…](crates/baloncore-core/src/web_api.rs#L128-L129)). Runs against `labs/vulnerable-api` and `labs/vulnerable-saas`. |
| `validate-lab-idor`, `demo-idor` | **REAL** HTTP / fixture demo ([crates/baloncore-cli/src/main.rs:1944, 2019](crates/baloncore-cli/src/main.rs#L1944)). |
| GraphQL BOLA validator | **REAL** HTTP (introspection + replay) in `web_api.rs`; unit tests use synthetic fixtures. End-to-end CLI driver against `labs/vulnerable-saas /graphql` is missing. |
| Business-logic validator | **PURE LOGIC** (no I/O). Operates on `BusinessLogicValidationCase` someone else must build. No CLI command invokes it. |
| Cloud IAM analyzer (`analyze-cloud-iam`) | **OFFLINE** static analysis of provided JSON/Terraform/CloudFormation files. Correct for offline analysis; no live AWS calls (this is the intended design per safety rules). |
| Web3 analyzer (`analyze-web3`) | **OFFLINE** Solidity parser + Slither JSON ingest + Forge fuzz shell-out. Forge fuzz invokes a local `forge` binary if installed. |

### 4.3 Which findings were produced against a target *not authored by us*?

**None in the repository.** All produced runs/artifacts under `.baloncore/` (where present) target one of `labs/vulnerable-api`, `labs/vulnerable-saas`, `labs/vulnerable-protocol`, `labs/cloud-iam/aws-risky.json`. The corpus of "license-clear, externally-authored vulnerable targets" that P2.S3 demands (crAPI, VAmPI, DVGA, Damn Vulnerable DeFi, TerraGoat, …) is not vendored, not scripted-to-fetch, not present.

### 4.4 Which investor metrics in the roadmap are actually computed and stored today?

Computed from data (REAL): `verified_findings_per_scan`, `false_positive_reduction_rate*`, `time_to_proof.{mean,median,p90,min,max,sample_count}`, `time_to_fix.*`, `retest_success_rate*`, `scan_volume_over_time`, `model_calls_per_verified`, `tokens_per_verified`, `vuln_class_breakdown`, `compute_metrics_summary`, `MetricsRollup` (save/load). All in [crates/baloncore-core/src/metrics.rs](crates/baloncore-core/src/metrics.rs).

Reported but misleading: `ci_blocked_criticals` ([metrics.rs:291-293](crates/baloncore-core/src/metrics.rs#L291-L293)) returns `sum(verified_findings)`, not the count of *CI-blocked* criticals.

Surfaced via API but not in the dashboard: `/api/metrics/{summary,trend,drilldown}` ([baloncore-api/src/main.rs:264-285](crates/baloncore-api/src/main.rs#L264-L285)). The Next.js dashboard never calls them. So a hypothetical investor opening `http://127.0.0.1:3001/dashboard` will not see drillable metrics — they will see whatever `executive_brief.board_metrics` returns from the command-center handler.

### 4.5 Where are JSON files standing in for a real database?

Everywhere on the control plane:

- Jobs ledger: `.baloncore/workbench/jobs/<job-id>.json`.
- Workers: `.baloncore/workbench/workers.json` (`load_workers`, [baloncore-api/src/main.rs:2306-2333](crates/baloncore-api/src/main.rs#L2306-L2333)).
- Audit events: append-only JSON (`append_audit_event`, [baloncore-api/src/main.rs:1754](crates/baloncore-api/src/main.rs#L1754)).
- Projects / assets / scope contracts: JSON.
- Evidence index / scan records: `.baloncore/evidence/index.json` + per-scan files (core, not API).
- Hypothesis ledger: `.baloncore/hypotheses/index.json`.
- Findings store: `.baloncore/findings/index.json`.

`crates/baloncore-api/Cargo.toml` confirms zero database driver dependencies. The Postgres migration SQL is shipped but unused.

### 4.6 Is tenant isolation actually enforced (test that fails if isolation removed)?

**No.** As detailed in the P5.S1 row above, the running HTTP API parses no caller identity, so there is no isolation to enforce and no negative test that could fail. A mutation-check is structurally impossible against the current implementation.

### 4.7 Does `baloncore-eval` run targets end-to-end and SCORE them, or are scores stubbed?

**Scores are stubbed for the headline path.** See §2. The `evaluate-benchmark` command can optionally re-score a previously produced `matrix_summary.json` (if the operator manually ran the scan), but `benchmark-ci` — the command that the diligence docs prescribe — never invokes any scan or validator and grades a `prediction = ground_truth` baseline against itself.

---

## 5. What a technical diligence reviewer concludes in 30 minutes

A reviewer who clones the repo and follows the docs will find the following picture:

1. The Rust workspace builds and `cargo test` is green (502 unit tests, 511 with the live-models feature). This buys real credibility — most of the *kernel* (provider abstraction, JSON-strict parsing, redaction, budgets, BOLA/BFLA/missing-auth validators against a local Node lab, evidence sealing/signing, lifecycle state machine, metrics math, business-logic validator) is actually implemented and exercised.
2. **The pitch breaks the moment they run the one-command benchmark.** The numbers are 100/100/100/A+ regardless of input, because the gate compares the ground-truth baseline against itself. A diligence reviewer who has read the master plan will spot this within 10 minutes and lose trust for the rest of the read.
3. **"Postgres-ready, multi-tenant, encrypted, audited control plane" is not what the code does.** It's a single-process synchronous TCP server backed by JSON files, with XOR "encryption" mislabeled AES-256-GCM, no caller identity, and no tenant isolation. The migration SQL file is a description of a future system, not a working dependency.
4. The Next.js dashboard renders, but the "Program Health" view with clickable drill-down (P3.S3) does not exist; the page shows pre-baked executive_brief data and never calls `/api/metrics/*`.
5. The model side is genuinely sound: fixture-default, real Anthropic/OpenAI clients gated behind a feature flag, strict JSON repair, hard budgets, fail-closed redaction, and a parity test across three providers. **The most defensible part of the project is P1.**
6. The vulnerable-saas lab and the OpenAPI matrix scanner *do* produce real evidence against the local cross-tenant BOLA — but there is no integration that ties this back to the benchmark headline number, and no externally-authored target in the corpus, so the claim "we measure capability on third-party benchmarks" is not yet true.

**Net assessment:** kernel quality is genuinely good and shouldn't be discounted; the customer-facing rind — the benchmark headline, the control-plane story, the encryption claim, the dashboard — is theater. The audit-honest move is to retract the "100 % precision/recall" framing immediately and replace it with the small number of real measurements the system actually does today (verified findings against `labs/vulnerable-saas` cross-tenant BOLA, decoy rejection on `proj-b-secret`, redaction of bearer tokens).

---

## 6. Top 5 gaps ranked by funding impact

| # | Gap | Why it's fundable now | Fix scope |
|---|---|---|---|
| 1 | **Benchmark is a tautology** (§2; P2.S2/S3/S6) | The single artifact a VC will re-run is dishonest. Until this is fixed, every other claim is suspect. | Implement a real runner: pick 1 vendored target (e.g. VAmPI as a Docker case), bring it up, scan it, score the produced `matrix_summary.json` against a hand-labeled `ground_truth.json`, tear it down. Delete the `generate_golden_baseline` shortcut from `benchmark-ci`. |
| 2 | **No tenant isolation; no caller identity in the API** (P5.S1) | The enterprise narrative falls apart under one cross-org curl. | Add bearer-or-cookie auth to the API, plumb the caller to every read/write, write the cross-tenant negative tests, then mutation-check by deleting the check. |
| 3 | **"AES-256-GCM" evidence encryption is XOR with a literal-string key** (P5.S2) | This is a soft fraud risk: claiming a named algorithm while shipping toy code. A reviewer who decodes `encrypt_evidence` once will not recover from the impression. | Either remove the encryption claim entirely or wire `aes-gcm` properly with keys from env/KMS. |
| 4 | **Firewall test only proves the *structural* pre-filter** (P1.S5) | The product's central claim — "model proposes, validator proves" — needs an adversarial test that drives a schema-clean false hypothesis through the **live** lab validator and shows it is rejected with sealed evidence. | Add one test: stub client emits a confident, well-formed false BOLA on a `lab` endpoint that actually returns 403; assert no sealed Verified finding is produced. |
| 5 | **No externally-authored corpus + no flagship report wired end-to-end** (P2.S3, P4.S4) | All evidence today is against self-written labs; PDF reporting is missing entirely. | Vendor at least one third-party target (license-checked), produce one real verified cross-tenant BOLA report in HTML *and* PDF, link evidence from the report. |

---

## 7. Audit completeness checklist

- [x] `cargo build` — run, exit recorded.
- [x] `cargo test --workspace` — run, totals recorded (17 + 15 + 502).
- [x] `cargo test --features live-models` — run, totals recorded (17 + 15 + 511).
- [x] `cargo fmt --check` — run, single diff recorded.
- [x] `cargo clippy --all-targets` — run, 163 warnings / 0 errors recorded.
- [x] `corepack pnpm --dir apps/web typecheck` — run, clean.
- [x] `corepack pnpm --dir apps/web build` — run, 7 static pages emitted.
- [x] Every P-stage classified REAL / FIXTURE / STUB with file:line evidence.
- [x] Benchmark tautology proven by running the documented command in `/tmp` and capturing the literal output.
- [x] §4 questions answered with evidence.
- [x] Top-5 gaps ranked by funding impact.

No fixes applied. Stage V1 (firewall integrity audit) is unblocked.
