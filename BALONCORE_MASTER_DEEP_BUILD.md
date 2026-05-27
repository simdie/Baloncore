# BALONCORE — Master Deep Build Plan (P0 → P6, all sessions)

This single file consolidates every deep build sequence for BALONCORE in execution
order: **P0 → P1 → P2 → P3 → P4 → P5 → P6**. Each numbered session (e.g. `P1.S2`,
`P4.S3`) is one focused build session for an AI coding agent (Codex 5.5 xhigh or
Claude Code). Paste a session, let the agent finish it end-to-end with tests,
review, then move to the next. **Do the sessions in order** — later sessions assume
the artifacts of earlier ones.

Session map (≈36 sessions total):
- P0 Honest State Audit — S0–S1 (no feature code)
- P1 Real Model-in-the-Loop — S0–S8
- P2 Evaluation & Benchmark Harness — S0–S7
- P3 Investor Metrics Instrumentation — S0–S4
- P4 One Vertical, Demo-Hardened End to End — S0–S4
- P5 Productionize the Control Plane — S0–S4
- P6 The Diligence Package — S0–S1

## Two invariants that apply to EVERY session and must never be relaxed

- **Authorized scope only.** No active traffic ever leaves configured scope.
- **The validator firewall is absolute.** A model may *propose* an
  `AgentHypothesis`. Only the existing deterministic path
  (`validate_agent_output` → `challenge_hypotheses` →
  `bridge_hypotheses_to_validators` → `validator_for_classification` → the live
  validator → sealed evidence) may move a hypothesis to `FindingState::Verified`.
  No metric, report, dashboard, or tenant feature may shortcut this. The model
  never writes a finding.

## Grounding facts about the current repo (verified)

- `crates/baloncore-core/src/agent.rs` defines `ModelConfig {provider, model,
  api_base, api_key_env, max_tokens, temperature}`, `AgentInput`, `AgentOutput`,
  `AgentHypothesis`, `AgentObservation`, `AgentOutputStatus`,
  `AgentOutputValidation`, `VerifierChallenge`, `ValidatorBridge`,
  `AgentPipelineResult`, plus `run_fixture_agent`, `run_fixture_agent_pipeline`,
  `validate_agent_output`, `challenge_hypotheses`,
  `bridge_hypotheses_to_validators`, `validator_for_classification`,
  `prompt_template`.
- The only model "provider" today is `"fixture"` (canned output). There is **no**
  network model call anywhere in the codebase.
- `baloncore-core` is currently a **synchronous** crate. Keep it sync; confine
  async to the already-async `baloncore-api` crate.
- `crates/baloncore-core/src/evidence.rs` defines `RedactionStatus`,
  `RedactionRule`, `default_redaction_rules()`.
- `crates/baloncore-core/src/lifecycle.rs` defines `FindingState {Hypothesis,
  Rejected, NeedsMoreEvidence, Verified, Reported, Fixed, Retested, Closed}`,
  `FindingStore`, `FindingRecord`, `FindingTransition`, `ScanRecord`.
- Evidence store: `.baloncore/evidence/index.json` + per-scan records under
  `.baloncore/evidence/scans/`; `index-evidence-run` normalizes a run into it.
- `crates/baloncore-api/src/main.rs` is the async Rust control plane exposing the
  `/api/*` surface; `crates/baloncore-api/migrations/0001_saas_control_plane.sql`
  is the Postgres-ready schema; the live workbench uses JSON files as a dev
  adapter.
- `apps/web` is the Next.js operator surface (`app/{dashboard,admin,login}/
  page.tsx`, `lib/baloncore.ts`).
- `crates/baloncore-core/src/web_api.rs` holds the live BOLA/BFLA/missing-auth
  validators, `SensitiveFieldFinding`, `SensitiveDataCategory`, response-shape +
  impact scoring.

## After every session

Run `cargo fmt --check`, `cargo test`, the session's specific verification, then a
short report: what changed, where artifacts live, what passed, what remains.

================================================================================
# P0 — HONEST STATE AUDIT (do first; no feature code)
================================================================================

Purpose: a truthful map so every later session builds on reality, not on README
optimism. This is also the spine of the P6 diligence package.

## P0.S0 — Capability ledger

```text
Audit the BALONCORE repo against its own claims. Write docs/STATE_AUDIT.md. Do
NOT write feature code.

For every roadmap stage 1-10, list each claimed capability and classify it:
- REAL: runs real work on real/external input, has positive AND negative tests,
  and produces durable evidence.
- FIXTURE: only deterministic/canned output, or only runs against a
  self-authored lab.
- STUB: type/CLI/schema surface exists but behavior is a placeholder.

Determine and state plainly, with file:line evidence:
- Is there ANY real LLM provider network call? (grep providers + reqwest usage.)
- Which validators send live HTTP vs operate on fixtures?
- Which findings have ever been produced against a target NOT written by us?
- Which investor metrics in the roadmap are actually computed and stored today?
- Where are JSON files standing in for a real database?

End with: (a) one honest table; (b) a 1-paragraph "what a technical diligence
reviewer concludes in 30 minutes"; (c) the top 5 gaps ranked by funding impact.
No marketing language anywhere.
```

## P0.S1 — Build/test ground truth + risk register

```text
Run and record verbatim (exit codes + tail of output): cargo build, cargo test,
cargo fmt --check, cargo clippy --all-targets if available, and any frontend
build/lint in apps/web. For each failure or warning, file an entry in
docs/STATE_AUDIT.md under "Known breakage".

Then write docs/RISK_REGISTER.md: technical risks (async leakage, JSON-as-DB,
fixture-as-AI, single-lab evaluation, secret handling), each with likelihood,
blast radius, and the P-stage that closes it. Keep it blunt.

Acceptance: both docs exist; numbers are real; no claim is left unverified.
```

================================================================================
# P1 — REAL MODEL-IN-THE-LOOP (deep sequence)
================================================================================

Goal of P1: a real LLM proposes hypotheses that fixtures never could, those
hypotheses flow through the unchanged firewall, and only validator-proven ones
become findings — with strict JSON contracts, a repair loop, hard cost/time
budgets, redaction-before-send, and full offline determinism preserved.

## P1.S0 — Provider abstraction skeleton (no network yet)

```text
Read first: crates/baloncore-core/src/agent.rs (entire), agents.rs, lib.rs,
config.rs, evidence.rs. Do not change behavior yet — build the seam.

Create crates/baloncore-core/src/model_client.rs:

- Define an error enum ModelError {Transport(String), Status{code:u16,
  body:String}, Decode(String), Timeout, BudgetExceeded(String),
  Refused(String), MissingKey(String)} implementing std::error::Error + Display.
- Define request/response value types (provider-neutral):
  pub struct ModelRequest { pub system: String, pub user: String,
    pub max_tokens: u32, pub temperature: f32, pub stop: Vec<String> }
  pub struct ModelUsage { pub input_tokens: u32, pub output_tokens: u32 }
  pub struct ModelResponse { pub text: String, pub usage: ModelUsage,
    pub model: String, pub provider: String }
- Define the trait (SYNCHRONOUS — the core crate stays sync):
  pub trait ModelClient: Send + Sync {
    fn complete(&self, req: &ModelRequest) -> Result<ModelResponse, ModelError>;
    fn provider(&self) -> &str;
    fn model(&self) -> &str;
  }
- Implement FixtureModelClient that wraps the EXISTING fixture output so it
  satisfies the trait without changing run_fixture_agent. It returns the canned
  text for a role; this guarantees offline tests keep working.
- Add a factory: pub fn client_for(model: &ModelConfig) ->
  Result<Box<dyn ModelClient>, ModelError> that returns FixtureModelClient for
  provider "fixture" (the default) and returns ModelError::Refused for unknown
  providers for now (real providers land in P1.S2/S3).
- Register the module in lib.rs and re-export ModelClient, ModelRequest,
  ModelResponse, ModelError, ModelUsage, client_for.

Acceptance:
- cargo build and cargo test pass with ZERO behavior change (fixture is still
  default everywhere).
- A new unit test asserts client_for(&ModelConfig::default()) returns a client
  whose provider()=="fixture".

Verify: cargo fmt --check; cargo test.
Report what was added and confirm no existing test changed.
```

## P1.S1 — Strict JSON contract + repair loop (still provider-neutral)

```text
Read first: model_client.rs (just built), the AgentOutput/AgentHypothesis
schemas in agent.rs, and validate_agent_output.

Goal: turn raw model text into a validated AgentOutput, deterministically and
safely, independent of which provider produced the text.

In agent.rs (or a new agent_runtime.rs module that agent.rs re-exports):

- Add pub fn parse_agent_output(role: &str, raw: &str) ->
  Result<AgentOutput, AgentParseError> that:
  1. Strips any code fences / preamble and extracts the first balanced top-level
     JSON object.
  2. Deserializes into AgentOutput via serde.
  3. Forces output.agent_role = role (never trust the model's self-reported role)
     and output.model_used to the caller-supplied value.
- Add pub fn build_repair_request(role: &str, prior_raw: &str,
  errors: &[String]) -> ModelRequest that produces a strict "your previous output
  was invalid JSON / failed schema for these reasons: ...; return ONLY corrected
  JSON" instruction.
- Add the orchestration function:
  pub fn run_live_agent(client: &dyn ModelClient, input: &AgentInput,
    model: &ModelConfig, budget: &mut ModelBudget) -> AgentOutput
  Behavior:
  1. Build ModelRequest from prompt_template(role) (system) + a serialized,
     REDACTED AgentInput (user). (Redaction lands in P1.S4; for now call a
     redact stub that is identity but clearly marked TODO-S4.)
  2. Call client.complete; on transport/timeout error, return an AgentOutput
     with status=Skipped and skipped_reason set (never panic, never fabricate
     hypotheses).
  3. parse_agent_output; if it fails, run validate_agent_output; if invalid,
     issue ONE repair call via build_repair_request; if still invalid, return
     AgentOutput status=Skipped with skipped_reason listing the schema errors.
  4. Record token usage into budget.
- Define ModelBudget { max_tokens_total, max_calls, max_wall_ms, used_tokens,
  used_calls, started_at } with a fn check(&self) -> Result<(),ModelError> and a
  fn record(&mut self, usage:&ModelUsage). run_live_agent must call
  budget.check() before EVERY model call and abort (status=Skipped,
  skipped_reason="budget exceeded: ...") when exceeded.

Acceptance:
- Unit tests with a stub ModelClient that returns: (a) clean JSON -> valid
  AgentOutput; (b) fenced JSON with preamble -> still parses; (c) malformed JSON
  then valid on repair -> one retry then success; (d) malformed twice ->
  status=Skipped, no hypotheses; (e) budget exhausted before first call ->
  status=Skipped.
- Assert in every case that run_live_agent NEVER returns a hypothesis the model
  did not actually emit, and never sets any FindingState.

Verify: cargo fmt --check; cargo test.
```

## P1.S2 — Anthropic client (first real provider)

```text
Read first: model_client.rs, the network_configuration note (api.anthropic.com
is reachable). Use reqwest with the "blocking" + "json" features. Add reqwest to
crates/baloncore-core/Cargo.toml behind a feature flag `live-models` so default
builds/tests stay network-free.

Implement AnthropicClient in model_client.rs (compiled only under
feature="live-models"):
- new(model: &ModelConfig) reads the API key from the env var named by
  model.api_key_env (default "ANTHROPIC_API_KEY"); if absent ->
  ModelError::MissingKey. NEVER read keys from config files or args. NEVER log
  the key.
- complete() POSTs to {api_base or "https://api.anthropic.com"}/v1/messages with
  the documented headers and body (model, max_tokens, temperature, system, single
  user message). Use a 60s timeout. Map non-2xx to ModelError::Status. Parse the
  response content blocks of type "text", concatenate, and return ModelResponse
  with usage from the response.
- Extend client_for to return AnthropicClient for provider "anthropic" when
  feature="live-models", else ModelError::Refused with a message telling the user
  to build with --features live-models.

Use the product-self-knowledge skill / current docs to confirm the exact request
shape, headers, and model string before coding — do not guess the API.

Acceptance:
- Default build (no feature): unchanged, offline, all tests pass.
- With --features live-models and a mocked HTTP server (wiremock or a tiny local
  hyper stub), an integration test asserts AnthropicClient sends the right shape
  and parses a canned 200 response into ModelResponse. No real network in tests.
- A test asserts MissingKey when the env var is unset.

Verify: cargo fmt --check; cargo test; cargo test --features live-models.
```

## P1.S3 — OpenAI client + provider parity tests

```text
Mirror P1.S2 for an OpenAiClient (provider "openai", env OPENAI_API_KEY, POST to
{api_base or "https://api.openai.com"}/v1/chat/completions, map roles
system/user, parse choices[0].message.content and usage). Same feature gate, same
mocked-server test discipline, same key-handling rules.

Add a shared parity test (mocked) that runs the SAME AgentInput through fixture,
anthropic-mock, and openai-mock and asserts all three produce a schema-valid
AgentOutput and that parse/repair/budget behavior is identical across providers.

Acceptance: provider can be switched purely via ModelConfig.provider with no
other code change; parity test green for all three.
Verify: cargo fmt --check; cargo test --features live-models.
```

## P1.S4 — Redaction-before-send (no secret ever reaches a provider)

```text
Read first: evidence.rs (RedactionStatus, RedactionRule, default_redaction_rules),
web_api.rs SensitiveFieldFinding / SensitiveDataCategory.

Replace the S1 redact stub with a real pre-send sanitizer:
- pub fn redact_for_model(input: &AgentInput) -> AgentInput that applies
  default_redaction_rules() (and any config rules) to every string field,
  evidence_ref preview, and context value before it is serialized into the user
  message. Authorization headers, session tokens, and PII patterns must be
  replaced with their placeholders.
- run_live_agent must call redact_for_model and assert (debug_assert + runtime
  check) that the serialized user payload contains none of the known secret
  markers before client.complete is called. If a secret slips through, abort with
  ModelError::Refused("unredacted secret would reach provider") — fail closed.

Acceptance:
- Test: an AgentInput whose context contains a bearer token and an email is
  redacted such that the outgoing ModelRequest.user contains the placeholders and
  NOT the raw token/email.
- Test: the fail-closed path triggers if redaction is bypassed.

Verify: cargo fmt --check; cargo test.
```

## P1.S5 — Live pipeline wired through the UNCHANGED firewall

```text
Read first: run_fixture_agent_pipeline (the exact firewall sequence). You will
build the live analogue WITHOUT touching validate_agent_output,
challenge_hypotheses, bridge_hypotheses_to_validators, or
validator_for_classification.

Add:
  pub fn run_live_agent_pipeline(client: &dyn ModelClient, input: &AgentInput,
    model: &ModelConfig, budget: &mut ModelBudget) -> AgentPipelineResult
It must replicate run_fixture_agent_pipeline EXACTLY except the output comes from
run_live_agent instead of run_fixture_agent. Same validate -> challenge -> bridge
-> counts logic, reusing the existing functions verbatim.

Then add the CRITICAL firewall test (this is the test investors' technical
diligence will effectively re-run):
- Construct a stub ModelClient that returns a confident but FALSE hypothesis
  (e.g. claims BOLA on an endpoint that, when actually validated, returns 403).
- Run run_live_agent_pipeline, then run the resulting eligible bridges through
  the REAL web/API validator against the local lab.
- Assert the false hypothesis is NOT promoted to Verified — it is rejected or
  blocked-as-expected, and no sealed finding is produced for it.
- Add the positive twin: a TRUE hypothesis against the planted lab BOLA IS
  promoted with sealed evidence.

Acceptance: both firewall tests green; the false claim cannot become a finding by
any path.
Verify: cargo fmt --check; cargo test (fixture path); and the lab-backed test.
```

## P1.S6 — CLI + config surface for provider selection

```text
Read first: crates/baloncore-cli/src/main.rs (how scan-openapi-bola, agent-
pipeline, show-agent parse flags and write artifacts), config.rs.

- Add a global --provider {fixture|anthropic|openai} and --model <string> flag,
  defaulting to fixture, plumbed into ModelConfig. Allow config file defaults
  under a [model] table (provider, model, api_key_env, api_base, max_tokens,
  temperature) but env var holds the actual key.
- Add --token-budget, --call-budget, --time-budget-ms flags that construct
  ModelBudget; sane conservative defaults.
- Make agent-pipeline and autonomous-run use run_live_agent_pipeline when
  provider != fixture, else the fixture path. Persist the model run + budget
  usage into the run artifacts (extend the existing AgentRun artifact with a
  ModelBudgetReport: provider, model, calls, tokens, wall_ms, aborted_reason).
- README + docs/AI_LOOP.md: document env-var key handling, the firewall
  guarantee, the budget flags, and that secrets are redacted before any provider
  call.

Acceptance:
- `cargo run -p baloncore -- agent-pipeline api-auth --scan-dir <dir>` works
  offline with fixture (unchanged).
- `... --provider anthropic` (with key + --features live-models) performs a real
  call, writes ModelBudgetReport, and still only reports validator-proven
  findings.
Verify: cargo fmt --check; cargo test; one fixture pipeline; one mocked live
pipeline.
```

## P1.S7 — Prompt hardening per agent role (the actual model-facing prompts)

```text
Read first: agents/*.md (recon, api-auth, business-logic, verifier, etc.),
prompt_template, the AgentOutput JSON schema.

For each execution-capable role (recon, api-auth, schema-discovery,
business-logic, attack-chain, verifier, reporter, detection-engineer), upgrade
prompt_template to a versioned, role-specific system prompt that:
- States the authorized-scope rule and that the model proposes, validators prove.
- Embeds the EXACT AgentOutput JSON schema and demands JSON-only output, no prose.
- Gives 1-2 in-context examples of a GOOD hypothesis (with endpoint, object_id,
  profile, confidence in [0,1], evidence_refs) and a BAD one (vague, no endpoint)
  and says the bad one will be rejected.
- For api-auth/business-logic: instructs the model to express each hypothesis as
  something a deterministic validator can replay (concrete endpoint + concrete
  alternate-user/object), NOT a general worry.
- For verifier: instructs it to actively argue AGAINST each hypothesis and emit
  VerifierChallenge-shaped objections.
- Bump each PromptTemplate.version and keep old versions retrievable (registry by
  role+version) so prompt changes are auditable and benchmarkable (P2 will diff
  scores across prompt versions).

Acceptance: prompt registry returns versioned templates; a test asserts each
execution role's template embeds the schema and the scope/firewall language.
Verify: cargo fmt --check; cargo test.
```

## P1.S8 — Hallucination & cost regression gates

```text
Add a deterministic "hallucination harness" using recorded model transcripts
(JSON fixtures captured from real runs, committed under
tests/transcripts/) so CI can replay real-shaped model output offline:
- A suite that replays N transcripts (some containing plausible-but-false
  hypotheses) through run_live_agent_pipeline + real lab validators and asserts
  the false-positive promotion rate is exactly 0.
- A cost guard test asserting budget enforcement aborts before exceeding configured
  tokens/calls/time.
- Wire both into `ci-run` so a regression that lets a model claim through fails CI.

Acceptance: CI fails if any false hypothesis is ever promoted, or if budgets are
not enforced. Offline and deterministic.
Verify: cargo fmt --check; cargo test; ci-run.
```

P1 done means: provider-agnostic real model calls, strict JSON + repair, hard
budgets, redaction-before-send, the firewall provably intact under adversarial
model output, full offline determinism via fixture default, and the model-facing
prompts versioned for benchmarking. Now you can actually measure it — P2.

================================================================================
# P2 — EVALUATION & BENCHMARK HARNESS (deep sequence)
================================================================================

Goal of P2: one command produces a reproducible scorecard — precision, recall,
false-positive rate against decoys, time-to-proof, model-calls-per-verified-
finding, retest success — across a corpus of authorized vulnerable targets, with
a leaderboard that shows improvement over time and across prompt/model versions.
This is the artifact that funds the company.

## P2.S0 — Eval crate + corpus schema (no targets yet)

```text
Create crates/baloncore-eval (new workspace member; add to root Cargo.toml).

Define the corpus contract in benchmarks/ (create dir):
- Each case = benchmarks/cases/<case-id>/ containing:
  - case.toml: { id, name, kind (web_api|graphql|cloud_iam|web3),
    license, source_url, authorized=true, setup (how to start it, e.g. docker or
    node command), base_url_or_path }
  - scope.toml: the BALONCORE scope contract authorizing this target.
  - ground_truth.json: {
      vulnerabilities: [ { id, class, location (endpoint/contract/resource),
        expected_severity, expected_profile?, expected_object? } ],
      decoys: [ { id, location, why_safe } ]   // MUST NOT be flagged
    }
- Define matching Rust types (CorpusCase, GroundTruth, GtVuln, Decoy) in the eval
  crate with serde + loader functions and validation (e.g. authorized must be
  true or the loader refuses the case).

Acceptance: eval crate compiles; a unit test loads a sample case dir (commit one
tiny synthetic case under benchmarks/cases/_sample/) and validates it; a case
with authorized=false is refused.
Verify: cargo build; cargo test -p baloncore-eval.
```

## P2.S1 — Scoring engine (the math, tested in isolation)

```text
In crates/baloncore-eval, implement scoring as PURE functions over (ground_truth,
produced_findings) so it is unit-testable without running any scan:

- Matching: a produced verified finding matches a GtVuln if class matches AND
  location matches (normalize endpoints/paths; for web3 match contract+function;
  for cloud match principal+resource+action). Define the normalization explicitly.
- Compute per case and aggregate:
  true_positives, false_negatives (unmatched GtVulns),
  false_positives (verified findings matching no GtVuln),
  decoy_hits (verified findings whose location matches a decoy — weighted heavily),
  precision = TP/(TP+FP), recall = TP/(TP+FN),
  false_positive_rate = FP/(TP+FP) (and a separate decoy_fp_rate),
  time_to_proof_ms (scan start -> first verified evidence ts),
  model_calls_per_verified, tokens_per_verified,
  retest_success_rate (Verified->Fixed->Retested pass rate where applicable).
- Per-vuln-class breakdown of precision/recall.

Acceptance: exhaustive unit tests on hand-built inputs covering perfect score,
all-miss, all-false-positive, decoy-hit penalty, and partial. Numbers must match
hand calculation exactly (assert literal values).
Verify: cargo test -p baloncore-eval.
```

## P2.S2 — Runner: execute BALONCORE end-to-end per case

```text
Implement `cargo run -p baloncore-eval -- run --provider <p> [--case <id>]
[--out benchmarks/results/]`:
- For each case: bring the target up per case.toml setup (shell out; enforce a
  per-case timeout and always tear down, even on failure/panic — use a guard).
- Invoke the real BALONCORE pipeline for the case kind (reuse the library/CLI
  paths, NOT a reimplementation): web_api/graphql -> scan-openapi-bola/graphql
  validation; cloud_iam -> analyze-cloud-iam; web3 -> analyze-web3.
- Collect produced verified findings + timing + model budget report from the run
  artifacts.
- Score via P2.S1. Write per-case result + aggregate to
  benchmarks/results/<utc-timestamp>.json including provider, model, prompt
  versions, git commit, and corpus hash for reproducibility.

Safety: the runner only ever starts the vendored authorized targets in
benchmarks/cases/. It must refuse any case whose scope.toml is not satisfied or
authorized!=true. No external hosts.

Acceptance: `... run --provider fixture` runs the committed _sample case and
existing local labs end-to-end and writes a scorecard JSON. Teardown always runs.
Verify: cargo test -p baloncore-eval; one full fixture eval run.
```

## P2.S3 — Vendor the real authorized corpus

```text
Add at least 5 license-clear, intentionally-vulnerable targets under
benchmarks/cases/, each with case.toml + scope.toml + hand-authored
ground_truth.json (vulns AND decoys). Prefer Docker-runnable targets and pin
versions/commit hashes. Candidates (verify license + current availability before
vendoring; choose ones whose licenses permit redistribution or vendor via a
documented fetch script rather than copying):
- OWASP crAPI (web/API, BOLA/BFLA/mass-assignment).
- VAmPI (REST API auth/IDOR).
- OWASP DVGA (GraphQL).
- Damn Vulnerable DeFi exercises (web3, run under Foundry/Hardhat).
- A deliberately misconfigured Terraform/AWS IAM module (cloud path: GH Actions
  OIDC -> assumable admin role).
Plus your existing vulnerable-api, vulnerable-protocol, and aws-risky.json as
cases.

For EACH: hand-label ground truth carefully (this is the most valuable manual
work in the whole project — the corpus IS the moat) and include realistic decoys
that a naive scanner would flag.

Acceptance: each case loads, starts, scans, and tears down under the runner with
fixture provider; ground_truth.json is complete (vulns + >=2 decoys per case).
Verify: `cargo run -p baloncore-eval -- run --provider fixture` across all cases.
```

## P2.S4 — Leaderboard report + run-over-run diff

```text
Render benchmarks/results/<timestamp>.md (and update a stable
benchmarks/LEADERBOARD.md):
- Headline aggregate table: precision, recall, FP-rate, decoy-FP-rate (must trend
  to 0), median time-to-proof, model-calls/verified, retest success.
- Per-case and per-vuln-class tables.
- A diff vs. the previous run: which cases improved/regressed, with deltas.
- Record provider/model/prompt-version/commit so a number is always attributable.

Add `cargo run -p baloncore-eval -- compare <a.json> <b.json>` for explicit
A/B (e.g. prompt v1 vs v2, anthropic vs openai, fixture vs live).

Acceptance: two runs produce a readable leaderboard and a correct diff; deltas
match hand-checked values on a constructed pair.
Verify: cargo test -p baloncore-eval; generate two scorecards and a compare.
```

## P2.S5 — Determinism lock + live reproducibility

```text
- Determinism test: fixture-provider eval over the corpus must produce BYTE-
  IDENTICAL aggregate scores across repeated runs (lock in a test that runs twice
  and asserts equality). This protects the headline number from silent drift.
- Live reproducibility: real-provider runs record provider+model+temperature
  (force temperature 0 in eval mode)+prompt versions+corpus hash so a run can be
  described precisely even though model output varies; report mean +/- stddev
  over K repetitions for live providers, not a single sample.

Acceptance: determinism test green; live mode reports K-sample mean/stddev.
Verify: cargo test -p baloncore-eval (fixture determinism); a small live K=3 run
if a key is available.
```

## P2.S6 — CI integration + regression gate

```text
- Add `cargo run -p baloncore-eval -- gate --baseline benchmarks/LEADERBOARD.md
  --min-precision X --max-decoy-fp 0 --max-recall-drop Y` that exits nonzero when
  a change regresses precision below threshold, allows ANY decoy hit, or drops
  recall more than Y vs. baseline.
- Wire a GitHub Actions workflow (offline, fixture provider) that runs the eval
  gate on every PR so capability cannot silently regress.

Acceptance: a deliberately introduced regression (e.g. loosen a validator so it
flags a decoy) fails the gate with a clear message; reverting passes.
Verify: cargo test; run gate against a passing and a failing scorecard.
```

## P2.S7 — Diligence-facing benchmark doc

```text
Write benchmarks/METHODOLOGY.md and docs/DILIGENCE/BENCHMARK.md:
- Exactly what the corpus is, how targets are authorized, how ground truth and
  decoys were labeled, how scoring works, and the one command to reproduce.
- The current headline numbers, auto-quoted from the latest LEADERBOARD.md (add a
  small generator so the doc never drifts from real results).
- An explicit honest "limitations" section (corpus size, vuln classes covered,
  fixture-vs-live caveats). Honesty here is a credibility multiplier in diligence.

Acceptance: a stranger can clone, run one command, and reproduce the headline
numbers; the doc's numbers match the latest scorecard.
Verify: regenerate doc; diff against scorecard.
```

P2 done means: every capability claim is a reproducible number, decoys prove your
false-positive discipline, the leaderboard shows progress across prompt/model
versions, CI blocks capability regressions, and you can hand a VC a one-command
reproduction. Combined with P1, "a real model proposed it, a deterministic
validator proved it, here's the benchmark" stops being a pitch and becomes a fact.

================================================================================
# P3 — INVESTOR METRICS INSTRUMENTATION (deep sequence)
================================================================================

Goal: the roadmap's metrics become real, computed from actual run/evidence data,
queryable via the API and visible (with drill-down) in the dashboard. No invented
numbers; every figure traces to the runs that produced it.

## P3.S0 — Pure metric functions

```text
Read first: lifecycle.rs (FindingState, FindingStore, FindingTransition,
ScanRecord), evidence index format under .baloncore/evidence/, the artifacts a
run writes (matrix_summary.json, impact.json, evidence_manifest.json timestamps).

Create crates/baloncore-core/src/metrics.rs with PURE functions over already-
loaded data structures (no I/O), so they are unit-testable:
- verified_findings_per_scan(scans: &[ScanRecord]) -> f64
- false_positive_reduction_rate(...): (suppressed + rejected) / total_candidates
- time_to_proof(scan): first Verified evidence ts - scan start ts (per scan;
  expose mean + median + p90 aggregators)
- time_to_fix(finding): Verified->Fixed transition delta from FindingTransition
- retest_success_rate(findings): Retested-pass / (Fixed that were retested)
- ci_blocked_criticals(scans)
- scan_volume_over_time(scans, bucket) -> Vec<(period, count)>
- model_calls_per_verified / tokens_per_verified (from ModelBudgetReport added in
  P1.S6)
Define a MetricsSummary struct holding all of the above plus per-vuln-class
breakdown, and a MetricPoint trace type {metric, value, source_run_ids,
source_finding_ids} so every number is drillable.

Acceptance: exhaustive unit tests on hand-built ScanRecord/FindingRecord inputs;
assert literal expected values (incl. empty-input edge cases returning 0/None
cleanly, never NaN/panic).
Verify: cargo fmt --check; cargo test.
```

## P3.S1 — Rollup persistence in the evidence store

```text
Add an incremental rollup: when index-evidence-run normalizes a run, recompute
and persist a metrics rollup into the evidence index (e.g.
.baloncore/evidence/metrics.json) holding MetricsSummary + the MetricPoint traces.
Recompute incrementally (don't rescan all history each run; update aggregates).

Add CLI: `cargo run -p baloncore -- metrics-summary [--store ...] [--json]` and
`metrics-trend --metric <name> --bucket day|week`.

Acceptance: after indexing the lab runs, metrics-summary prints values that match
a hand computation from the underlying artifacts (add a test asserting equality
on the benchmark corpus runs from P2). Traces resolve to real run/finding ids.
Verify: cargo fmt --check; cargo test; index lab runs; metrics-summary --json.
```

## P3.S2 — API endpoints

```text
Read first: baloncore-api/src/main.rs (how existing /api/security/* handlers read
artifacts and serialize JSON).

Add (consistent with existing handler style + auth/tenant scoping that lands in
P5):
- GET /api/metrics/summary -> MetricsSummary for the caller's authorized scope.
- GET /api/metrics/trend?metric=&bucket= -> Vec<MetricPoint>/series.
- GET /api/metrics/drilldown?metric=&period= -> the source run/finding records.
All must respect scope: a caller only sees metrics derived from runs they are
authorized for (enforced for real once P5 lands; until then, single-tenant).

Acceptance: endpoints return values identical to the CLI metrics-summary for the
same store; a request for a metric with no data returns an explicit empty series,
not an error.
Verify: cargo test; start API; curl the endpoints against indexed lab runs.
```

## P3.S3 — Dashboard "Program Health" view with drill-down

```text
Read first: apps/web/app/dashboard/page.tsx, apps/web/lib/baloncore.ts, globals.css.
Match the existing restrained, evidence-first visual style (no marketing styling).

Add a Program Health view:
- Headline cards: verified findings/scan, false-positive reduction rate, median
  time-to-proof, retest success rate, CI-blocked criticals.
- Time-series charts (scan volume, time-to-proof trend, FP-reduction trend).
- EVERY number is clickable and routes to a drill-down listing the exact
  runs/findings that produced it (calls /api/metrics/drilldown). A number that
  cannot be drilled into must not be shown.
- Empty/loading/error states for each card.

Acceptance: dashboard renders real metrics from the API; clicking any figure
shows its source runs/findings; values match the API exactly; responsive at
desktop and mobile widths with no overlap.
Verify: build + lint apps/web; run dev server; verify in browser against indexed
lab runs.
```

## P3.S4 — Traceability + anti-gaming test

```text
Add an integration test over the P2 benchmark corpus asserting: (a) every
MetricsSummary figure equals an independent recomputation from raw artifacts; (b)
no metric counts an unverified hypothesis as a verified finding (feed a store
containing rejected/suppressed/hypothesis records and assert they are excluded
from verified counts). This prevents "metrics drift" and accidental gaming.
Verify: cargo test; eval corpus run + metrics check.
```

================================================================================
# P4 — ONE VERTICAL, DEMO-HARDENED END TO END (deep sequence)
================================================================================

Goal: take the API/SaaS authorization vertical (your strongest) and harden it so a
skeptical security engineer cannot dismiss it. NO new verticals in P4 — depth, not
breadth. Cloud/Web3 stay where they are.

## P4.S0 — Auth scheme expansion beyond bearer tokens

```text
Read first: config.rs (AuthProfile, AuthCredentialRef), web_api.rs request runner
+ how profiles attach credentials to requests, scope.rs.

Extend AuthProfile to support, in addition to bearer tokens:
- cookie/session auth (named cookies, CSRF token capture/replay),
- API key headers,
- OAuth2 (authorization_code + client_credentials): obtain/refresh a token from a
  configured token endpoint within scope, store it as an ephemeral credential,
  never log it.
- per-profile header/cookie templating so the matrix can replay one user's
  request as another user across any scheme.

Add a local lab variant (or extend labs/vulnerable-api) that uses cookie/session
auth so this is tested against a real flow, not just unit mocks.

Acceptance: the BOLA/BFLA matrix can prove cross-user access where the auth scheme
is cookie/session and where it is OAuth2; tokens are obtained within scope and
redacted in artifacts. Tests cover each scheme.
Verify: cargo fmt --check; cargo test; lab run against the cookie-auth variant.
```

## P4.S1 — Multi-tenant org-scoped roles + tenant-isolation fixture

```text
Build the flagship "wow" finding: cross-tenant data access.

- Add a labs/vulnerable-saas target with two organizations (Org A, Org B), a role
  hierarchy (viewer < member < admin < owner), and a planted cross-tenant BOLA
  (Org A member can read an Org B object via a guessable/sequential id) PLUS a
  decoy (an object that LOOKS cross-tenant-reachable but is correctly 403'd).
- Extend the matrix to model org-scoped tokens and role hierarchy so it tests:
  viewer-as-admin (BFLA), Org A-as-Org B (tenant isolation), anonymous-as-user
  (missing auth), and correctly classifies the decoy as blocked-as-expected.
- Tenant-isolation findings get a first-class classification + impact note
  ("Org A principal read Org B resource X").

Acceptance: the lab proves the cross-tenant BOLA with full request/response
evidence and does NOT flag the decoy; classification distinguishes tenant
isolation from same-tenant BOLA; tests cover the matrix expansion.
Verify: cargo fmt --check; cargo test; lab run; inspect matrix_summary.json.
```

## P4.S2 — GraphQL active validation parity

```text
Read first: discovery.rs / schema discovery (it already DETECTS GraphQL but
cannot actively validate it).

Implement GraphQL active validation:
- From introspection (or a provided schema), enumerate queries/mutations and
  object-id-bearing fields.
- Generate candidates: replay an owner's object query/mutation as another
  profile; detect cross-user/cross-tenant object access and missing auth on
  mutations.
- Capture GraphQL request/response as evidence in the same proof-package shape as
  REST findings.
- Add a GraphQL lab (or extend vulnerable-saas with a GraphQL endpoint) with a
  planted BOLA-over-GraphQL + a decoy.

Acceptance: a GraphQL cross-user object read is proven with evidence; decoy not
flagged; coverage artifacts show GraphQL operations tested vs skipped.
Verify: cargo fmt --check; cargo test; GraphQL lab run.
```

## P4.S3 — Business-logic validation (what scanners miss)

```text
This is the capability that justifies an AI security tool over a scanner.

Implement a deterministic business-logic validator for multi-step workflow abuse,
driven by the workflow/state-transition inventory you already build:
- Express workflow invariants as replayable checks, e.g.:
  - price/quantity tamper: change a client-supplied amount and confirm the server
    honors it (proof = order created at tampered price),
  - state-skip: invoke step N without completing step N-1 (proof = forbidden
    state reached),
  - replay: resubmit a one-time action (proof = double effect),
  - quantity/limit bypass.
- The model (P1) may PROPOSE which workflows to probe; the deterministic check
  PROVES it. No business-logic finding is verified without a replayable proof.
- Add the planted business-logic bug + decoy to the SaaS lab.

Acceptance: at least one multi-step business-logic abuse is proven with evidence
(before/after state captured); a benign decoy workflow is not flagged; the
model-proposed-vs-validator-proven boundary holds (a false model proposal here is
rejected, mirroring P1.S5).
Verify: cargo fmt --check; cargo test; SaaS lab run covering business logic.
```

## P4.S4 — Flagship customer report (HTML + PDF)

```text
Read first: the existing Markdown/HTML report renderers and report.md/run_report.md
generation.

Produce a single flagship report for one verified cross-tenant BOLA + one verified
business-logic abuse:
- Sections: executive summary (business impact in plain language), exact
  reproduction (curl/GraphQL), request/response evidence with secrets redacted,
  blast radius, severity rationale, fix (concrete code-level), regression test
  (executable), detection rule (Sigma/log guidance from the defense engine).
- Render HTML (self-contained, opens with no server) AND PDF. For PDF, generate
  from the HTML via a headless-Chrome step or a Rust HTML-to-PDF crate; pin the
  approach and make it reproducible in CI. The report must be visually clean and
  unambiguous — this is the sales/diligence artifact.
- Add `cargo run -p baloncore -- export-flagship-report --run-dir <dir>
  --format html|pdf`.

Acceptance: the report renders cleanly in both formats; every claim links to
evidence; redaction is applied; a reviewer can reproduce the finding from the
report alone.
Verify: cargo fmt --check; cargo test; generate both formats; open them.
```

================================================================================
# P5 — PRODUCTIONIZE THE CONTROL PLANE (deep sequence)
================================================================================

Goal: kill the "it's just local JSON files" objection. Real Postgres-backed
multi-tenant control plane with PROVEN isolation, encrypted evidence, a real
background worker, and complete audit coverage. The JSON adapter stays for local
dev behind a trait.

## P5.S0 — Storage trait + Postgres adapter

```text
Read first: baloncore-api/src/main.rs (current JSON workbench adapter),
migrations/0001_saas_control_plane.sql (the target schema:
organizations, members, projects, scope_contracts, assets, scan_jobs,
queue_leases, worker_nodes, job_attempts, artifact_records, evidence_bundles,
audit_events).

- Define a ControlPlaneStore trait covering every read/write the API performs
  (orgs, members, projects, scope contracts, assets, jobs, leases, workers,
  attempts, artifacts, evidence bundles, audit events).
- Keep the existing JSON implementation as JsonStore (local dev default).
- Add PostgresStore using sqlx with compile-time-checked queries; run
  0001_saas_control_plane.sql as the baseline migration; add a migration runner.
- Select store via config/env (BALONCORE_STORE=json|postgres); default json so
  local dev/tests are unchanged and offline.

Acceptance: with Postgres configured, the API boots, migrates, and serves the
same endpoints against Postgres; with json, behavior is unchanged. A store-
contract test suite runs against BOTH implementations and asserts identical
semantics.
Verify: cargo test (json); cargo test against a Postgres test container; API boot
on both.
```

## P5.S1 — RBAC + tenant isolation, proven by negative tests

```text
- Implement RBAC enforcement at the API boundary keyed to the platform roles/
  permissions model (Organization, Workspace, User, Role, Permission, Project).
  Every handler resolves caller -> org/workspace -> permission before any read or
  write.
- Tenant isolation: all queries are org-scoped; no handler may return cross-org
  data.
- The point of this session is the NEGATIVE tests:
  - Org A user CANNOT read Org B scans, findings, evidence, artifacts, audit log,
    or metrics (assert 403/empty, never leakage).
  - A user without permission X cannot perform action X.
  - A forged/expired token is rejected.
  Run these against BOTH stores.

Acceptance: a comprehensive cross-tenant negative-test suite passes; attempting
any cross-org access fails closed; coverage includes every data-returning
endpoint.
Verify: cargo test (isolation suite) on json + postgres.
```

## P5.S2 — Encrypted evidence at rest + permissioned export

```text
- Encrypt evidence bundle contents at rest (envelope encryption: per-bundle data
  key wrapped by a workspace key; keys from env/KMS-style provider interface,
  never committed). Decryption only on authorized, audited export.
- Gate evidence export on permission + an audit event; preserve the existing
  redaction-required export block (sensitive unredacted evidence still cannot be
  exported).
- Verify the existing evidence signature/manifest integrity flow still holds over
  encrypted-at-rest bundles (decrypt -> verify hash/signature -> serve).

Acceptance: evidence files on disk/DB are ciphertext; authorized export decrypts +
verifies + audits; unauthorized export is refused and audited; tamper still
detected.
Verify: cargo test; export as authorized vs unauthorized user; inspect at-rest
ciphertext.
```

## P5.S3 — Real background worker (lease/heartbeat/reclaim)

```text
Read first: the durable job ledger + queue metadata already in the API.

Replace inline scan execution with a real worker:
- Worker process leases a job (queue_leases), heartbeats, executes the scan via
  the library path, writes artifacts + evidence, and releases.
- Crash safety: a lease with a stale heartbeat is reclaimable by another worker
  exactly once (no double-execution); job_attempts records each try.
- Budgets from P1 apply to model usage inside worker runs.

Acceptance: a job runs to completion via the worker; a worker killed mid-job has
its lease reclaimed and the job completes once (assert no duplicate findings); the
attempt history is accurate.
Verify: cargo test incl. a kill-and-reclaim test; run a real scan through the
worker against a lab.
```

## P5.S4 — Complete audit coverage

```text
Ensure EVERY sensitive action writes an immutable audit_event: scope change, scan
start/stop, evidence export, signer-trust change, suppression change, report
download, role/permission change, key rotation, login.
- Add a test that enumerates sensitive handlers and asserts each emits a correctly-
  attributed audit event (actor, org, action, target, timestamp, outcome).
- Audit log is append-only and tenant-scoped (Org A cannot read Org B's log —
  already covered by P5.S1, re-assert here).

Acceptance: audit coverage test passes for all sensitive actions; events are
immutable and attributable.
Verify: cargo test; perform each sensitive action and confirm the audit entry.
```

================================================================================
# P6 — THE DILIGENCE PACKAGE (deep sequence)
================================================================================

Goal: from REAL artifacts (not claims), produce the package a technical investor or
design partner asks for, reproducible by a stranger.

## P6.S0 — Generate the diligence docs from real outputs

```text
Create docs/DILIGENCE/ generated from real artifacts (add small generators so docs
never drift from results):
- BENCHMARK.md: latest P2 leaderboard numbers, methodology, corpus description,
  one-command reproduction. Numbers auto-quoted from benchmarks/LEADERBOARD.md.
- ARCHITECTURE_ONE_PAGER.md: data flow scope -> recon -> model hypothesis (P1) ->
  validator -> sealed evidence -> report -> defense, with the trust boundary
  marked and the firewall guarantee stated.
- SAFETY.md (extend existing): authorization model, scope enforcement, the
  AI-proposes/validators-prove firewall, redaction-before-send, encrypted
  evidence, audit coverage, and an explicit "what BALONCORE will NOT do" list.
  Frame safety as an enterprise feature, not a disclaimer.
- METRICS.md: current investor metrics (P3), auto-quoted from the live store.

Acceptance: every number in these docs is generated from a real artifact and
matches its source; no hand-typed metrics.
Verify: run generators; diff docs against source scorecards/metrics.
```

## P6.S1 — Scripted reproducible demo + clone-to-proof check

```text
Write docs/DILIGENCE/DEMO.md: a literal 5-minute scripted demo that, with one API
key set, runs against a vendored authorized target (P2 corpus / P4 SaaS lab) and
ends on the P4 flagship report and the P2 benchmark scorecard, with exact commands.

Add scripts/diligence_repro.sh that a stranger runs after cloning:
- builds, runs the fixture-provider benchmark, runs the flagship report on the
  SaaS lab, prints the headline metrics, and exits nonzero if any step fails or
  any number drifts from the committed baseline beyond tolerance.

Add a short text "loom script" for the flagship finding: real bug -> proof ->
fix -> regression test that proves it stays dead.

Acceptance: a clean clone + one key + one script reproduces the flagship verified
finding and the benchmark headline numbers. Reproducibility IS the pitch.
Verify: run scripts/diligence_repro.sh from a fresh checkout.
```

================================================================================
# What "enterprise-grade / XBOW-like" actually requires across all stages
================================================================================

Hold these as global acceptance bars; a stage isn't done until it can answer them
(this is your BUILD_RIGOR doc's seven questions, operationalized):

1. Authorization: what proves this scan was allowed? (scope contract + audit)
2. Evidence: what exact, sealed, signed evidence proves the issue?
3. False-positive control: what decoys/challenges tried to kill it and failed?
4. Customer artifact: what redacted, reproducible report was produced?
5. Regression: what executable check proves the fix and that it stays fixed?
6. Defense: what detection/prevention artifact closes the loop?
7. Audit + isolation: who ran it, when, and is every other tenant provably unable
   to see it?

And the three things that DON'T scale and will sink you if neglected:
- Never let a model claim become a finding to inflate a metric (P1.S5, P3.S4).
- Never test an unauthorized target to "prove" capability — the corpus is how you
  prove it safely (P2).
- Depth over breadth: one vertical proven cold (P4) beats five half-built ones.