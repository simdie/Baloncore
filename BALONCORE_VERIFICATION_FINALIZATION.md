# BALONCORE — Verification & Finalization Pass (V0–VF)

Use this AFTER an initial implementation (e.g. by GLM 5.1) to have a stronger
model (Claude Code Opus 4.7 or Codex 5.5 xhigh) independently verify that every
stage P0–P6 actually does what the master plan intended — and finish anything
that doesn't. Feed these in order. They map 1:1 to the P-stages in
`BALONCORE_MASTER_DEEP_BUILD.md`; keep that file open beside this one.

## The auditor's mindset (state this to the model, it matters)

- **Trust nothing self-reported.** README "✅ done" notes, code comments, commit
  messages, and prior session summaries are UNVERIFIED CLAIMS. Only running code,
  passing tests that genuinely test the behavior, and produced artifacts count.
- **Tests must actually test.** For every key test, confirm it FAILS when the
  feature is removed/broken (a quick mutation check). A test that passes against
  broken code is worse than no test.
- **The firewall is the crown jewel.** The highest-priority thing to verify is
  that a model hypothesis can NEVER become a `FindingState::Verified` without the
  deterministic validator + sealed evidence path. If this is broken, nothing else
  matters.
- **Honesty over green checks.** A truthful "this is STUB" beats a faked pass.
  Classify, don't paper over.

================================================================================
## V0 — Independent ground-truth audit (run first; gate for everything else)
================================================================================

```text
You are auditing an existing BALONCORE implementation that was built by a less-
capable model. Do NOT trust any self-reported status. Produce docs/VERIFICATION/
V0_GROUND_TRUTH.md.

1. Run and record verbatim (command, exit code, output tail): cargo build, cargo
   test, cargo fmt --check, cargo clippy --all-targets, and the apps/web build +
   lint. List every failure and warning.
2. For EVERY capability the repo/README/roadmap claims across P0-P6, classify it:
   - REAL: runs real work, has a test that genuinely fails if the feature breaks,
     produces durable output.
   - FIXTURE: only canned/deterministic output, or only runs against a self-
     authored lab.
   - STUB / FAKE: placeholder, or a test that passes without exercising the
     behavior, or hardcoded output masquerading as computed.
   Cite file:line evidence for each verdict.
3. Specifically determine, with evidence:
   - Does run_live_agent / a real provider call actually exist and work, or is
     "fixture" still the only path? (P1)
   - Do the validators send real traffic, or operate on fixtures? (P1/P4)
   - Does baloncore-eval actually run targets end-to-end and SCORE them, or are
     scores stubbed/hardcoded? (P2)
   - Are P3 metrics computed from artifacts, or hardcoded/random?
   - Is tenant isolation (P5) actually enforced, proven by a test that fails when
     isolation is removed?
4. Output: one honest table (capability → verdict → evidence), a ranked list of
   the gaps that most threaten the project's purpose, and a "what a technical
   diligence reviewer concludes in 30 minutes" paragraph.

Do not fix anything yet. This is the map. Stop and report.
```

================================================================================
## V1 — Firewall integrity audit (highest priority)
================================================================================

```text
Verify the validator firewall in agent.rs is intact and cannot be bypassed.
Reference P1.S5 acceptance criteria in the master plan.

1. Trace EVERY code path that can set FindingState::Verified. Confirm each one
   passes through validate_agent_output -> challenge_hypotheses ->
   bridge_hypotheses_to_validators -> validator_for_classification -> a real
   validator -> sealed evidence. List any path that shortcuts this. ANY shortcut
   is a critical defect.
2. Confirm a model can only PROPOSE. Grep for any place model/agent output is
   written directly into a finding, report, or metric without validator proof.
3. Run (or write, if missing) the adversarial test: feed a confident but FALSE
   model hypothesis (claims a vuln that the live validator will refute) and assert
   it is NOT promoted. Then mutation-check it: temporarily weaken the validator and
   confirm the test FAILS (proving the test is real). Restore.
4. Verify redaction-before-send (P1.S4): confirm a secret in an AgentInput is
   replaced with a placeholder before any provider call, with a test that fails if
   redaction is bypassed.
5. Verify budgets (P1.S1/S6) are enforced in code, not just configured.

Write docs/VERIFICATION/V1_FIREWALL.md with verdicts + evidence. Then FIX any
defect found, re-run, and confirm green with genuine (mutation-checked) tests.
```

================================================================================
## V2 — Benchmark integrity audit
================================================================================

```text
Verify baloncore-eval actually measures capability honestly. Reference P2.

1. Confirm the runner truly executes BALONCORE end-to-end per case (target up ->
   scan -> teardown) and is NOT returning canned scores. Prove it by running one
   case and showing the live scan artifacts it produced.
2. Verify the scoring math (P2.S1) with the existing unit tests AND a fresh hand-
   calculated case you add: assert literal precision/recall/FP-rate values.
3. Verify DECOYS are actually tested and that a decoy hit lowers the score. Add a
   temporary deliberately-broken validator that flags a decoy; confirm the score
   drops and (P2.S6) the CI gate fails. Restore.
4. Verify the corpus (P2.S3) against BALONCORE_BENCHMARK_CORPUS_TARGETS.md:
   - each vendored target's repo exists and is pinned to a commit/tag,
   - each LICENSE was actually checked (record SPDX in case.toml),
   - Damn Vulnerable DeFi points at theredguild (not the old URL),
   - cloud cases use STATIC IaC (TerraGoat etc.) analyzed offline, NOT live AWS,
   - VAmPI/DVGA use secure-mode/benign ops as real decoys.
   Flag any target that is missing, dead, unlicensed, or mislabeled.
5. Verify determinism (P2.S5): run the fixture-provider eval twice; assert byte-
   identical aggregate scores.

Write docs/VERIFICATION/V2_BENCHMARK.md. Fix gaps, re-run, confirm.
```

================================================================================
## V3 — Metrics honesty audit
================================================================================

```text
Verify P3 metrics are real and cannot be gamed.

1. Confirm every metric in MetricsSummary is computed from artifacts, not
   hardcoded/random. Trace each to its source data.
2. Add/confirm the anti-gaming test: feed a store containing rejected/suppressed/
   hypothesis-only records and assert they are EXCLUDED from verified counts.
3. Verify drill-down: every dashboard number links to the exact runs/findings that
   produced it; a number with no traceable source must not exist.
4. Recompute 2-3 headline metrics by hand from raw artifacts and assert the
   dashboard/API match exactly.

Write docs/VERIFICATION/V3_METRICS.md. Fix gaps, re-run, confirm.
```

================================================================================
## V4 — Vertical depth audit (API/SaaS authorization)
================================================================================

```text
Verify P4 actually proves the flagship findings with evidence, not just claims.

1. Run the API/SaaS vertical against its labs. Confirm a cross-tenant BOLA and a
   business-logic abuse are each PROVEN with captured request/response evidence
   (open the evidence and read it). 
2. Confirm the planted DECOYS are NOT flagged (run them; assert zero findings).
3. Verify auth scheme coverage (P4.S0): bearer + cookie/session + OAuth2 actually
   work against a lab, with tokens redacted in artifacts.
4. Verify GraphQL active validation (P4.S2) produces a real proven finding, not
   just schema detection.
5. Generate the flagship report (P4.S4) in HTML and PDF; open both; confirm every
   claim links to evidence and secrets are redacted.

Write docs/VERIFICATION/V4_VERTICAL.md. Fix gaps, re-run, confirm.
```

================================================================================
## V5 — Control-plane & isolation audit
================================================================================

```text
Verify P5's enterprise claims are real and fail-closed.

1. Tenant isolation: run the negative tests proving Org A cannot read Org B's
   scans/evidence/findings/audit/metrics. Mutation-check: remove an isolation
   check and confirm a test FAILS. Restore. If these tests don't exist, the
   isolation claim is unproven — build them.
2. RBAC: confirm a permission-less user is refused each gated action.
3. Evidence-at-rest encryption (P5.S2): confirm on-disk/DB bundles are ciphertext;
   confirm authorized export decrypts + verifies + audits, unauthorized is refused.
4. Worker reclaim (P5.S3): kill a worker mid-job; confirm the job is reclaimed and
   completes exactly once (no duplicate findings).
5. Audit coverage (P5.S4): enumerate sensitive actions; confirm each emits an
   immutable, attributable audit event.
Run against BOTH the json and postgres stores if Postgres is wired.

Write docs/VERIFICATION/V5_CONTROL_PLANE.md. Fix gaps, re-run, confirm.
```

================================================================================
## V6 — Diligence reproducibility audit
================================================================================

```text
Verify a stranger can reproduce the headline results. Reference P6.

1. From a CLEAN checkout in a fresh directory, run scripts/diligence_repro.sh (or
   build it if missing). Confirm it builds, runs the fixture benchmark, generates
   the flagship report, prints headline metrics, and exits nonzero on any drift.
2. Confirm docs/DILIGENCE numbers are auto-generated from real artifacts and match
   the latest scorecard/metrics (no hand-typed figures).
3. Confirm SAFETY.md accurately describes the firewall, scope enforcement,
   redaction, encryption, and audit as IMPLEMENTED (not aspirational).

Write docs/VERIFICATION/V6_DILIGENCE.md. Fix gaps, re-run, confirm.
```

================================================================================
## VF — Finalization & full-gate sign-off
================================================================================

```text
Consolidate and close out.

1. Merge all V0-V6 findings into docs/VERIFICATION/FINAL_REPORT.md: per stage,
   state REAL/FIXTURE/STUB BEFORE this audit vs AFTER your fixes, with evidence.
2. Ensure the whole workspace passes: cargo build, cargo test, cargo fmt --check,
   cargo clippy --all-targets clean; apps/web builds and lints; the eval gate
   (P2.S6) passes; the firewall and isolation mutation-checks are green.
3. Produce a short, honest "remaining gaps" list — anything still FIXTURE/STUB
   that a future session must address. Do NOT mark something done that isn't.
4. Confirm the project's CORE PURPOSE holds end-to-end with one live demonstration:
   a real (or recorded-transcript) model proposes a hypothesis -> the validator
   proves it -> sealed evidence -> flagship report -> the benchmark scores it ->
   the metric reflects it -> a stranger can reproduce it. If any link is broken,
   it is not done.

Output FINAL_REPORT.md and the passing gate output.
```

## How to drive this audit

- Run V0 first and READ it before anything else — it tells you how much GLM
  actually delivered vs claimed, which determines how much V1-VF will need to fix.
- Do them in order; V1 (firewall) is non-negotiable and gates the product's whole
  value proposition.
- After each V-stage, YOU personally re-run the key test it describes before
  accepting the model's "fixed" claim — especially the firewall (V1) and isolation
  (V5) mutation-checks. The auditor model is verifying GLM; you are verifying the
  auditor.
- If the auditor reports a stage is largely STUB/FAKE, that's not failure — it's
  the audit doing its job. Have it finish that stage using the matching deep
  prompt from BALONCORE_MASTER_DEEP_BUILD.md, then re-audit.
```