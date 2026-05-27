# BALONCORE Benchmark — Diligence Documentation

## RETRACTION — read this first

A previous version of this document published a one-command "100% precision /
100% recall / A+" headline for all four benchmark suites. That headline was a
tautology: the `benchmark-ci` CLI silently called an internal helper
(`generate_golden_baseline`) that copied each case's `ground_truth` into the
`prediction` field, then graded that against the same ground truth. No scan
was ever executed. The numbers measured nothing.

The audit that uncovered this is in
[`docs/VERIFICATION/V0_GROUND_TRUTH.md`](../VERIFICATION/V0_GROUND_TRUTH.md) §2.
The shortcut has been removed (`docs/VERIFICATION/PROGRESS.md` T0.a/T0.b), and
the CLI now refuses to produce a score without real run artifacts.

**Retracted claims (do not reuse anywhere):**

- 100 % precision, 100 % recall, 100 % F1, grade A+ on any BALONCORE benchmark
  suite.
- "The numbers in this document match the latest scorecard generated from the
  golden baseline" — the golden baseline was a synthetic fixture for unit-testing
  the scoring math, not a measurement of any system capability.
- "Eval gate passes on every PR" framing for the CI gate as it stood — the gate
  passed because the synthetic input always passed; a deliberately broken
  validator would not have changed the score.

---

## What is currently measurable, end-to-end (honest baseline)

These are real today, against in-tree local labs only. There is no externally
authored corpus yet (`docs/VERIFICATION/V0_GROUND_TRUTH.md` §4.3).

| What | Where to reproduce | What it proves |
|---|---|---|
| **Verified cross-tenant BOLA on `labs/vulnerable-saas`** | Start the lab (`node labs/vulnerable-saas/server.js`), then `cargo run -p baloncore -- scan-openapi-bola --base-url http://127.0.0.1:3010 --openapi-url http://127.0.0.1:3010/openapi.json --owner-profile org_b_member` (with a config defining the org_a_* / org_b_* profiles). Inspect `<run-dir>/matrix_summary.json` for an `org-a` member proving cross-tenant access to `org-b` `proj-b-001`. | Real HTTP traffic to a planted bug, sealed evidence written to disk. |
| **Decoy rejection on `proj-b-secret`** | Same lab. The same scan must NOT flag `org-a` member requests to `proj-b-secret` (it is correctly 403'd). | Decoy discipline against a planted-but-properly-blocked endpoint. |
| **Bearer-token redaction before any provider call** | Unit tests `redact_for_model_removes_bearer_tokens`, `…_emails`, `…_passwords` in `crates/baloncore-core/src/agent_runtime.rs::tests`; plus the fail-closed guard in `run_live_agent` at the same file. | Secrets are replaced with placeholders before serialization into a model request; `run_live_agent` aborts with a `Skipped` output if a known secret marker survives. |
| **Firewall pre-filter** | Tests `live_pipeline_false_hypothesis_is_not_promoted_to_verified` and `live_pipeline_true_hypothesis_is_promoted` in `crates/baloncore-core/src/agent_runtime.rs::tests`. | A vague/no-endpoint/no-evidence hypothesis is blocked before validator bridging; a well-formed one is bridged. (See T1.a in PROGRESS.md for the live-validator extension of this test.) |
| **Strict JSON repair + budgets** | Tests `parse_*`, `*_repair`, `model_budget_*` in the same module. | Malformed model output triggers exactly one repair attempt, then `Skipped`; budget exhaustion aborts before any model call. |
| **Scoring math (unit-tested in isolation)** | `compute_evaluation_metrics`, `generate_scorecard`, `compare_runs`, `verify_determinism` exhaustive unit tests in `crates/baloncore-core/src/evaluation.rs`. | The math itself (precision/recall/F1/FPR/per-difficulty-weighted accuracy) computes the right values from any `BenchmarkRun` you hand it. The math is real; what was missing was a real input. |

Headline numbers from real scans of the in-tree labs will be added back to this
document once T1.b (the real benchmark runner that brings up `vulnerable-saas`,
scans it, and scores the produced `matrix_summary.json` against a hand-labeled
`ground_truth.json`) is complete.

## How to produce a real benchmark run today (manual path)

The CLI now refuses to score without real artifacts. The minimal manual path:

```bash
# 1. start the lab
node labs/vulnerable-saas/server.js &

# 2. run the real scan to produce matrix_summary.json
cargo run -p baloncore -- scan-openapi-bola \
  --base-url http://127.0.0.1:3010 \
  --openapi-url http://127.0.0.1:3010/openapi.json \
  --owner-profile org_b_member \
  --out-dir .baloncore/runs/saas-bench

# 3. score it
cargo run -p baloncore -- evaluate-benchmark \
  --suite baloncore-web-api-v1 \
  --run-dir .baloncore/runs/saas-bench

# 4. (optional) gate it
cargo run -p baloncore -- benchmark-ci \
  --suite baloncore-web-api-v1 \
  --run-results .baloncore/runs/saas-bench/scorecard.json
```

If step 2 is skipped, steps 3 and 4 will error with an explicit "produce real
scan artifacts first" message instead of producing a number.

## Scoring methodology (unchanged; the math is real)

| Metric | Formula | Why it matters |
|--------|---------|----------------|
| Precision | TP / (TP + FP) | Fraction of alerts that are real. Low precision = alert fatigue. |
| Recall | TP / (TP + FN) | Fraction of real vulnerabilities found. Low recall = missed attacks. |
| F1 | 2·P·R / (P+R) | Balance between precision and recall. |
| Accuracy | (TP + TN) / Total | Overall correctness across all cases. |
| FPR | FP / (FP + TN) | False-alarm rate; must trend to 0 for production use. |
| Decoy FP rate | Decoy TP / Total Decoys | Fraction of decoys incorrectly flagged. |

Difficulty weighting (trivial 0.5×, basic 1×, moderate 2×, advanced 3×, expert 5×)
is applied as before. The math is correct; only its production callers were lying.

## Suite descriptions (cases unchanged; runs are gated on real input)

- **Web/API suite** — 10 cases covering BOLA, BFLA, missing-auth, intended access, decoys.
- **Cloud IAM suite** — 5 cases covering over-permissive IAM, privilege paths, compliant policies.
- **Web3 suite** — 5 cases covering reentrancy, access control, integer overflow, compliant contracts.
- **Evidence lifecycle suite** — 4 cases covering verified findings, rejected hypotheses, integrity failures, invalid lifecycle states.

## Determinism

`benchmark-determinism` now takes K real `BenchmarkRun` JSON paths and asserts
they are score-identical. It cannot be passed a synthetic baseline that
trivially matches itself.

## Attribution

Every real benchmark run records: provider, model, prompt version, engine
version, git commit, corpus hash. Synthetic fixture runs are not eligible.

## Limitations (now also honest)

1. **No externally authored corpus yet.** All evidence is against the in-tree
   labs (`labs/vulnerable-api`, `labs/vulnerable-saas`, `labs/vulnerable-protocol`,
   `labs/cloud-iam/aws-risky.json`). External corpus vendoring is NEEDS-HUMAN
   pending `BALONCORE_BENCHMARK_CORPUS_TARGETS.md`.
2. **24 hardcoded cases across 4 domains.** Not exhaustive of all vulnerability classes.
3. **Live model results vary.** The eval reports mean ± stddev over K real runs (no synthetic determinism shortcut).
4. **Ground truth is hand-labeled.** Reasonable professionals may disagree on edge cases.
5. **No live cloud scanning.** Cloud IAM analysis is offline static analysis.
6. **Local targets only.** Production behavior may differ.
7. **No timing guarantees.** Relative comparisons only.
8. **Decoy coverage is limited.** Does not cover all FP scenarios.
9. **Headline numbers retracted pending T1.b.** See top of this document.

## Reproduction (revised)

1. Clone the repo, install Rust (stable).
2. Bring up `labs/vulnerable-saas` (or another in-tree lab).
3. Run the real scan (`scan-openapi-bola` or equivalent).
4. Score with `evaluate-benchmark --run-dir <real-scan-dir>`.
5. Gate with `benchmark-ci --suite … --run-results <real-run.json>`.

No step in this pipeline accepts synthetic input. If any step is omitted, the
next will error.
