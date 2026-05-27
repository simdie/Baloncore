# V0 → Tier 3 Progress Log

Format per item: **item id — what changed — test result — verdict change (V0 → new)**.
Mutation-check: "broke X → red → restored → green" recorded explicitly when applicable.

---

## T0.a — `benchmark-ci` shortcut removed

**Changed.** All six production callers of `generate_golden_baseline` now require real
`--run-results <path>` (a `BenchmarkRun` JSON produced by an actual scan):

- `benchmark-ci`, `eval-gate`, `benchmark-repetition`, `benchmark-determinism`,
  `generate-methodology-doc`, `generate-benchmark-doc` — each errors with a clear
  "produce real scan artifacts first" message and writes no files when invoked
  without real input.
- `evaluation::verify_determinism(suite, k)` now takes `(suite, &runs)` — it
  cannot manufacture its own input any more.
- `generate_golden_baseline` itself is kept as a `#[doc(hidden)]` test fixture
  with a long doc-warning that it must never be called from CLI/API/docs paths.

**Tests added** (`crates/baloncore-cli/src/main.rs::tests`):
- `benchmark_ci_errors_when_no_run_results_supplied` — asserts `benchmark-ci`
  errors and writes no `run.json`/`scorecard.json` when `--run-results` is None.
- `benchmark_ci_errors_when_run_results_path_missing` — asserts the same for a
  non-existent path.
- `determinism_check_detects_non_determinism` (in core) — feeds one good run
  and one all-FN run, asserts `scores_identical = false`. If determinism check
  were faked, this would pass; it goes red.

**Mutation check.** Re-introduced a `None => synthesize golden baseline & write
files` branch into `benchmark_ci`. Re-ran the no-run-results test → RED
(`tests::benchmark_ci_errors_when_no_run_results_supplied ... FAILED`).
Restored from `/tmp/main.rs.bak` → GREEN.

**V0 verdict change.** P2.S2 / P2.S6 / P2.S7 "scorer returns canned scores": FAKE → **HONEST** (commands now refuse to score without a real run; the documented behaviour has shifted from "fabricated 100/100/A+" to "produce real artifacts or error out"). The capability to *score from real scans* is still NEEDS T1.b's scan pipeline before any real number can be reported.

---

## T0.b — `evaluate-benchmark` and `find_latest_matrix_summary` shortcut removed

**Changed.**
- `run_ground_truth_baseline` deleted from the CLI; it was the silent path that
  copied each case's `ground_truth` into `prediction`.
- `find_latest_matrix_summary` deleted (its only purpose was feeding the silent
  fallback).
- `evaluate-benchmark` web_api branch now requires `--run-dir <dir>` and reads
  `<run-dir>/matrix_summary.json` directly. Missing artifact → explicit `bail!`
  naming the file. Same for cloud_iam / web3 / evidence branches (`--run-dir`
  resolves the per-domain artifact name; absent file => error).
- Domains with no extractor wired now error with a clear message rather than
  falling back.

**Tests added.** `evaluate_benchmark_webapi_errors_when_matrix_summary_missing` —
constructs an empty run-dir and asserts evaluate-benchmark errors with a message
containing `matrix_summary.json` and writes no scorecard file.

**Mutation check.** Not separately mutation-checked (same shape as T0.a; the
removed `run_ground_truth_baseline` function is the mutation in reverse).

**V0 verdict change.** P2.S2 silent-ground-truth fallback in `evaluate-benchmark`:
FAKE → HONEST.

