# BALONCORE Benchmark Methodology

## RETRACTION — read this first

A previous version of this document recommended
`benchmark-ci --suite … --save-golden --json` as a one-command reproduction.
That command produced a 100 %-by-construction tautology — it copied each case's
`ground_truth` into the `prediction` field and graded that against the same
ground truth. The shortcut has been removed (see
[`docs/VERIFICATION/V0_GROUND_TRUTH.md`](../docs/VERIFICATION/V0_GROUND_TRUTH.md) §2
and [`docs/VERIFICATION/PROGRESS.md`](../docs/VERIFICATION/PROGRESS.md) T0.a/T0.b).

The CLI now refuses to score without real run artifacts. Any reproduction must
bring up a real target (start with `labs/vulnerable-saas`), run a real scan,
and pass the produced `BenchmarkRun` JSON to the gate.

## Overview

BALONCORE evaluates security validation accuracy using benchmark suites with
hand-labeled ground truth. The scoring math (precision, recall, F1, FPR,
weighted accuracy, decoy FP rate) operates on `BenchmarkRun` artifacts produced
by real scans of authorized targets.

**Reproduction (manual; the runner is T1.b in PROGRESS.md):**

```bash
node labs/vulnerable-saas/server.js &
cargo run -p baloncore -- scan-openapi-bola \
  --base-url http://127.0.0.1:3010 \
  --openapi-url http://127.0.0.1:3010/openapi.json \
  --owner-profile org_b_member \
  --out-dir .baloncore/runs/saas-bench
cargo run -p baloncore -- evaluate-benchmark \
  --suite baloncore-web-api-v1 \
  --run-dir .baloncore/runs/saas-bench
```

If the scan step is omitted, `evaluate-benchmark` and `benchmark-ci` will both
error with a "produce real scan artifacts first" message.

## Corpus

### Suites

| Suite ID | Domain | Cases | Version |
|----------|--------|-------|---------|
| `baloncore-web-api-v1` | Web/API | 10 | 1.0.0 |
| `baloncore-cloud-iam-v1` | Cloud IAM | 5 | 1.0.0 |
| `baloncore-web3-v1` | Web3 | 5 | 1.0.0 |
| `baloncore-evidence-v1` | Evidence Lifecycle | 4 | 1.0.0 |

**Total: 24 benchmark cases across 4 domains.**

### Ground Truth Labels

Each case is labeled with one of:

| Label | Meaning |
|-------|---------|
| `TruePositive` | A real vulnerability that should be detected and reported |
| `TrueNegative` | Intended access or benign behavior that should NOT be flagged |
| `FalsePositive` | A deliberately planted decoy — looks like a vulnerability but is not |
| `FalseNegative` | A real vulnerability that naive scanners miss |
| `Inconclusive` | Insufficient evidence to make a determination |

### Decoy Cases

Decoy cases are labeled `FalsePositive` and/or tagged with `"decoy"`. These represent scenarios where a naive or over-eager scanner would produce a false alarm. BALONCORE's eval gate treats any decoy flagged as `TruePositive` as a violation (configurable via `--max-decoy-fp`).

### Difficulty Levels

| Level | Weight | Description |
|-------|--------|-------------|
| Trivial | 0.5 | Obvious, single-step validation |
| Basic | 1.0 | Standard vulnerability pattern |
| Moderate | 2.0 | Requires multi-step reasoning |
| Advanced | 3.0 | Subtle or complex patterns |
| Expert | 5.0 | Requires deep domain knowledge |

Weighted accuracy accounts for difficulty, giving more credit for harder cases.

## Scoring

### Metrics

- **Precision**: TP / (TP + FP) — of all flagged findings, how many are real
- **Recall**: TP / (TP + FN) — of all real vulnerabilities, how many were found
- **F1**: Harmonic mean of precision and recall
- **Accuracy**: (TP + TN) / Total — overall correctness
- **FPR**: FP / (FP + TN) — false alarm rate
- **FNR**: FN / (FN + TP) — miss rate
- **Weighted Accuracy**: Accuracy weighted by difficulty level
- **Evidence Coverage**: Fraction of expected evidence keys found
- **Classification Accuracy**: Correct classification label matching
- **Severity Accuracy**: Correct severity label matching

### Grades

| Grade | Accuracy |
|-------|----------|
| A+ | >= 97% |
| A | >= 90% |
| B | >= 80% |
| C | >= 70% |
| D | >= 60% |
| F | < 60% |

## Authorization

All benchmark targets are local, intentionally-vulnerable lab applications:

- **Web/API**: `labs/vulnerable-api/` — local Express.js API with planted BOLA, BFLA, and missing-auth vulnerabilities
- **Cloud IAM**: `labs/cloud-iam/aws-risky.json` — intentionally misconfigured AWS IAM policies
- **Web3**: `labs/vulnerable-protocol/` — local Solidity contracts with known vulnerabilities

No external hosts are contacted during evaluation. The runner enforces scope authorization before any request.

## Reproduction (gated on real run artifacts)

All of the commands below require a real `BenchmarkRun` JSON produced by an
actual scan. There is no `--save-golden` synthetic shortcut any more.

### Single suite

```bash
# 1. produce a real run (example: SaaS lab)
node labs/vulnerable-saas/server.js &
cargo run -p baloncore -- scan-openapi-bola \
  --base-url http://127.0.0.1:3010 \
  --openapi-url http://127.0.0.1:3010/openapi.json \
  --owner-profile org_b_member \
  --out-dir .baloncore/runs/saas-bench

# 2. score it
cargo run -p baloncore -- evaluate-benchmark \
  --suite baloncore-web-api-v1 \
  --run-dir .baloncore/runs/saas-bench

# 3. (optional) gate it
cargo run -p baloncore -- benchmark-ci \
  --suite baloncore-web-api-v1 \
  --run-results .baloncore/runs/saas-bench/benchmark_run.json
```

### Determinism verification (K independent real runs)

```bash
cargo run -p baloncore -- benchmark-determinism \
  --suite baloncore-web-api-v1 \
  --k 3 \
  --run-results run1.json run2.json run3.json
```

### Eval gate (real run required)

```bash
cargo run -p baloncore -- eval-gate \
  --suite baloncore-web-api-v1 \
  --run-results .baloncore/runs/saas-bench/benchmark_run.json \
  --min-precision 0.70 --max-decoy-fp 0 --max-recall-drop 0.10
```

### Leaderboard generation (real runs only)

```bash
cargo run -p baloncore -- leaderboard --runs run1.json run2.json ...
```

### Cross-domain correlation (real runs only)

```bash
cargo run -p baloncore -- cross-domain --runs run1.json run2.json run3.json run4.json
```

## Limitations

1. **Corpus size**: 24 cases is small. BALONCORE's benchmark covers 4 vulnerability domains but does not cover all OWASP API Security Top 10 categories, all cloud IAM misconfiguration types, or all Web3 vulnerability classes.

2. **Fixture provider**: Golden baseline results use a deterministic fixture provider. Live model providers (Anthropic, OpenAI) will produce different results on each run. The `benchmark-repetition` command reports mean +/- stddev for live providers.

3. **Ground truth subjectivity**: Ground truth labels are hand-authored and represent the BALONCORE team's assessment. Reasonable security professionals may disagree on edge cases (e.g., whether a specific access pattern constitutes BOLA or intended multi-tenancy).

4. **Local targets only**: Benchmarks run against local, intentionally-vulnerable lab applications. Real-world targets may exhibit different behavior patterns, rate limiting, and authentication mechanisms not represented in the corpus.

5. **No timing guarantees**: Time-to-proof metrics depend on hardware, network conditions (for live providers), and system load. Only relative timing comparisons are meaningful.

6. **Decoy coverage**: Decoy cases test false-positive discipline but do not cover all false-positive scenarios a production scanner would encounter.

## Headline Numbers — RETRACTED

The numbers previously published here were a tautology (see the retraction at
the top of this file and `docs/VERIFICATION/V0_GROUND_TRUTH.md` §2). They have
been removed and will only be reinstated when the real benchmark runner (T1.b
in `docs/VERIFICATION/PROGRESS.md`) produces them from a real scan of an
authorized target.

| Domain | Accuracy | Precision | Recall | F1 | Grade |
|--------|----------|-----------|--------|----|-------|
| WebApi | RETRACTED | RETRACTED | RETRACTED | RETRACTED | RETRACTED |
| CloudIam | RETRACTED | RETRACTED | RETRACTED | RETRACTED | RETRACTED |
| Web3 | RETRACTED | RETRACTED | RETRACTED | RETRACTED | RETRACTED |
| Evidence | RETRACTED | RETRACTED | RETRACTED | RETRACTED | RETRACTED |

**Overall: NOT YET MEASURED against any real target. Do not quote a headline
number from BALONCORE until T1.b is complete.**