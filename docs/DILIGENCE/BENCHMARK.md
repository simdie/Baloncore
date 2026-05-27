# BALONCORE Benchmark — Diligence Documentation

## Executive Summary

BALONCORE's security validation accuracy is measured against hand-labeled ground truth with deterministic reproducibility. Every claim in this document is verifiable by a single command.

## Verification Command

```bash
git clone <repo> && cd Baloncore
cargo build --release -p baloncore
./scripts/run_benchmarks.sh --check-determinism --fail-on-regression
```

This single command builds BALONCORE, runs all 4 benchmark suites, verifies determinism (K=2 identical runs), and exits nonzero if any suite regresses below configurable thresholds.

## What We Measure

BALONCORE measures **security validation accuracy** — not whether a vulnerability exists (which is determined by ground truth labeling), but whether the system correctly identifies, classifies, and provides evidence for each finding.

The four measured outcomes per case:

| Outcome | Meaning |
|---------|---------|
| True Positive | Real vulnerability correctly identified |
| True Negative | Benign or intended access correctly NOT flagged |
| False Positive | Benign behavior incorrectly flagged as a vulnerability |
| False Negative | Real vulnerability missed |
| Inconclusive | Insufficient evidence to make a determination |

**Decoy cases** are planted traps: scenarios that look like vulnerabilities but are not. Any decoy flagged as a True Positive is a false alarm that reveals over-eager detection.

## Scoring Methodology

### Primary Metrics

| Metric | Formula | Why It Matters |
|--------|---------|----------------|
| Precision | TP / (TP + FP) | Fraction of alerts that are real. Low precision = alert fatigue. |
| Recall | TP / (TP + FN) | Fraction of real vulnerabilities found. Low recall = missed attacks. |
| F1 | 2 * P * R / (P + R) | Balance between precision and recall. |
| Accuracy | (TP + TN) / Total | Overall correctness across all cases. |
| FPR | FP / (FP + TN) | False alarm rate. Must trend to zero for production use. |
| Decoy FP rate | Decoy TP / Total Decoys | Fraction of decoys incorrectly flagged. |

### Difficulty Weighting

Not all cases are equally hard. BALONCORE weights accuracy by difficulty:

- **Trivial** (0.5x): Obvious single-step validations
- **Basic** (1.0x): Standard vulnerability patterns
- **Moderate** (2.0x): Multi-step reasoning required
- **Advanced** (3.0x): Subtle or complex patterns
- **Expert** (5.0x): Deep domain knowledge required

This ensures headline numbers reflect real-world difficulty, not just easy cases.

### Eval Gate Thresholds

The CI gate enforces these minimum thresholds on every PR:

| Threshold | Default | Rationale |
|-----------|---------|-----------|
| Precision | >= 70% | Less than 70% precision means >30% of alerts are false |
| Decoy FP | = 0 | Any decoy hit reveals over-eager detection |
| Recall drop | <= 10pp | Code changes should not regress recall by more than 10 percentage points |

## Corpus Design

### Web/API Suite (10 cases)

Covers BOLA, BFLA, missing authentication, intended owner access, and blocked-as-expected scenarios across REST API endpoints.

| Case | Ground Truth | Difficulty | Category |
|------|-------------|------------|----------|
| Owner accesses own invoice | TrueNegative | Trivial | Negative control |
| Cross-user invoice (BOLA) | TruePositive | Basic | IDOR |
| Non-admin admin report (BFLA) | TruePositive | Basic | BFLA |
| Anonymous invoice access | TruePositive | Moderate | Missing auth |
| Intended multi-tenant access | TrueNegative | Basic | Negative control |
| BOLA with business data | TruePositive | Moderate | Sensitive data |
| BFLA with privileged data | TruePositive | Advanced | Privilege escalation |
| Rate-limited endpoint blocked | TrueNegative | Basic | Rate limiting |
| BOLA on parameterized path | TruePositive | Advanced | Parameterized IDOR |
| Admin endpoint properly blocked | TrueNegative | Trivial | Auth enforcement |

### Cloud IAM Suite (5 cases)

Covers overly permissive IAM policies, privilege escalation paths, and compliant policies.

### Web3 Suite (5 cases)

Covers reentrancy, access control, integer overflow, and compliant contract patterns.

### Evidence Lifecycle Suite (4 cases)

Covers verified findings, rejected hypotheses, evidence integrity failures, and lifecycle invalid states.

## Determinism

BALONCORE's fixture provider produces **byte-identical** results across repeated runs. This is enforced by a determinism test:

```bash
cargo run -p baloncore -- benchmark-determinism --suite baloncore-web-api-v1 --k 3
```

For live model providers, we report mean +/- stddev over K repetitions rather than a single sample.

## Attribution

Every benchmark run records:

- **Provider**: fixture / anthropic / openai
- **Model**: e.g., claude-sonnet-4-20250514, gpt-4
- **Prompt version**: e.g., v1
- **Engine version**: BALONCORE package version
- **Git commit**: Source code version
- **Corpus hash**: Hash of the benchmark suite for reproducibility

## Limitations

See `benchmarks/METHODOLOGY.md` for a complete limitations section. Key points:

1. **24 cases** across 4 domains — not exhaustive of all vulnerability classes
2. **Fixture results are deterministic** — live model results vary
3. **Ground truth is hand-labeled** — reasonable professionals may disagree on edge cases
4. **Local targets only** — production behavior may differ
5. **No timing guarantees** — relative comparisons only
6. **Decoy coverage is limited** — does not cover all FP scenarios

## Reproduction Steps

1. Clone the repository
2. Install Rust (stable)
3. Run: `./scripts/run_benchmarks.sh --check-determinism --fail-on-regression`
4. Verify: all 4 suites pass, determinism check passes, eval gate passes
5. Generate leaderboard: `cargo run -p baloncore -- leaderboard --runs <run_files...>`

The numbers in this document match the latest scorecard generated from the golden baseline.