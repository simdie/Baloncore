#!/usr/bin/env bash
# RETRACTED — see docs/VERIFICATION/V0_GROUND_TRUTH.md §2 and PROGRESS.md T0.e.
#
# Previously this script invoked `benchmark-ci … --save-golden` which produced a
# 100%-by-construction tautology (the golden baseline copied each case's
# ground_truth into the prediction field). The synthetic shortcut has been
# removed from the CLI, so this script can no longer fabricate a passing run.
#
# A real benchmark runner that brings up an in-tree lab, runs a real scan,
# scores it, and tears the lab down is being built as T1.b (see
# docs/VERIFICATION/PROGRESS.md). Until that lands, run the benchmark by hand
# as documented in benchmarks/METHODOLOGY.md.

set -euo pipefail

cat <<'EOF' >&2
[run_benchmarks.sh] RETRACTED

The one-command-from-fixtures path produced a synthetic 100% baseline and has
been removed. To produce real numbers today:

  1. Start an in-tree lab, e.g.:
       node labs/vulnerable-saas/server.js &
  2. Run the real scan:
       cargo run -p baloncore -- scan-openapi-bola \
         --base-url http://127.0.0.1:3010 \
         --openapi-url http://127.0.0.1:3010/openapi.json \
         --owner-profile org_b_member \
         --out-dir .baloncore/runs/saas-bench
  3. Score it:
       cargo run -p baloncore -- evaluate-benchmark \
         --suite baloncore-web-api-v1 \
         --run-dir .baloncore/runs/saas-bench
  4. Gate it (optional):
       cargo run -p baloncore -- benchmark-ci \
         --suite baloncore-web-api-v1 \
         --run-results .baloncore/runs/saas-bench/benchmark_run.json

The fully scripted version lands as T1.b in docs/VERIFICATION/PROGRESS.md.
EOF

exit 2
