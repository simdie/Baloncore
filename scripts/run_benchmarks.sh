#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GOLDEN_DIR="${GOLDEN_DIR:-.baloncore/benchmark/golden}"
HISTORY_DIR="${HISTORY_DIR:-.baloncore/benchmark/history}"
MIN_ACCURACY="${MIN_ACCURACY:-0.80}"
MIN_PRECISION="${MIN_PRECISION:-0.70}"
MIN_RECALL="${MIN_RECALL:-0.70}"
MIN_F1="${MIN_F1:-0.70}"
MAX_FPR="${MAX_FPR:-0.20}"
DRIFT_THRESHOLD="${DRIFT_THRESHOLD:-0.05}"
JSON_OUTPUT=0
FAIL_ON_REGRESSION=0
TRACK_HISTORY=0
CHECK_DRIFT=0
CHECK_DETERMINISM=0
DETERMINISM_K=2
SUITES="web_api cloud_iam web3 evidence"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)
      JSON_OUTPUT=1
      shift
      ;;
    --fail-on-regression)
      FAIL_ON_REGRESSION=1
      shift
      ;;
    --track-history)
      TRACK_HISTORY=1
      shift
      ;;
    --check-drift)
      CHECK_DRIFT=1
      shift
      ;;
    --check-determinism)
      CHECK_DETERMINISM=1
      shift
      ;;
    --determinism-k)
      DETERMINISM_K="$2"
      shift 2
      ;;
    --suites)
      SUITES="$2"
      shift 2
      ;;
    --golden-dir)
      GOLDEN_DIR="$2"
      shift 2
      ;;
    --drift-threshold)
      DRIFT_THRESHOLD="$2"
      shift 2
      ;;
    --help|-h)
      cat <<'EOF'
Usage: ./scripts/run_benchmarks.sh [--json] [--fail-on-regression] [--track-history] [--check-drift] [--suites "..."] [--golden-dir DIR] [--drift-threshold N]

Runs BALONCORE benchmark evaluation against golden baselines for each domain.

Flags:
  --json                  Print machine-readable JSON output per suite.
  --fail-on-regression   Exit nonzero if any suite fails CI gate thresholds.
  --track-history         Append results to benchmark history after each suite.
  --check-drift           Run drift detection against history after evaluation.
  --check-determinism     Run determinism check (K repetitions) after evaluation.
  --determinism-k N       Number of repetitions for determinism check (default: 2).
  --suites               Space-separated list of suites (default: all).
  --golden-dir           Directory for golden baseline files.
  --drift-threshold      Threshold for drift detection (default: 0.05).

Environment overrides:
  MIN_ACCURACY, MIN_PRECISION, MIN_RECALL, MIN_F1, MAX_FPR, GOLDEN_DIR, DRIFT_THRESHOLD

This script:
  1. Generates or loads golden baseline results for each suite.
  2. Evaluates each suite against ground truth.
  3. Runs CI gate checks (accuracy, precision, recall, F1, FPR).
  4. Optionally tracks history and detects drift.
  5. Reports pass/fail per suite and overall.
EOF
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
}

require_command cargo

echo "== BALONCORE Benchmark Suite =="
echo "golden dir: $GOLDEN_DIR"
echo "suites: $SUITES"
echo "track history: $TRACK_HISTORY"
echo "check drift: $CHECK_DRIFT"
echo ""

OVERALL_PASSED=1
PASS_COUNT=0
FAIL_COUNT=0
SUMMARY_LINES=()

mkdir -p "$GOLDEN_DIR"
mkdir -p "$HISTORY_DIR"

RUN_FILES=()

for SUITE_SLUG in $SUITES; do
  case "$SUITE_SLUG" in
    web_api) SUITE_FLAG="--suite baloncore-web-api-v1" ;;
    cloud_iam) SUITE_FLAG="--suite baloncore-cloud-iam-v1" ;;
    web3) SUITE_FLAG="--suite baloncore-web3-v1" ;;
    evidence) SUITE_FLAG="--suite baloncore-evidence-v1" ;;
    *)
      echo "unknown suite: $SUITE_SLUG" >&2
      continue
      ;;
  esac

  echo "--- Evaluating: ${SUITE_SLUG} ---"

  RUN_OUTPUT="$HISTORY_DIR/run_${SUITE_SLUG}.json"
  SCORECARD_OUTPUT="$HISTORY_DIR/scorecard_${SUITE_SLUG}.json"

  if cargo run -p baloncore -- benchmark-ci \
    $SUITE_FLAG \
    --golden-dir "$GOLDEN_DIR" \
    --output "$RUN_OUTPUT" \
    --scorecard-output "$SCORECARD_OUTPUT" \
    --min-accuracy "$MIN_ACCURACY" \
    --min-precision "$MIN_PRECISION" \
    --min-recall "$MIN_RECALL" \
    --min-f1 "$MIN_F1" \
    --max-fpr "$MAX_FPR" \
    --save-golden \
    --json 2>/dev/null; then
    RESULT="PASSED"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    RESULT="FAILED"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    OVERALL_PASSED=0
  fi

  RUN_FILES+=("$RUN_OUTPUT")

  if [[ "$TRACK_HISTORY" -eq 1 && -f "$RUN_OUTPUT" ]]; then
    HISTORY_PATH="$HISTORY_DIR/history_${SUITE_SLUG}.json"
    echo "  Appending to history: $HISTORY_PATH"
    cargo run -p baloncore -- benchmark-history \
      --domain "$SUITE_SLUG" \
      --history-path "$HISTORY_PATH" \
      --append-run "$RUN_OUTPUT" \
      --json 2>/dev/null || true
  fi

  SUMMARY_LINES+=("${SUITE_SLUG}: ${RESULT}")
  echo ""
done

if [[ "$CHECK_DRIFT" -eq 1 ]]; then
  echo "== Drift Detection =="
  for SUITE_SLUG in $SUITES; do
    HISTORY_PATH="$HISTORY_DIR/history_${SUITE_SLUG}.json"
    RUN_OUTPUT="$HISTORY_DIR/run_${SUITE_SLUG}.json"
    if [[ -f "$HISTORY_PATH" && -f "$RUN_OUTPUT" ]]; then
      echo "--- Drift: ${SUITE_SLUG} ---"
      cargo run -p baloncore -- drift-report \
        --history-path "$HISTORY_PATH" \
        --current-run "$RUN_OUTPUT" \
        --drift-threshold "$DRIFT_THRESHOLD" \
        --json 2>/dev/null || echo "  Drift detected for ${SUITE_SLUG}"
    fi
  done
  echo ""
fi

if [[ "${#RUN_FILES[@]}" -gt 1 ]]; then
  echo "== Cross-Domain Correlation =="
  cargo run -p baloncore -- cross-domain \
    --runs "${RUN_FILES[@]}" \
    --json 2>/dev/null || true
  echo ""

  echo "== Leaderboard =="
  LEADERBOARD_JSON="$HISTORY_DIR/leaderboard.json"
  LEADERBOARD_MD="$HISTORY_DIR/leaderboard.md"
  cargo run -p baloncore -- leaderboard \
    --runs "${RUN_FILES[@]}" \
    --output "$LEADERBOARD_JSON" \
    --markdown-output "$LEADERBOARD_MD" 2>/dev/null || true
  echo ""
fi

if [[ "$CHECK_DETERMINISM" -eq 1 ]]; then
  echo "== Determinism Check =="
  for SUITE_SLUG in $SUITES; do
    case "$SUITE_SLUG" in
      web_api) SUITE_FLAG="--suite baloncore-web-api-v1" ;;
      cloud_iam) SUITE_FLAG="--suite baloncore-cloud-iam-v1" ;;
      web3) SUITE_FLAG="--suite baloncore-web3-v1" ;;
      evidence) SUITE_FLAG="--suite baloncore-evidence-v1" ;;
      *) continue ;;
    esac
    echo "--- Determinism: ${SUITE_SLUG} (k=${DETERMINISM_K}) ---"
    cargo run -p baloncore -- benchmark-determinism \
      $SUITE_FLAG \
      --k "$DETERMINISM_K" \
      --output "$HISTORY_DIR/determinism_${SUITE_SLUG}.json" 2>/dev/null || echo "  Determinism check failed for ${SUITE_SLUG}"
  done
  echo ""
fi

echo "== Benchmark Summary =="
for line in "${SUMMARY_LINES[@]}"; do
  echo "  $line"
done
echo ""
echo "Passed: ${PASS_COUNT}, Failed: ${FAIL_COUNT}"

if [[ "$OVERALL_PASSED" -eq 1 ]]; then
  echo "Overall: ALL SUITES PASSED"
else
  echo "Overall: SOME SUITES FAILED" >&2
fi

if [[ "$FAIL_ON_REGRESSION" -eq 1 && "$OVERALL_PASSED" -eq 0 ]]; then
  echo "Benchmark regression check failed" >&2
  exit 1
fi