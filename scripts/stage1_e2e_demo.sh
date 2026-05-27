#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DEMO_PORT="${DEMO_PORT:-31337}"
BASE_URL="${BASE_URL:-http://127.0.0.1:${DEMO_PORT}}"
OPENAPI_URL="${OPENAPI_URL:-$BASE_URL/openapi.json}"
CONFIG_PATH="${CONFIG_PATH:-baloncore.toml}"
OWNER_PROFILE="${OWNER_PROFILE:-user_b}"
SIGNER_NAME="${SIGNER_NAME:-stage1-e2e-signer}"
KEY_PATH="${KEY_PATH:-.baloncore/keys/signing_key.json}"
TRUST_STORE_PATH="${TRUST_STORE_PATH:-.baloncore/keys/trusted_signers.json}"
RUN_DIR="${RUN_DIR:-.baloncore/runs/stage1-e2e-$(date +%s)}"
LAB_LOG="${LAB_LOG:-.baloncore/runs/stage1-e2e-lab.log}"
SUMMARY_JSON_NAME="${SUMMARY_JSON_NAME:-stage1_e2e_summary.json}"
LAB_PID=""
STARTED_LAB=0
JSON_OUTPUT=0
FAIL_ON_REGRESSION="${FAIL_ON_REGRESSION:-0}"

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
    --help|-h)
      cat <<'EOF'
Usage: ./scripts/stage1_e2e_demo.sh [--json] [--fail-on-regression]

Flags:
  --json                Print a machine-readable summary JSON at the end.
  --fail-on-regression  Exit nonzero if regression verdict is StillFailing.

Environment overrides:
  BASE_URL, OPENAPI_URL, CONFIG_PATH, OWNER_PROFILE, SIGNER_NAME,
  KEY_PATH, TRUST_STORE_PATH, RUN_DIR, LAB_LOG, SUMMARY_JSON_NAME,
  FAIL_ON_REGRESSION
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
require_command node
require_command curl
require_command rg

cleanup() {
  if [[ "$STARTED_LAB" -eq 1 && -n "$LAB_PID" ]]; then
    if kill -0 "$LAB_PID" >/dev/null 2>&1; then
      kill "$LAB_PID" >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT

wait_for_health() {
  local retries=30
  local delay=1
  local health_url="$BASE_URL/health"
  for _ in $(seq 1 "$retries"); do
    if curl --silent --show-error --fail "$health_url" >/dev/null 2>&1; then
      if curl --silent "$health_url" | rg -q '"service"\s*:\s*"baloncore-vulnerable-api"'; then
        return 0
      fi
    fi
    if [[ "$STARTED_LAB" -eq 1 && -n "$LAB_PID" ]]; then
      if ! kill -0 "$LAB_PID" >/dev/null 2>&1; then
        echo "lab process exited before health check became ready" >&2
        echo "lab log: $LAB_LOG" >&2
        if [[ -f "$LAB_LOG" ]]; then
          tail -n 40 "$LAB_LOG" >&2 || true
        fi
        exit 1
      fi
    fi
    sleep "$delay"
  done
  echo "lab health check failed at $health_url" >&2
  echo "lab log: $LAB_LOG" >&2
  if [[ -f "$LAB_LOG" ]]; then
    tail -n 40 "$LAB_LOG" >&2 || true
  fi
  exit 1
}

start_lab_if_needed() {
  if curl --silent --show-error --fail "$BASE_URL/health" >/dev/null 2>&1; then
    if curl --silent "$BASE_URL/health" | rg -q '"service"\s*:\s*"baloncore-vulnerable-api"'; then
      echo "lab already running at $BASE_URL"
      return
    fi
    echo "health endpoint exists at $BASE_URL but is not the BALONCORE lab service" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$LAB_LOG")"
  PORT="$(echo "$BASE_URL" | sed -E 's#.*:([0-9]+)$#\1#')" node labs/vulnerable-api/server.js >"$LAB_LOG" 2>&1 &
  LAB_PID="$!"
  STARTED_LAB=1
  wait_for_health
  echo "started local lab (pid=$LAB_PID)"
}

echo "== BALONCORE Stage 1 End-to-End Demo =="
echo "run dir: $RUN_DIR"
echo "base url: $BASE_URL"
echo "openapi: $OPENAPI_URL"
echo "config: $CONFIG_PATH"
echo "owner profile: $OWNER_PROFILE"

start_lab_if_needed

if [[ ! -f "$KEY_PATH" ]]; then
  cargo run -p baloncore -- init-signing-key --key "$KEY_PATH" --signer "$SIGNER_NAME"
fi

cargo run -p baloncore -- scan-openapi-bola \
  --config "$CONFIG_PATH" \
  --base-url "$BASE_URL" \
  --openapi-url "$OPENAPI_URL" \
  --owner-profile "$OWNER_PROFILE" \
  --out-dir "$RUN_DIR"

REMEDIATION_PATH="$(find "$RUN_DIR" -type f -name remediation.json | sort | head -n 1)"
if [[ -z "$REMEDIATION_PATH" ]]; then
  echo "no remediation.json found under $RUN_DIR; expected at least one verified unsuppressed finding" >&2
  exit 1
fi

EVIDENCE_DIR="$(dirname "$REMEDIATION_PATH")"
SIGNATURE_PATH="$EVIDENCE_DIR/evidence_signature.json"
MANIFEST_PATH="$EVIDENCE_DIR/evidence_manifest.json"
REGRESSION_RESULT_JSON="$EVIDENCE_DIR/regression_result.json"
SUMMARY_JSON_PATH="$RUN_DIR/$SUMMARY_JSON_NAME"

cargo run -p baloncore -- run-regression "$REMEDIATION_PATH"
cargo run -p baloncore -- seal-evidence "$EVIDENCE_DIR" --sign --key "$KEY_PATH"
cargo run -p baloncore -- trust-evidence-signer "$SIGNATURE_PATH" --trust-store "$TRUST_STORE_PATH"
cargo run -p baloncore -- verify-evidence "$MANIFEST_PATH" --require-signature --trusted-only --trust-store "$TRUST_STORE_PATH"
cargo run -p baloncore -- verify-evidence-run "$RUN_DIR" --trusted-only --trust-store "$TRUST_STORE_PATH" --ci

REGRESSION_VERDICT="unknown"
if [[ -f "$REGRESSION_RESULT_JSON" ]]; then
  if rg -q '"verdict"\s*:\s*"StillFailing"' "$REGRESSION_RESULT_JSON"; then
    REGRESSION_VERDICT="StillFailing"
  elif rg -q '"verdict"\s*:\s*"Fixed"' "$REGRESSION_RESULT_JSON"; then
    REGRESSION_VERDICT="Fixed"
  fi
fi

cat >"$SUMMARY_JSON_PATH" <<EOF
{
  "run_dir": "$RUN_DIR",
  "base_url": "$BASE_URL",
  "openapi_url": "$OPENAPI_URL",
  "config_path": "$CONFIG_PATH",
  "owner_profile": "$OWNER_PROFILE",
  "lab_started_by_script": $([[ "$STARTED_LAB" -eq 1 ]] && echo "true" || echo "false"),
  "remediation_path": "$REMEDIATION_PATH",
  "evidence_dir": "$EVIDENCE_DIR",
  "regression_verdict": "$REGRESSION_VERDICT",
  "fail_on_regression": $([[ "$FAIL_ON_REGRESSION" -eq 1 ]] && echo "true" || echo "false"),
  "reports": {
    "run_report": "$RUN_DIR/run_report.md",
    "coverage_report": "$RUN_DIR/coverage_report.md",
    "regression_report": "$EVIDENCE_DIR/regression_result.md",
    "evidence_manifest": "$MANIFEST_PATH",
    "evidence_signature": "$SIGNATURE_PATH",
    "evidence_run_verification": "$RUN_DIR/evidence_run_verification.json"
  }
}
EOF

if [[ "$JSON_OUTPUT" -eq 1 ]]; then
  cat "$SUMMARY_JSON_PATH"
else
  echo
  echo "== Stage 1 Demo Complete =="
  echo "run artifacts: $RUN_DIR"
  echo "finding folder: $EVIDENCE_DIR"
  echo "executive report: $RUN_DIR/run_report.md"
  echo "coverage report: $RUN_DIR/coverage_report.md"
  echo "regression result: $EVIDENCE_DIR/regression_result.md"
  echo "evidence manifest: $MANIFEST_PATH"
  echo "evidence signature: $SIGNATURE_PATH"
  echo "evidence run verification: $RUN_DIR/evidence_run_verification.json"
  echo "summary json: $SUMMARY_JSON_PATH"
fi

if [[ "$FAIL_ON_REGRESSION" -eq 1 && "$REGRESSION_VERDICT" == "StillFailing" ]]; then
  echo "regression verdict is StillFailing and --fail-on-regression is enabled" >&2
  exit 1
fi
