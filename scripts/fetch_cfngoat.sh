#!/usr/bin/env bash
#
# fetch_cfngoat.sh — vendor the bridgecrewio/Cfngoat external benchmark target.
#
# Cfngoat is a STATIC CloudFormation (YAML) corpus of intentionally-misconfigured
# cloud resources. Like TerraGoat it is analyzed OFFLINE (no server, no Docker,
# no network at analysis time): `bench-cfngoat` parses the vendored `.yaml`
# templates into an IAM graph and runs the same analyze-cloud-iam detection.
#
# ⚠️  LICENSE: the Cfngoat repo has NO license file (the GitHub API reports
#     "license: null"). It is therefore all-rights-reserved by default and we do
#     NOT redistribute it — this script FETCHES it into the gitignored
#     .baloncore/corpus/ directory at build time and the templates are never
#     committed to this repo. The BALONCORE negative-control template
#     (benchmarks/cases/cfngoat-iam/negative_controls.yaml) is authored by us and
#     is the only committed CloudFormation here.
#
# Usage:
#   scripts/fetch_cfngoat.sh
set -euo pipefail

# --- pinned provenance (keep in sync with benchmarks/cases/cfngoat-iam/case.toml) ---
CFNGOAT_REPO="https://github.com/bridgecrewio/cfngoat.git"
CFNGOAT_COMMIT="0c09b69cfc3dbc6cb3ef01883415c35c588ced48"   # 2022-01-12
CFNGOAT_SPDX="NOASSERTION (no LICENSE file in repo — all rights reserved)"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFNGOAT_DIR="${CFNGOAT_DIR:-${ROOT_DIR}/.baloncore/corpus/cfngoat}"
CHECKOUT_DIR="${CFNGOAT_DIR}/cfngoat"

echo "[fetch_cfngoat] repo:    $CFNGOAT_REPO @ $CFNGOAT_COMMIT"
echo "[fetch_cfngoat] license: $CFNGOAT_SPDX"
echo "[fetch_cfngoat] dest:    $CHECKOUT_DIR (gitignored; never committed)"

mkdir -p "$CFNGOAT_DIR"

# --- clone + pin (idempotent) ---
if [ ! -d "$CHECKOUT_DIR/.git" ]; then
  git clone "$CFNGOAT_REPO" "$CHECKOUT_DIR"
fi
git -C "$CHECKOUT_DIR" fetch --depth 1 origin "$CFNGOAT_COMMIT" 2>/dev/null || git -C "$CHECKOUT_DIR" fetch origin
git -C "$CHECKOUT_DIR" checkout -q "$CFNGOAT_COMMIT"

# --- honesty check: confirm there is still no license file (so the recorded
#     status stays accurate). If upstream ADDS a license later, surface it. ---
if ls "$CHECKOUT_DIR"/LICENSE* >/dev/null 2>&1; then
  echo "[fetch_cfngoat] NOTE: a LICENSE file now exists upstream — update case.toml's SPDX." >&2
else
  echo "[fetch_cfngoat] confirmed: still no LICENSE file (fetch-only, not redistributed)"
fi
echo "[fetch_cfngoat] templates:"
ls "$CHECKOUT_DIR"/*.yaml | sed 's/^/  /'

echo "[fetch_cfngoat] DONE. Now run:  cargo run -p baloncore -- bench-cfngoat"
