#!/usr/bin/env bash
#
# fetch_terragoat.sh — vendor the bridgecrewio/TerraGoat external benchmark target.
#
# TerraGoat is a STATIC Terraform (HCL) corpus of intentionally-misconfigured
# cloud resources. Unlike the HTTP targets (VAmPI/DVGA/crAPI) there is NO server,
# no Docker, no daemon — `bench-terragoat` parses the vendored `.tf` files
# OFFLINE into an IAM graph and runs the same `analyze-cloud-iam` detection
# (public exposure, over-privileged IAM) the product ships.
#
# License: TerraGoat is Apache-2.0 (verified against the repo LICENSE file at the
# pinned commit below — SPDX: Apache-2.0).
#
# Usage:
#   scripts/fetch_terragoat.sh
set -euo pipefail

# --- pinned provenance (keep in sync with benchmarks/cases/terragoat-iam/case.toml) ---
TERRAGOAT_REPO="https://github.com/bridgecrewio/terragoat.git"
TERRAGOAT_COMMIT="729f8da62c6a85ce4af5ad3d123de97776d954c4"   # 2023-04-27, Apache-2.0
TERRAGOAT_SPDX="Apache-2.0"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TERRAGOAT_DIR="${TERRAGOAT_DIR:-${ROOT_DIR}/.baloncore/corpus/terragoat}"
CHECKOUT_DIR="${TERRAGOAT_DIR}/terragoat"

echo "[fetch_terragoat] repo: $TERRAGOAT_REPO @ $TERRAGOAT_COMMIT (SPDX: $TERRAGOAT_SPDX)"
echo "[fetch_terragoat] dest: $CHECKOUT_DIR"

mkdir -p "$TERRAGOAT_DIR"

# --- clone + pin (idempotent) ---
if [ ! -d "$CHECKOUT_DIR/.git" ]; then
  git clone "$TERRAGOAT_REPO" "$CHECKOUT_DIR"
fi
git -C "$CHECKOUT_DIR" fetch --depth 1 origin "$TERRAGOAT_COMMIT" 2>/dev/null || git -C "$CHECKOUT_DIR" fetch origin
git -C "$CHECKOUT_DIR" checkout -q "$TERRAGOAT_COMMIT"

# --- verify the license is still Apache-2.0 ---
LICENSE_FILE="$CHECKOUT_DIR/LICENSE"
[ -f "$LICENSE_FILE" ] || LICENSE_FILE="$CHECKOUT_DIR/LICENSE.md"
if ! grep -qi "Apache License" "$LICENSE_FILE"; then
  echo "ERROR: $LICENSE_FILE is no longer an Apache License; case.toml says Apache-2.0." >&2
  exit 3
fi
echo "[fetch_terragoat] license: LICENSE header confirms Apache-2.0"
echo "[fetch_terragoat] aws .tf files:"
ls "$CHECKOUT_DIR/terraform/aws/"*.tf | sed 's/^/  /'

echo "[fetch_terragoat] DONE. Now run:  cargo run -p baloncore -- bench-terragoat"
