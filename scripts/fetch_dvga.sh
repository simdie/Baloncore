#!/usr/bin/env bash
#
# fetch_dvga.sh — vendor the DVGA external benchmark target.
#
# DVGA (dolevf/Damn-Vulnerable-GraphQL-Application) is a deliberately-vulnerable
# GraphQL app. BALONCORE's `bench-dvga` runner exercises the GraphQL BOLA
# validator against its JWT-identity authorization bypass: `get_identity`
# decodes the auth token with signature verification DISABLED
# (core/helpers.py:20-21), and `UserObject.resolve_password`
# (core/views.py:60-65) returns a user's real password whenever the request
# identity is "admin". So a non-admin principal forges an unsigned
# `{"identity":"admin"}` token and reads admin's secret — a cross-user object
# authorization bypass the validator can VERIFY.
#
# This requires Docker (image pull) — a NEEDS-HUMAN step. After it, `bench-dvga`
# runs the pinned image locally.
#
# License: DVGA is MIT (verified against the repo LICENSE.md at the pinned
# commit below — SPDX: MIT). We clone the source for provenance/audit and run
# the upstream-published Docker image pinned by digest.
#
# Usage:
#   scripts/fetch_dvga.sh
set -euo pipefail

# --- pinned provenance (keep in sync with benchmarks/cases/dvga-graphql-bola/case.toml) ---
DVGA_REPO="https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application.git"
DVGA_COMMIT="a961308c02d1fb462b192681c336b0739e432da7"   # 2025-05-24, MIT
DVGA_SPDX="MIT"
# Image digest validated for this benchmark (dolevf/dvga:latest at fetch time).
DVGA_IMAGE_DIGEST="sha256:040aa33c199d99f3380c9ff9a1ee5d725e9abca7b189c63a35a2a73bda79c957"
DVGA_IMAGE_TAG="dolevf/dvga:latest"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DVGA_DIR="${DVGA_DIR:-${ROOT_DIR}/.baloncore/corpus/dvga}"
CHECKOUT_DIR="${DVGA_DIR}/DVGA"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found. DVGA runs as a Docker image." >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: the Docker daemon is not running. Start Docker Desktop and re-run." >&2
  exit 2
fi

echo "[fetch_dvga] repo:  $DVGA_REPO @ $DVGA_COMMIT (SPDX: $DVGA_SPDX)"
echo "[fetch_dvga] image: ${DVGA_IMAGE_TAG} (${DVGA_IMAGE_DIGEST})"

mkdir -p "$DVGA_DIR"

# --- clone source at the pinned commit (provenance + license audit) ---
if [ ! -d "$CHECKOUT_DIR/.git" ]; then
  git clone "$DVGA_REPO" "$CHECKOUT_DIR"
fi
git -C "$CHECKOUT_DIR" fetch --depth 1 origin "$DVGA_COMMIT" 2>/dev/null || git -C "$CHECKOUT_DIR" fetch origin
git -C "$CHECKOUT_DIR" checkout -q "$DVGA_COMMIT"

# --- re-verify the license header still says MIT ---
LICENSE_FILE="$CHECKOUT_DIR/LICENSE.md"
[ -f "$LICENSE_FILE" ] || LICENSE_FILE="$CHECKOUT_DIR/LICENSE"
if ! grep -qi "MIT License" "$LICENSE_FILE"; then
  echo "ERROR: $LICENSE_FILE is no longer an MIT License header; case.toml says MIT." >&2
  exit 3
fi
echo "[fetch_dvga] license: LICENSE header confirms MIT"

# --- pull the image (prefer the validated digest; fall back to the tag) ---
if ! docker pull "dolevf/dvga@${DVGA_IMAGE_DIGEST}" 2>/dev/null; then
  echo "[fetch_dvga] digest pull unavailable; pulling ${DVGA_IMAGE_TAG} by tag" >&2
  docker pull "${DVGA_IMAGE_TAG}"
fi

echo "[fetch_dvga] DONE. Now run:  cargo run -p baloncore -- bench-dvga"
