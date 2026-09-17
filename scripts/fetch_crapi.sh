#!/usr/bin/env bash
#
# fetch_crapi.sh — vendor the OWASP crAPI external benchmark target.
#
# crAPI is a multi-service (Docker Compose) intentionally-vulnerable API. The
# `bench-crapi` runner brings the stack up, drives crAPI's flagship BOLA (read
# another user's vehicle location by GUID) through the real BolaValidator,
# scores it against the hand-labelled ground truth, and tears the WHOLE stack
# down. The seed users + vehicle GUIDs are deterministic (baked into the
# identity service), so the scan is reproducible.
#
# This requires Docker + Compose and a multi-image pull (heavy) — a NEEDS-HUMAN
# step. After it, `bench-crapi` runs the pinned stack locally.
#
# License: crAPI is Apache-2.0 (verified against the repo LICENSE.md at the
# pinned commit below — SPDX: Apache-2.0). We clone the source (compose files +
# provenance) and run the upstream-published images pinned to a VERSION tag.
#
# Usage:
#   scripts/fetch_crapi.sh
set -euo pipefail

# --- pinned provenance (keep in sync with benchmarks/cases/crapi-bola-vehicle/case.toml) ---
CRAPI_REPO="https://github.com/OWASP/crAPI.git"
# Pinned to git tag v1.1.6-rc8 so the vendored source matches the published
# image tag below (no `1.1.5`/`1.1.6` images are published; rc8 is the latest
# concrete tag). Apache-2.0.
CRAPI_COMMIT="d1cbf263a310ea4ed342e44a21a3ea32431e8ea6"   # tag v1.1.6-rc8
CRAPI_SPDX="Apache-2.0"
CRAPI_VERSION="1.1.6-rc8"   # image tag to pin instead of :latest

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRAPI_DIR="${CRAPI_DIR:-${ROOT_DIR}/.baloncore/corpus/crapi}"
CHECKOUT_DIR="${CRAPI_DIR}/crAPI"
COMPOSE_DIR="${CHECKOUT_DIR}/deploy/docker"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found. crAPI runs as a Docker Compose stack." >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: the Docker daemon is not running. Start Docker Desktop and re-run." >&2
  exit 2
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: 'docker compose' (v2) is required." >&2
  exit 2
fi

echo "[fetch_crapi] repo:    $CRAPI_REPO @ $CRAPI_COMMIT (SPDX: $CRAPI_SPDX)"
echo "[fetch_crapi] version: pinning images to crapi/*:${CRAPI_VERSION}"

mkdir -p "$CRAPI_DIR"

# --- clone source at the pinned commit ---
if [ ! -d "$CHECKOUT_DIR/.git" ]; then
  git clone "$CRAPI_REPO" "$CHECKOUT_DIR"
fi
git -C "$CHECKOUT_DIR" fetch --depth 1 origin "$CRAPI_COMMIT" 2>/dev/null || git -C "$CHECKOUT_DIR" fetch origin
git -C "$CHECKOUT_DIR" checkout -q "$CRAPI_COMMIT"

# --- re-verify the license ---
LICENSE_FILE="$CHECKOUT_DIR/LICENSE.md"
[ -f "$LICENSE_FILE" ] || LICENSE_FILE="$CHECKOUT_DIR/LICENSE"
if ! grep -qi "Apache License" "$LICENSE_FILE"; then
  echo "ERROR: $LICENSE_FILE is no longer an Apache License; case.toml says Apache-2.0." >&2
  exit 3
fi
echo "[fetch_crapi] license: LICENSE header confirms Apache-2.0"

# --- pin VERSION in the vendored .env so compose uses the tag, not :latest ---
ENV_FILE="${COMPOSE_DIR}/.env"
if [ -f "$ENV_FILE" ]; then
  if grep -q '^VERSION=' "$ENV_FILE"; then
    sed -i.bak "s/^VERSION=.*/VERSION=${CRAPI_VERSION}/" "$ENV_FILE" && rm -f "${ENV_FILE}.bak"
  else
    echo "VERSION=${CRAPI_VERSION}" >> "$ENV_FILE"
  fi
fi

# --- pull the images ---
echo "[fetch_crapi] pulling images (this is large; Java/Go/Python service images)…"
docker compose --project-directory "$COMPOSE_DIR" \
  -f "${COMPOSE_DIR}/docker-compose.yml" \
  pull

echo "[fetch_crapi] DONE. Now run:  cargo run -p baloncore -- bench-crapi"
