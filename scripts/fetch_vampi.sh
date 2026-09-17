#!/usr/bin/env bash
#
# fetch_vampi.sh — vendor the VAmPI external benchmark target.
#
# VAmPI (erev0s/VAmPI) is a Flask "vulnerable API" with a global
# `vulnerable=1/0` switch. BALONCORE's `bench-vampi` runner boots BOTH a
# vulnerable and a secure instance of the SAME target and measures whether the
# BolaValidator fires on the vulnerable build (true positive) and stays silent
# on the secure build (the secure build is the decoy / negative set). That is
# the cleanest possible false-positive measurement: same endpoints, bug toggled
# off, must produce ZERO findings.
#
# This requires a NETWORK fetch (git clone) and a `pip install` of VAmPI's
# pinned, 2022-era requirements. It is therefore a NEEDS-HUMAN step: a stranger
# reproducing the benchmark runs THIS script once, then `bench-vampi` is fully
# offline/local from then on.
#
# License: VAmPI is MIT (verified against the repo LICENSE file at the pinned
# commit below — SPDX: MIT). MIT permits redistribution, but we vendor via this
# fetch script rather than copying the source into the BALONCORE tree so the
# pin and provenance stay explicit and the working copy lands under the
# gitignored .baloncore/ directory.
#
# Usage:
#   scripts/fetch_vampi.sh            # clone + venv + deps into .baloncore/corpus/vampi
#   VAMPI_DIR=/some/where scripts/fetch_vampi.sh
#
set -euo pipefail

# --- pinned provenance (keep in sync with benchmarks/cases/vampi-bola-books/case.toml) ---
VAMPI_REPO="https://github.com/erev0s/VAmPI.git"
VAMPI_COMMIT="f16052dce83f05847133ec98f01c5193a41de7d8"   # 2026-04-07, MIT
VAMPI_SPDX="MIT"

# --- destination (gitignored) ---
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VAMPI_DIR="${VAMPI_DIR:-${ROOT_DIR}/.baloncore/corpus/vampi}"
CHECKOUT_DIR="${VAMPI_DIR}/VAmPI"
VENV_DIR="${CHECKOUT_DIR}/.venv"

# --- pick a Python that satisfies VAmPI's 2022-era pins ---
# Flask 2.2.2 / connexion 2.14.2 / markupsafe 2.1.2 do NOT run on Python 3.14+.
PY=""
for cand in python3.12 python3.11 python3.10 python3.9; do
  if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
  echo "ERROR: need python3.9-3.12 for VAmPI's pinned deps; none found." >&2
  echo "       (python3.14 is too new for Flask 2.2.2 / connexion 2.14.2.)" >&2
  exit 2
fi

echo "[fetch_vampi] python:   $PY ($($PY --version 2>&1))"
echo "[fetch_vampi] repo:     $VAMPI_REPO @ $VAMPI_COMMIT (SPDX: $VAMPI_SPDX)"
echo "[fetch_vampi] dest:     $CHECKOUT_DIR"

mkdir -p "$VAMPI_DIR"

# --- clone + pin (idempotent) ---
if [ ! -d "$CHECKOUT_DIR/.git" ]; then
  git clone "$VAMPI_REPO" "$CHECKOUT_DIR"
fi
git -C "$CHECKOUT_DIR" fetch --depth 1 origin "$VAMPI_COMMIT" 2>/dev/null || git -C "$CHECKOUT_DIR" fetch origin
git -C "$CHECKOUT_DIR" checkout -q "$VAMPI_COMMIT"

# --- verify the license is still what we recorded ---
if ! grep -qi "MIT License" "$CHECKOUT_DIR/LICENSE"; then
  echo "ERROR: $CHECKOUT_DIR/LICENSE is no longer an MIT License header." >&2
  echo "       Re-verify the SPDX id before vendoring; case.toml says MIT." >&2
  exit 3
fi
echo "[fetch_vampi] license:  LICENSE header confirms MIT"

# --- venv + pinned deps ---
if [ ! -x "$VENV_DIR/bin/python" ]; then
  "$PY" -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1091
"$VENV_DIR/bin/pip" install --quiet --disable-pip-version-check -r "$CHECKOUT_DIR/requirements.txt"

echo "[fetch_vampi] deps installed into $VENV_DIR"
echo "[fetch_vampi] DONE. Now run:  cargo run -p baloncore -- bench-vampi"
