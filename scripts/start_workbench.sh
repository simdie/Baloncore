#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
cargo run -p baloncore-api -- --host 127.0.0.1 --port "${BALONCORE_API_PORT:-8788}"
