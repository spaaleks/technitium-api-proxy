#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

source .venv/bin/activate
pip install --quiet .

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-31399}"

exec uvicorn proxy.main:app --host "$HOST" --port "$PORT"
