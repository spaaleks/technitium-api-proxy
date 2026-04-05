#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

IMAGE_NAME="technitium-api-proxy"
DEFAULT_PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
)

if [[ "$#" -gt 0 ]]; then
  PLATFORMS=("$@")
else
  PLATFORMS=("${DEFAULT_PLATFORMS[@]}")
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker command not found. Please install Docker." >&2
  exit 1
fi

mkdir -p dist

for TARGET_PLATFORM in "${PLATFORMS[@]}"; do
  OUTPUT_NAME="dist/${IMAGE_NAME}.${TARGET_PLATFORM//\//-}"
  echo "Building ${OUTPUT_NAME}..."
  docker run --rm \
    --platform="${TARGET_PLATFORM}" \
    -v "${PWD}":/src \
    -w /src \
    -e OUTPUT_PATH="${OUTPUT_NAME}" \
    python:3.12-slim \
    bash -lc '
      set -euo pipefail
      apt-get update && apt-get install -y binutils curl && rm -rf /var/lib/apt/lists/*
      curl -LsSf https://astral.sh/uv/install.sh | sh
      export PATH="$HOME/.local/bin:$PATH"
      uv run --with pyinstaller pyinstaller --onefile --name technitium-api-proxy src/technitium_api_proxy.py
      cp dist/technitium-api-proxy "/src/${OUTPUT_PATH}"
    '
  echo "Built ${OUTPUT_NAME}"
done
