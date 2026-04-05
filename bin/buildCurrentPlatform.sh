#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

uv run --with pyinstaller pyinstaller --onefile --name technitium-api-proxy src/technitium_api_proxy.py

platform_tag="$(python3 - <<'PY'
import platform
system = platform.system().lower()
arch = platform.machine().lower()
print(f"{system}-{arch}")
PY
)"

mkdir -p dist
cp dist/technitium-api-proxy "dist/technitium-api-proxy.${platform_tag}"
echo "Built binary available at dist/technitium-api-proxy and dist/technitium-api-proxy.${platform_tag}"
