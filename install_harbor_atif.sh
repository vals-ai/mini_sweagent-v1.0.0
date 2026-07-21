#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HARBOR_REF="17bc7141ccb681e354e700fdf1dd90ee7c9856e3"
HARBOR_ATIF_VENV="${HARBOR_ATIF_VENV:-$SCRIPT_DIR/.harbor-atif-venv}"

uv venv --python 3.12 --seed "$HARBOR_ATIF_VENV"
uv pip install --python "$HARBOR_ATIF_VENV/bin/python"   "harbor @ git+https://github.com/harbor-framework/harbor.git@$HARBOR_REF"

"$HARBOR_ATIF_VENV/bin/python" - <<'PY'
from harbor.agents.installed.mini_swe_agent import convert_mini_swe_agent_to_atif

assert callable(convert_mini_swe_agent_to_atif)
PY

