#!/bin/bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HARBOR_REF="17bc7141ccb681e354e700fdf1dd90ee7c9856e3"
HARBOR_ATIF_VENV="${HARBOR_ATIF_VENV:-$SCRIPT_DIR/.harbor-atif-venv}"
HARBOR_ATIF_READY="${HARBOR_ATIF_READY:-$SCRIPT_DIR/.harbor-atif-ready}"

unlink "$HARBOR_ATIF_READY" 2>/dev/null || true

harbor_unavailable() {
  echo "[agent-setup] Optional Harbor ATIF conversion unavailable: $1" >&2
  exit 0
}

command -v uv >/dev/null 2>&1 || harbor_unavailable "uv is not installed"
uv venv --python 3.12 --seed "$HARBOR_ATIF_VENV" || \
  harbor_unavailable "could not create the isolated environment"
uv pip install --python "$HARBOR_ATIF_VENV/bin/python" \
  "harbor @ git+https://github.com/harbor-framework/harbor.git@$HARBOR_REF" || \
  harbor_unavailable "the pinned Harbor package could not be installed"

"$HARBOR_ATIF_VENV/bin/python" - <<'PY' || \
  harbor_unavailable "the pinned Mini SWE-agent converter could not be imported"
from harbor.agents.installed.mini_swe_agent import convert_mini_swe_agent_to_atif

assert callable(convert_mini_swe_agent_to_atif)
PY

printf '%s\n' "$HARBOR_REF" > "$HARBOR_ATIF_READY" || \
  harbor_unavailable "the readiness marker could not be written"
