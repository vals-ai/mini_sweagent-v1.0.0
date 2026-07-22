#!/bin/bash
set -o pipefail

problem_statement_path="${1:?problem_statement_path is required}"
task_id="${2:?task_id is required}"
model="${3:?model is required}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
log_dir="${LOG_DIR:-/logs/mini_sweagent-v1.0.0}"
repo="${REPO_ROOT:-$PWD}"
mini_runner="${MINI_RUNNER:-mini-sweagent-run-task}"
model_patch_python="$SCRIPT_DIR/.venv/bin/python"
model_patch_helper="$SCRIPT_DIR/src/minisweagent/utils/model_patch.py"
harbor_python="$SCRIPT_DIR/.harbor-atif-venv/bin/python"
harbor_ready="$SCRIPT_DIR/.harbor-atif-ready"
atif_helper="$SCRIPT_DIR/src/minisweagent/utils/atif.py"
model_patch_base="$log_dir/model_patch_base"
model_patch_dir="$log_dir/artifacts"
mkdir -p "$log_dir"
status=1

export_optional_artifacts() {
  if [[ -x "$model_patch_python" && -f "$model_patch_helper" && -f "$model_patch_base" ]]; then
    "$model_patch_python" "$model_patch_helper" export "$repo" "$model_patch_dir" \
      "$model_patch_base" --native-source "$log_dir/trajectory.json" || \
      echo "[agent-wrapper] Model Patch export failed" >&2
  else
    echo "[agent-wrapper] Model Patch export unavailable" >&2
  fi
  if [[ -f "$harbor_ready" && -x "$harbor_python" && -f "$atif_helper" ]] && \
    "$harbor_python" -c \
      'from harbor.agents.installed.mini_swe_agent import convert_mini_swe_agent_to_atif' \
      >/dev/null 2>&1; then
    "$harbor_python" "$atif_helper" \
      "$log_dir/trajectory.json" "$log_dir/atif/trajectory.json" "$task_id" || \
      echo "[agent-wrapper] Harbor ATIF export failed" >&2
  else
    echo "[agent-wrapper] Harbor ATIF export unavailable" >&2
    return
  fi
  if [[ -x "$model_patch_python" && -f "$model_patch_helper" ]]; then
    "$model_patch_python" "$model_patch_helper" attach \
      "$log_dir/atif/trajectory.json" "$model_patch_dir" || \
      echo "[agent-wrapper] Model Patch reference failed" >&2
  fi
}

if [[ -x "$model_patch_python" && -f "$model_patch_helper" ]]; then
  "$model_patch_python" "$model_patch_helper" capture \
    "$repo" "$model_patch_base" "$model_patch_dir" || \
    echo "[agent-wrapper] Model Patch base capture failed" >&2
else
  echo "[agent-wrapper] Model Patch base capture unavailable" >&2
fi

trap export_optional_artifacts EXIT
"$mini_runner" "$problem_statement_path" --config=swebench.yaml \
  --environment-class=local --config="model.model_name=$model" \
  --output="$log_dir/trajectory.json" --agent-class=default --exit-immediately --yolo
status=$?
exit "$status"
