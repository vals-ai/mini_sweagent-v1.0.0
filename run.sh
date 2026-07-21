#!/bin/bash
set -o pipefail

problem_statement_path="${1:?problem_statement_path is required}"
task_id="${2:?task_id is required}"
model="${3:?model is required}"
log_dir="/logs/mini_sweagent-v1.0.0"
repo="$PWD"
base_commit="$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)"
mkdir -p "$log_dir"
status=1

export_optional_artifacts() {
  if [[ -n "$base_commit" ]]; then
    python -m minisweagent.utils.model_patch "$repo" "$log_dir/artifacts/model.patch" \
      "$log_dir/model_patch.json" "$base_commit" || echo "[agent-wrapper] Model Patch export failed" >&2
  fi
  .harbor-atif-venv/bin/python -m minisweagent.utils.atif \
    "$log_dir/trajectory.json" "$log_dir/atif/trajectory.json" "$task_id" \
    --patch-metadata "$log_dir/model_patch.json" || echo "[agent-wrapper] Harbor ATIF export failed" >&2
}

trap export_optional_artifacts EXIT
mini-sweagent-run-task "$problem_statement_path" --config=swebench.yaml \
  --environment-class=local --config="model.model_name=$model" \
  --output="$log_dir/trajectory.json" --agent-class=default --exit-immediately --yolo
status=$?
exit "$status"
