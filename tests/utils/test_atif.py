import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

MODULE_PATH = Path(__file__).parents[2] / "src/minisweagent/utils/atif.py"
ROOT = Path(__file__).parents[2]


def load_atif_module():
    if not MODULE_PATH.exists():
        pytest.fail("mini-SWE Harbor ATIF exporter is missing")
    spec = importlib.util.spec_from_file_location("minisweagent_atif", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", repo, *args], text=True).strip()


class FakeTrajectory:
    def __init__(self, data: dict[str, Any]):
        self.data = data

    def to_json_dict(self) -> dict[str, Any]:
        return self.data


def test_export_atif_uses_harbor_converter_and_writes_atomically(tmp_path: Path) -> None:
    export_atif = load_atif_module().export_atif

    source = tmp_path / "native.json"
    destination = tmp_path / "atif" / "trajectory.json"
    native = {"trajectory_format": "mini-swe-agent-1.1", "messages": []}
    source.write_text(json.dumps(native))

    def convert(data: dict[str, Any], session_id: str) -> FakeTrajectory:
        assert data == native
        assert session_id == "session-123"
        return FakeTrajectory({"schema_version": "ATIF-v1.7", "session_id": session_id})

    export_atif(source, destination, "session-123", converter=convert)

    assert json.loads(destination.read_text()) == {
        "schema_version": "ATIF-v1.7",
        "session_id": "session-123",
    }
    assert list(destination.parent.iterdir()) == [destination]


def test_export_atif_failure_preserves_existing_file(tmp_path: Path) -> None:
    export_atif = load_atif_module().export_atif

    source = tmp_path / "native.json"
    destination = tmp_path / "atif" / "trajectory.json"
    source.write_text("{}")
    destination.parent.mkdir()
    destination.write_text('{"schema_version":"ATIF-v1.6"}')

    def fail(_data: dict[str, Any], _session_id: str) -> FakeTrajectory:
        raise ValueError("conversion failed")

    with pytest.raises(ValueError, match="conversion failed"):
        export_atif(source, destination, "session-123", converter=fail)

    assert json.loads(destination.read_text()) == {"schema_version": "ATIF-v1.6"}
    assert list(destination.parent.iterdir()) == [destination]


def test_main_passes_paths_and_session_id_to_exporter(tmp_path: Path) -> None:
    module = load_atif_module()
    source = tmp_path / "native.json"
    destination = tmp_path / "atif/trajectory.json"
    calls: list[tuple[Path, Path, str]] = []

    assert (
        module.main(
            [str(source), str(destination), "task-42"],
            exporter=lambda *args: calls.append(args),
        )
        == 0
    )
    assert calls == [(source, destination, "task-42")]


def test_contract_declares_optional_atif_and_model_patch() -> None:
    contract = (ROOT / "contract.yaml").read_text()
    runner = (ROOT / "run.sh").read_text()

    assert "source: /logs/mini_sweagent-v1.0.0/atif/trajectory.json\n    required: false" in contract
    assert "source: /logs/mini_sweagent-v1.0.0/artifacts/model.patch\n    required: false" in contract
    assert "Model Patch export failed" in runner
    assert "Harbor ATIF export failed" in runner


def test_harbor_install_failure_is_best_effort(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_uv = fake_bin / "uv"
    fake_uv.write_text("#!/bin/sh\nexit 73\n")
    fake_uv.chmod(0o755)
    venv = tmp_path / "harbor-venv"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "HARBOR_ATIF_VENV": str(venv),
        "HARBOR_ATIF_READY": str(tmp_path / "harbor-ready"),
    }

    result = subprocess.run(
        ["bash", str(ROOT / "install_harbor_atif.sh")],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0
    assert "unavailable" in result.stderr.lower()
    assert not (tmp_path / "harbor-ready").exists()


def test_standalone_bundle_uses_direct_helpers_and_readiness_gate(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    shutil.copytree(
        ROOT,
        bundle,
        ignore=shutil.ignore_patterns(".git", ".venv", ".harbor-atif-venv", "__pycache__"),
    )
    runner = (bundle / "run.sh").read_text()

    for helper in (
        bundle / "src/minisweagent/utils/model_patch.py",
        bundle / "src/minisweagent/utils/atif.py",
    ):
        result = subprocess.run(
            [sys.executable, str(helper), "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

    assert '"$SCRIPT_DIR/src/minisweagent/utils/model_patch.py"' in runner
    assert '"$SCRIPT_DIR/src/minisweagent/utils/atif.py"' in runner
    assert ".harbor-atif-ready" in runner
    assert "python -m minisweagent.utils" not in runner
    assert '"{problem_statement_path}" "{task_id}" "{model}"' in (bundle / "contract.yaml").read_text()


def test_wrapper_preserves_agent_status_when_optional_exports_are_unavailable(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    shutil.copytree(
        ROOT,
        bundle,
        ignore=shutil.ignore_patterns(".git", ".venv", ".harbor-atif-venv", "__pycache__"),
    )
    python = bundle / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    python.symlink_to(sys.executable)
    runner = tmp_path / "agent-runner"
    runner.write_text("#!/bin/sh\nexit 37\n")
    runner.chmod(0o755)
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")
    (repo / "answer.txt").write_text("base\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")

    result = subprocess.run(
        ["bash", str(bundle / "run.sh"), "problem with spaces", "task-1", "openai/test"],
        cwd=repo,
        env={
            **os.environ,
            "LOG_DIR": str(tmp_path / "logs"),
            "MINI_RUNNER": str(runner),
        },
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 37
    assert "Harbor ATIF export unavailable" in result.stderr
