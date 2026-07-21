import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[2] / "src/minisweagent/utils/model_patch.py"


def load_module():
    if not MODULE_PATH.exists():
        pytest.fail("model patch exporter is missing")
    spec = importlib.util.spec_from_file_location("model_patch", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", repo, *args], text=True).strip()


def test_exports_validated_text_patch(tmp_path: Path) -> None:
    module = load_module()
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")
    (repo / "file.txt").write_text("old\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "file.txt").write_text("new\n")
    patch = tmp_path / "artifacts/model.patch"
    metadata = tmp_path / "metadata.json"

    assert module.export_model_patch(repo, patch, metadata, base)
    assert json.loads(metadata.read_text())["base_commit"] == base
    assert json.loads(metadata.read_text())["path"] == "artifacts/model.patch"
    assert "diff --git" in patch.read_text()


def test_rejects_binary_patch(tmp_path: Path) -> None:
    module = load_module()
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")
    (repo / "file.bin").write_bytes(b"old\0")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "file.bin").write_bytes(b"new\0")

    with pytest.raises(ValueError, match="binary"):
        module.export_model_patch(repo, tmp_path / "model.patch", tmp_path / "metadata.json", base)
