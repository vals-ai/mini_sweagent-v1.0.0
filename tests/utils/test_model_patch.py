import hashlib
import importlib.util
import io
import json
import subprocess
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[2] / "src/minisweagent/utils/model_patch.py"


def load_module():
    spec = importlib.util.spec_from_file_location("model_patch", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", repo, *args], text=True).strip()


def test_bundle_helper_streams_and_validates_complete_patch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")
    (repo / "tracked.txt").write_text("old\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    base_file = tmp_path / "base"
    output_dir = tmp_path / "artifacts"
    assert module.capture_base(repo, base_file, output_dir)
    (repo / "tracked.txt").write_text("new\n")
    (repo / "new file.txt").write_text("created\n")

    assert module.export_model_patch(repo, output_dir, base_file)
    patch = output_dir / "model.patch"
    metadata = json.loads((output_dir / "model_patch.json").read_text())
    assert metadata["base_commit"] == base
    assert metadata["file_count"] == 2
    assert metadata["sha256"] == hashlib.sha256(patch.read_bytes()).hexdigest()
    assert "new file.txt" in patch.read_text()

    assert module.capture_base(repo, base_file, output_dir)
    monkeypatch.setattr(module, "MAX_PATCH_BYTES", 128)
    (repo / "tracked.txt").write_text("x" * 4096)
    with pytest.raises(ValueError, match="limit|large|10 MiB"):
        module.export_model_patch(repo, output_dir, base_file)
    assert not output_dir.exists()


@pytest.mark.parametrize(
    "unsafe",
    [
        b"safe\0binary",
        b'{"client_api_key":"sk-secret-value-123456"}\n',
        b"Authorization: Basic dXNlcjpwYXNzd29yZA==\n",
        b"https://user:password@example.com/private\n",
    ],
)
def test_bundle_helper_rejects_binary_and_credentials(tmp_path: Path, unsafe: bytes) -> None:
    module = load_module()
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")
    (repo / "value.txt").write_text("safe\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    base_file = tmp_path / "base"
    output_dir = tmp_path / "artifacts"
    assert module.capture_base(repo, base_file, output_dir)
    (repo / "value.txt").write_bytes(unsafe)

    with pytest.raises(ValueError, match="binary|secret|credential"):
        module.export_model_patch(repo, output_dir, base_file)


@pytest.mark.parametrize(
    "redacted",
    [
        "OPENAI_API_KEY=[REDACTED]",
        "Authorization: Bearer [REDACTED]",
        "https://user:<REDACTED>@example.com/private",
    ],
)
def test_bundle_helper_allows_explicit_redactions(tmp_path: Path, redacted: str) -> None:
    module = load_module()
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")
    (repo / "value.txt").write_text("safe\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    base_file = tmp_path / "base"
    output_dir = tmp_path / "artifacts"
    assert module.capture_base(repo, base_file, output_dir)
    (repo / "value.txt").write_text(redacted + "\n")

    assert module.export_model_patch(repo, output_dir, base_file)


def test_bundle_helper_rejects_short_secret_and_nonstandard_hash_width(tmp_path: Path) -> None:
    module = load_module()
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")
    (repo / "value.txt").write_text("safe\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    base_file = tmp_path / "base"
    output_dir = tmp_path / "artifacts"
    assert module.capture_base(repo, base_file, output_dir)
    (repo / "value.txt").write_text("api_key=short\n")
    with pytest.raises(ValueError, match="secret|credential"):
        module.export_model_patch(repo, output_dir, base_file)

    base_file.write_text("a" * 41)
    with pytest.raises(ValueError, match="invalid base"):
        module.export_model_patch(repo, output_dir, base_file)


def test_bundle_helper_discards_subprocess_stderr(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    stderr_values = []

    class CompletedProcess:
        def __init__(self, *args, stderr, **kwargs):
            stderr_values.append(stderr)
            self.stdout = io.BytesIO(b"")

        def wait(self):
            return 0

        def poll(self):
            return 0

        def kill(self):
            raise AssertionError("completed process should not be killed")

    monkeypatch.setattr(module.subprocess, "Popen", CompletedProcess)
    module._bounded_command_bytes(["git", "status"], tmp_path, 32)
    with (tmp_path / "patch").open("wb") as destination:
        module._stream_command(
            ["git", "diff"], cwd=tmp_path, destination=destination, current_size=0
        )

    assert stderr_values == [subprocess.DEVNULL, subprocess.DEVNULL]
