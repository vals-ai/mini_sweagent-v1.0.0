import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from uuid import uuid4

MAX_PATCH_BYTES = 10 * 1024 * 1024
MAX_NATIVE_SOURCE_BYTES = 2 * MAX_PATCH_BYTES
MAX_UNTRACKED_LIST_BYTES = 2 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
BASE_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
REDACTED_VALUES = frozenset(
    {"[REDACTED]", "<REDACTED>", "{REDACTED}", "REDACTED", "***", "XXXXX"}
)
CREDENTIAL_ASSIGNMENT_PATTERN = re.compile(
    r"(?ix)(?:[\"']?[a-z0-9_.-]*(?:api[_-]?key|secret(?:[_-]?(?:access[_-]?key|key))?|"
    r"access[_-]?token|token|password|passwd|private[_-]?key|credential)"
    r"[a-z0-9_.-]*[\"']?)\s*[:=]\s*"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
AUTHORIZATION_PATTERN = re.compile(
    r"(?im)\bauthorization\s*:\s*(?:(?:basic|bearer)\s+)?(?P<value>[^\s,;]+)"
)
URL_CREDENTIAL_PATTERN = re.compile(
    r"(?i)[a-z][a-z0-9+.-]*://[^\s/:@]+:(?P<value>[^\s/@]+)@"
)
SECRET_PATTERNS = (
    re.compile(r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(?:github_pat_|gh[pousr]_|xox[baprs]-|sk-)[a-z0-9_-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
)


def _run(repo: Path, *args: str, env: dict[str, str] | None = None) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args],
        stderr=subprocess.DEVNULL,
        env=env,
    )


def _remove_output(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_bytes(content)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def capture_base(repo: Path, base_file: Path, output_dir: Path) -> bool:
    """Capture the exact repository base and remove stale generated output."""
    base_file.unlink(missing_ok=True)
    _remove_output(output_dir)
    try:
        base = _run(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError):
        return False
    if BASE_PATTERN.fullmatch(base) is None:
        return False
    _atomic_write(base_file, f"{base}\n".encode())
    return True


def _stream_command(
    command: list[str],
    *,
    cwd: Path,
    destination,
    current_size: int,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> int:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert process.stdout is not None
    try:
        total = current_size
        while chunk := process.stdout.read(CHUNK_BYTES):
            total += len(chunk)
            if total > MAX_PATCH_BYTES:
                process.kill()
                process.wait()
                raise ValueError("model patch exceeds the 10 MiB streaming limit")
            destination.write(chunk)
        returncode = process.wait()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    if returncode not in allowed_returncodes:
        raise subprocess.CalledProcessError(returncode, command)
    return total


def _bounded_command_bytes(command: list[str], cwd: Path, limit: int) -> bytes:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert process.stdout is not None
    output = bytearray()
    try:
        while chunk := process.stdout.read(CHUNK_BYTES):
            output.extend(chunk)
            if len(output) > limit:
                process.kill()
                process.wait()
                raise ValueError("Git path listing exceeds the bounded limit")
        returncode = process.wait()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    if returncode != 0:
        raise subprocess.CalledProcessError(returncode, command)
    return bytes(output)


def _safe_untracked_paths(repo: Path) -> list[str]:
    raw = _bounded_command_bytes(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        repo,
        MAX_UNTRACKED_LIST_BYTES,
    )
    paths = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        try:
            relative = encoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("untracked path is not valid UTF-8") from exc
        _validate_relative_path(relative)
        candidate = repo / relative
        mode = candidate.lstat().st_mode
        if stat.S_ISREG(mode):
            paths.append(relative)
    return sorted(paths)


def _native_patch(source: Path | None) -> bytes | None:
    if source is None or not source.is_file():
        return None
    if source.stat().st_size > MAX_NATIVE_SOURCE_BYTES:
        raise ValueError("native patch source is too large to inspect safely")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("native patch source is not bounded UTF-8 JSON") from exc
    candidates = [value]
    if isinstance(value, dict) and len(value) == 1:
        candidates.extend(value.values())
    for candidate in candidates:
        if isinstance(candidate, dict) and isinstance(candidate.get("model_patch"), str):
            patch = candidate["model_patch"].encode()
            if len(patch) > MAX_PATCH_BYTES:
                raise ValueError("model patch exceeds the 10 MiB streaming limit")
            return patch
    return None


def _validate_relative_path(relative: str) -> None:
    path = PurePosixPath(relative)
    if (
        not relative
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in relative
        or any(ord(character) < 32 for character in relative)
    ):
        raise ValueError(f"unsafe diff path: {relative!r}")


def _header_path(line: str, prefix: str, expected_side: str) -> str | None:
    if not line.startswith(prefix):
        raise ValueError("malformed unified diff header")
    field = line[len(prefix) :].split("\t", 1)[0]
    if field == "/dev/null":
        return None
    if field.startswith('"') or not field.startswith(f"{expected_side}/"):
        raise ValueError("unsafe or uncertain diff header path")
    relative = field[2:]
    _validate_relative_path(relative)
    return relative


def _is_redacted(value: str) -> bool:
    normalized = value.strip().strip("\"'").upper()
    return normalized in REDACTED_VALUES


def _contains_unredacted_secret(text: str) -> bool:
    if any(pattern.search(text) for pattern in SECRET_PATTERNS):
        return True
    for pattern in (
        CREDENTIAL_ASSIGNMENT_PATTERN,
        AUTHORIZATION_PATTERN,
        URL_CREDENTIAL_PATTERN,
    ):
        for match in pattern.finditer(text):
            if not _is_redacted(match.group("value")):
                return True
    return False


def _validate_and_measure(patch: bytes) -> tuple[int, int, int]:
    if b"\0" in patch or b"GIT binary patch" in patch or b"Binary files " in patch:
        raise ValueError("binary model patch is not allowed")
    try:
        text = patch.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("model patch is not valid UTF-8") from exc
    if _contains_unredacted_secret(text):
        raise ValueError("potential unredacted credential or secret in model patch")
    starts = [match.start() for match in re.finditer(r"(?m)^diff --git ", text)]
    if not starts or starts[0] != 0:
        raise ValueError("model patch must contain only complete Git diffs")
    starts.append(len(text))
    additions = 0
    deletions = 0
    for index in range(len(starts) - 1):
        chunk = text[starts[index] : starts[index + 1]]
        lines = chunk.splitlines()
        old_headers = [line for line in lines if line.startswith("--- ")]
        new_headers = [line for line in lines if line.startswith("+++ ")]
        if len(old_headers) != 1 or len(new_headers) != 1:
            raise ValueError("each Git diff must contain one old and one new path header")
        old_relative = _header_path(old_headers[0], "--- ", "a")
        new_relative = _header_path(new_headers[0], "+++ ", "b")
        relative = old_relative or new_relative
        if relative is None:
            raise ValueError("diff cannot have two null paths")
        expected_old = f"a/{old_relative or relative}"
        expected_new = f"b/{new_relative or relative}"
        if lines[0] != f"diff --git {expected_old} {expected_new}":
            raise ValueError("diff --git header does not match unified path headers")
        in_hunk = False
        for line in lines[1:]:
            if line.startswith("@@ "):
                in_hunk = True
            elif in_hunk and line.startswith("+"):
                additions += 1
            elif in_hunk and line.startswith("-"):
                deletions += 1
    return len(starts) - 1, additions, deletions


def _validate_base_and_application(repo: Path, base: str, patch_path: Path) -> None:
    if BASE_PATTERN.fullmatch(base) is None:
        raise ValueError("invalid base commit")
    resolved = _run(repo, "rev-parse", "--verify", f"{base}^{{commit}}").decode().strip()
    if resolved != base:
        raise ValueError("base commit does not resolve exactly")
    with tempfile.TemporaryDirectory(prefix="model-patch-index-") as temporary:
        index_path = Path(temporary) / "index"
        env = {**os.environ, "GIT_INDEX_FILE": str(index_path)}
        _run(repo, "read-tree", base, env=env)
        try:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "apply",
                    "--cached",
                    "--check",
                    "--whitespace=nowarn",
                    str(patch_path),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )
        except subprocess.CalledProcessError as exc:
            raise ValueError("model patch does not apply to the captured base commit") from exc


def _metadata(patch_path: Path, base: str) -> dict[str, str | int]:
    patch = patch_path.read_bytes()
    file_count, additions, deletions = _validate_and_measure(patch)
    return {
        "path": "artifacts/model.patch",
        "media_type": "text/x-diff",
        "sha256": hashlib.sha256(patch).hexdigest(),
        "base_commit": base,
        "file_count": file_count,
        "additions": additions,
        "deletions": deletions,
    }


def export_model_patch(
    repo: Path,
    output_dir: Path,
    base_file: Path,
    *,
    native_source: Path | None = None,
) -> bool:
    """Stream, validate, and atomically publish a Model Patch bundle."""
    _remove_output(output_dir)
    base = base_file.read_text(encoding="utf-8").strip()
    if BASE_PATTERN.fullmatch(base) is None:
        raise ValueError("invalid base commit")
    staging = output_dir.with_name(f".{output_dir.name}.{uuid4().hex}.tmp")
    staging.mkdir(parents=True)
    patch_path = staging / "model.patch"
    try:
        native_patch = _native_patch(native_source)
        if native_patch is not None:
            patch_path.write_bytes(native_patch)
        else:
            with patch_path.open("wb") as patch_file:
                size = _stream_command(
                    [
                        "git",
                        "diff",
                        "--no-ext-diff",
                        "--no-textconv",
                        "--no-renames",
                        "--full-index",
                        base,
                        "--",
                        ".",
                    ],
                    cwd=repo,
                    destination=patch_file,
                    current_size=0,
                )
                for relative in _safe_untracked_paths(repo):
                    size = _stream_command(
                        [
                            "git",
                            "diff",
                            "--no-index",
                            "--no-ext-diff",
                            "--no-textconv",
                            "--",
                            "/dev/null",
                            relative,
                        ],
                        cwd=repo,
                        destination=patch_file,
                        current_size=size,
                        allowed_returncodes=(0, 1),
                    )
        if patch_path.stat().st_size == 0:
            return False
        metadata = _metadata(patch_path, base)
        _validate_base_and_application(repo, base, patch_path)
        (staging / "model_patch.json").write_text(
            json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
        )
        staging.replace(output_dir)
        return True
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def attach_reference(trajectory_path: Path, output_dir: Path) -> bool:
    """Revalidate a published patch bundle and atomically attach its ATIF reference."""
    patch_path = output_dir / "model.patch"
    metadata_path = output_dir / "model_patch.json"
    if not patch_path.is_file() and not metadata_path.is_file():
        return False
    if not patch_path.is_file() or not metadata_path.is_file():
        raise ValueError("model patch bundle is incomplete")
    recorded = json.loads(metadata_path.read_text(encoding="utf-8"))
    base = recorded.get("base_commit")
    if not isinstance(base, str) or BASE_PATTERN.fullmatch(base) is None:
        raise ValueError("model patch metadata has an invalid base commit")
    expected = _metadata(patch_path, base)
    if recorded != expected:
        raise ValueError("model patch metadata checksum or stats mismatch")
    trajectory = json.loads(trajectory_path.read_text(encoding="utf-8"))
    extra = trajectory.setdefault("extra", {})
    if not isinstance(extra, dict):
        raise ValueError("ATIF extra must be an object")
    vals = extra.setdefault("vals", {})
    if not isinstance(vals, dict):
        raise ValueError("ATIF extra.vals must be an object")
    vals["model_patch"] = recorded
    _atomic_write(
        trajectory_path,
        (json.dumps(trajectory, indent=2) + "\n").encode(),
    )
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("repo", type=Path)
    capture.add_argument("base_file", type=Path)
    capture.add_argument("output_dir", type=Path)
    export = commands.add_parser("export")
    export.add_argument("repo", type=Path)
    export.add_argument("output_dir", type=Path)
    export.add_argument("base_file", type=Path)
    export.add_argument("--native-source", type=Path)
    attach = commands.add_parser("attach")
    attach.add_argument("trajectory", type=Path)
    attach.add_argument("output_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            return 0 if capture_base(args.repo, args.base_file, args.output_dir) else 1
        if args.command == "export":
            export_model_patch(
                args.repo,
                args.output_dir,
                args.base_file,
                native_source=args.native_source,
            )
            return 0
        attach_reference(args.trajectory, args.output_dir)
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"Model Patch unavailable: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
