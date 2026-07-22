import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from uuid import uuid4

MAX_PATCH_BYTES = 10 * 1024 * 1024
MAX_PATH_LIST_BYTES = 2 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_TRAJECTORY_BYTES = 10 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
BASE_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
REDACTED_VALUES = frozenset({"[REDACTED]", "<REDACTED>", "{REDACTED}", "REDACTED", "***", "XXXXX"})
CREDENTIAL_ASSIGNMENT_PATTERN = re.compile(
    r"(?ix)(?:[\"']?[a-z0-9_.-]*(?:api[_-]?key|secret(?:[_-]?(?:access[_-]?key|key))?|"
    r"access[_-]?token|token|password|passwd|private[_-]?key|credential)"
    r"[a-z0-9_.-]*[\"']?)\s*[:=]\s*"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
AUTHORIZATION_PATTERN = re.compile(
    r"(?im)[\"']?(?:proxy[_-]?)?authorization[\"']?\s*[:=]\s*"
    r"(?:(?:basic|bearer)\s+)?"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
URL_CREDENTIAL_PATTERN = re.compile(r"(?i)[a-z][a-z0-9+.-]*://[^\s/:@]+:(?P<value>[^\s/@]+)@")
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


def _absolute_path(path: Path) -> Path:
    combined = path if path.is_absolute() else Path.cwd() / path
    parts: list[str] = []
    for part in combined.parts:
        if part in (os.sep, "."):
            continue
        if part == "..":
            if not parts:
                raise ValueError("unsafe destination path")
            parts.pop()
        else:
            parts.append(part)
    return Path(os.sep).joinpath(*parts)


def _open_parent(path: Path, *, create: bool) -> tuple[int, str]:
    """Open a destination parent without following any user-controlled symlink."""
    absolute = _absolute_path(path)
    if not absolute.name:
        raise ValueError("unsafe empty destination name")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(os.sep, flags)
    try:
        for part in absolute.parent.parts[1:]:
            try:
                child = os.open(part, flags, dir_fd=directory)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o755, dir_fd=directory)
                child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory, absolute.name
    except BaseException:
        os.close(directory)
        raise


def _entry_stat(directory: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _remove_entry(directory: int, name: str) -> None:
    entry = _entry_stat(directory, name)
    if entry is None:
        return
    if stat.S_ISDIR(entry.st_mode):
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        child = os.open(name, flags, dir_fd=directory)
        try:
            for child_name in os.listdir(child):
                _remove_entry(child, child_name)
        finally:
            os.close(child)
        os.rmdir(name, dir_fd=directory)
    else:
        os.unlink(name, dir_fd=directory)


def _remove_path(path: Path, *, reject_symlink: bool = False) -> None:
    try:
        directory, name = _open_parent(path, create=False)
    except FileNotFoundError:
        return
    try:
        entry = _entry_stat(directory, name)
        if entry is None:
            return
        if reject_symlink and stat.S_ISLNK(entry.st_mode):
            raise ValueError(f"refusing symlink destination: {path}")
        _remove_entry(directory, name)
        os.fsync(directory)
    finally:
        os.close(directory)


def _cleanup_path(path: Path) -> None:
    try:
        _remove_path(path)
    except (OSError, ValueError):
        pass


def _create_directory(path: Path) -> None:
    directory, name = _open_parent(path, create=True)
    try:
        os.mkdir(name, 0o700, dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(directory)


def _publish_directory(staging: Path, destination: Path) -> None:
    staging_absolute = _absolute_path(staging)
    destination_absolute = _absolute_path(destination)
    if staging_absolute.parent != destination_absolute.parent:
        raise ValueError("staging and artifact directories must share a parent")
    directory, staging_name = _open_parent(staging_absolute, create=False)
    try:
        staged = _entry_stat(directory, staging_name)
        if staged is None or not stat.S_ISDIR(staged.st_mode):
            raise ValueError("artifact staging directory is unavailable or unsafe")
        if _entry_stat(directory, destination_absolute.name) is not None:
            raise ValueError("artifact destination appeared during publication")
        os.rename(
            staging_name,
            destination_absolute.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        os.fsync(directory)
    finally:
        os.close(directory)


def _atomic_write_at(directory: int, name: str, content: bytes) -> None:
    temporary = f".{name}.{uuid4().hex}.tmp"
    initial = _entry_stat(directory, name)
    if initial is not None and not stat.S_ISREG(initial.st_mode):
        raise ValueError(f"refusing non-regular destination: {name}")
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("atomic write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        current = _entry_stat(directory, name)
        if initial is None:
            if current is not None:
                raise ValueError("destination appeared during atomic publication")
        elif (
            current is None
            or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino)
        ):
            raise ValueError("destination changed during atomic publication")
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except OSError:
            pass


def _atomic_write(path: Path, content: bytes) -> None:
    directory, name = _open_parent(path, create=True)
    try:
        _atomic_write_at(directory, name, content)
    finally:
        os.close(directory)


@contextlib.contextmanager
def _exclusive_binary_writer(path: Path):
    directory, name = _open_parent(path, create=False)
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as destination:
            yield destination
            destination.flush()
            os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


@contextlib.contextmanager
def _exclusive_binary_writer_at(directory: int, name: str):
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=directory,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as destination:
            yield destination
            destination.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_directory(path: Path) -> int:
    parent = -1
    try:
        parent, name = _open_parent(path, create=False)
        return os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
    finally:
        if parent >= 0:
            os.close(parent)


def _object_directory(base_file: Path) -> Path:
    return base_file.with_name(f"{base_file.name}.objects")


def _real_object_directory(repo: Path) -> Path:
    value = _run(
        repo,
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "objects",
    ).decode("utf-8")
    path = Path(value.strip())
    _require_directory(path, "repository object database")
    return path


def _object_environment(repo: Path, object_dir: Path) -> dict[str, str]:
    alternates = [str(_real_object_directory(repo))]
    inherited = os.environ.get("GIT_ALTERNATE_OBJECT_DIRECTORIES")
    if inherited:
        alternates.append(inherited)
    return {
        **os.environ,
        "GIT_OBJECT_DIRECTORY": str(_absolute_path(object_dir)),
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": os.pathsep.join(alternates),
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _stream_command(
    command: list[str],
    *,
    cwd: Path,
    destination,
    current_size: int,
    allowed_returncodes: tuple[int, ...] = (0,),
    env: dict[str, str] | None = None,
) -> int:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
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


def _bounded_command_bytes(
    command: list[str],
    cwd: Path,
    limit: int,
    *,
    env: dict[str, str] | None = None,
) -> bytes:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
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


def _decode_path_list(raw: bytes) -> list[str]:
    paths: list[str] = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        try:
            relative = encoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Git path is not valid UTF-8") from exc
        _validate_relative_path(relative)
        paths.append(relative)
    return sorted(paths)


def _pathspec(exclude_paths: Sequence[str]) -> list[str]:
    values = ["."]
    for relative in sorted(set(exclude_paths)):
        _validate_relative_path(relative)
        normalized = PurePosixPath(relative).as_posix().rstrip("/")
        if normalized in ("", "."):
            raise ValueError("cannot exclude the entire repository")
        values.extend(
            (
                f":(exclude,top,literal){normalized}",
                f":(exclude,top,literal){normalized}/**",
            )
        )
    return values


def _changed_paths(
    repo: Path,
    base: str,
    env: dict[str, str],
    exclude_paths: Sequence[str],
) -> list[str]:
    pathspec = _pathspec(exclude_paths)
    tracked = _bounded_command_bytes(
        [
            "git",
            "-C",
            str(repo),
            "diff",
            "--name-only",
            "--no-renames",
            "-z",
            base,
            "--",
            *pathspec,
        ],
        repo,
        MAX_PATH_LIST_BYTES,
        env=env,
    )
    untracked = _bounded_command_bytes(
        [
            "git",
            "-C",
            str(repo),
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            *pathspec,
        ],
        repo,
        MAX_PATH_LIST_BYTES,
        env=env,
    )
    return sorted(set(_decode_path_list(tracked) + _decode_path_list(untracked)))


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
    for scheme in ("BASIC ", "BEARER "):
        if normalized.startswith(scheme):
            normalized = normalized.removeprefix(scheme).strip()
            break
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


def _read_bounded_regular_at(directory: int, name: str, limit: int, label: str) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        file_stat = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ValueError(f"{label} is unavailable") from exc
    try:
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if file_stat.st_size > limit:
            raise ValueError(f"{label} exceeds the bounded size limit")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(CHUNK_BYTES, limit + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ValueError(f"{label} exceeds the bounded size limit")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_bounded_regular(path: Path, limit: int, label: str) -> bytes:
    directory = -1
    try:
        directory, name = _open_parent(path, create=False)
        return _read_bounded_regular_at(directory, name, limit, label)
    finally:
        if directory >= 0:
            os.close(directory)


def _path_exists(path: Path) -> bool:
    try:
        directory, name = _open_parent(path, create=False)
    except FileNotFoundError:
        return False
    try:
        return _entry_stat(directory, name) is not None
    finally:
        os.close(directory)


def _require_directory(path: Path, label: str) -> None:
    directory = -1
    descriptor = -1
    try:
        directory, name = _open_parent(path, create=False)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
    except OSError as exc:
        raise ValueError(f"{label} is unavailable or unsafe") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory >= 0:
            os.close(directory)


def _preflight_paths(repo: Path, paths: list[str]) -> None:
    root = repo.resolve(strict=True)
    for relative in paths:
        _validate_relative_path(relative)
        candidate = repo / relative
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError:
            continue
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"unsafe repository path: {relative!r}") from exc
        content = _read_bounded_regular(
            candidate,
            MAX_PATCH_BYTES,
            f"changed file {relative!r}",
        )
        if b"\0" in content:
            raise ValueError(f"changed file {relative!r} is binary")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"changed file {relative!r} is not valid UTF-8") from exc
        if _contains_unredacted_secret(text):
            raise ValueError(f"changed file {relative!r} contains an unredacted secret or credential")


def _snapshot_tree(
    repo: Path,
    base: str,
    object_env: dict[str, str],
    index_path: Path,
    exclude_paths: Sequence[str],
) -> str:
    env = {**object_env, "GIT_INDEX_FILE": str(index_path)}
    _run(repo, "read-tree", base, env=env)
    pathspec = _pathspec(exclude_paths)
    _preflight_paths(repo, _changed_paths(repo, base, env, exclude_paths))
    _run(repo, "add", "-A", "--", *pathspec, env=env)
    return _run(repo, "write-tree", env=env).decode("utf-8").strip()


def capture_base(
    repo: Path,
    base_file: Path,
    output_dir: Path,
    *,
    exclude_paths: Sequence[str] = (),
) -> bool:
    """Capture a validated pre-model tree in an isolated temporary object store."""
    object_dir = _object_directory(base_file)
    staging = object_dir.with_name(f".{object_dir.name}.{uuid4().hex}.tmp")
    success = False
    try:
        _remove_path(output_dir, reject_symlink=True)
        for stale in (base_file, object_dir):
            _remove_path(stale)
        _create_directory(staging)
        head = _run(repo, "rev-parse", "--verify", "HEAD^{commit}").decode("utf-8").strip()
        object_env = _object_environment(repo, staging)
        with tempfile.TemporaryDirectory(prefix="model-patch-capture-") as temporary:
            tree = _snapshot_tree(
                repo,
                head,
                object_env,
                Path(temporary) / "index",
                exclude_paths,
            )
        head_tree = _run(repo, "rev-parse", f"{head}^{{tree}}", env=object_env).decode("utf-8").strip()
        if tree == head_tree:
            base = head
        else:
            commit_env = {
                **object_env,
                "GIT_AUTHOR_NAME": "Vals Model Patch",
                "GIT_AUTHOR_EMAIL": "model-patch@vals.ai",
                "GIT_AUTHOR_DATE": "1970-01-01T00:00:00Z",
                "GIT_COMMITTER_NAME": "Vals Model Patch",
                "GIT_COMMITTER_EMAIL": "model-patch@vals.ai",
                "GIT_COMMITTER_DATE": "1970-01-01T00:00:00Z",
            }
            base = (
                subprocess.check_output(
                    ["git", "-C", str(repo), "commit-tree", tree, "-p", head],
                    input=b"Model Patch pre-model baseline\n",
                    stderr=subprocess.DEVNULL,
                    env=commit_env,
                )
                .decode("utf-8")
                .strip()
            )
        if BASE_PATTERN.fullmatch(base) is None:
            raise ValueError("captured base commit is invalid")
        _publish_directory(staging, object_dir)
        _atomic_write(base_file, f"{base}\n".encode())
        success = True
        return True
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError):
        return False
    finally:
        _cleanup_path(staging)
        if not success:
            _cleanup_path(base_file)
            _cleanup_path(object_dir)


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


def _validate_base_and_application(
    repo: Path,
    base: str,
    patch: bytes,
    object_env: dict[str, str],
) -> None:
    if BASE_PATTERN.fullmatch(base) is None:
        raise ValueError("invalid base commit")
    resolved = _run(repo, "rev-parse", "--verify", f"{base}^{{commit}}", env=object_env).decode("utf-8").strip()
    if resolved != base:
        raise ValueError("base commit does not resolve exactly")
    with tempfile.TemporaryDirectory(prefix="model-patch-index-") as temporary:
        index_path = Path(temporary) / "index"
        env = {**object_env, "GIT_INDEX_FILE": str(index_path)}
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
                    "-",
                ],
                input=patch,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )
        except subprocess.CalledProcessError as exc:
            raise ValueError("model patch does not apply to the captured base commit") from exc


def _metadata_bytes(patch: bytes, base: str) -> dict[str, str | int]:
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


def _metadata(patch_path: Path, base: str) -> dict[str, str | int]:
    return _metadata_bytes(
        _read_bounded_regular(patch_path, MAX_PATCH_BYTES, "model patch"),
        base,
    )


def export_model_patch(
    repo: Path,
    output_dir: Path,
    base_file: Path,
    *,
    exclude_paths: Sequence[str] = (),
) -> bool:
    """Publish the exact final-tree delta from the captured pre-model baseline."""
    object_dir = _object_directory(base_file)
    output_parent = -1
    staging_directory = -1
    staging_name = f".{output_dir.name}.{uuid4().hex}.tmp"
    try:
        output_parent, output_name = _open_parent(output_dir, create=True)
        existing_output = _entry_stat(output_parent, output_name)
        if existing_output is not None:
            if stat.S_ISLNK(existing_output.st_mode):
                raise ValueError(f"refusing symlink destination: {output_dir}")
            _remove_entry(output_parent, output_name)
            os.fsync(output_parent)
        base = _read_bounded_regular(base_file, 128, "model patch base marker").decode("utf-8").strip()
        if BASE_PATTERN.fullmatch(base) is None:
            raise ValueError("invalid base commit")
        _require_directory(object_dir, "isolated model patch object store")
        object_env = _object_environment(repo, object_dir)
        os.mkdir(staging_name, 0o700, dir_fd=output_parent)
        staging_directory = os.open(
            staging_name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=output_parent,
        )
        with tempfile.TemporaryDirectory(prefix="model-patch-export-") as temporary:
            index_path = Path(temporary) / "index"
            _snapshot_tree(repo, base, object_env, index_path, exclude_paths)
            env = {**object_env, "GIT_INDEX_FILE": str(index_path)}
            with _exclusive_binary_writer_at(staging_directory, "model.patch") as patch_file:
                _stream_command(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "diff",
                        "--cached",
                        "--no-ext-diff",
                        "--no-textconv",
                        "--no-renames",
                        "--full-index",
                        base,
                        "--",
                        *_pathspec(exclude_paths),
                    ],
                    cwd=repo,
                    destination=patch_file,
                    current_size=0,
                    env=env,
                )
        patch = _read_bounded_regular_at(
            staging_directory,
            "model.patch",
            MAX_PATCH_BYTES,
            "model patch",
        )
        if not patch:
            return False
        metadata = _metadata_bytes(patch, base)
        _validate_base_and_application(repo, base, patch, object_env)
        _atomic_write_at(
            staging_directory,
            "model_patch.json",
            (json.dumps(metadata, indent=2) + "\n").encode(),
        )
        if _entry_stat(output_parent, output_name) is not None:
            raise ValueError("artifact destination appeared during publication")
        os.rename(
            staging_name,
            output_name,
            src_dir_fd=output_parent,
            dst_dir_fd=output_parent,
        )
        os.fsync(output_parent)
        return True
    finally:
        if staging_directory >= 0:
            os.close(staging_directory)
        if output_parent >= 0:
            try:
                _remove_entry(output_parent, staging_name)
                os.fsync(output_parent)
            except OSError:
                pass
            os.close(output_parent)
        _cleanup_path(base_file)
        _cleanup_path(object_dir)


def attach_reference(trajectory_path: Path, output_dir: Path) -> bool:
    """Revalidate a published patch bundle and atomically attach its ATIF reference."""
    bundle_directory = -1
    trajectory_directory = -1
    try:
        try:
            bundle_directory = _open_directory(output_dir)
        except FileNotFoundError:
            return False
        patch_exists = _entry_stat(bundle_directory, "model.patch") is not None
        metadata_exists = _entry_stat(bundle_directory, "model_patch.json") is not None
        if not patch_exists and not metadata_exists:
            return False
        if not patch_exists or not metadata_exists:
            raise ValueError("model patch bundle is incomplete")
        metadata_bytes = _read_bounded_regular_at(
            bundle_directory,
            "model_patch.json",
            MAX_METADATA_BYTES,
            "model patch metadata",
        )
        recorded = json.loads(metadata_bytes.decode("utf-8"))
        base = recorded.get("base_commit")
        if not isinstance(base, str) or BASE_PATTERN.fullmatch(base) is None:
            raise ValueError("model patch metadata has an invalid base commit")
        patch = _read_bounded_regular_at(
            bundle_directory,
            "model.patch",
            MAX_PATCH_BYTES,
            "model patch",
        )
        expected = _metadata_bytes(patch, base)
        if recorded != expected:
            raise ValueError("model patch metadata checksum or stats mismatch")

        trajectory_directory, trajectory_name = _open_parent(
            trajectory_path,
            create=False,
        )
        trajectory = json.loads(
            _read_bounded_regular_at(
                trajectory_directory,
                trajectory_name,
                MAX_TRAJECTORY_BYTES,
                "ATIF trajectory",
            ).decode("utf-8")
        )
        extra = trajectory.setdefault("extra", {})
        if not isinstance(extra, dict):
            raise ValueError("ATIF extra must be an object")
        vals = extra.setdefault("vals", {})
        if not isinstance(vals, dict):
            raise ValueError("ATIF extra.vals must be an object")
        vals["model_patch"] = recorded
        _atomic_write_at(
            trajectory_directory,
            trajectory_name,
            (json.dumps(trajectory, indent=2) + "\n").encode(),
        )
        return True
    finally:
        if trajectory_directory >= 0:
            os.close(trajectory_directory)
        if bundle_directory >= 0:
            os.close(bundle_directory)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("repo", type=Path)
    capture.add_argument("base_file", type=Path)
    capture.add_argument("output_dir", type=Path)
    capture.add_argument("--exclude", action="append", default=[])
    export = commands.add_parser("export")
    export.add_argument("repo", type=Path)
    export.add_argument("output_dir", type=Path)
    export.add_argument("base_file", type=Path)
    export.add_argument("--exclude", action="append", default=[])
    attach = commands.add_parser("attach")
    attach.add_argument("trajectory", type=Path)
    attach.add_argument("output_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            return (
                0
                if capture_base(
                    args.repo,
                    args.base_file,
                    args.output_dir,
                    exclude_paths=args.exclude,
                )
                else 1
            )
        if args.command == "export":
            export_model_patch(
                args.repo,
                args.output_dir,
                args.base_file,
                exclude_paths=args.exclude,
            )
            return 0
        attach_reference(args.trajectory, args.output_dir)
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"Model Patch unavailable: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
