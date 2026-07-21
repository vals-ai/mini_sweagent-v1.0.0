import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

SECRET_PATTERN = re.compile(
    rb"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*['\"]?[^\s'\"]+"
    rb"|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL)


def export_model_patch(repo: Path, destination: Path, metadata_destination: Path, base_commit: str) -> bool:
    _git(repo, "rev-parse", "--verify", f"{base_commit}^{{commit}}")
    numstat = _git(repo, "diff", "--numstat", base_commit, "--", ".").decode()
    if not numstat.strip():
        return False
    rows = [line.split("\t", 2) for line in numstat.splitlines()]
    if any(added == "-" or deleted == "-" for added, deleted, _ in rows):
        raise ValueError("binary changes cannot be exported as a model patch")
    patch = _git(repo, "diff", "--no-ext-diff", "--no-textconv", "--full-index", base_commit, "--", ".")
    if b"GIT binary patch" in patch or b"Binary files " in patch:
        raise ValueError("binary changes cannot be exported as a model patch")
    if SECRET_PATTERN.search(patch):
        raise ValueError("potential secret detected in model patch")
    metadata = {
        "path": "artifacts/model.patch", "media_type": "text/x-diff",
        "sha256": hashlib.sha256(patch).hexdigest(), "base_commit": base_commit,
        "file_count": len(rows), "additions": sum(int(a) for a, _, _ in rows),
        "deletions": sum(int(d) for _, d, _ in rows),
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    metadata_destination.parent.mkdir(parents=True, exist_ok=True)
    patch_tmp = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
    metadata_tmp = metadata_destination.with_name(f".{metadata_destination.name}.{uuid4().hex}.tmp")
    try:
        patch_tmp.write_bytes(patch)
        metadata_tmp.write_text(json.dumps(metadata, indent=2) + "\n")
        patch_tmp.replace(destination)
        metadata_tmp.replace(metadata_destination)
    finally:
        patch_tmp.unlink(missing_ok=True)
        metadata_tmp.unlink(missing_ok=True)
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("metadata_destination", type=Path)
    parser.add_argument("base_commit")
    args = parser.parse_args(argv)
    export_model_patch(args.repo, args.destination, args.metadata_destination, args.base_commit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
