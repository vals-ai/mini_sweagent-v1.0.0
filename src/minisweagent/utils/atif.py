import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

try:
    from minisweagent.utils.model_patch import (
        MAX_METADATA_BYTES,
        MAX_TRAJECTORY_BYTES,
        _atomic_write,
        _path_exists,
        _read_bounded_regular,
    )
except ModuleNotFoundError:  # Direct execution from the source directory.
    from model_patch import (  # type: ignore[no-redef]
        MAX_METADATA_BYTES,
        MAX_TRAJECTORY_BYTES,
        _atomic_write,
        _path_exists,
        _read_bounded_regular,
    )


def export_atif(
    source: Path,
    destination: Path,
    session_id: str,
    *,
    patch_metadata: Path | None = None,
    converter: Callable[[dict[str, Any], str], Any] | None = None,
) -> None:
    """Convert a native mini-SWE trajectory with Harbor and replace the ATIF output atomically."""
    if converter is None:
        from harbor.agents.installed.mini_swe_agent import convert_mini_swe_agent_to_atif

        converter = convert_mini_swe_agent_to_atif

    trajectory = converter(
        json.loads(
            _read_bounded_regular(
                source,
                MAX_TRAJECTORY_BYTES,
                "native trajectory",
            ).decode("utf-8")
        ),
        session_id,
    )
    output = trajectory.to_json_dict()
    if patch_metadata is not None and _path_exists(patch_metadata):
        output.setdefault("extra", {}).setdefault("vals", {})["model_patch"] = json.loads(
            _read_bounded_regular(
                patch_metadata,
                MAX_METADATA_BYTES,
                "model patch metadata",
            ).decode("utf-8")
        )
    _atomic_write(destination, (json.dumps(output, indent=2) + "\n").encode())


def main(
    argv: Sequence[str] | None = None,
    *,
    exporter: Callable[[Path, Path, str], None] = export_atif,
) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("session_id")
    parser.add_argument("--patch-metadata", type=Path)
    args = parser.parse_args(argv)
    if args.patch_metadata is None:
        exporter(args.source, args.destination, args.session_id)
    else:
        export_atif(
            args.source,
            args.destination,
            args.session_id,
            patch_metadata=args.patch_metadata,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
