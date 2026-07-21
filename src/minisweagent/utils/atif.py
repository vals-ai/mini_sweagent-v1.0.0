import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any
from uuid import uuid4


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

    trajectory = converter(json.loads(source.read_text()), session_id)
    output = trajectory.to_json_dict()
    if patch_metadata is not None and patch_metadata.is_file():
        output.setdefault("extra", {}).setdefault("vals", {})["model_patch"] = json.loads(
            patch_metadata.read_text()
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(output, indent=2) + "\n")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


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
