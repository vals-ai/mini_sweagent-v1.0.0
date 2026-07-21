import importlib.util
import json
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

    assert module.main(
        [str(source), str(destination), "task-42"],
        exporter=lambda *args: calls.append(args),
    ) == 0
    assert calls == [(source, destination, "task-42")]


def test_contract_declares_optional_atif_and_model_patch() -> None:
    contract = (ROOT / "contract.yaml").read_text()
    runner = (ROOT / "run.sh").read_text()

    assert "source: /logs/mini_sweagent-v1.0.0/atif/trajectory.json\n    required: false" in contract
    assert "source: /logs/mini_sweagent-v1.0.0/artifacts/model.patch\n    required: false" in contract
    assert "Model Patch export failed" in runner
    assert "Harbor ATIF export failed" in runner
