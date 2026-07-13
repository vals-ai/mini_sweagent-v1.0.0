from __future__ import annotations

import json
from typing import Any

import pytest
from model_library import model_library_settings

from minisweagent.models.vals_model import ValsModel

GATEWAY_ENV_VARS = (
    "MODEL_GATEWAY_URL",
    "MODEL_GATEWAY_API_KEY",
    "RUN_ID",
    "QUESTION_ID",
    "TASK_ID",
    "IDENTITY",
)


@pytest.fixture(autouse=True)
def reset_model_library_settings(monkeypatch: pytest.MonkeyPatch):
    model_library_settings.reset()
    for name in GATEWAY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "test-provider-key")
    yield
    model_library_settings.reset()


def test_direct_provider_mode_remains_available_without_gateway_configuration():
    model = ValsModel(model_name="openai/gpt-4o")

    assert getattr(model._model, "gateway_mode", False) is False


@pytest.mark.parametrize(
    ("gateway_url", "gateway_api_key"),
    [
        ("https://gateway.example.test", None),
        (None, "test-gateway-key"),
        ("", "test-gateway-key"),
        ("https://gateway.example.test", ""),
    ],
)
def test_partial_gateway_configuration_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    gateway_url: str | None,
    gateway_api_key: str | None,
):
    if gateway_url is not None:
        monkeypatch.setenv("MODEL_GATEWAY_URL", gateway_url)
    if gateway_api_key is not None:
        monkeypatch.setenv("MODEL_GATEWAY_API_KEY", gateway_api_key)

    with pytest.raises(ValueError, match="must be configured together"):
        ValsModel(model_name="openai/gpt-4o")


def test_gateway_mode_propagates_valkyrie_metadata(monkeypatch: pytest.MonkeyPatch):
    identity = {
        "benchmark_name": "swebench",
        "agent_name": "mini_sweagent-v1.0.0",
        "email": "runner@example.test",
    }
    monkeypatch.setenv("MODEL_GATEWAY_URL", "https://gateway.example.test")
    monkeypatch.setenv("MODEL_GATEWAY_API_KEY", "test-gateway-key")
    monkeypatch.setenv("RUN_ID", "run-123")
    monkeypatch.setenv("TASK_ID", "astropy__astropy-7606")
    monkeypatch.setenv("IDENTITY", json.dumps(identity))

    model = ValsModel(model_name="openai/gpt-4o")
    assert getattr(model._model, "gateway_mode", False) is True

    class GatewayRequestCaptured(Exception):
        def __init__(self, path: str, body: dict[str, Any]):
            self.path = path
            self.body = body

    async def capture_gateway_request(path: str, body: dict[str, Any]):
        raise GatewayRequestCaptured(path, body)

    monkeypatch.setattr(model._model, "_post_gateway", capture_gateway_request)

    with pytest.raises(GatewayRequestCaptured) as captured:
        model.query([{"role": "user", "content": "Inspect the repository."}])

    assert captured.value.path == "/query"
    assert captured.value.body["model"] == "openai/gpt-4o"
    assert captured.value.body["run_id"] == "run-123"
    assert captured.value.body["question_id"] == "astropy__astropy-7606"
    assert captured.value.body["identity"] == identity
