from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

from model_library import model_library_settings
from model_library.base.base import LLMConfig
from model_library.base.input import InputItem, SystemInput, TextInput, ToolBody, ToolCall, ToolDefinition, ToolResult
from model_library.registry_utils import get_registry_model
from pydantic import BaseModel

from minisweagent.models import GLOBAL_MODEL_STATS
from minisweagent.models.utils.actions_toolcall import format_toolcall_observation_messages, parse_toolcall_actions


class EventLoopManager:
    """Manages a shared asyncio event loop in a background thread.

    gRPC-based providers (e.g. xai_sdk / grok) bind channels to the event loop
    that is running when the client is created. Using asyncio.run() creates a
    new loop each call, breaking those channels. This class keeps a single
    persistent loop so the model and all queries share the same one.

    """

    _shared_loop: asyncio.AbstractEventLoop | None = None
    _shared_loop_thread: threading.Thread | None = None
    _shared_loop_lock = threading.Lock()

    def __init__(self):
        self._loop = self._ensure_shared_loop()

    @classmethod
    def _ensure_shared_loop(cls) -> asyncio.AbstractEventLoop:
        with cls._shared_loop_lock:
            if cls._shared_loop is not None and cls._shared_loop.is_running():
                return cls._shared_loop

            loop = asyncio.new_event_loop()

            def _run_loop(loop_: asyncio.AbstractEventLoop) -> None:
                asyncio.set_event_loop(loop_)
                loop_.run_forever()

            thread = threading.Thread(target=_run_loop, args=(loop,), daemon=True)
            thread.start()

            cls._shared_loop = loop
            cls._shared_loop_thread = thread

            return loop

    def submit(self, coro: Any):
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result()


class ValsModelConfig(BaseModel):
    model_name: str
    model_kwargs: dict[str, Any] = {}
    format_error_template: str = "{{ error }}"
    """Template used when the LM's output is not in the expected format."""
    observation_template: str = (
        "{% if output.exception_info %}<exception>{{output.exception_info}}</exception>\n{% endif %}"
        "<returncode>{{output.returncode}}</returncode>\n<output>\n{{output.output}}</output>"
    )


class ValsModel:
    def __init__(self, *, config_class: Callable = ValsModelConfig, **kwargs):
        self.config = config_class(**kwargs)

        gateway_url = model_library_settings.get("MODEL_GATEWAY_URL", None)
        gateway_api_key = model_library_settings.get("MODEL_GATEWAY_API_KEY", None)
        gateway_values = (gateway_url, gateway_api_key)
        if any(value is not None for value in gateway_values) and not all(
            isinstance(value, str) and value.strip() for value in gateway_values
        ):
            raise ValueError(
                "MODEL_GATEWAY_URL and MODEL_GATEWAY_API_KEY must be configured together with non-empty values"
            )

        self._event_loop_manager = EventLoopManager()

        override_config = LLMConfig(**self.config.model_kwargs) if self.config.model_kwargs else None

        async def _create_model():
            return get_registry_model(self.config.model_name, override_config=override_config)

        self._model = self._event_loop_manager.submit(_create_model())

        self._bash_tool = ToolDefinition(
            name="bash",
            body=ToolBody(
                name="bash",
                description="Execute a bash command",
                properties={"command": {"type": "string", "description": "The bash command to execute"}},
                required=["command"],
            ),
        )

        # model-library splits conversation into (history, input) with an
        # optional SystemInput as the first item. The agent passes a single
        # append-only message list. We track the message count at the time of
        # our last query so we can extract only the newly appended messages.
        self._history: list[InputItem] = []
        self._msg_cursor: int = 0
        self._last_tool_calls: dict[str, ToolCall] = {}

    def query(self, messages: list[dict[str, str]], **kwargs) -> dict:
        input_items = self._build_input_items(messages)
        if not self._history and messages and messages[0].get("role") == "system":
            input_items = [SystemInput(text=messages[0].get("content", "")), *input_items]

        result = self._event_loop_manager.submit(
            self._model.query(
                input=input_items,
                history=self._history,
                tools=[self._bash_tool],
            )
        )

        self._history = result.history
        self._msg_cursor = len(messages)
        self._last_tool_calls = {tc.id: tc for tc in result.tool_calls}

        cost = result.metadata.cost.total if result.metadata.cost else 0.0
        GLOBAL_MODEL_STATS.add(cost)

        actions = self._parse_actions(result.tool_calls)

        return {
            "role": "assistant",
            "content": result.output_text,
            "tool_calls": [
                {
                    "id": tc.id,
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.args) if isinstance(tc.args, dict) else tc.args,
                    },
                    "type": "function",
                }
                for tc in result.tool_calls
            ],
            "extra": {
                "actions": actions,
                "response": result.model_dump(mode="json", exclude={"history", "raw"}),
                "metrics": self._extract_metrics(result.metadata),
                "cost": cost,
                "timestamp": time.time(),
            },
        }

    def _build_input_items(self, messages: list[dict]) -> list:
        """Convert newly appended agent messages into model-library InputItems.

        The agent's message list is append-only. Between queries, new messages
        are appended (tool results, format error retries, etc.). We convert
        everything after _msg_cursor, skipping assistant messages which are
        already captured in model-library's history via RawResponse.
        """
        items = []
        for msg in messages[self._msg_cursor :]:
            tool_call_id = msg.get("tool_call_id")
            if tool_call_id and tool_call_id in self._last_tool_calls:
                items.append(ToolResult(tool_call=self._last_tool_calls[tool_call_id], result=msg.get("content", "")))
            elif msg.get("role") == "user":
                items.append(TextInput(text=msg.get("content", "")))
        return items

    def _parse_actions(self, tool_calls: list) -> list[dict]:
        openai_format = [
            SimpleNamespace(
                id=tc.id,
                function=SimpleNamespace(
                    name=tc.name,
                    arguments=json.dumps(tc.args) if isinstance(tc.args, dict) else tc.args,
                ),
            )
            for tc in tool_calls
        ]
        return parse_toolcall_actions(openai_format, format_error_template=self.config.format_error_template)

    @staticmethod
    def _extract_metrics(metadata) -> dict:
        return metadata.model_dump(mode="json")

    def format_message(self, **kwargs) -> dict:
        return kwargs

    def format_observation_messages(
        self, message: dict, outputs: list[dict], template_vars: dict | None = None
    ) -> list[dict]:
        actions = message.get("extra", {}).get("actions", [])
        return format_toolcall_observation_messages(
            actions=actions,
            outputs=outputs,
            observation_template=self.config.observation_template,
            template_vars=template_vars,
        )

    def get_template_vars(self, **kwargs) -> dict[str, Any]:
        return self.config.model_dump()

    def serialize(self) -> dict:
        return {
            "info": {
                "config": {
                    "model": self.config.model_dump(mode="json"),
                    "model_type": f"{self.__class__.__module__}.{self.__class__.__name__}",
                },
            }
        }
