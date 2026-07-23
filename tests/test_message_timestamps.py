from unittest.mock import Mock

from minisweagent.agents.default import DefaultAgent


def test_add_messages_records_missing_source_timestamps() -> None:
    agent = object.__new__(DefaultAgent)
    agent.messages = []
    agent.logger = Mock()

    agent.add_messages(
        {"role": "system", "content": "system"},
        {"role": "user", "content": "task", "extra": {}},
    )

    assert all(isinstance(message["extra"]["timestamp"], float) for message in agent.messages)
