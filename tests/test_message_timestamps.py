from unittest.mock import Mock

from minisweagent.agents.default import DefaultAgent


def test_trajectory_timestamps_do_not_mutate_model_history() -> None:
    agent = object.__new__(DefaultAgent)
    agent.messages = []
    agent._message_timestamps = []
    agent.logger = Mock()
    message = {"role": "user", "content": "task"}

    agent.add_messages(message)

    assert agent.messages[0] == message == {"role": "user", "content": "task"}
    assert isinstance(agent._serialized_messages()[0]["extra"]["timestamp"], float)


def test_serialization_timestamps_directly_restored_history() -> None:
    agent = object.__new__(DefaultAgent)
    agent.messages = [{"role": "user", "content": "restored"}]
    agent._message_timestamps = []

    assert isinstance(agent._serialized_messages()[0]["extra"]["timestamp"], float)
