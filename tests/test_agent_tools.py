"""Tests that the demo harness only offers the LLM the tools listed in its Baseline's
commands, so a call to an ungranted tool cannot be an innocent mistake caused by
seeing that tool in the tool list."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from afe.agent.harness import TOOL_DEFINITIONS, Agent
from afe.baseline.baseline import Baseline
from afe.storage.store import BaselineStore


def _agent(commands: list[str]) -> tuple[Agent, MagicMock]:
    baseline = Baseline(
        agent_id="agent-1",
        dispatcher="alice@example.com",
        task="Summarize quarterly reports",
        task_embedding=[0.0, 1.0],
        commands=commands,
        allowed_resources=[],
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    client = MagicMock()
    # One turn with no tool use: the loop ends after the first API call.
    client.messages.create.return_value = SimpleNamespace(
        content=[SimpleNamespace(type="text", text="done")], stop_reason="end_turn"
    )
    agent = Agent(
        baseline, "sig", MagicMock(spec=BaselineStore), "You are helpful.", client=client
    )
    return agent, client


def _offered_tool_names(client: MagicMock) -> list[str]:
    return [t["name"] for t in client.messages.create.call_args.kwargs["tools"]]


def test_llm_is_offered_only_the_tools_in_commands():
    agent, client = _agent(commands=["read_file"])

    agent.run(task="Summarize the report.")

    assert _offered_tool_names(client) == ["read_file"]


def test_llm_is_offered_every_granted_tool():
    granted = ["read_file", "send_email", "query_db"]
    agent, client = _agent(commands=granted)

    agent.run(task="Summarize the report.")

    assert sorted(_offered_tool_names(client)) == sorted(granted)
    assert len(TOOL_DEFINITIONS) == len(granted)  # the demo registers exactly these
