"""Tests for src/afe/baseline/baseline.py's Baseline model."""

from datetime import datetime, timezone

import pytest

from afe.baseline.baseline import Baseline


def _make_baseline(**overrides) -> Baseline:
    fields = {
        "agent_id": "agent-1",
        "dispatcher": "alice@example.com",
        "task": "Summarize quarterly reports",
        "task_embedding": [0.1, -0.2, 0.3, 0.0, 5.5],
        "commands": ["read_file", "query_db"],
        "allowed_resources": ["reports/*.md"],
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    }
    fields.update(overrides)
    return Baseline(**fields)


def test_round_trip_preserves_task_embedding():
    original = _make_baseline()

    restored = Baseline.from_json(original.to_json())

    assert restored.task_embedding == pytest.approx(original.task_embedding)
    assert restored.agent_id == original.agent_id
    assert restored.dispatcher == original.dispatcher
    assert restored.task == original.task
    assert restored.commands == original.commands
    assert restored.allowed_resources == original.allowed_resources
    assert restored.created_at == original.created_at
    assert restored.status == original.status


def test_status_defaults_to_active():
    baseline = _make_baseline()

    assert baseline.status == "active"
