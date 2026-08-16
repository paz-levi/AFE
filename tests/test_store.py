"""Tests for src/afe/storage/store.py's JSONFileStore and CachedStore."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from afe.baseline.baseline import Baseline
from afe.storage.store import AgentNotFoundError, BaselineStore, CachedStore, JSONFileStore

# Store tests only need an opaque signature string — computing a real HMAC is
# signing.py's concern, not this file's.
SIGNATURE = "deadbeef"


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


def test_json_file_store_round_trip(tmp_path):
    store = JSONFileStore(tmp_path)
    baseline = _make_baseline()

    store.save(baseline, SIGNATURE)
    restored_baseline, restored_signature = store.get(baseline.agent_id)

    assert restored_baseline == baseline
    assert restored_signature == SIGNATURE


def test_json_file_store_missing_agent_raises(tmp_path):
    store = JSONFileStore(tmp_path)

    with pytest.raises(AgentNotFoundError):
        store.get("no-such-agent")


def test_json_file_store_corrupted_baseline_raises_agent_not_found(tmp_path):
    store = JSONFileStore(tmp_path)
    # Syntactically valid JSON, but "baseline" is missing a required field
    # (dispatcher) — should surface as AgentNotFoundError, not a raw
    # pydantic.ValidationError.
    corrupted = {
        "baseline": {
            "agent_id": "agent-corrupt",
            "task": "Summarize quarterly reports",
            "task_embedding": [0.1, -0.2, 0.3],
            "commands": ["read_file"],
            "allowed_resources": ["reports/*.md"],
            "created_at": "2026-01-01T00:00:00Z",
            "status": "active",
        },
        "signature": SIGNATURE,
    }
    (tmp_path / "agent-corrupt.json").write_text(
        json.dumps(corrupted), encoding="utf-8"
    )

    with pytest.raises(AgentNotFoundError):
        store.get("agent-corrupt")


def test_cached_store_avoids_second_disk_read():
    baseline = _make_baseline()
    inner = MagicMock(spec=BaselineStore)
    inner.get.return_value = (baseline, SIGNATURE)
    cached = CachedStore(inner)

    first = cached.get(baseline.agent_id)
    second = cached.get(baseline.agent_id)

    assert first == (baseline, SIGNATURE)
    assert second == (baseline, SIGNATURE)
    inner.get.assert_called_once_with(baseline.agent_id)


def test_cached_store_save_writes_through_and_updates_cache():
    inner = MagicMock(spec=BaselineStore)
    cached = CachedStore(inner)
    baseline = _make_baseline()

    cached.save(baseline, SIGNATURE)

    inner.save.assert_called_once_with(baseline, SIGNATURE)
    # get() must see the freshly saved value without hitting the inner store again.
    assert cached.get(baseline.agent_id) == (baseline, SIGNATURE)
    inner.get.assert_not_called()
