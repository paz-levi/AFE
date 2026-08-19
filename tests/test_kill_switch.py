"""Tests for the chokepoint kill switch: a red decision freezes the baseline, and a
frozen baseline short-circuits all future evaluation without any semantic check."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from afe.baseline.baseline import Baseline
from afe.gateway import audit, chokepoint
from afe.gateway.chokepoint import evaluate_request
from afe.gateway.policy import Tier
from afe.storage.store import JSONFileStore

SIGNATURE = "deadbeef"


def _make_baseline(**overrides) -> Baseline:
    fields = {
        "agent_id": "agent-1",
        "dispatcher": "alice@example.com",
        "task": "Summarize quarterly reports",
        "task_embedding": [0.1, -0.2, 0.3, 0.0, 5.5],
        "commands": ["read_file"],
        "allowed_resources": ["reports/board.md"],
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    }
    fields.update(overrides)
    return Baseline(**fields)


@pytest.fixture(autouse=True)
def isolate_audit_log(tmp_path, monkeypatch):
    """Redirect the audit trail to a throwaway file so these tests never touch the
    real storage/audit.jsonl."""
    monkeypatch.setattr(audit, "AUDIT_LOG_PATH", tmp_path / "audit.jsonl")


@pytest.fixture
def store(tmp_path):
    return JSONFileStore(tmp_path / "baselines")


def test_red_decision_freezes_baseline_and_persists_to_store(monkeypatch, store):
    baseline = _make_baseline(allowed_resources=["reports/board.md"])
    store.save(baseline, SIGNATURE)
    monkeypatch.setattr(chokepoint, "get_classification", lambda resource: "SECRET")
    monkeypatch.setattr(chokepoint, "compute_similarity", lambda description, baseline: 0.99)
    monkeypatch.setattr(chokepoint, "get_hmac_secret", lambda: b"test-secret")

    decision, updated_baseline, updated_signature = evaluate_request(
        baseline, SIGNATURE, "read_file", {"path": "finance/payroll.csv"}, store
    )

    assert decision.tier == Tier.RED
    assert updated_baseline.status == "frozen"

    persisted_baseline, persisted_signature = store.get(baseline.agent_id)
    assert persisted_baseline.status == "frozen"
    assert persisted_signature == updated_signature


def test_second_call_with_frozen_baseline_short_circuits(monkeypatch, store):
    baseline = _make_baseline(allowed_resources=["reports/board.md"])
    store.save(baseline, SIGNATURE)
    monkeypatch.setattr(chokepoint, "get_classification", lambda resource: "SECRET")
    monkeypatch.setattr(chokepoint, "compute_similarity", lambda description, baseline: 0.99)
    monkeypatch.setattr(chokepoint, "get_hmac_secret", lambda: b"test-secret")

    _, frozen_baseline, frozen_signature = evaluate_request(
        baseline, SIGNATURE, "read_file", {"path": "finance/payroll.csv"}, store
    )
    assert frozen_baseline.status == "frozen"

    calls = {"classification": 0, "similarity": 0, "decide_tier": 0}

    def _count_classification(resource):
        calls["classification"] += 1
        return "PUBLIC"

    def _count_similarity(description, baseline):
        calls["similarity"] += 1
        return 1.0

    def _count_decide_tier(score, classification, resource, baseline):
        calls["decide_tier"] += 1
        raise AssertionError("decide_tier must not be called for a frozen baseline")

    monkeypatch.setattr(chokepoint, "get_classification", _count_classification)
    monkeypatch.setattr(chokepoint, "compute_similarity", _count_similarity)
    monkeypatch.setattr(chokepoint, "decide_tier", _count_decide_tier)

    decision, returned_baseline, returned_signature = evaluate_request(
        frozen_baseline, frozen_signature, "read_file", {"path": "reports/board.md"}, store
    )

    assert decision.tier == Tier.RED
    assert decision.triggered_by == "frozen"
    assert returned_baseline is frozen_baseline
    assert returned_signature == frozen_signature
    assert calls == {"classification": 0, "similarity": 0, "decide_tier": 0}
