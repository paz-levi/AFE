"""Tests for src/afe/gateway/chokepoint.py's evaluate_request().

Monkeypatches chokepoint's own imported get_classification and compute_similarity
directly rather than exercising the real embedding model or the real signed
config/classification.json / config/thresholds.json — evaluate_request's precedence
logic is what's under test here, not classification.py's file-parsing or
similarity.py's embedding pipeline (both already covered by their own test files). Also
redirects audit.AUDIT_LOG_PATH to a tmp_path so these runs never append to the real
storage/audit.jsonl.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from afe.baseline.baseline import Baseline
from afe.gateway import audit, chokepoint
from afe.gateway.chokepoint import evaluate_request
from afe.gateway.policy import Tier
from afe.storage.store import BaselineStore

SIGNATURE = "deadbeef"


def _make_baseline(**overrides) -> Baseline:
    fields = {
        "agent_id": "agent-1",
        "dispatcher": "alice@example.com",
        "task": "Summarize quarterly reports",
        # Never actually read through cosine similarity in these tests —
        # compute_similarity itself is monkeypatched below, so this value is inert.
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


def test_allowlisted_resource_is_green_regardless_of_similarity(monkeypatch):
    baseline = _make_baseline(allowed_resources=["reports/board.md"])
    monkeypatch.setattr(chokepoint, "get_classification", lambda resource: "CONFIDENTIAL")
    monkeypatch.setattr(chokepoint, "compute_similarity", lambda description, baseline: 0.0)
    store = MagicMock(spec=BaselineStore)

    decision, _, _ = evaluate_request(
        baseline, SIGNATURE, "read_file", {"path": "reports/board.md"}, store
    )

    assert decision.tier == Tier.GREEN
    assert decision.triggered_by == "allowlist"


def test_public_classification_is_green(monkeypatch):
    baseline = _make_baseline(allowed_resources=[])
    monkeypatch.setattr(chokepoint, "get_classification", lambda resource: "PUBLIC")
    monkeypatch.setattr(chokepoint, "compute_similarity", lambda description, baseline: 0.0)
    store = MagicMock(spec=BaselineStore)

    decision, _, _ = evaluate_request(
        baseline, SIGNATURE, "read_file", {"path": "public/handbook.md"}, store
    )

    assert decision.tier == Tier.GREEN
    assert decision.triggered_by == "classification"


def test_secret_classification_not_allowlisted_is_red_regardless_of_similarity(monkeypatch):
    baseline = _make_baseline(allowed_resources=["reports/board.md"])
    monkeypatch.setattr(chokepoint, "get_classification", lambda resource: "SECRET")
    monkeypatch.setattr(chokepoint, "compute_similarity", lambda description, baseline: 0.99)
    monkeypatch.setattr(chokepoint, "get_hmac_secret", lambda: b"test-secret")
    store = MagicMock(spec=BaselineStore)

    decision, _, _ = evaluate_request(
        baseline, SIGNATURE, "read_file", {"path": "finance/payroll.csv"}, store
    )

    assert decision.tier == Tier.RED
    assert decision.triggered_by == "classification"
