"""Tests for src/afe/gateway/policy.py's decide_tier()."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from afe.baseline.baseline import Baseline
from afe.gateway import policy
from afe.gateway.policy import Tier, decide_tier

# Hardcoded thresholds — never touches config/thresholds.json or its signature.
THRESHOLDS = {
    "INTERNAL": {"yellow": 0.35, "green": 0.55},
    "CONFIDENTIAL": {"yellow": 0.55, "green": 0.75},
}


def _make_baseline(**overrides) -> Baseline:
    fields = {
        "agent_id": "agent-1",
        "dispatcher": "alice@example.com",
        "task": "Summarize quarterly reports",
        "task_embedding": [0.1, -0.2, 0.3, 0.0, 5.5],
        "commands": ["read_file", "query_db"],
        "allowed_resources": ["reports/board.md"],
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    }
    fields.update(overrides)
    return Baseline(**fields)


@pytest.fixture(autouse=True)
def hardcoded_thresholds(monkeypatch):
    monkeypatch.setattr(policy, "_THRESHOLDS", THRESHOLDS)
    yield
    monkeypatch.setattr(policy, "_THRESHOLDS", None)


@pytest.mark.parametrize(
    "score, classification, resource, expected",
    [
        # (a) allowlisted resource wins regardless of score/classification.
        (0.0, "SECRET", "reports/board.md", Tier.GREEN),
        # (b) PUBLIC is always green regardless of score.
        (0.0, "PUBLIC", "other/file.md", Tier.GREEN),
        # (c) SECRET is always red regardless of score, when not allowlisted.
        (0.99, "SECRET", "other/file.md", Tier.RED),
        # (d) INTERNAL: score at/above green threshold.
        (0.60, "INTERNAL", "other/file.md", Tier.GREEN),
        # (d) INTERNAL: score between yellow and green thresholds.
        (0.40, "INTERNAL", "other/file.md", Tier.YELLOW),
        # (d) INTERNAL: score below yellow threshold.
        (0.10, "INTERNAL", "other/file.md", Tier.RED),
    ],
)
def test_decide_tier_precedence(score, classification, resource, expected):
    baseline = _make_baseline()

    result = decide_tier(score, classification, resource, baseline)

    assert result.tier == expected


@pytest.mark.parametrize(
    "score, classification, resource, expected_triggered_by",
    [
        # (a) allowlisted resource.
        (0.0, "SECRET", "reports/board.md", "allowlist"),
        # (b) PUBLIC classification.
        (0.0, "PUBLIC", "other/file.md", "classification"),
        # (c) SECRET classification, not allowlisted.
        (0.99, "SECRET", "other/file.md", "classification"),
        # (d) threshold-based decisions, all classification-dependent semantic checks.
        (0.60, "INTERNAL", "other/file.md", "semantic"),
        (0.40, "INTERNAL", "other/file.md", "semantic"),
        (0.10, "INTERNAL", "other/file.md", "semantic"),
    ],
)
def test_decide_tier_triggered_by(score, classification, resource, expected_triggered_by):
    baseline = _make_baseline()

    result = decide_tier(score, classification, resource, baseline)

    assert result.triggered_by == expected_triggered_by
