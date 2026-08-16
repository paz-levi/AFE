"""Tests for src/afe/baseline/signing.py's HMAC sign/verify functions."""

from datetime import datetime, timezone

import pytest

from afe.baseline.baseline import Baseline
from afe.baseline.signing import sign_baseline, verify_baseline

# Hardcoded test-only secret — never call get_hmac_secret() or touch .env here.
SECRET_KEY = b"test-secret-key-do-not-use-in-prod"


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


def test_verify_baseline_round_trip():
    baseline = _make_baseline()

    signature = sign_baseline(baseline, SECRET_KEY)

    assert verify_baseline(baseline, signature, SECRET_KEY) is True


@pytest.mark.parametrize(
    ("field", "new_value"),
    [
        ("task", "A completely different task"),
        ("dispatcher", "mallory@example.com"),
        ("commands", ["send_email"]),
        ("task_embedding", [9.9, 9.9, 9.9, 9.9, 9.9]),
    ],
)
def test_verify_baseline_fails_after_mutation(field, new_value):
    baseline = _make_baseline()
    signature = sign_baseline(baseline, SECRET_KEY)

    setattr(baseline, field, new_value)

    assert verify_baseline(baseline, signature, SECRET_KEY) is False


def test_verify_baseline_ignores_status_but_not_other_fields():
    baseline = _make_baseline()
    signature = sign_baseline(baseline, SECRET_KEY)

    # status is expected to change legitimately over an agent's lifetime (e.g. the
    # kill switch flipping active -> frozen) — it must not invalidate the signature.
    baseline.status = "frozen"
    assert verify_baseline(baseline, signature, SECRET_KEY) is True

    # but a change to any other field still must invalidate it.
    baseline.task = "A completely different task"
    assert verify_baseline(baseline, signature, SECRET_KEY) is False
