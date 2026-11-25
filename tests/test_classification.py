"""Tests for src/afe/gateway/classification.py."""

import json
import logging
from pathlib import Path

import pytest

from afe.baseline.signing import sign_bytes
from afe.gateway import classification
from afe.gateway.classification import PolicyIntegrityError, get_classification

TEST_SECRET = "test-secret-for-classification-tests"

RAW_POLICY = {
    "folders": {
        "/finance": "SECRET",
        "/reports": "INTERNAL",
    },
    "file_overrides": {
        "/reports/board_summary.md": {"level": "SECRET"},
        "/finance/press_release_draft.md": {
            "level": "PUBLIC",
            "downward_override": True,
        },
    },
}


def _write_signed_policy(path: Path, policy: dict, secret: str) -> None:
    canonical = json.dumps(policy, sort_keys=True).encode("utf-8")
    signature = sign_bytes(canonical, secret.encode("utf-8"))
    path.write_text(json.dumps({"policy": policy, "signature": signature}), encoding="utf-8")


@pytest.fixture
def signed_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("AFE_HMAC_SECRET", TEST_SECRET)
    policy_path = tmp_path / "classification.json"
    _write_signed_policy(policy_path, RAW_POLICY, TEST_SECRET)

    monkeypatch.setattr(classification, "_CLASSIFICATION_PATH", policy_path)
    monkeypatch.setattr(classification, "_POLICY", None)

    return policy_path


def test_folder_default_resolves(signed_policy):
    assert get_classification("/reports/quarterly.md") == "INTERNAL"
    assert get_classification("/finance/payroll.csv") == "SECRET"


def test_file_override_without_downward_flag_no_warning(signed_policy, caplog):
    caplog.set_level(logging.WARNING)

    result = get_classification("/reports/board_summary.md")

    assert result == "SECRET"
    assert not any("downward" in record.message.lower() for record in caplog.records)


def test_file_override_with_downward_flag_logs_warning(signed_policy, caplog):
    caplog.set_level(logging.WARNING)

    result = get_classification("/finance/press_release_draft.md")

    assert result == "PUBLIC"
    assert any("downward" in record.message.lower() for record in caplog.records)


def test_unmatched_path_defaults_to_confidential(signed_policy):
    assert get_classification("/unrelated/whatever.txt") == "CONFIDENTIAL"


def test_tampered_policy_raises_policy_integrity_error(signed_policy, monkeypatch, tmp_path):
    # Tamper with a *separate* temp copy — the real signed file from the fixture is
    # never modified.
    tampered_path = tmp_path / "classification_tampered.json"
    data = json.loads(signed_policy.read_text(encoding="utf-8"))
    data["policy"]["folders"]["/finance"] = "PUBLIC"  # content changed, signature stale
    tampered_path.write_text(json.dumps(data), encoding="utf-8")

    monkeypatch.setattr(classification, "_CLASSIFICATION_PATH", tampered_path)
    monkeypatch.setattr(classification, "_POLICY", None)

    with pytest.raises(PolicyIntegrityError):
        get_classification("/finance/payroll.csv")


def test_missing_leading_slash_still_resolves_via_normalization(monkeypatch):
    """Proves normalization closes the real risk: an LLM-supplied path missing its
    leading slash must still resolve to the same classification as the canonical
    form, against the real signed config/classification.json — not a test fixture."""
    monkeypatch.setattr(classification, "_POLICY", None)

    assert get_classification("finance/payroll.csv") == "SECRET"


def test_path_traversal_resolves_to_true_target_not_bypassed(monkeypatch):
    """Proves the traversal bypass is closed for real against the actual signed
    config/classification.json, not just unit-tested on normalize_resource_path in
    isolation. "reports/../finance/payroll.csv" string-prefix-matches /reports
    (INTERNAL) if ".." isn't collapsed first — but the OS, when the file is
    actually opened, resolves ".." and reaches the real file under /finance
    (SECRET). Before the fix, this test would have failed, returning "INTERNAL"."""
    monkeypatch.setattr(classification, "_POLICY", None)

    assert get_classification("reports/../finance/payroll.csv") == "SECRET"


# --- case variants (strict-only case folding) ---------------------------------------


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/Finance/payroll.csv", "SECRET"),  # folder rule, any casing
        ("/FINANCE/Payroll.CSV", "SECRET"),
        ("/Reports/quarterly.md", "INTERNAL"),
        ("/REPORTS/Board_Summary.md", "SECRET"),  # upward override, any casing
    ],
)
def test_case_variants_resolve_like_canonical_path(signed_policy, path, expected):
    assert get_classification(path) == expected


def test_downward_override_requires_exact_case(signed_policy):
    """A downward (PUBLIC) override only loosens the exact path it names: on a
    case-sensitive filesystem a case variant is a different file, so it falls back
    to its folder's level instead of inheriting PUBLIC."""
    assert get_classification("/finance/press_release_draft.md") == "PUBLIC"
    assert get_classification("/finance/Press_Release_Draft.md") == "SECRET"


def test_case_variant_against_real_signed_config(monkeypatch):
    monkeypatch.setattr(classification, "_POLICY", None)

    assert get_classification("/Finance/payroll.csv") == "SECRET"


def test_audit_log_keeps_original_casing(signed_policy, monkeypatch, tmp_path):
    """Case folding is for matching only: the audit log records the path as requested."""
    from unittest.mock import MagicMock

    from afe.baseline.baseline import Baseline
    from afe.gateway import audit, chokepoint, policy
    from afe.storage.store import BaselineStore

    monkeypatch.setattr(audit, "AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    # Plain thresholds, so a mis-resolved (non-SECRET) path fails on the assertion
    # below rather than on verifying the real thresholds.json with the test secret.
    monkeypatch.setattr(
        policy, "_THRESHOLDS",
        {"INTERNAL": {"yellow": 0.1, "green": 0.3},
         "CONFIDENTIAL": {"yellow": 0.1, "green": 0.3}},
    )
    monkeypatch.setattr(chokepoint, "compute_similarity", lambda d, b: 0.0)
    baseline = Baseline(
        agent_id="a", dispatcher="d", task="t", task_embedding=[0.0],
        commands=["read_file"], allowed_resources=[],
        created_at="2026-01-01T00:00:00+00:00",
    )

    decision, _, _ = chokepoint.evaluate_request(
        baseline, "sig", "read_file", {"path": "/Finance/payroll.csv"},
        MagicMock(spec=BaselineStore),
    )

    entry = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8"))
    assert entry["resource"] == "/Finance/payroll.csv"
    assert entry["classification"] == "SECRET"
    assert decision.triggered_by == "classification"
