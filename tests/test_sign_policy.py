"""Tests for scripts/sign_policy.py's sign_policy_file()."""

import json
import sys
from pathlib import Path

# scripts/ is a standalone directory, not part of the afe package — add it to the
# path so the test can import the script directly, same as a human would run it.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from sign_policy import sign_policy_file  # noqa: E402

from afe.gateway import classification  # noqa: E402
from afe.gateway.classification import get_classification  # noqa: E402

TEST_SECRET = "test-secret-for-sign-policy-tests"

RAW_POLICY = {
    "folders": {
        "/finance": "SECRET",
        "/reports": "INTERNAL",
    },
    "file_overrides": {
        "/reports/board_summary.md": {"level": "SECRET"},
    },
}


def test_sign_policy_file_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("AFE_HMAC_SECRET", TEST_SECRET)

    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(RAW_POLICY), encoding="utf-8")

    # First sign: raw JSON -> signed envelope.
    sign_policy_file(str(policy_path))
    data = json.loads(policy_path.read_text(encoding="utf-8"))
    assert set(data.keys()) == {"policy", "signature"}
    assert data["policy"] == RAW_POLICY  # not double-wrapped

    # Second sign: already-signed envelope -> still a single-level envelope, not
    # nested inside itself.
    sign_policy_file(str(policy_path))
    data = json.loads(policy_path.read_text(encoding="utf-8"))
    assert set(data.keys()) == {"policy", "signature"}
    assert data["policy"] == RAW_POLICY

    # The re-signed file must still load and resolve correctly.
    monkeypatch.setattr(classification, "_CLASSIFICATION_PATH", policy_path)
    monkeypatch.setattr(classification, "_POLICY", None)
    assert get_classification("/finance/payroll.csv") == "SECRET"
