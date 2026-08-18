"""Tests for src/afe/config.py's get_hmac_secret()."""

import pytest

from afe.config import get_hmac_secret


def test_get_hmac_secret_raises_when_unset(monkeypatch):
    monkeypatch.delenv("AFE_HMAC_SECRET", raising=False)
    # get_hmac_secret() calls load_dotenv() internally, and load_dotenv()'s default
    # behavior is to populate any env var that is currently unset — so without this,
    # a real .env file with AFE_HMAC_SECRET set (as this repo has) would silently
    # refill the var we just deleted, and the test would pass or fail depending on
    # machine state instead of testing the "is it set" check itself.
    monkeypatch.setattr("afe.config.load_dotenv", lambda *args, **kwargs: None)

    with pytest.raises(RuntimeError):
        get_hmac_secret()
