"""Tests for src/afe/config.py's get_hmac_secret()."""

import pytest

from afe import config
from afe.config import DEV_HMAC_SECRET, get_hmac_secret


@pytest.fixture
def no_dotenv(monkeypatch):
    # get_hmac_secret() calls load_dotenv() internally, and load_dotenv()'s default
    # behavior is to populate any env var that is currently unset — so without this,
    # a local .env file with AFE_HMAC_SECRET set would silently refill the var a test
    # just deleted, and the result would depend on machine state.
    monkeypatch.setattr("afe.config.load_dotenv", lambda *args, **kwargs: None)
    monkeypatch.setattr(config, "_warned_dev_key", False)


def test_unset_secret_falls_back_to_dev_key_with_warning(monkeypatch, no_dotenv, capsys):
    monkeypatch.delenv("AFE_HMAC_SECRET", raising=False)

    assert get_hmac_secret() == DEV_HMAC_SECRET.encode("utf-8")
    assert "PUBLIC development" in capsys.readouterr().err


def test_empty_secret_falls_back_to_dev_key(monkeypatch, no_dotenv):
    monkeypatch.setenv("AFE_HMAC_SECRET", "")

    assert get_hmac_secret() == DEV_HMAC_SECRET.encode("utf-8")


def test_dev_key_warning_printed_once_per_process(monkeypatch, no_dotenv, capsys):
    monkeypatch.delenv("AFE_HMAC_SECRET", raising=False)

    get_hmac_secret()
    get_hmac_secret()

    assert capsys.readouterr().err.count("PUBLIC development") == 1


def test_set_secret_is_used_and_no_warning(monkeypatch, no_dotenv, capsys):
    monkeypatch.setenv("AFE_HMAC_SECRET", "my-real-secret")

    assert get_hmac_secret() == b"my-real-secret"
    assert "PUBLIC development" not in capsys.readouterr().err
