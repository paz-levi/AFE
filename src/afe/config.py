"""
Central configuration for AFE.

Provides get_hmac_secret(): the HMAC key used to sign/verify Baselines and the signed
policy files (config/classification.json, config/thresholds.json).

If AFE_HMAC_SECRET is unset, a PUBLIC development key (DEV_HMAC_SECRET below) is used
instead, with a loud warning on stderr. It exists only so a fresh clone can run the
tests and the eval: the repo's policy files are signed with it. Because it is
published in this file, it provides no integrity guarantee at all — anyone can forge
a signature with it. Never use it outside local development.
"""

from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

# PUBLIC, INSECURE development key. Committed on purpose so a fresh clone works with
# no setup. Anyone can read it, so anything signed with it can be forged.
DEV_HMAC_SECRET = "AFE_PUBLIC_DEV_KEY_NOT_FOR_PRODUCTION"

_DEV_KEY_WARNING = (
    "\n"
    "**********************************************************************\n"
    "* WARNING: AFE_HMAC_SECRET is not set. Using the PUBLIC development  *\n"
    "* key from src/afe/config.py. It is committed to the repository, so  *\n"
    "* policy and Baseline signatures provide NO integrity protection.    *\n"
    "* Never use it in production: set AFE_HMAC_SECRET and re-sign the    *\n"
    "* policy files with scripts/sign_policy.py.                          *\n"
    "**********************************************************************\n"
)

_warned_dev_key = False


def get_hmac_secret() -> bytes:
    """
    Read the AFE_HMAC_SECRET environment variable (loading .env first, same
    python-dotenv pattern harness.py uses for ANTHROPIC_API_KEY) and return it encoded
    as bytes, ready to pass to signing.py's sign_baseline/verify_baseline.

    If the variable is unset or empty, return the public DEV_HMAC_SECRET instead and
    print a warning to stderr (once per process).
    """
    global _warned_dev_key
    load_dotenv()
    secret = os.environ.get("AFE_HMAC_SECRET")
    if not secret:
        if not _warned_dev_key:
            print(_DEV_KEY_WARNING, file=sys.stderr)
            _warned_dev_key = True
        secret = DEV_HMAC_SECRET
    return secret.encode("utf-8")
