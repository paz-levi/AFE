"""
Central configuration for AFE.

Loads and exposes settings that must stay out of code so they can be recalibrated without
a code change (config-driven design, per docs/work_plan.md): paths to the signed policy
files (config/classification.json, config/thresholds.json), the HMAC secret key used to
sign/verify Baselines and policy files, the local embedding model name, and the storage
location for Baselines and the audit log.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv


def get_hmac_secret() -> bytes:
    """
    Read the AFE_HMAC_SECRET environment variable (loading .env first, same
    python-dotenv pattern harness.py uses for ANTHROPIC_API_KEY) and return it encoded
    as bytes, ready to pass to signing.py's sign_baseline/verify_baseline.

    Raises RuntimeError if the variable is unset or empty — fail loudly here, at
    startup, rather than with a confusing error deep inside signing.py later.
    """
    load_dotenv()
    secret = os.environ.get("AFE_HMAC_SECRET")
    if not secret:
        raise RuntimeError(
            "AFE_HMAC_SECRET is not set. Set it in your environment or in a local "
            ".env file before running anything that signs or verifies a Baseline."
        )
    return secret.encode("utf-8")
