"""
Signed policy loading — shared verify-and-unwrap logic for signed policy files.

Provides load_signed_policy(path): reads a {"policy": ..., "signature": ...} JSON
envelope, verifies its HMAC signature via afe.baseline.signing.verify_bytes and
afe.config.get_hmac_secret (the same canonical json.dumps(policy, sort_keys=True)
pattern used everywhere else policies are signed/verified), and returns the inner
"policy" dict. Raises PolicyIntegrityError — defined here, not tied to any one
policy's shape — on any problem: missing file, malformed JSON, missing keys, or a
signature that doesn't verify. Deliberately does no caching: callers (classification.py,
policy.py) each own their own module-level cache, since each has its own notion of when
to invalidate it (e.g. tests monkeypatching a module attribute back to None).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from afe.baseline.signing import verify_bytes
from afe.config import get_hmac_secret


class PolicyIntegrityError(RuntimeError):
    """Raised when a signed policy file (classification.json, thresholds.json) is
    missing, unreadable, malformed, or fails HMAC verification. Fail-secure: AFE
    refuses to start rather than trust an unsigned or tampered policy."""


def load_signed_policy(path: Path) -> dict[str, Any]:
    """Read, verify, and unwrap the signed policy envelope at `path`, returning just
    the inner "policy" dict. Any problem — missing file, malformed JSON, missing keys,
    or a signature that doesn't verify — raises PolicyIntegrityError immediately
    rather than falling back to an unsigned or partially-trusted read. No caching:
    every call re-reads and re-verifies `path`."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        policy = data["policy"]
        signature = data["signature"]
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as exc:
        raise PolicyIntegrityError(
            f"Could not read or parse policy file {path}: {exc}"
        ) from exc

    canonical = json.dumps(policy, sort_keys=True).encode("utf-8")
    if not verify_bytes(canonical, signature, get_hmac_secret()):
        raise PolicyIntegrityError(
            f"Signature verification failed for {path} — refusing to start. The "
            "policy file may have been tampered with."
        )

    return policy
