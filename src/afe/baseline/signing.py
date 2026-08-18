"""
Signing — HMAC integrity for Baselines and policy files.

Provides sign/verify functions (HMAC-SHA256) used both to sign a newly created Baseline
and, per docs/concept.md §2.4, to sign the policy files themselves (classification.json,
thresholds.json) so they can't be silently edited at runtime. Guarantees integrity — that
the signed content hasn't changed — not secrecy (docs/glossary.md's Integrity-vs-Secrecy
entry): anyone holding a signed Baseline can still read it. secret_key must therefore
never be written to disk in plaintext alongside what it signs — that would let anyone who
can read the signed file also forge new signatures for it. Both functions take
secret_key as a plain parameter; this file has no opinion on where it comes from (env,
config, a secrets manager) — that's the caller's responsibility (see config.py's
get_hmac_secret for the one used elsewhere in this project).

sign_bytes/verify_bytes are the general mechanism underneath everything above: raw HMAC
over arbitrary bytes, with no knowledge of Baseline or any other document shape. Policy
files are signed with the exact same mechanism, but not by this file directly — that
happens out-of-band, via scripts/sign_policy.py, a standalone script a human runs
manually (per §2.4: the policy is edited and re-signed by a person, not by app code at
runtime).

The signed payload deliberately excludes `status`: status is expected to change
legitimately over an agent's lifetime (e.g. the kill switch flipping active -> frozen),
so a signature should attest to the original approved task — agent_id, dispatcher, task,
task_embedding, commands, allowed_resources, created_at — not current lifecycle state.
Signing the full document would make every legitimate freeze look indistinguishable from
tampering.
"""

from __future__ import annotations

import hashlib
import hmac
import json

from afe.baseline.baseline import Baseline


def sign_bytes(payload: bytes, secret_key: bytes) -> str:
    """Compute an HMAC-SHA256 signature over arbitrary `payload` bytes, returned as a
    hex string. No knowledge of what `payload` represents — the general mechanism
    everything else in this file (and scripts/sign_policy.py) builds on."""
    return hmac.new(secret_key, payload, hashlib.sha256).hexdigest()


def verify_bytes(payload: bytes, signature: str, secret_key: bytes) -> bool:
    """Recompute the HMAC over `payload` the same way sign_bytes does, and compare it
    against `signature` in constant time. Returns True only on an exact match."""
    return hmac.compare_digest(sign_bytes(payload, secret_key), signature)


def _canonical_payload(baseline: Baseline) -> bytes:
    """Build the deterministic byte payload that gets signed: every Baseline field
    except `status` (see module docstring for why), as sort-keyed JSON so the same
    Baseline always produces the same bytes regardless of field-declaration order."""
    data = baseline.model_dump(mode="json", exclude={"status"})
    return json.dumps(data, sort_keys=True).encode("utf-8")


def sign_baseline(baseline: Baseline, secret_key: bytes) -> str:
    """Compute an HMAC-SHA256 signature over `baseline`'s canonical payload (every
    field except `status`), returned as a hex string."""
    return sign_bytes(_canonical_payload(baseline), secret_key)


def verify_baseline(baseline: Baseline, signature: str, secret_key: bytes) -> bool:
    """Recompute the HMAC the same way sign_baseline does, and compare it against
    `signature` in constant time. Returns True only on an exact match. Since the
    signed payload excludes `status`, a Baseline whose only change since signing is its
    `status` field still verifies True."""
    return verify_bytes(_canonical_payload(baseline), signature, secret_key)
