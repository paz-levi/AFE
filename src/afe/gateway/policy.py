"""
Policy — the three-tier decision engine.

Implements decide_tier(score, classification, resource, baseline): maps a similarity
score and a resource's classification level to green/yellow/red, using
classification-dependent thresholds from config/thresholds.json (never hardcoded —
docs/concept.md §5.3). Encodes the allowlist rule (a resource in allowed_resources is
always green), the PUBLIC always-green rule, and the SECRET rule (blocked unless
explicitly allowlisted, regardless of similarity score) — see docs/concept.md §6.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from afe.baseline.baseline import Baseline
from afe.gateway.signed_policy import load_signed_policy

# repo_root/src/afe/gateway/policy.py -> parents[3] is repo_root.
_THRESHOLDS_PATH = Path(__file__).resolve().parents[3] / "config" / "thresholds.json"

_THRESHOLDS: dict[str, Any] | None = None


class Tier(str, Enum):
    """The three possible outcomes of a JIT request decision (docs/concept.md §6)."""

    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


def _load_thresholds(path: Path | None = None) -> dict[str, Any]:
    """Load and verify the signed thresholds file at `path` once, caching the result
    at module level. `path` defaults to the current value of _THRESHOLDS_PATH, looked
    up dynamically (not bound at def-time) so tests can monkeypatch that module
    attribute and have it take effect; normal use never passes `path` explicitly.
    Delegates the actual read/verify/unwrap to
    afe.gateway.signed_policy.load_signed_policy — this module only owns the
    caching."""
    global _THRESHOLDS
    if _THRESHOLDS is not None:
        return _THRESHOLDS
    if path is None:
        path = _THRESHOLDS_PATH

    _THRESHOLDS = load_signed_policy(path)
    return _THRESHOLDS


def decide_tier(
    score: float, classification: str, resource: str, baseline: Baseline
) -> Tier:
    """Resolve a JIT request into green/yellow/red, in strict precedence order
    (docs/concept.md §6):

    1. `resource` is in `baseline.allowed_resources` -> GREEN, regardless of score or
       classification (the allowlist rule).
    2. `classification` is PUBLIC -> GREEN, regardless of score.
    3. `classification` is SECRET -> RED, regardless of score (blocked unless
       explicitly allowlisted — see rule 1).
    4. Otherwise (INTERNAL/CONFIDENTIAL): compare `score` against the
       classification's green/yellow thresholds from config/thresholds.json.
    """
    if resource in baseline.allowed_resources:
        return Tier.GREEN

    if classification == "PUBLIC":
        return Tier.GREEN

    if classification == "SECRET":
        return Tier.RED

    thresholds = _load_thresholds()
    level = thresholds.get(classification)
    if level is None:
        raise ValueError(
            f"Unexpected classification {classification!r}: no thresholds configured "
            "for it in config/thresholds.json (expected INTERNAL or CONFIDENTIAL here "
            "— PUBLIC/SECRET are handled above and never reach this lookup)."
        )
    if score >= level["green"]:
        return Tier.GREEN
    if score >= level["yellow"]:
        return Tier.YELLOW
    return Tier.RED
