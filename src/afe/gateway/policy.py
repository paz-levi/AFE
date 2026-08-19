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

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from afe.baseline.baseline import Baseline
from afe.gateway.resource_paths import normalize_resource_path
from afe.gateway.signed_policy import load_signed_policy

# repo_root/src/afe/gateway/policy.py -> parents[3] is repo_root.
_THRESHOLDS_PATH = Path(__file__).resolve().parents[3] / "config" / "thresholds.json"

_THRESHOLDS: dict[str, Any] | None = None


class Tier(str, Enum):
    """The three possible outcomes of a JIT request decision (docs/concept.md §6)."""

    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


@dataclass(frozen=True)
class Decision:
    """The outcome of decide_tier: the resulting Tier, a human-readable explanation of
    why, and which check actually decided it — "allowlist", "classification", or
    "semantic" — so every decision is self-explaining in the audit log
    (docs/concept.md §8), not just a bare tier."""

    tier: Tier
    reason: str
    triggered_by: str


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
) -> Decision:
    """Resolve a JIT request into a Decision (green/yellow/red, plus why and which
    check decided it), in strict precedence order (docs/concept.md §6):

    1. `resource` is in `baseline.allowed_resources` -> GREEN, regardless of score or
       classification (the allowlist rule).
    2. `classification` is PUBLIC -> GREEN, regardless of score.
    3. `classification` is SECRET -> RED, regardless of score (blocked unless
       explicitly allowlisted — see rule 1).
    4. Otherwise (INTERNAL/CONFIDENTIAL): compare `score` against the
       classification's green/yellow thresholds from config/thresholds.json.
    """
    normalized_resource = normalize_resource_path(resource)
    if any(
        normalize_resource_path(r) == normalized_resource
        for r in baseline.allowed_resources
    ):
        return Decision(
            tier=Tier.GREEN,
            reason=f"Resource {resource!r} is explicitly allowlisted in the agent's baseline.",
            triggered_by="allowlist",
        )

    if classification == "PUBLIC":
        return Decision(
            tier=Tier.GREEN,
            reason=f"Resource {resource!r} is classified PUBLIC.",
            triggered_by="classification",
        )

    if classification == "SECRET":
        return Decision(
            tier=Tier.RED,
            reason=(
                f"Resource {resource!r} is classified SECRET and is not in the "
                "agent's allowed_resources."
            ),
            triggered_by="classification",
        )

    thresholds = _load_thresholds()
    level = thresholds.get(classification)
    if level is None:
        raise ValueError(
            f"Unexpected classification {classification!r}: no thresholds configured "
            "for it in config/thresholds.json (expected INTERNAL or CONFIDENTIAL here "
            "— PUBLIC/SECRET are handled above and never reach this lookup)."
        )
    if score >= level["green"]:
        return Decision(
            tier=Tier.GREEN,
            reason=(
                f"Similarity score {score:.3f} for {classification} resource "
                f"{resource!r} meets the green threshold ({level['green']})."
            ),
            triggered_by="semantic",
        )
    if score >= level["yellow"]:
        return Decision(
            tier=Tier.YELLOW,
            reason=(
                f"Similarity score {score:.3f} for {classification} resource "
                f"{resource!r} is between the yellow ({level['yellow']}) and green "
                f"({level['green']}) thresholds."
            ),
            triggered_by="semantic",
        )
    return Decision(
        tier=Tier.RED,
        reason=(
            f"Similarity score {score:.3f} for {classification} resource {resource!r} "
            f"is below the yellow threshold ({level['yellow']})."
        ),
        triggered_by="semantic",
    )
