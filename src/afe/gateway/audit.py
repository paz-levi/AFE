"""
Audit — the decision log.

Appends one JSONL line per chokepoint decision — agent_id, timestamp, resource,
classification, similarity_score, tier, reason, and triggered_by (which check actually
decided: classification, allowlist, or semantics) — so every decision is explainable and
investigable after the fact, not a black box (docs/concept.md §8).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from afe.gateway.policy import Decision

# repo_root/src/afe/gateway/audit.py -> parents[3] is repo_root.
AUDIT_LOG_PATH = Path(__file__).resolve().parents[3] / "storage" / "audit.jsonl"
AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def log_decision(
    agent_id: str,
    resource: str,
    classification: str,
    similarity_score: float,
    decision: Decision,
) -> None:
    """Append one JSONL line to AUDIT_LOG_PATH recording this chokepoint decision:
    agent_id, a UTC ISO-8601 timestamp, resource, classification, similarity_score,
    tier (decision.tier.value — a plain string, not the Enum), reason, and
    triggered_by. Append-only — never rewrites or truncates prior lines — so the log is
    a durable, explainable history of every decision."""
    entry = {
        "agent_id": agent_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resource": resource,
        "classification": classification,
        "similarity_score": similarity_score,
        "tier": decision.tier.value,
        "reason": decision.reason,
        "triggered_by": decision.triggered_by,
    }
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
