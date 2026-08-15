"""
Audit — the decision log.

Appends one JSONL line per chokepoint decision — agent_id, timestamp, resource,
classification, similarity_score, tier, reason, and triggered_by (which check actually
decided: classification, allowlist, or semantics) — so every decision is explainable and
investigable after the fact, not a black box (docs/concept.md §8).
"""
