"""
Policy — the three-tier decision engine.

Implements decide_tier(score, classification, baseline): maps a similarity score and a
resource's classification level to green/yellow/red, using classification-dependent
thresholds from config/thresholds.json (never hardcoded — docs/concept.md §5.3). Encodes
the allowlist rule (a resource in allowed_resources is always green), the PUBLIC
always-green rule, and the SECRET rule (blocked unless explicitly allowlisted, regardless
of similarity score) — see docs/concept.md §6.
"""
