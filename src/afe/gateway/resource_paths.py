"""
Resource path normalization — canonical form for resource identifiers.

Provides normalize_resource_path(path): converts a resource identifier (an
incoming tool-call argument, a config/classification.json key, or a
Baseline.allowed_resources entry) to one canonical form, so matching between them
doesn't depend on incidental formatting an LLM (or a human editing config) might
introduce — a missing leading slash, Windows-style backslashes, etc. Used by
classification.py, policy.py, and chokepoint.py — kept as a separate,
dependency-free module so none of the three needs to import from another and risk
a circular import.
"""

from __future__ import annotations


def normalize_resource_path(path: str) -> str:
    """Normalize `path` to a canonical resource-identifier form: backslashes
    become forward slashes, and exactly one leading '/' is enforced. Idempotent —
    normalizing an already-canonical path returns it unchanged."""
    normalized = path.replace("\\", "/")
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized
