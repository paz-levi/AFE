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

Also collapses ".."/"." traversal segments (via posixpath.normpath) before any
leading-slash handling. Without this, a path like "reports/../finance/payroll.csv"
would match the "/reports" folder as a raw string prefix — a classic path-traversal
bypass — while the OS, when the file is actually opened, resolves ".." and reaches
the real file under "/finance". That divergence between what get_classification()
validates and what open() actually touches is exactly the class of bug this
function exists to prevent.
"""

from __future__ import annotations

import posixpath


def normalize_resource_path(path: str) -> str:
    """Normalize `path` to a canonical resource-identifier form: backslashes
    become forward slashes, ".."/"." segments are collapsed via posixpath.normpath
    (so traversal sequences resolve to the same target the OS would actually open,
    before the string is ever compared against config/classification.json or
    allowed_resources), and exactly one leading '/' is enforced. Idempotent —
    normalizing an already-canonical path returns it unchanged.

    If the collapsed path still starts with ".." (it tried to escape above any
    intended root even after resolving traversal segments), it is returned as-is
    without a leading slash forced onto it. Such a path can never match a real
    folder or file_override entry, so it correctly falls through to the
    fail-secure CONFIDENTIAL default in classification.py — no special detection
    needed here, just not silently masking the escape attempt into something that
    looks like a normal resolved path.
    """
    normalized = path.replace("\\", "/")
    normalized = posixpath.normpath(normalized)
    if normalized.startswith(".."):
        return normalized
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized
