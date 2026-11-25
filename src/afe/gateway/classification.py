"""
Classification — resolving a resource's sensitivity level.

Implements get_classification(path): resolves PUBLIC/INTERNAL/CONFIDENTIAL/SECRET for a
resource from config/classification.json, applying folder inheritance with file-level
override (upward override always allowed; downward override must be explicitly marked and
is logged) and fail-secure defaults (an unclassified resource is CONFIDENTIAL, not PUBLIC).
Verifies the config file's HMAC signature before trusting it — an invalid signature means
AFE refuses to start (docs/concept.md §2.4, §5).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from afe.gateway.resource_paths import normalize_resource_path
from afe.gateway.signed_policy import PolicyIntegrityError, load_signed_policy

logger = logging.getLogger(__name__)

# repo_root/src/afe/gateway/classification.py -> parents[3] is repo_root.
_CLASSIFICATION_PATH = Path(__file__).resolve().parents[3] / "config" / "classification.json"

_POLICY: dict[str, Any] | None = None


def _load_policy(path: Path | None = None) -> dict[str, Any]:
    """Load and verify the signed policy file at `path` once, caching the result at
    module level. `path` defaults to the current value of _CLASSIFICATION_PATH,
    looked up dynamically (not bound at def-time) so tests can monkeypatch that
    module attribute and have it take effect; normal use never passes `path`
    explicitly. Delegates the actual read/verify/unwrap to
    afe.gateway.signed_policy.load_signed_policy — this module only owns the
    caching."""
    global _POLICY
    if _POLICY is not None:
        return _POLICY
    if path is None:
        path = _CLASSIFICATION_PATH

    _POLICY = load_signed_policy(path)
    return _POLICY


def _is_under_folder(path: str, folder: str) -> bool:
    """True if `path` is `folder` itself or a path under it — matched on path-segment
    boundaries, not a bare string prefix, so "/reports_backup/x.md" doesn't
    false-match the "/reports" folder."""
    return path == folder or path.startswith(folder.rstrip("/") + "/")


def get_classification(path: str) -> str:
    """Resolve the classification level for `path`: a matching file_overrides entry
    wins first (logging a warning if it's a downward override), then the longest
    matching folder prefix in folders, else the fail-secure default CONFIDENTIAL
    (docs/concept.md §5.2) — never PUBLIC for an unclassified resource. `path` is
    normalized before lookup (see resource_paths.py) so an incoming path missing a
    leading slash, or using backslashes, still matches config/classification.json's
    canonical (already leading-slash) keys instead of silently falling through to
    the fail-secure default.

    Matching is case-insensitive only where that can make the result stricter:
    folder rules and upward file overrides match in any casing, so
    "/Finance/payroll.csv" resolves like "/finance/payroll.csv". A downward
    override (which loosens a file's level) matches its exact path only: on a
    case-sensitive filesystem a case variant is a different file, so it falls back
    to its folder's level instead of inheriting the looser one. The lower-cased
    form is used for matching only; callers keep the original string (e.g. for
    the audit log)."""
    path = normalize_resource_path(path)
    folded = path.lower()
    policy = _load_policy()

    file_overrides = policy.get("file_overrides", {})
    if path in file_overrides:
        override_key = path
    else:
        override_key = next(
            (
                key
                for key, override in file_overrides.items()
                if not override.get("downward_override") and key.lower() == folded
            ),
            None,
        )
    if override_key is not None:
        override = file_overrides[override_key]
        level = override["level"]
        if override.get("downward_override"):
            logger.warning(
                "Downward classification override applied for %s: level=%s", path, level
            )
        return level

    folders = policy.get("folders", {})
    best_match: tuple[str, str] | None = None
    for folder, level in folders.items():
        if _is_under_folder(folded, folder.lower()):
            if best_match is None or len(folder) > len(best_match[0]):
                best_match = (folder, level)
    if best_match is not None:
        return best_match[1]

    logger.warning(
        "No classification match for %s; defaulting to CONFIDENTIAL (fail-secure).",
        path,
    )
    return "CONFIDENTIAL"
