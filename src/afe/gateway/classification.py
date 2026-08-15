"""
Classification — resolving a resource's sensitivity level.

Implements get_classification(path): resolves PUBLIC/INTERNAL/CONFIDENTIAL/SECRET for a
resource from config/classification.json, applying folder inheritance with file-level
override (upward override always allowed; downward override must be explicitly marked and
is logged) and fail-secure defaults (an unclassified resource is CONFIDENTIAL, not PUBLIC).
Verifies the config file's HMAC signature before trusting it — an invalid signature means
AFE refuses to start (docs/concept.md §2.4, §5).
"""
