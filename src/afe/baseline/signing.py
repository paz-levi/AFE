"""
Signing — HMAC integrity for Baselines and policy files.

Provides sign/verify functions (HMAC-SHA256) used both to sign a newly created Baseline
and, per docs/concept.md §2.4, to sign the policy files themselves (classification.json,
thresholds.json) so they can't be silently edited at runtime. Guarantees integrity — that
the signed content hasn't changed — not secrecy.
"""
