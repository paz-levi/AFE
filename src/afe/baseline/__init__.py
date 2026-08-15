"""
Baseline package — Pre-Flight scanning and Baseline creation/signing.

Covers the first of AFE's three architecture stages (docs/concept.md §3): before an
agent starts running, its prompt is scanned for malicious intent, and if clean, a signed
Baseline (its "ID card") is created for every later request to be checked against.
"""
