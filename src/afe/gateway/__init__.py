"""
Gateway package — the JIT chokepoint and its decision engine.

Covers the third of AFE's three architecture stages (docs/concept.md §3): every request
an agent makes for a classified resource passes through here, where it is compared against
the agent's signed Baseline and resolved into a green/yellow/red decision, logged to the
audit trail.
"""
