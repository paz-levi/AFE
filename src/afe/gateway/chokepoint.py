"""
Chokepoint — the mandatory pass-through point between the agent and every resource.

Implements evaluate_request(baseline, tool_name, tool_args): builds a request description
from the actual tool call — tool name + arguments + resource — never from the agent's own
self-reported intent (docs/concept.md §7), then orchestrates classification, similarity
and policy as needed, records the outcome via audit, and returns a Decision. Also owns the
kill switch: a red decision freezes the agent's Baseline so every subsequent request is
blocked without further semantic checking (docs/concept.md §6).
"""
