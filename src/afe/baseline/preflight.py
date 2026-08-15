"""
Pre-Flight — malicious-intent scanning at agent creation.

Asks the LLM whether a proposed system prompt/task looks malicious before a Baseline is
ever created for it, returning a boolean verdict plus an explanation. This is what catches
*direct* prompt injection (a malicious instruction present from the start); *indirect*
prompt injection, introduced later via a document the agent reads, is only caught
downstream at the JIT chokepoint (gateway/chokepoint.py) — see docs/concept.md §2.1.
"""
