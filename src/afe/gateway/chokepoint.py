"""
Chokepoint — the mandatory pass-through point between the agent and every resource.

Implements evaluate_request(baseline, tool_name, tool_args): builds a request description
from the actual tool call — tool name + arguments + resource — never from the agent's own
self-reported intent (docs/concept.md §7), then orchestrates classification, similarity
and policy as needed, records the outcome via audit, and returns a Decision. Also owns the
kill switch: a red decision freezes the agent's Baseline so every subsequent request is
blocked without further semantic checking (docs/concept.md §6).
"""

from __future__ import annotations

from typing import Any

from afe.baseline.baseline import Baseline
from afe.gateway import audit
from afe.gateway.classification import get_classification
from afe.gateway.policy import Decision, decide_tier
from afe.gateway.similarity import compute_similarity


def _extract_resource(tool_name: str, tool_args: dict[str, Any]) -> str:
    """Resolve the resource identifier a tool call is acting on. "read_file" is the
    only tool with a real, classifiable resource today: its `path` argument is
    returned directly, matching entries in config/classification.json and a
    Baseline's allowed_resources.

    Every other tool gets a synthetic identifier "{tool_name}:{first_arg_value}"
    instead. This is a known POC simplification — config/classification.json only
    models file-shaped resources today — and the synthetic string is built so it never
    matches a real folder or file_override, so get_classification() always falls
    through to its fail-secure CONFIDENTIAL default for these tools
    (docs/concept.md §5.2) rather than silently defaulting an unmodeled resource to
    PUBLIC.
    """
    if tool_name == "read_file":
        return tool_args["path"]
    first_value = next(iter(tool_args.values()), "")
    return f"{tool_name}:{first_value}"


def _build_description(tool_name: str, tool_args: dict[str, Any]) -> str:
    """Build the request description that enters the semantic comparison — built
    entirely from the actual tool call (tool name + arguments), never from the agent's
    own self-reported intent (docs/concept.md §7): an attacker able to inject
    instructions into what the agent does could just as easily inject a report that
    sounds aligned, so the comparison has to be grounded in what the agent is actually
    about to do."""
    return f"{tool_name}({tool_args})"


def evaluate_request(baseline: Baseline, tool_name: str, tool_args: dict[str, Any]) -> Decision:
    """The chokepoint itself: evaluate one tool call against `baseline` and return a
    Decision.

    Extracts the resource and a request description from the actual tool call,
    resolves the resource's classification, computes its semantic similarity against
    the baseline's task unconditionally (every decision gets a real similarity_score in
    the audit log, even when allowlist or classification precedence ends up deciding
    the tier instead), applies policy precedence via decide_tier, logs the outcome via
    audit.log_decision, and returns the Decision.

    Does not implement the kill switch (freezing baseline.status to "frozen" on a red
    decision) mentioned in this module's own docstring above — that's Day 9 scope. A
    red Decision here is simply returned to the caller like any other; harness.py is
    responsible for refusing to act on it.
    """
    resource = _extract_resource(tool_name, tool_args)
    description = _build_description(tool_name, tool_args)

    classification = get_classification(resource)
    score = compute_similarity(description, baseline)
    decision = decide_tier(score, classification, resource, baseline)

    audit.log_decision(baseline.agent_id, resource, classification, score, decision)

    return decision
