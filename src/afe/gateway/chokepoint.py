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
from afe.baseline.signing import sign_baseline
from afe.config import get_hmac_secret
from afe.gateway import audit
from afe.gateway.classification import get_classification
from afe.gateway.policy import Decision, Tier, decide_tier
from afe.gateway.resource_paths import normalize_resource_path
from afe.gateway.similarity import compute_similarity
from afe.storage.store import BaselineStore


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
        return normalize_resource_path(tool_args["path"])
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


def evaluate_request(
    baseline: Baseline,
    signature: str,
    tool_name: str,
    tool_args: dict[str, Any],
    store: BaselineStore,
    current_intent: str | None = None,
) -> tuple[Decision, Baseline, str]:
    """The chokepoint itself: evaluate one tool call against `baseline` and return
    (decision, baseline, signature).

    Implements the kill switch (docs/concept.md §6): if `baseline` is already frozen,
    every subsequent request is blocked immediately with no further semantic
    checking — get_classification/compute_similarity/decide_tier are not called.
    Otherwise, extracts the resource and a request description from the actual tool
    call, resolves the resource's classification, computes its semantic similarity
    against the baseline's task unconditionally (every decision gets a real
    similarity_score in the audit log, even when allowlist or classification
    precedence ends up deciding the tier instead), applies policy precedence via
    decide_tier, and logs the outcome via audit.log_decision.

    `current_intent` is the agent's self-reported reasoning for this turn (see
    harness.py's run()). It is passed straight through to audit.log_decision as
    evidence (docs/concept.md §7) and nowhere else — it never reaches
    get_classification, compute_similarity, or decide_tier, so it cannot influence the
    decision it is merely being logged alongside.

    A red decision freezes the baseline: status is updated to "frozen", the updated
    baseline is re-signed and persisted via `store`, and the *updated* (baseline,
    signature) pair is returned — not the ones passed in. The caller (Agent) holds
    baseline/signature as instance state across an entire run; returning the stale
    pre-freeze pair would mean the very next tool call in this same process still
    sees status="active" and only learns about the freeze after a future store.get()
    reload. Returning the updated pair makes the freeze visible immediately, within
    this same run.
    """
    resource = _extract_resource(tool_name, tool_args)

    if baseline.status == "frozen":
        decision = Decision(
            tier=Tier.RED,
            reason=f"Agent {baseline.agent_id} is frozen due to a prior violation.",
            triggered_by="frozen",
        )
        audit.log_decision(
            baseline.agent_id, resource, "N/A", 0.0, decision, current_intent
        )
        return decision, baseline, signature

    description = _build_description(tool_name, tool_args)
    classification = get_classification(resource)
    score = compute_similarity(description, baseline)
    decision = decide_tier(score, classification, resource, baseline)

    audit.log_decision(
        baseline.agent_id, resource, classification, score, decision, current_intent
    )

    if decision.tier == Tier.RED:
        updated_baseline = baseline.model_copy(update={"status": "frozen"})
        updated_signature = sign_baseline(updated_baseline, get_hmac_secret())
        store.save(updated_baseline, updated_signature)
        return decision, updated_baseline, updated_signature

    return decision, baseline, signature
