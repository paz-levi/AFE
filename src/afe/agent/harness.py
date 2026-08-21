"""
Agent harness — the demo agent's LLM + tool-calling loop.

Runs a system prompt + task through the Claude API (default model: claude-sonnet-5),
handles tool_use blocks by dispatching to the mock tools in tools.py, and routes every
tool call through the gateway chokepoint before it executes. Per docs/concept.md §2.3
and §11, this is the one deliberate place in the project that talks to an external LLM
API — a documented demo simplification, not part of AFE's own (local-only) design.
"""

from __future__ import annotations

import inspect
import json
from typing import Any, Callable

import anthropic

from afe.agent.tools import query_db, read_file, send_email
from afe.baseline.baseline import Baseline
from afe.baseline.preflight import PreFlightRejectedError, check_intent
from afe.baseline.signing import sign_baseline
from afe.config import get_hmac_secret
from afe.gateway.chokepoint import evaluate_request
from afe.gateway.policy import Decision, Tier
from afe.storage.store import BaselineStore

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_TOKENS = 1024

# The tools available to the demo agent, by name. This is the only place tool
# functions are looked up for execution — see Agent._execute_tool_call below.
TOOL_REGISTRY: dict[str, Callable[..., Any]] = {
    "read_file": read_file,
    "send_email": send_email,
    "query_db": query_db,
}

# JSON Schema for each tool's arguments. Kept separate from TOOL_REGISTRY because a
# schema isn't recoverable from a plain Python function signature without a decorator
# or extra typing metadata, and the mock tools in tools.py are deliberately undecorated.
_INPUT_SCHEMAS: dict[str, dict[str, Any]] = {
    "read_file": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path of the file to read."},
        },
        "required": ["path"],
    },
    "send_email": {
        "type": "object",
        "properties": {
            "to": {"type": "string", "description": "Recipient email address."},
            "body": {"type": "string", "description": "Email body text."},
        },
        "required": ["to", "body"],
    },
    "query_db": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The query to run against the mock database.",
            },
        },
        "required": ["query"],
    },
}


def _build_tool_definitions() -> list[dict[str, Any]]:
    """Build Claude tool definitions from TOOL_REGISTRY: name, docstring-derived
    description, and the matching JSON Schema input_schema."""
    return [
        {
            "name": name,
            "description": inspect.getdoc(func) or "",
            "input_schema": _INPUT_SCHEMAS[name],
        }
        for name, func in TOOL_REGISTRY.items()
    ]


TOOL_DEFINITIONS = _build_tool_definitions()


class MaxTurnsExceededError(RuntimeError):
    """
    Raised when Agent.run's tool-use loop exceeds max_turns.

    A hard turn-count ceiling is a second, independent safety stop against runaway
    agent loops — separate from the gateway chokepoint's kill switch. Neither
    mechanism relies on the other: this one stops the loop purely by counting turns,
    regardless of what the chokepoint would eventually decide about any given
    request. The check runs before client.messages.create() is called, so once the
    ceiling is reached no further API call is ever made — execution isn't merely
    blocked afterward.
    """


class Agent:
    """A demo agent bound to a signed Baseline, with every tool call routed through
    the gateway chokepoint. Bundles baseline/signature/store as instance state so a
    chokepoint freeze (kill switch) is immediately visible to every subsequent call
    in the same run, without manually re-threading updated values through return
    values."""

    def __init__(
        self,
        baseline: Baseline,
        signature: str,
        store: BaselineStore,
        system_prompt: str,
        client: anthropic.Anthropic | None = None,
    ) -> None:
        self.baseline = baseline
        self.signature = signature
        self.store = store
        # The system prompt this agent was Pre-Flight-screened with (see create). run()
        # reads it from here rather than taking it as a parameter, so the prompt that
        # actually reaches the API is the same one check_intent cleared — a run can't
        # substitute a different, unscreened prompt after the fact.
        self.system_prompt = system_prompt
        self.client = client or anthropic.Anthropic()

    @classmethod
    def create(
        cls,
        agent_id: str,
        dispatcher: str,
        system_prompt: str,
        task: str,
        commands: list[str],
        allowed_resources: list[str],
        store: BaselineStore,
        client: anthropic.Anthropic | None = None,
    ) -> "Agent":
        """Pre-Flight-screen `system_prompt`, then build a new Baseline
        (Baseline.create), sign it, persist it via `store`, and return a ready-to-run
        Agent — bundles the screen+create+sign+register sequence into one call, same
        alternate-constructor pattern as Baseline.create.

        The screen runs FIRST, before Baseline.create: if check_intent flags the prompt
        as malicious this raises PreFlightRejectedError immediately, and no Baseline is
        built, signed, or saved. That ordering is the point — AFE must never end up
        holding a signed Baseline that authorizes a prompt it would have rejected
        (docs/concept.md §2.1). Catching *direct* prompt injection here is Pre-Flight's
        whole job; *indirect* injection arriving later via a document the agent reads is
        caught downstream at the chokepoint instead.
        """
        client = client or anthropic.Anthropic()
        is_malicious, explanation = check_intent(system_prompt, client=client)
        if is_malicious:
            raise PreFlightRejectedError(explanation)

        baseline = Baseline.create(
            agent_id=agent_id,
            dispatcher=dispatcher,
            task=task,
            commands=commands,
            allowed_resources=allowed_resources,
        )
        signature = sign_baseline(baseline, get_hmac_secret())
        store.save(baseline, signature)
        return cls(baseline, signature, store, system_prompt, client=client)

    def _execute_tool_call(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        current_intent: str | None = None,
    ) -> tuple[Any, Decision]:
        """The single call site where a tool actually gets invoked, and the
        chokepoint's mandatory pass-through point. Updates self.baseline/
        self.signature from evaluate_request's return value on every call, frozen or
        not, so the kill switch is visible immediately within this run.

        `current_intent` is passed straight through to evaluate_request, which passes
        it straight through to the audit log as evidence only (docs/concept.md §7) —
        it plays no part in the decision made here.

        Returns a (result, decision) pair — `result` is either the real tool's return
        value or a {"blocked": True, "reason": ...} dict when the decision is red;
        `decision` is always the Decision evaluate_request produced, so run can
        record it in the tool_calls log without evaluating the request a second time.
        """
        decision, self.baseline, self.signature = evaluate_request(
            self.baseline,
            self.signature,
            tool_name,
            tool_input,
            self.store,
            current_intent,
        )
        if decision.tier == Tier.RED:
            return {"blocked": True, "reason": decision.reason}, decision

        try:
            tool = TOOL_REGISTRY[tool_name]
        except KeyError:
            raise ValueError(
                f"Unknown tool: {tool_name!r}. Registered tools: {sorted(TOOL_REGISTRY)}"
            ) from None
        return tool(**tool_input), decision

    def run(
        self,
        task: str,
        *,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        max_turns: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Run the agent loop: send self.system_prompt (the Pre-Flight-screened prompt this
        agent was created with — not a parameter, so an unscreened prompt can't be
        swapped in at run time) + `task` to Claude along with the tool definitions,
        execute every tool_use block via self._execute_tool_call
        (which routes it through the gateway chokepoint against self.baseline first),
        send the results back as a tool_result message, and repeat until the API's
        stop_reason is no longer "tool_use". A text block in the final response is
        the agent's answer — printed here since this loop is only a usage demo; a
        later day wires the return value into demo/run_demo.py instead of printing.

        `task` is the literal opening user message. It is independent of the task string
        used to build the Baseline's embedding at creation time — the demo happens to
        reuse one string for both, but nothing requires that.

        `max_turns` caps the number of tool_use turns; exceeding it raises
        MaxTurnsExceededError instead of looping forever — see that class's docstring.

        Returns the full sequence of tool calls made during the run, in order, as
        {"name", "input", "result", "current_intent", "decision"} dicts.
        """
        messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
        tool_calls: list[dict[str, Any]] = []
        turns = 0

        while True:
            if turns >= max_turns:
                raise MaxTurnsExceededError(
                    f"Agent exceeded max_turns={max_turns} while running task: {task!r}. "
                    f"Tool calls made so far: {tool_calls!r}"
                )

            response = self.client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=self.system_prompt,
                tools=TOOL_DEFINITIONS,
                messages=messages,
            )
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason != "tool_use":
                final_text = "\n".join(
                    block.text for block in response.content if block.type == "text"
                )
                if final_text:
                    print(f"Final answer:\n{final_text}")
                break

            turns += 1

            # The agent's own account of what it's doing this turn, collected purely as
            # evidence per docs/concept.md §7 — NOT used by the chokepoint's decision
            # logic. The request description used for the semantic comparison there is
            # built from the tool call itself (name + args + resource), never from this
            # self-reported text, since an attacker who can inject instructions could
            # also phrase a report that sounds aligned.
            current_intent = (
                "\n".join(block.text for block in response.content if block.type == "text")
                or None
            )

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result, decision = self._execute_tool_call(
                        block.name, block.input, current_intent
                    )
                    tool_calls.append(
                        {
                            "name": block.name,
                            "input": block.input,
                            "result": result,
                            "current_intent": current_intent,
                            "decision": decision,
                        }
                    )
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result
                            if isinstance(result, str)
                            else json.dumps(result),
                        }
                    )
            messages.append({"role": "user", "content": tool_results})

        return tool_calls


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv()

    from afe.storage.store import CachedStore, JSONFileStore

    store = CachedStore(JSONFileStore("storage/baselines"))
    task = "Read scenarios/clean_report.md and summarize it in two sentences."
    agent = Agent.create(
        agent_id="demo-agent",
        dispatcher="cli",
        system_prompt=(
            "You are a helpful assistant with access to read_file, send_email, and "
            "query_db tools."
        ),
        task=task,
        commands=["read_file", "send_email", "query_db"],
        allowed_resources=["scenarios/clean_report.md"],
        store=store,
    )

    calls = agent.run(task=task)
    print(f"\nMade {len(calls)} tool call(s):")
    for call in calls:
        print(f"  - {call['name']}({call['input']})")
