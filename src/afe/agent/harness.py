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

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_TOKENS = 1024

# The tools available to the demo agent, by name. This is the only place tool
# functions are looked up for execution — see execute_tool_call below. On day 8 this
# becomes the seam where the gateway chokepoint is inserted, ahead of the real call.
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


def execute_tool_call(tool_name: str, tool_input: dict[str, Any]) -> Any:
    """
    The single call site where a tool actually gets invoked.

    Looks up `tool_name` in TOOL_REGISTRY and calls it with `tool_input` unpacked as
    keyword arguments. Every tool call made anywhere in the agent loop must go through
    this function — not be inlined or duplicated elsewhere — because this is exactly
    where the gateway chokepoint will be inserted on day 8, ahead of the real call.
    """
    try:
        tool = TOOL_REGISTRY[tool_name]
    except KeyError:
        raise ValueError(
            f"Unknown tool: {tool_name!r}. Registered tools: {sorted(TOOL_REGISTRY)}"
        ) from None
    return tool(**tool_input)


def run_agent(
    system_prompt: str,
    task: str,
    *,
    model: str = DEFAULT_MODEL,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    client: anthropic.Anthropic | None = None,
) -> list[dict[str, Any]]:
    """
    Run the agent loop: send `system_prompt` + `task` to Claude along with the tool
    definitions, execute every tool_use block via execute_tool_call, send the results
    back as a tool_result message, and repeat until the API's stop_reason is no longer
    "tool_use". A text block in the final response is the agent's answer — printed here
    since this loop is only a usage demo; a later day wires the return value into
    demo/run_demo.py instead of printing.

    Returns the full sequence of tool calls made during the run, in order, as
    {"name", "input", "result"} dicts.
    """
    client = client or anthropic.Anthropic()
    messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
    tool_calls: list[dict[str, Any]] = []

    while True:
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt,
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

        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                result = execute_tool_call(block.name, block.input)
                tool_calls.append(
                    {"name": block.name, "input": block.input, "result": result}
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

    calls = run_agent(
        system_prompt=(
            "You are a helpful assistant with access to read_file, send_email, and "
            "query_db tools."
        ),
        task="Read scenarios/clean_report.md and summarize it in two sentences.",
    )
    print(f"\nMade {len(calls)} tool call(s):")
    for call in calls:
        print(f"  - {call['name']}({call['input']})")
