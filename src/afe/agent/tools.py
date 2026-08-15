"""
Mock tools for the demo agent.

Test doubles for real resource access — read_file(path), send_email(to, body),
query_db(query) — that log every call made against them and return fake data, so the
harness has tools to call and the chokepoint has requests to intercept, without any real
I/O or external dependency.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

# Shared call log — every mock tool call appends one entry here: tool name, arguments,
# and a UTC timestamp. The harness and, later, the chokepoint both read from this log.
TOOL_CALLS: list[dict] = []


def _log_call(tool: str, **args) -> None:
    """Append one entry to TOOL_CALLS for a call to `tool` made with `args`."""
    TOOL_CALLS.append(
        {
            "tool": tool,
            "args": args,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def read_file(path: str) -> str:
    """
    Mock file read — logs the call, then returns the real content of `path` if it
    exists on disk (utf-8 text), so scenario documents under scenarios/ (including any
    hidden injection payload) actually reach the agent. Falls back to fake placeholder
    content if `path` doesn't exist, instead of raising — this stays a mock tool, not a
    real filesystem API.
    """
    _log_call("read_file", path=path)
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return (
            f"[mock content of {path}]\n"
            "Quarterly summary: revenue up 4% QoQ, expenses flat, no material incidents "
            "to report this period."
        )


def send_email(to: str, body: str) -> dict:
    """Mock email send — logs the call and returns a fake send confirmation."""
    _log_call("send_email", to=to, body=body)
    return {
        "status": "sent",
        "to": to,
        "message_id": f"msg-{uuid.uuid4()}",
    }


def query_db(query: str) -> list[dict]:
    """Mock DB query — logs the call and returns a fixed set of fake rows."""
    _log_call("query_db", query=query)
    return [
        {"id": 1, "name": "Acme Corp", "amount": 12500.00},
        {"id": 2, "name": "Globex Inc", "amount": 8320.50},
        {"id": 3, "name": "Initech LLC", "amount": 4110.75},
    ]
