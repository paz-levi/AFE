"""
Baseline model — an agent's signed "ID card".

Defines the Baseline (pydantic model) per the schema in docs/concept.md §4: agent_id,
dispatcher, task, task_embedding, commands, allowed_resources, created_at, and status
("active"/"frozen"). task_embedding is produced by AFE's local embedding model
(sentence-transformers), never an external API. The stored JSON schema also includes a
signature field, but it is not part of this pydantic model — signing.py (day 5) produces
it separately, over the serialized Baseline. Every JIT request at the chokepoint is
ultimately compared against a stored Baseline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

# Small, well-known local embedding model — no external API call, no network at
# runtime. Loaded once, lazily, and reused (see _get_embedding_model), not reloaded on
# every Baseline.create() call.
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

_model: SentenceTransformer | None = None


def _get_embedding_model() -> SentenceTransformer:
    """Return the shared local embedding model, loading it on first use only."""
    global _model
    if _model is None:
        _model = SentenceTransformer(EMBEDDING_MODEL_NAME)
    return _model


class Baseline(BaseModel):
    """An agent's signed ID card — the task, tools, and resources it was dispatched
    with, that every later request is compared against. Signing (HMAC) is added in
    baseline/signing.py, not on this model itself."""

    agent_id: str
    dispatcher: str
    task: str
    task_embedding: list[float]
    commands: list[str]
    allowed_resources: list[str]
    created_at: datetime
    status: Literal["active", "frozen"] = "active"

    @classmethod
    def create(
        cls,
        agent_id: str,
        dispatcher: str,
        task: str,
        commands: list[str],
        allowed_resources: list[str],
    ) -> "Baseline":
        """Build a Baseline, producing task_embedding by encoding `task` with the
        shared local sentence-transformers model — no external API call."""
        model = _get_embedding_model()
        task_embedding = model.encode(task).tolist()
        return cls(
            agent_id=agent_id,
            dispatcher=dispatcher,
            task=task,
            task_embedding=task_embedding,
            commands=commands,
            allowed_resources=allowed_resources,
            created_at=datetime.now(timezone.utc),
        )

    def to_json(self) -> str:
        """Serialize this Baseline to a JSON string, task_embedding included."""
        return self.model_dump_json()

    @classmethod
    def from_json(cls, data: str) -> "Baseline":
        """Reconstruct a Baseline from a JSON string produced by to_json()."""
        return cls.model_validate_json(data)
