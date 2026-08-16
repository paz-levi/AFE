"""
Store — Baseline persistence, two-tier.

Defines an abstract BaselineStore interface (get/save), a JSONFileStore implementation
(on-disk, persistent, readable), and a CachedStore that wraps any Store with an in-memory
dict cache so chokepoint lookups are fast without touching disk on every request. Per
docs/work_plan.md, CachedStore is a deliberate, documented substitute for Redis in this
POC — not a production caching layer.
"""

from __future__ import annotations

import abc
import json
from pathlib import Path

from pydantic import ValidationError

from afe.baseline.baseline import Baseline


class AgentNotFoundError(KeyError):
    """Raised by BaselineStore.get() when no Baseline exists for the given agent_id."""


class BaselineStore(abc.ABC):
    """Abstract interface for Baseline persistence — get by agent_id, save a Baseline
    together with its signature. Concrete backends (JSONFileStore, CachedStore, and any
    future SQL-backed store) implement this so callers never depend on a specific
    storage mechanism."""

    @abc.abstractmethod
    def get(self, agent_id: str) -> tuple[Baseline, str]:
        """Return (baseline, signature) for `agent_id`, or raise AgentNotFoundError."""
        raise NotImplementedError

    @abc.abstractmethod
    def save(self, baseline: Baseline, signature: str) -> None:
        """Persist `baseline` and its `signature` together, keyed by agent_id."""
        raise NotImplementedError


class JSONFileStore(BaselineStore):
    """On-disk BaselineStore: one {agent_id}.json file per agent under `directory`,
    holding {"baseline": <baseline fields>, "signature": "<hex>"}."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, agent_id: str) -> Path:
        return self.directory / f"{agent_id}.json"

    def get(self, agent_id: str) -> tuple[Baseline, str]:
        try:
            data = json.loads(self._path(agent_id).read_text(encoding="utf-8"))
            baseline = Baseline.model_validate(data["baseline"])
            signature = data["signature"]
        except (FileNotFoundError, json.JSONDecodeError, KeyError, ValidationError):
            # Collapses "missing" and "corrupted/tampered" into one exception type for
            # POC simplicity — a production version might want a distinct
            # CorruptedBaselineError to tell the two apart for incident response.
            raise AgentNotFoundError(
                f"No baseline found for agent_id {agent_id!r}"
            ) from None
        return baseline, signature

    def save(self, baseline: Baseline, signature: str) -> None:
        payload = {"baseline": baseline.model_dump(mode="json"), "signature": signature}
        self._path(baseline.agent_id).write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )


class CachedStore(BaselineStore):
    """
    Wraps any BaselineStore with an in-memory dict cache: get() serves the cached
    (baseline, signature) pair when present, otherwise delegates to the wrapped store
    and populates the cache; save() always writes through to the wrapped store and
    updates the cache, so the cache never goes stale after a save.

    This is a deliberate, documented substitute for Redis in this POC (docs/concept.md
    §2.3 and the roadmap) — a plain in-process dict, not a real cache: no cross-process
    sharing (a second process sees none of this cache), and no concurrency guarantees
    (see the TOCTOU note in docs/concept.md §11 — near-simultaneous requests for the
    same agent can still race; nothing here makes get()-then-save() atomic).
    """

    def __init__(self, store: BaselineStore) -> None:
        self._store = store
        self._cache: dict[str, tuple[Baseline, str]] = {}

    def get(self, agent_id: str) -> tuple[Baseline, str]:
        if agent_id not in self._cache:
            self._cache[agent_id] = self._store.get(agent_id)
        return self._cache[agent_id]

    def save(self, baseline: Baseline, signature: str) -> None:
        self._store.save(baseline, signature)
        self._cache[baseline.agent_id] = (baseline, signature)
