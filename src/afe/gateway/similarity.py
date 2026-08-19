"""
Similarity — local semantic comparison.

Produces an embedding for a request description using AFE's local sentence-transformers
model (loaded once, no network call at runtime — docs/concept.md §2.3), and computes
cosine similarity between that embedding and a Baseline's task_embedding to score how
consistent the current request is with the task the agent was dispatched for.
"""

from __future__ import annotations

from sentence_transformers import util

from afe.baseline.baseline import Baseline, get_embedding_model


def compute_similarity(description: str, baseline: Baseline) -> float:
    """Encode `description` with the shared local embedding model (the same instance
    Baseline.create() uses — see afe.baseline.baseline.get_embedding_model) and return
    its cosine similarity against baseline.task_embedding, as a plain Python float
    clamped to [0, 1]."""
    model = get_embedding_model()
    description_embedding = model.encode(description)
    similarity = util.cos_sim(description_embedding, baseline.task_embedding)
    return max(0.0, min(1.0, float(similarity.item())))
