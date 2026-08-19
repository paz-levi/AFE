"""Tests for src/afe/gateway/similarity.py's compute_similarity().

Exercises the real local sentence-transformers model (not mocked) — the point of this
test is to confirm the embedding + cosine similarity pipeline actually produces a high
score for matching text and a lower score for unrelated text. No other test in this repo
does this (test_baseline.py and friends build Baseline directly with a literal
task_embedding specifically to avoid loading the model); the model is already cached
locally, so this doesn't trigger a download, only a load. HF_HUB_OFFLINE is set before
import so this never depends on network access even with a warm cache.
"""

from __future__ import annotations

import os

os.environ.setdefault("HF_HUB_OFFLINE", "1")

import pytest

from afe.baseline.baseline import Baseline
from afe.gateway.similarity import compute_similarity

TASK = "Summarize the Q3 financial reports for the finance team"


@pytest.fixture(scope="module")
def baseline() -> Baseline:
    return Baseline.create(
        agent_id="agent-1",
        dispatcher="alice@example.com",
        task=TASK,
        commands=["read_file"],
        allowed_resources=["reports/*.md"],
    )


def test_matching_description_scores_near_one(baseline):
    score = compute_similarity(TASK, baseline)

    assert score == pytest.approx(1.0, abs=1e-4)


def test_unrelated_description_scores_lower(baseline):
    matching_score = compute_similarity(TASK, baseline)
    unrelated_score = compute_similarity(
        "Order a large pepperoni pizza for the office party", baseline
    )

    assert unrelated_score < matching_score
    assert unrelated_score < 0.5
