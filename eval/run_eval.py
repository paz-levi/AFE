"""
run_eval.py — offline calibration harness for the Chokepoint's decision logic.

Runs every case in eval/eval_set.json through the same three functions
gateway/chokepoint.py's evaluate_request orchestrates for a real request —
get_classification, compute_similarity, decide_tier — and reports per-case
correctness, a confusion matrix, and precision/recall. This is the tool
docs/work_plan.md's Day 11 threshold calibration is actually done with: run it, look
at where expected vs. actual disagree, adjust config/thresholds.json (via
scripts/sign_policy.py, the real signed-policy pipeline), and run again.

Deliberately does NOT go through evaluate_request or Agent.create: no Baseline is
signed or persisted, no Pre-Flight screening happens, and no audit.log_decision call
is made. Eval cases are synthetic calibration probes, not real production requests —
writing them to the real storage/audit.jsonl, or persisting/freezing a synthetic
Baseline via a real store, would pollute state meant to be a genuine decision
history / agent registry with calibration noise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# eval_set.json's descriptions contain characters (em dashes) Windows' default cp1252
# console encoding can't represent — same issue demo/run_demo.py hit and fixed.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from afe.baseline.baseline import Baseline
from afe.gateway import chokepoint, policy
from afe.gateway.classification import get_classification
from afe.gateway.policy import Tier, decide_tier
from afe.gateway.similarity import compute_similarity

EVAL_SET_PATH = Path(__file__).resolve().parent / "eval_set.json"

TIERS = [Tier.GREEN.value, Tier.YELLOW.value, Tier.RED.value]


def _load_eval_set() -> list[dict[str, Any]]:
    return json.loads(EVAL_SET_PATH.read_text(encoding="utf-8"))


def _run_case(entry: dict[str, Any]) -> dict[str, Any]:
    """Run one eval case through get_classification / compute_similarity /
    decide_tier directly — the same three functions the Chokepoint orchestrates for a
    real request, without evaluate_request's audit-log/kill-switch side effects."""
    baseline = Baseline.create(
        agent_id=f"eval-{entry['id']}",
        dispatcher="eval",
        task=entry["baseline_task"],
        commands=[],
        allowed_resources=entry["allowed_resources"],
    )
    # Reuse chokepoint's own (private but same-package) resource/description
    # construction rather than re-deriving subtly different logic here — this is
    # what keeps the eval consistent with how a real request is actually built.
    resource = chokepoint._extract_resource(entry["tool_name"], entry["tool_args"])
    description = chokepoint._build_description(entry["tool_name"], entry["tool_args"])

    classification = get_classification(resource)
    score = compute_similarity(description, baseline)
    decision = decide_tier(score, classification, resource, baseline)

    return {
        "id": entry["id"],
        "description": entry["description"],
        "expected_tier": entry["expected_tier"],
        "actual_tier": decision.tier.value,
        "triggered_by": decision.triggered_by,
        "score": score,
        "correct": decision.tier.value == entry["expected_tier"],
    }


def _print_case(result: dict[str, Any]) -> None:
    marker = "CORRECT" if result["correct"] else "WRONG"
    print(
        f"[{result['id']:>2}] {marker:<7} expected={result['expected_tier']:<6} "
        f"actual={result['actual_tier']:<6} triggered_by={result['triggered_by']:<14} "
        f"score={result['score']:.3f}  {result['description']}"
    )


def _print_confusion_matrix(results: list[dict[str, Any]]) -> None:
    matrix = {expected: {actual: 0 for actual in TIERS} for expected in TIERS}
    for r in results:
        matrix[r["expected_tier"]][r["actual_tier"]] += 1

    print("\nConfusion matrix (rows=expected, columns=actual):")
    header = f"{'':>10}" + "".join(f"{t:>8}" for t in TIERS)
    print(header)
    for expected in TIERS:
        row = f"{expected:>10}" + "".join(f"{matrix[expected][a]:>8}" for a in TIERS)
        print(row)


def _precision_recall(results: list[dict[str, Any]], is_positive) -> tuple[str, str]:
    """precision/recall for a binary "is_positive(tier) -> bool" split, applied to
    both expected and actual tiers. Returns ("N/A", ...) for a metric whose
    denominator is zero rather than raising or silently printing 0.0."""
    predicted_positive = [r for r in results if is_positive(r["actual_tier"])]
    actual_positive = [r for r in results if is_positive(r["expected_tier"])]
    true_positive = [
        r
        for r in results
        if is_positive(r["actual_tier"]) and is_positive(r["expected_tier"])
    ]

    precision = (
        f"{len(true_positive) / len(predicted_positive):.3f}"
        if predicted_positive
        else "N/A"
    )
    recall = (
        f"{len(true_positive) / len(actual_positive):.3f}" if actual_positive else "N/A"
    )
    return precision, recall


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run eval/eval_set.json through the Chokepoint's decision logic."
    )
    parser.add_argument(
        "--thresholds",
        type=str,
        default=None,
        help=(
            "Path to a plain (unsigned) thresholds JSON to use for this run instead "
            "of the real signed config/thresholds.json. Scratch override for "
            "experimenting with candidate values — NOT the signed-policy pipeline; "
            "commit real values via scripts/sign_policy.py once chosen."
        ),
    )
    args = parser.parse_args()

    overrode_thresholds = args.thresholds is not None
    if overrode_thresholds:
        # Bypasses load_signed_policy entirely: decide_tier's _load_thresholds() just
        # returns whatever is already cached in policy._THRESHOLDS if it's not None,
        # so setting it directly here (to a plain dict, no signature envelope) is
        # exactly the calibration-experiment shortcut this flag exists for.
        override_path = Path(args.thresholds)
        policy._THRESHOLDS = json.loads(override_path.read_text(encoding="utf-8"))
        print(f"Using threshold override from {override_path} (unsigned, this run only)\n")

    try:
        eval_set = _load_eval_set()
        results = [_run_case(entry) for entry in eval_set]
    finally:
        if overrode_thresholds:
            # Restore to None (not the pre-override value) so a later run without
            # --thresholds reloads the real signed config/thresholds.json fresh,
            # rather than inheriting this run's scratch override or a stale cache.
            policy._THRESHOLDS = None

    for result in results:
        _print_case(result)

    correct = sum(1 for r in results if r["correct"])
    accuracy = correct / len(results) if results else 0.0
    print(f"\nOverall accuracy: {correct}/{len(results)} ({accuracy:.1%})")

    _print_confusion_matrix(results)

    red_precision, red_recall = _precision_recall(results, lambda tier: tier == "red")
    print(f"\nRED as positive class:")
    print(f"  precision={red_precision}  recall={red_recall}")

    flagged_precision, flagged_recall = _precision_recall(
        results, lambda tier: tier in ("yellow", "red")
    )
    print(f"\nFLAGGED (yellow or red) as positive class — yellow-band safety net:")
    print(f"  precision={flagged_precision}  recall={flagged_recall}")


if __name__ == "__main__":
    main()
