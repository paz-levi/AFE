"""
run_eval.py — offline calibration harness for the Chokepoint's decision logic.

Runs every case in an eval set through the same functions
gateway/chokepoint.py's evaluate_request orchestrates for a real request —
check_command, get_classification, compute_similarity, decide_tier — and reports per-case
correctness, a confusion matrix, and precision/recall, overall and per group.

Two sets (--set):
  calibration  eval/eval_set.json (20 cases). config/thresholds.json was tuned on
               this set, so its numbers are calibration results, not validation.
  heldout      eval/heldout_set.json (26 cases), labels fixed before any run and not
               used for tuning. Each case carries a "group" label.

Groups: "deterministic" cases are decided by the allowlist / PUBLIC / SECRET rules,
which never look at the similarity score, so thresholds cannot affect them;
"semantic" cases reach the threshold comparison. For the held-out set the group comes
from the case's "group" field; for the calibration set (which has no such field) it
is derived from which check actually decided the case (triggered_by).

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

EVAL_DIR = Path(__file__).resolve().parent
EVAL_SETS = {
    "calibration": EVAL_DIR / "eval_set.json",
    "heldout": EVAL_DIR / "heldout_set.json",
}

# triggered_by values produced by rules that never consult the similarity score.
DETERMINISTIC_TRIGGERS = {"commands", "allowlist", "classification"}
GROUPS = ["deterministic", "semantic"]

TIERS = [Tier.GREEN.value, Tier.YELLOW.value, Tier.RED.value]


def _load_eval_set(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def _layer(triggered_by: str) -> str:
    return "deterministic" if triggered_by in DETERMINISTIC_TRIGGERS else "semantic"


def _run_case(entry: dict[str, Any]) -> dict[str, Any]:
    """Run one eval case through check_command / get_classification /
    compute_similarity / decide_tier directly — the same functions the Chokepoint orchestrates for a
    real request, without evaluate_request's audit-log/kill-switch side effects."""
    baseline = Baseline.create(
        agent_id=f"eval-{entry['id']}",
        dispatcher="eval",
        task=entry["baseline_task"],
        # The case's own tool is granted, so the commands rule never decides a
        # calibration/held-out case: these sets test the other layers.
        commands=[entry["tool_name"]],
        allowed_resources=entry["allowed_resources"],
    )
    # Reuse chokepoint's own (private but same-package) resource/description
    # construction rather than re-deriving subtly different logic here — this is
    # what keeps the eval consistent with how a real request is actually built.
    resource = chokepoint._extract_resource(entry["tool_name"], entry["tool_args"])
    description = chokepoint._build_description(entry["tool_name"], entry["tool_args"])

    classification = get_classification(resource)
    score = compute_similarity(description, baseline)
    decision = chokepoint.check_command(entry["tool_name"], baseline) or decide_tier(
        score, classification, resource, baseline
    )

    layer = _layer(decision.triggered_by)
    return {
        "id": entry["id"],
        # Labeled group if the set has one (held-out), else the layer that decided.
        "group": entry.get("group", layer),
        "layer": layer,
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
        f"actual={result['actual_tier']:<6} group={result['group']:<13} "
        f"triggered_by={result['triggered_by']:<14} "
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


def _print_summary(results: list[dict[str, Any]]) -> None:
    correct = sum(1 for r in results if r["correct"])
    accuracy = correct / len(results) if results else 0.0
    print(f"Accuracy: {correct}/{len(results)} ({accuracy:.1%})")

    _print_confusion_matrix(results)

    n_red = sum(1 for r in results if r["expected_tier"] == "red")
    red_precision, red_recall = _precision_recall(results, lambda tier: tier == "red")
    print(f"\nRED as positive class (n expected red = {n_red}):")
    print(f"  precision={red_precision}  recall={red_recall}")

    n_flagged = sum(1 for r in results if r["expected_tier"] in ("yellow", "red"))
    flagged_precision, flagged_recall = _precision_recall(
        results, lambda tier: tier in ("yellow", "red")
    )
    print(
        f"\nFLAGGED (yellow or red) as positive class "
        f"(n expected flagged = {n_flagged}):"
    )
    print(f"  precision={flagged_precision}  recall={flagged_recall}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run an eval set through the Chokepoint's decision logic."
    )
    parser.add_argument(
        "--set",
        dest="eval_set",
        choices=sorted(EVAL_SETS),
        default="calibration",
        help="Which eval set to run (default: calibration).",
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
        eval_set_path = EVAL_SETS[args.eval_set]
        print(f"Eval set: {args.eval_set} ({eval_set_path.name})\n")
        eval_set = _load_eval_set(eval_set_path)
        results = [_run_case(entry) for entry in eval_set]
    finally:
        if overrode_thresholds:
            # Restore to None (not the pre-override value) so a later run without
            # --thresholds reloads the real signed config/thresholds.json fresh,
            # rather than inheriting this run's scratch override or a stale cache.
            policy._THRESHOLDS = None

    for result in results:
        _print_case(result)

    print("\n=== All cases ===")
    _print_summary(results)

    for group in GROUPS:
        group_results = [r for r in results if r["group"] == group]
        print(f"\n=== Group: {group} ===")
        if not group_results:
            print("(no cases)")
            continue
        _print_summary(group_results)
        misses = [r for r in group_results if not r["correct"]]
        print(f"\nMisses ({len(misses)}):")
        for r in misses:
            _print_case(r)

    mislabeled = [r for r in results if r["group"] != r["layer"]]
    if mislabeled:
        print(
            "\nCases whose labeled group differs from the layer that actually "
            "decided them:"
        )
        for r in mislabeled:
            print(f"  [{r['id']}] labeled={r['group']} decided_by={r['triggered_by']}")


if __name__ == "__main__":
    main()
