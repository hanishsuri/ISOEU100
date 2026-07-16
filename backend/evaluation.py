"""Evaluation harness for the fallback clinical triage engine (ISO 42001 / NIST MEASURE).

Runs backend/risk_engine.py against the labeled clinical dataset in data/eval_dataset.json
and writes the measured metrics to docs/eval_results.json.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from backend.risk_engine import FALLBACK_MODEL_NAME, heuristic_risk

DATASET_PATH = Path(__file__).resolve().parent.parent / "data" / "eval_dataset.json"
RESULTS_PATH = Path(__file__).resolve().parent.parent / "docs" / "eval_results.json"


def run_evaluation() -> dict:
    dataset = json.loads(DATASET_PATH.read_text())
    cases = dataset["cases"]

    tp = fp = tn = fn = 0
    per_case = []
    for case in cases:
        predicted_level, _ = heuristic_risk(case["symptoms"], case["declared_duration"])
        predicted_high = predicted_level == "HIGH"
        actual_high = case["label"] == "HIGH"
        if predicted_high and actual_high:
            tp += 1
        elif predicted_high and not actual_high:
            fp += 1
        elif not predicted_high and actual_high:
            fn += 1
        else:
            tn += 1
        per_case.append(
            {
                "id": case["id"],
                "predicted": predicted_level,
                "label": case["label"],
                "correct": predicted_high == actual_high,
            }
        )

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / len(cases) if cases else 0.0

    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_scope": (
            f"These metrics measure ONLY the deterministic fallback engine "
            f"({FALLBACK_MODEL_NAME}). They say nothing about the accuracy of the "
            f"OpenAI-backed path, which has not been evaluated."
        ),
        "dataset": {
            "name": dataset["dataset_name"],
            "version": dataset["version"],
            "n_cases": len(cases),
            "caveat": dataset["description"],
        },
        "positive_class": dataset["positive_class"],
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "false_positive_rate": round(false_positive_rate, 4),
            "accuracy": round(accuracy, 4),
        },
        "per_case": per_case,
    }
    return results


def run_and_save() -> dict:
    results = run_evaluation()
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    saved = run_and_save()
    print(json.dumps(saved["metrics"], indent=2))
    print(f"Full report written to {RESULTS_PATH}")
