"""Command-line entry point: ``python -m oktatrace.detection_engine``.

Runs every rule over the stored dataset (generating it first if needed), prints
the alerts and the precision/recall evaluation, and stores the results.

Example (run from the ``backend`` directory)::

    python -m oktatrace.detection_engine --json ../data/generated/detections.json
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from oktatrace import DISCLAIMER
from oktatrace.config import get_settings
from oktatrace.detection_engine.evaluation import EvaluationReport
from oktatrace.detection_engine.models import DetectionResult
from oktatrace.detection_engine.pipeline import run_on_store
from oktatrace.log_generator import generate_dataset
from oktatrace.storage import SqliteStore


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def format_report(result: DetectionResult, evaluation: EvaluationReport) -> str:
    """Render alerts and metrics as plain text."""
    lines = [DISCLAIMER, "", f"{result.events_analyzed} events analysed, {len(result.alerts)} alerts", ""]
    lines.append(f"{'ID':<9} {'RULE':<11} {'SEVERITY':<9} {'FIRST SEEN (UTC)':<17} {'EVENTS':>6}  ACTOR")
    for alert in result.alerts:
        lines.append(
            f"{alert.id:<9} {alert.rule_id:<11} {alert.severity.value:<9} "
            f"{alert.first_seen:%Y-%m-%d %H:%M}  {len(alert.event_uuids):>6}  {alert.actor}"
        )
    a, e = evaluation.alert_level, evaluation.event_level
    lines += [
        "",
        f"Alert level: {a.true_positive_alerts} TP / {a.false_positive_alerts} FP, precision {_pct(a.precision)}",
        f"Event level: precision {_pct(e.precision)}, recall {_pct(e.recall)}, F1 {_pct(e.f1)} "
        f"(TP {e.true_positive}, FP {e.false_positive}, FN {e.false_negative})",
        "Phase coverage: " + ", ".join(
            f"{p.phase.value} {p.detected_events}/{p.attack_events}" for p in evaluation.phases),
        "False positives by cause: " + (", ".join(
            f"{k} {v}" for k, v in evaluation.false_positive_scenarios.items()) or "none"),
        "",
        f"{'RULE':<11} {'ALERTS':>6} {'TP':>4} {'FP':>4} {'PRECISION':>10}  NAME",
    ]
    for rule in evaluation.per_rule:
        lines.append(f"{rule.rule_id:<11} {rule.alerts:>6} {rule.true_positive_alerts:>4} "
                     f"{rule.false_positive_alerts:>4} {_pct(rule.precision):>10}  {rule.name}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Run detections and return a process exit code."""
    settings = get_settings()
    parser = argparse.ArgumentParser(prog="python -m oktatrace.detection_engine", description=DISCLAIMER)
    parser.add_argument("--db", type=Path, default=settings.db_path, help="SQLite dataset file")
    parser.add_argument("--json", type=Path, help="write alerts and evaluation as JSON")
    args = parser.parse_args(argv)

    store = SqliteStore(args.db)
    if not store.has_dataset():
        store.save_dataset(generate_dataset(settings.seed))
    result, evaluation = run_on_store(store)
    print(format_report(result, evaluation))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        payload = {"result": result.model_dump(mode="json"), "evaluation": evaluation.model_dump(mode="json")}
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
