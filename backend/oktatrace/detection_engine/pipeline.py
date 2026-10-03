"""Run detections over a stored dataset, evaluate them and persist the results."""

from __future__ import annotations

from oktatrace.detection_engine.engine import run_detections
from oktatrace.detection_engine.evaluation import EvaluationReport, evaluate_alerts
from oktatrace.detection_engine.models import DetectionConfig, DetectionResult
from oktatrace.log_generator.models import LogDataset
from oktatrace.storage import SqliteStore


def detect_and_evaluate(
    dataset: LogDataset, config: DetectionConfig | None = None
) -> tuple[DetectionResult, EvaluationReport]:
    """Run the engine on the events only, then score the alerts against the labels."""
    result = run_detections(dataset.events, dataset.users, config)
    evaluation = evaluate_alerts(result.alerts, dataset.labels, dataset.attack_steps, result.rules)
    return result, evaluation


def run_on_store(
    store: SqliteStore, config: DetectionConfig | None = None
) -> tuple[DetectionResult, EvaluationReport]:
    """Detect over the stored dataset and replace the stored detection run."""
    result, evaluation = detect_and_evaluate(store.load_dataset(), config)
    store.save_detection(result, evaluation)
    return result, evaluation
