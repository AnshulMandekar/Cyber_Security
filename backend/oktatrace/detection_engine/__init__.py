"""Module 3 - detection engine.

Deterministic rules over the System Log, alert aggregation, and evaluation of
precision/recall against the labelled scenario.
"""

from oktatrace.detection_engine.engine import aggregate_matches, run_detections
from oktatrace.detection_engine.evaluation import EvaluationReport, evaluate_alerts
from oktatrace.detection_engine.models import (
    Alert,
    DetectionConfig,
    DetectionResult,
    RuleInfo,
    RuleMatch,
)
from oktatrace.detection_engine.rules import RULES, RULES_BY_ID

__all__ = [
    "RULES",
    "RULES_BY_ID",
    "Alert",
    "DetectionConfig",
    "DetectionResult",
    "EvaluationReport",
    "RuleInfo",
    "RuleMatch",
    "aggregate_matches",
    "evaluate_alerts",
    "run_detections",
]
