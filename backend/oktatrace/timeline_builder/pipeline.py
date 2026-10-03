"""Build a timeline from the stored dataset and detection run."""

from __future__ import annotations

from oktatrace.config import get_settings
from oktatrace.har_analyzer import analyze_har
from oktatrace.har_analyzer.sample_har import build_sample_har
from oktatrace.log_generator.attack import HAR_FILENAME
from oktatrace.scenario import SUPPORT_CASE_ID
from oktatrace.storage import SqliteStore
from oktatrace.timeline_builder.builder import HarEvidence, build_timeline
from oktatrace.timeline_builder.evaluation import TimelineEvaluation, evaluate_timeline
from oktatrace.timeline_builder.models import TimelineResult, TimelineScope


def sample_har_evidence(seed: int, long_lived_threshold_seconds: int | None = None) -> HarEvidence:
    """The scenario's HAR for ``seed`` (its tokens match that seed's log), analysed."""
    threshold = long_lived_threshold_seconds or get_settings().long_lived_threshold_seconds
    analysis = analyze_har(build_sample_har(seed), long_lived_threshold_seconds=threshold)
    return HarEvidence(analysis=analysis, case_id=SUPPORT_CASE_ID, filename=HAR_FILENAME)


def timeline_for_store(
    store: SqliteStore, scope: TimelineScope = "incident"
) -> tuple[TimelineResult, TimelineEvaluation]:
    """Build the timeline over the stored events and alerts, and evaluate it."""
    dataset = store.load_dataset()
    alerts = store.detection_result().alerts
    result = build_timeline(dataset.events, alerts, sample_har_evidence(dataset.seed), scope)
    return result, evaluate_timeline(result, dataset.labels)
