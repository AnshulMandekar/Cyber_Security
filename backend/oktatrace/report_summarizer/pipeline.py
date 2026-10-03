"""Gather facts from the stored dataset and detection run."""

from __future__ import annotations

from oktatrace.report_summarizer.facts import IncidentFacts, build_facts
from oktatrace.storage import SqliteStore
from oktatrace.timeline_builder.pipeline import sample_har_evidence, timeline_for_store


def facts_for_store(store: SqliteStore) -> IncidentFacts:
    """Build :class:`IncidentFacts` from what modules 1-4 have stored or compute on demand."""
    timeline, _ = timeline_for_store(store, "incident")
    dataset_seed = store.summary().seed
    return build_facts(
        har=sample_har_evidence(dataset_seed).analysis,
        detection=store.detection_result(),
        evaluation=store.evaluation(),
        timeline=timeline,
        scenario=store.scenario(),
    )
