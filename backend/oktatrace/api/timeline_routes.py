"""HTTP routes for Module 4 (timeline builder)."""

from __future__ import annotations

from fastapi import APIRouter

from oktatrace.api.detection_routes import DetectionStoreDep
from oktatrace.timeline_builder import TimelineEvaluation, TimelineResult
from oktatrace.timeline_builder.models import TimelineScope
from oktatrace.timeline_builder.pipeline import timeline_for_store

router = APIRouter(prefix="/api/timeline", tags=["Timeline builder"])


@router.get("", response_model=TimelineResult, summary="Ordered, ATT&CK-tagged incident timeline")
def timeline(store: DetectionStoreDep, scope: TimelineScope = "incident") -> TimelineResult:
    """``scope=incident`` keeps alerts linked to the HAR evidence; ``all_alerts`` keeps all."""
    return timeline_for_store(store, scope)[0]


@router.get("/evaluation", response_model=TimelineEvaluation, summary="Timeline coverage vs ground truth")
def timeline_evaluation(store: DetectionStoreDep, scope: TimelineScope = "incident") -> TimelineEvaluation:
    return timeline_for_store(store, scope)[1]
