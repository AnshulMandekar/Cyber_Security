"""HTTP routes for Module 6 (report summarizer)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from oktatrace.api.detection_routes import DetectionStoreDep
from oktatrace.api.log_routes import SettingsDep
from oktatrace.report_summarizer import IncidentFacts, IncidentSummary, SummarizerError, summarize
from oktatrace.report_summarizer.pipeline import facts_for_store
from oktatrace.report_summarizer.summarizer import SummaryMode

router = APIRouter(prefix="/api/report", tags=["Report summarizer"])


@router.get("/facts", response_model=IncidentFacts, summary="Deterministic facts the summary is written from")
def facts(store: DetectionStoreDep) -> IncidentFacts:
    return facts_for_store(store)


@router.post("/summary", response_model=IncidentSummary, summary="Write the incident summary")
def summary(store: DetectionStoreDep, settings: SettingsDep, mode: SummaryMode | None = None) -> IncidentSummary:
    """``mode=llm`` makes one Claude API call (needs credentials); ``template`` is offline."""
    try:
        return summarize(facts_for_store(store), mode=mode, settings=settings)
    except SummarizerError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
