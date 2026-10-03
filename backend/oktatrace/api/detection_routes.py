"""HTTP routes for Module 3 (detection engine)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel

from oktatrace.api.log_routes import StoreDep
from oktatrace.common.severity import Severity
from oktatrace.detection_engine import RULES, Alert, DetectionConfig, EvaluationReport, RuleInfo
from oktatrace.detection_engine.pipeline import run_on_store
from oktatrace.log_generator.models import SystemLogEvent
from oktatrace.storage import AlertQuery, SqliteStore

router = APIRouter(prefix="/api/detections", tags=["Detection engine"])


def get_detection_store(store: StoreDep) -> SqliteStore:
    """The dataset store, with a default detection run created on first use."""
    if not store.has_detection():
        run_on_store(store)
    return store


DetectionStoreDep = Annotated[SqliteStore, Depends(get_detection_store)]


class DetectionRunSummary(BaseModel):
    """What a detection run produced."""

    config: DetectionConfig
    events_analyzed: int
    alert_count: int
    alerts_by_rule: dict[str, int]
    alerts_by_severity: dict[str, int]
    evaluation: EvaluationReport


class AlertDetail(BaseModel):
    """An alert with its evidence events expanded."""

    alert: Alert
    events: list[SystemLogEvent]
    context_events: list[SystemLogEvent]


def _summary(store: SqliteStore) -> DetectionRunSummary:
    result = store.detection_result()
    return DetectionRunSummary(
        config=result.config,
        events_analyzed=result.events_analyzed,
        alert_count=len(result.alerts),
        alerts_by_rule=dict(sorted(Counter(a.rule_id for a in result.alerts).items())),
        alerts_by_severity={s.value: sum(a.severity is s for a in result.alerts) for s in Severity},
        evaluation=store.evaluation(),
    )


@router.post("/run", response_model=DetectionRunSummary, summary="Run all rules (optionally with new thresholds)")
def run(store: StoreDep, config: Annotated[DetectionConfig | None, Body()] = None) -> DetectionRunSummary:
    """Re-run detections over the stored dataset and replace the stored alerts."""
    run_on_store(store, config)
    return _summary(store)


@router.get("/summary", response_model=DetectionRunSummary, summary="Latest run: counts and evaluation")
def summary(store: DetectionStoreDep) -> DetectionRunSummary:
    return _summary(store)


@router.get("/rules", response_model=list[RuleInfo], summary="Rule catalogue")
def rules() -> list[RuleInfo]:
    return [rule.info for rule in RULES]


@router.get("/config", response_model=DetectionConfig, summary="Thresholds used by the latest run")
def config(store: DetectionStoreDep) -> DetectionConfig:
    return store.detection_config()


@router.get("/alerts", response_model=list[Alert], summary="Filter alerts from the latest run")
def alerts(
    store: DetectionStoreDep,
    rule_id: str | None = None,
    severity: Severity | None = None,
    actor: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[Alert]:
    return store.query_alerts(AlertQuery(rule_id=rule_id, severity=severity, actor=actor, since=since,
                                         until=until))


@router.get("/alerts/{alert_id}", response_model=AlertDetail, summary="One alert with its evidence")
def alert_detail(alert_id: str, store: DetectionStoreDep) -> AlertDetail:
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"No alert {alert_id}")
    return AlertDetail(
        alert=alert,
        events=store.events_by_uuid(alert.event_uuids),
        context_events=store.events_by_uuid(alert.context_event_uuids),
    )


@router.get("/evaluation", response_model=EvaluationReport, summary="Precision/recall vs the labelled attack")
def evaluation(store: DetectionStoreDep) -> EvaluationReport:
    return store.evaluation()
