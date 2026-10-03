"""HTTP routes for Module 2 (log generator)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from oktatrace.config import Settings, get_settings
from oktatrace.log_generator import (
    AttackStep,
    DatasetInvariantError,
    DatasetSummary,
    LabelCategory,
    ScenarioFacts,
    generate_dataset,
    summarize_dataset,
)
from oktatrace.log_generator.models import DirectoryEntry
from oktatrace.storage import EventPage, EventQuery, SqliteStore
from oktatrace.storage.sqlite_store import MAX_PAGE_SIZE

router = APIRouter(prefix="/api/logs", tags=["Log generator"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


def get_store(settings: SettingsDep) -> SqliteStore:
    """Open the dataset store, generating the default dataset on first use."""
    store = SqliteStore(settings.db_path)
    if not store.has_dataset():
        store.save_dataset(generate_dataset(settings.seed))
    return store


StoreDep = Annotated[SqliteStore, Depends(get_store)]


class GenerateRequest(BaseModel):
    """Parameters for regenerating the dataset."""

    seed: int = Field(ge=0, le=2**31 - 1, description="Same seed, same dataset")


@router.post("/generate", response_model=DatasetSummary, summary="Regenerate the synthetic log")
def regenerate(request: GenerateRequest, settings: SettingsDep) -> DatasetSummary:
    """Generate a fresh dataset for ``seed`` and replace the stored one."""
    try:
        dataset = generate_dataset(request.seed)
    except DatasetInvariantError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc  # name varies by Starlette version
    SqliteStore(settings.db_path).save_dataset(dataset)
    return summarize_dataset(dataset)


@router.get("/summary", response_model=DatasetSummary, summary="Dataset headline numbers")
def summary(store: StoreDep) -> DatasetSummary:
    return store.summary()


@router.get("/events", response_model=EventPage, summary="Filter and page through events")
def events(
    store: StoreDep,
    event_type: str | None = None,
    actor: str | None = Query(None, description="Actor login (alternateId)"),
    session_id: str | None = None,
    ip_address: str | None = None,
    category: LabelCategory | None = Query(None, description="Ground-truth label (evaluation only)"),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(100, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(0, ge=0),
) -> EventPage:
    return store.query_events(
        EventQuery(event_type=event_type, actor=actor, session_id=session_id, ip_address=ip_address,
                   category=category, since=since, until=until, limit=limit, offset=offset)
    )


@router.get("/attack", response_model=list[AttackStep], summary="The labelled attack, step by step")
def attack_steps(store: StoreDep) -> list[AttackStep]:
    return store.attack_steps()


@router.get("/scenario", response_model=ScenarioFacts, summary="Facts about the planted incident")
def scenario(store: StoreDep) -> ScenarioFacts:
    return store.scenario()


@router.get("/users", response_model=list[DirectoryEntry], summary="Synthetic directory")
def users(store: StoreDep) -> list[DirectoryEntry]:
    return store.users()
