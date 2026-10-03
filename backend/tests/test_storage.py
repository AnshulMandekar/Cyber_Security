"""Tests for SQLite persistence."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from oktatrace.log_generator import LabelCategory, LogDataset
from oktatrace.storage import EventQuery, SqliteStore
from oktatrace.storage.sqlite_store import MAX_PAGE_SIZE


@pytest.fixture
def store(tmp_path: Path, dataset: LogDataset) -> SqliteStore:
    store = SqliteStore(tmp_path / "test.db")
    store.save_dataset(dataset)
    return store


def test_new_store_is_empty(tmp_path: Path) -> None:
    assert SqliteStore(tmp_path / "none.db").has_dataset() is False


def test_round_trip_preserves_dataset(store: SqliteStore, dataset: LogDataset) -> None:
    assert store.has_dataset()
    assert store.load_dataset().model_dump() == dataset.model_dump()


def test_saving_again_replaces_rather_than_appends(store: SqliteStore, dataset: LogDataset) -> None:
    store.save_dataset(dataset)
    assert store.query_events(EventQuery(limit=1)).total == len(dataset.events)


def test_filters(store: SqliteStore, dataset: LogDataset) -> None:
    attack = store.query_events(EventQuery(category=LabelCategory.ATTACK, limit=MAX_PAGE_SIZE))
    assert attack.total == len(dataset.attack_steps)
    assert all(item.label.is_attack for item in attack.items)

    victim = dataset.scenario.victim_login
    by_actor = store.query_events(EventQuery(actor=victim, event_type="user.session.start"))
    assert by_actor.total > 0
    assert {i.event.actor.alternate_id for i in by_actor.items} == {victim}

    session = store.query_events(EventQuery(session_id=dataset.scenario.victim_session_id, limit=MAX_PAGE_SIZE))
    assert {i.event.session_id for i in session.items} == {dataset.scenario.victim_session_id}

    since = datetime(2023, 10, 3, tzinfo=timezone.utc)
    until = datetime(2023, 10, 3, 12, tzinfo=timezone.utc)
    window = store.query_events(EventQuery(since=since, until=until, limit=MAX_PAGE_SIZE))
    assert window.total > 0
    assert all(since <= i.event.published < until for i in window.items)


def test_paging_and_limits(store: SqliteStore, dataset: LogDataset) -> None:
    first = store.query_events(EventQuery(limit=10, offset=0))
    second = store.query_events(EventQuery(limit=10, offset=10))
    assert [i.event.uuid for i in first.items] == [e.uuid for e in dataset.events[:10]]
    assert [i.event.uuid for i in second.items] == [e.uuid for e in dataset.events[10:20]]
    assert store.query_events(EventQuery(limit=10_000)).limit == MAX_PAGE_SIZE


def test_filter_values_are_parameterised(store: SqliteStore) -> None:
    assert store.query_events(EventQuery(actor="x' OR '1'='1")).total == 0


def test_metadata_accessors(store: SqliteStore, dataset: LogDataset) -> None:
    assert store.summary().event_count == len(dataset.events)
    assert store.scenario() == dataset.scenario
    assert len(store.users()) == len(dataset.users)
    assert store.attack_steps() == dataset.attack_steps
