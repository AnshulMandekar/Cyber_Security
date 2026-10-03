"""Tests for detection storage, HTTP routes and CLI."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from oktatrace.api.app import create_app
from oktatrace.config import get_settings
from oktatrace.detection_engine.__main__ import main as cli_main
from oktatrace.detection_engine.pipeline import run_on_store
from oktatrace.log_generator import LogDataset
from oktatrace.storage import AlertQuery, SqliteStore


@pytest.fixture
def store(tmp_path: Path, dataset: LogDataset) -> SqliteStore:
    store = SqliteStore(tmp_path / "det.db")
    store.save_dataset(dataset)
    return store


@pytest.fixture
def client(tmp_path: Path, store: SqliteStore) -> Iterator[TestClient]:
    app = create_app()
    settings = replace(get_settings(), db_path=store.path)
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app) as test_client:
        yield test_client


# -- storage ----------------------------------------------------------------------
def test_detection_round_trip_and_queries(store: SqliteStore) -> None:
    assert store.has_detection() is False
    result, evaluation = run_on_store(store)
    assert store.has_detection()
    assert store.detection_result().model_dump() == result.model_dump()
    assert store.evaluation() == evaluation
    replay = store.query_alerts(AlertQuery(rule_id="OT-DET-001", actor="jordan.rivera@acme.example"))
    assert len(replay) == 2
    first = result.alerts[0]
    assert store.get_alert(first.id) == first
    assert store.get_alert("ALR-9999") is None
    assert [e.uuid for e in store.events_by_uuid(first.event_uuids)] == first.event_uuids


def test_replacing_the_dataset_clears_stale_alerts(store: SqliteStore, dataset: LogDataset) -> None:
    run_on_store(store)
    store.save_dataset(dataset)
    assert store.has_detection() is False


# -- API --------------------------------------------------------------------------
def test_summary_runs_detections_on_first_use(client: TestClient) -> None:
    body = client.get("/api/detections/summary").json()
    assert body["alert_count"] == sum(body["alerts_by_rule"].values())
    assert body["evaluation"]["event_level"]["recall"] == 1.0


def test_rules_and_config(client: TestClient) -> None:
    rules = client.get("/api/detections/rules").json()
    assert [r["rule_id"] for r in rules] == [f"OT-DET-00{i}" for i in range(1, 8)]
    assert client.get("/api/detections/config").json()["business_hours_start"] == 7


def test_alert_filters_and_detail(client: TestClient) -> None:
    high = client.get("/api/detections/alerts", params={"severity": "high"}).json()
    assert high and {a["severity"] for a in high} == {"high"}
    detail = client.get(f"/api/detections/alerts/{high[0]['id']}").json()
    assert len(detail["events"]) == len(detail["alert"]["event_uuids"])
    assert "eventType" in detail["events"][0]
    assert client.get("/api/detections/alerts/ALR-9999").status_code == 404


def test_rerun_with_new_thresholds(client: TestClient) -> None:
    baseline = client.get("/api/detections/summary").json()["alert_count"]
    strict = client.post("/api/detections/run", json={"ignore_user_agent_version": False}).json()
    assert strict["alert_count"] > baseline
    assert strict["config"]["ignore_user_agent_version"] is False
    assert client.get("/api/detections/evaluation").json() == strict["evaluation"]


@pytest.mark.parametrize(
    "payload",
    [{"business_hours_start": 20, "business_hours_end": 7}, {"bulk_case_threshold": 1},
     {"max_travel_speed_kmh": 0}],
)
def test_invalid_thresholds_are_rejected(client: TestClient, payload: dict) -> None:  # type: ignore[type-arg]
    assert client.post("/api/detections/run", json=payload).status_code == 422


def test_cli_prints_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "cli.db"
    assert cli_main(["--db", str(db), "--json", str(tmp_path / "det.json")]) == 0
    out = capsys.readouterr().out
    assert "recall 100.0%" in out and "OT-DET-007" in out
    assert (tmp_path / "det.json").exists()
