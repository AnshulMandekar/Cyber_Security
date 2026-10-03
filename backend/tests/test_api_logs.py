"""Tests for the log generator HTTP routes."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from oktatrace.api.app import create_app
from oktatrace.config import get_settings


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app()
    settings = replace(get_settings(), db_path=tmp_path / "api.db")
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app) as test_client:
        yield test_client


def test_summary_generates_default_dataset_on_first_use(client: TestClient) -> None:
    body = client.get("/api/logs/summary").json()
    assert body["seed"] == get_settings().seed
    assert body["event_count"] >= 5000
    assert body["events_by_category"]["attack"] == body["attack_step_count"]


def test_events_are_paged_and_okta_shaped(client: TestClient) -> None:
    body = client.get("/api/logs/events", params={"limit": 5, "offset": 5}).json()
    assert body["limit"] == 5 and body["offset"] == 5 and len(body["items"]) == 5
    event = body["items"][0]["event"]
    assert "eventType" in event and "externalSessionId" in event["authenticationContext"]


def test_event_filters(client: TestClient) -> None:
    body = client.get("/api/logs/events", params={"category": "attack", "limit": 500}).json()
    assert body["total"] == len(client.get("/api/logs/attack").json())
    replay = client.get("/api/logs/events", params={"ip_address": "203.0.113.211", "limit": 500}).json()
    assert replay["total"] > 0
    assert {i["label"]["category"] for i in replay["items"]} == {"attack"}


def test_scenario_and_users(client: TestClient) -> None:
    scenario = client.get("/api/logs/scenario").json()
    assert scenario["victim_login"] == "jordan.rivera@acme.example"
    assert len(client.get("/api/logs/users").json()) == 51


def test_regenerate_with_new_seed(client: TestClient) -> None:
    body = client.post("/api/logs/generate", json={"seed": 7}).json()
    assert body["seed"] == 7
    assert client.get("/api/logs/summary").json()["seed"] == 7


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("post", "/api/logs/generate", {"json": {"seed": -1}}),
        ("get", "/api/logs/events", {"params": {"limit": 501}}),
        ("get", "/api/logs/events", {"params": {"category": "nonsense"}}),
    ],
)
def test_invalid_requests_are_rejected(client: TestClient, method: str, path: str, kwargs: dict) -> None:  # type: ignore[type-arg]
    assert getattr(client, method)(path, **kwargs).status_code == 422
