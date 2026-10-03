"""Tests for the HAR analyzer HTTP routes and CLI."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from oktatrace.api.app import create_app
from oktatrace.config import get_settings
from oktatrace.har_analyzer.__main__ import main as cli_main


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


def upload(client: TestClient, path: str, payload: bytes, name: str = "case.har") -> Any:
    return client.post(path, files={"file": (name, payload, "application/json")})


def test_health_carries_disclaimer(client: TestClient) -> None:
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["synthetic_data_only"] is True
    assert "SYNTHETIC" in body["disclaimer"]


def test_analyze_upload(client: TestClient, sample_har: dict[str, Any]) -> None:
    response = upload(client, "/api/har/analyze", json.dumps(sample_har).encode())
    assert response.status_code == 200
    body = response.json()
    assert body["stats"]["total_findings"] == 16
    assert body["findings"][0]["severity"] == "critical"


def test_analyze_rejects_invalid_har(client: TestClient) -> None:
    response = upload(client, "/api/har/analyze", b"definitely not json")
    assert response.status_code == 400
    assert "JSON" in response.json()["detail"]


def test_analyze_rejects_oversized_upload(client: TestClient, sample_har: dict[str, Any]) -> None:
    tiny = replace(get_settings(), max_har_bytes=100)
    client.app.dependency_overrides[get_settings] = lambda: tiny  # type: ignore[attr-defined]
    response = upload(client, "/api/har/analyze", json.dumps(sample_har).encode())
    assert response.status_code == 413


def test_redact_upload_returns_clean_attachment(
    client: TestClient, sample_har: dict[str, Any], sample_secrets: list[str]
) -> None:
    response = upload(client, "/api/har/redact", json.dumps(sample_har).encode(), name="../evil name.har")
    assert response.status_code == 200
    assert response.headers["content-disposition"] == 'attachment; filename="evil_name.redacted.har"'
    assert int(response.headers["x-oktatrace-redactions"]) > 0
    assert [s for s in sample_secrets if s in response.text] == []


def test_sample_endpoints(client: TestClient) -> None:
    assert client.get("/api/har/sample").json()["log"]["version"] == "1.2"
    assert client.get("/api/har/sample/analysis").json()["stats"]["total_findings"] == 16
    redacted = client.get("/api/har/sample/redacted")
    assert "filename=\"support_case_00421.redacted.har\"" in redacted.headers["content-disposition"]


def test_cli_writes_json_and_redacted_har(tmp_path: Path, sample_har: dict[str, Any]) -> None:
    har_path = tmp_path / "in.har"
    har_path.write_text(json.dumps(sample_har), encoding="utf-8")
    exit_code = cli_main(
        ["analyze", str(har_path), "--json", str(tmp_path / "f.json"), "--redacted", str(tmp_path / "r.har")]
    )
    assert exit_code == 0
    assert json.loads((tmp_path / "f.json").read_text(encoding="utf-8"))["stats"]["total_findings"] == 16
    assert json.loads((tmp_path / "r.har").read_text(encoding="utf-8"))["log"]["entries"]


def test_cli_reports_bad_input(tmp_path: Path) -> None:
    bad = tmp_path / "bad.har"
    bad.write_text("{}", encoding="utf-8")
    assert cli_main(["analyze", str(bad)]) == 2
