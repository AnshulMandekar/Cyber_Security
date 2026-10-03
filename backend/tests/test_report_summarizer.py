"""Tests for the report summarizer (Module 6). No test touches the network."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anthropic
import httpx2
import pytest
from fastapi.testclient import TestClient

from oktatrace.api.app import create_app
from oktatrace.config import get_settings
from oktatrace.detection_engine.pipeline import detect_and_evaluate
from oktatrace.har_analyzer.sample_har import sample_secret_values
from oktatrace.log_generator import LogDataset
from oktatrace.report_summarizer import (
    IncidentFacts,
    SummarizerError,
    build_facts,
    check_references,
    summarize,
)
from oktatrace.report_summarizer.__main__ import main as cli_main
from oktatrace.report_summarizer.summarizer import FALLBACK_BETA, SYSTEM_PROMPT
from oktatrace.storage import SqliteStore
from oktatrace.timeline_builder import build_timeline
from oktatrace.timeline_builder.pipeline import sample_har_evidence


@pytest.fixture(scope="session")
def facts(dataset: LogDataset) -> IncidentFacts:
    result, evaluation = detect_and_evaluate(dataset)
    har = sample_har_evidence(dataset.seed, 8 * 3600)
    timeline = build_timeline(dataset.events, result.alerts, har)
    return build_facts(har.analysis, result, evaluation, timeline, dataset.scenario)


class FakeClient:
    """Stands in for ``anthropic.Anthropic``: records the request, returns or raises a canned result."""

    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome
        self.calls: list[dict[str, Any]] = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def fake_response(text: str, stop_reason: str = "end_turn", category: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text)],
        stop_reason=stop_reason,
        stop_details=SimpleNamespace(category=category) if category else None,
        model="claude-opus-5-5",
        usage=SimpleNamespace(input_tokens=1200, output_tokens=640),
    )


# -- facts ------------------------------------------------------------------------
def test_facts_never_contain_secrets_or_raw_session_ids(dataset: LogDataset, facts: IncidentFacts) -> None:
    dumped = facts.model_dump_json()
    assert [s for s in sample_secret_values(dataset.seed) if s in dumped] == []
    assert dataset.scenario.victim_session_id not in dumped


def test_facts_mark_incident_and_unrelated_alerts(facts: IncidentFacts) -> None:
    alerts = facts.detections["alerts"]
    assert {a["id"] for a in alerts if not a["in_incident"]} == set(facts.timeline["excluded_alerts"])
    assert facts.detections["evaluation"]["event_recall"] == 1.0


# -- template writer ---------------------------------------------------------------
def test_template_summary_cites_only_known_evidence(facts: IncidentFacts) -> None:
    summary = summarize(facts, mode="template")
    assert summary.mode == "template" and summary.unknown_ids == []
    assert {"ALR-0005", "HAR-011", "OT-DET-007", "T1539"} <= set(summary.cited_ids)
    for heading in ("## Executive summary", "## What happened", "## Detection and evidence", "## Impact",
                    "## Recommended actions", "## Detection quality"):
        assert heading in summary.markdown
    assert "SYNTHETIC DATA ONLY" in summary.markdown


def test_auto_mode_without_credentials_uses_template(facts: IncidentFacts, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    summary = summarize(facts, mode="auto")
    assert summary.mode == "template"
    assert summary.fallback_reason and "ANTHROPIC_API_KEY" in summary.fallback_reason


def test_reference_checker_flags_invented_ids(facts: IncidentFacts) -> None:
    cited, unknown = check_references("See ALR-0005, TL-0001, ALR-9999 and T9999.", facts)
    assert cited == ["ALR-0005", "ALR-9999", "T9999", "TL-0001"]
    assert unknown == ["ALR-9999", "T9999"]


# -- LLM writer (fake client) ---------------------------------------------------------
def test_llm_request_uses_facts_only_and_current_api(facts: IncidentFacts) -> None:
    client = FakeClient(fake_response("# Summary\nThe replay (ALR-0005) and an invented ALR-9999."))
    summary = summarize(facts, mode="llm", client=client)

    [call] = client.calls
    assert call["model"] == "claude-opus-5-5"
    assert call["fallbacks"] == "default" and call["betas"] == [FALLBACK_BETA]
    assert call["output_config"] == {"effort": "medium"}
    assert "thinking" not in call  # adaptive thinking is the default on this model
    assert call["system"] == SYSTEM_PROMPT
    user_text = call["messages"][0]["content"]
    payload = json.loads(user_text.split("<facts>\n", 1)[1].split("\n</facts>", 1)[0])
    assert payload == facts.model_dump(mode="json")

    assert summary.mode == "llm" and summary.model == "claude-opus-5-5"
    assert summary.unknown_ids == ["ALR-9999"]
    assert any("ALR-9999" in w for w in summary.warnings)
    assert summary.usage == {"input_tokens": 1200, "output_tokens": 640}


def test_refusal_raises_in_llm_mode_and_falls_back_in_auto(facts: IncidentFacts) -> None:
    refused = fake_response("", stop_reason="refusal", category="cyber")
    with pytest.raises(SummarizerError, match="declined.*cyber"):
        summarize(facts, mode="llm", client=FakeClient(refused))
    fallback = summarize(facts, mode="auto", client=FakeClient(refused))
    assert fallback.mode == "template" and "declined" in (fallback.fallback_reason or "")


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (anthropic.APITimeoutError(request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages")),
         "timed out"),
        (anthropic.APIConnectionError(request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages")),
         "Could not reach"),
    ],
)
def test_api_errors_become_summarizer_errors(facts: IncidentFacts, error: Exception, message: str) -> None:
    with pytest.raises(SummarizerError, match=message):
        summarize(facts, mode="llm", client=FakeClient(error))
    assert summarize(facts, mode="auto", client=FakeClient(error)).mode == "template"


def test_truncated_and_empty_responses(facts: IncidentFacts) -> None:
    truncated = summarize(facts, mode="llm", client=FakeClient(fake_response("partial", stop_reason="max_tokens")))
    assert any("output limit" in w for w in truncated.warnings)
    with pytest.raises(SummarizerError, match="no text"):
        summarize(facts, mode="llm", client=FakeClient(fake_response("   ")))


# -- API and CLI --------------------------------------------------------------------
@pytest.fixture
def client(tmp_path: Path, dataset: LogDataset) -> Iterator[TestClient]:
    store = SqliteStore(tmp_path / "report.db")
    store.save_dataset(dataset)
    app = create_app()
    settings = replace(get_settings(), db_path=store.path, summary_mode="template")
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app) as test_client:
        yield test_client


def test_report_endpoints(client: TestClient) -> None:
    facts_body = client.get("/api/report/facts").json()
    assert facts_body["case_id"] == "CASE-00421"
    summary = client.post("/api/report/summary", params={"mode": "template"}).json()
    assert summary["mode"] == "template" and summary["unknown_ids"] == []
    assert client.post("/api/report/summary", params={"mode": "poetry"}).status_code == 422


def test_cli_writes_template_summary(tmp_path: Path) -> None:
    out = tmp_path / "summary.md"
    assert cli_main(["--db", str(tmp_path / "cli.db"), "--mode", "template", "--out", str(out),
                     "--facts", str(tmp_path / "facts.json")]) == 0
    assert out.read_text(encoding="utf-8").startswith("# Incident summary")
    assert json.loads((tmp_path / "facts.json").read_text(encoding="utf-8"))["case_id"] == "CASE-00421"
