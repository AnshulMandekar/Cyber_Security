"""SQLite storage for the generated dataset and detection results.

Events are stored as their full Okta-style JSON plus a few indexed columns for
filtering. Labels and attack steps live in their own tables, mirroring the rule
that detections never see ground truth. Alerts from the latest detection run are
stored alongside and cleared whenever the dataset is replaced. Every query is
parameterised.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from pydantic import BaseModel

from oktatrace.common.severity import Severity
from oktatrace.common.timeutil import ensure_utc
from oktatrace.detection_engine.evaluation import EvaluationReport
from oktatrace.detection_engine.models import Alert, DetectionConfig, DetectionResult, RuleInfo
from oktatrace.log_generator.generator import DatasetSummary, summarize_dataset
from oktatrace.log_generator.models import (
    AttackStep,
    DirectoryEntry,
    EventLabel,
    LabelCategory,
    LogDataset,
    ScenarioFacts,
    SystemLogEvent,
)

MAX_PAGE_SIZE: Final = 500

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    user_id  TEXT PRIMARY KEY,
    seq      INTEGER NOT NULL UNIQUE,
    login    TEXT NOT NULL UNIQUE,
    raw_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    uuid        TEXT PRIMARY KEY,
    seq         INTEGER NOT NULL UNIQUE,
    published   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    actor_login TEXT NOT NULL,
    session_id  TEXT,
    ip_address  TEXT NOT NULL,
    as_number   INTEGER NOT NULL,
    user_agent  TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    raw_json    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_published ON events (published);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_actor ON events (actor_login);
CREATE INDEX IF NOT EXISTS idx_events_session ON events (session_id);
CREATE TABLE IF NOT EXISTS labels (
    event_uuid TEXT PRIMARY KEY REFERENCES events (uuid) ON DELETE CASCADE,
    category   TEXT NOT NULL,
    scenario   TEXT NOT NULL,
    phase      TEXT
);
CREATE TABLE IF NOT EXISTS attack_steps (
    step       INTEGER PRIMARY KEY,
    event_uuid TEXT NOT NULL REFERENCES events (uuid) ON DELETE CASCADE,
    raw_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id         TEXT PRIMARY KEY,
    seq        INTEGER NOT NULL UNIQUE,
    rule_id    TEXT NOT NULL,
    severity   TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    actor      TEXT NOT NULL,
    raw_json   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts (rule_id);
CREATE TABLE IF NOT EXISTS detection_run (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    config_json     TEXT NOT NULL,
    rules_json      TEXT NOT NULL,
    evaluation_json TEXT NOT NULL,
    events_analyzed INTEGER NOT NULL
);
"""


def _timestamp(value: datetime) -> str:
    """Fixed-width UTC timestamp, so string comparison equals time comparison."""
    return ensure_utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True)
class EventQuery:
    """Filters for :meth:`SqliteStore.query_events`. ``None`` means "any"."""

    event_type: str | None = None
    actor: str | None = None
    session_id: str | None = None
    ip_address: str | None = None
    category: LabelCategory | None = None
    since: datetime | None = None
    until: datetime | None = None
    limit: int = 100
    offset: int = 0


class LabelledEvent(BaseModel):
    """An event with its ground-truth label (for evaluation views only)."""

    event: SystemLogEvent
    label: EventLabel


class EventPage(BaseModel):
    """One page of query results."""

    total: int
    limit: int
    offset: int
    items: list[LabelledEvent]


@dataclass(frozen=True)
class AlertQuery:
    """Filters for :meth:`SqliteStore.query_alerts`. ``None`` means "any"."""

    rule_id: str | None = None
    severity: Severity | None = None
    actor: str | None = None
    since: datetime | None = None
    until: datetime | None = None


class SqliteStore:
    """Reads and writes one dataset in a SQLite file."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.executescript(_SCHEMA)
            with conn:  # commit on success, roll back on error
                yield conn

    def has_dataset(self) -> bool:
        """True once a dataset has been saved."""
        if not self.path.exists():
            return False
        with self._connect() as conn:
            return conn.execute("SELECT 1 FROM meta WHERE key = 'seed'").fetchone() is not None

    def save_dataset(self, dataset: LogDataset) -> None:
        """Replace whatever is stored with ``dataset`` in one transaction."""
        meta = {
            "seed": str(dataset.seed),
            "window_start": _timestamp(dataset.window_start),
            "window_end": _timestamp(dataset.window_end),
            "scenario": dataset.scenario.model_dump_json(),
            "summary": summarize_dataset(dataset).model_dump_json(),
        }
        with self._connect() as conn:
            for table in ("detection_run", "alerts", "attack_steps", "labels", "events", "users", "meta"):
                conn.execute(f"DELETE FROM {table}")  # table names are constants, not input
            conn.executemany("INSERT INTO meta (key, value) VALUES (?, ?)", meta.items())
            conn.executemany(
                "INSERT INTO users (user_id, seq, login, raw_json) VALUES (?, ?, ?, ?)",
                [(u.user_id, seq, u.login, u.model_dump_json()) for seq, u in enumerate(dataset.users)],
            )
            conn.executemany(
                "INSERT INTO events (uuid, seq, published, event_type, actor_login, session_id,"
                " ip_address, as_number, user_agent, outcome, raw_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        e.uuid, seq, _timestamp(e.published), e.event_type, e.actor.alternate_id,
                        e.session_id, e.client.ip_address, e.security_context.as_number,
                        e.client.user_agent.raw_user_agent, e.outcome.result,
                        e.model_dump_json(by_alias=True),
                    )
                    for seq, e in enumerate(dataset.events)
                ],
            )
            conn.executemany(
                "INSERT INTO labels (event_uuid, category, scenario, phase) VALUES (?, ?, ?, ?)",
                [
                    (uuid, label.category.value, label.scenario, label.phase.value if label.phase else None)
                    for uuid, label in dataset.labels.items()
                ],
            )
            conn.executemany(
                "INSERT INTO attack_steps (step, event_uuid, raw_json) VALUES (?, ?, ?)",
                [(s.step, s.event_uuid, s.model_dump_json()) for s in dataset.attack_steps],
            )

    def _meta(self, conn: sqlite3.Connection, key: str) -> str:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        if row is None:
            raise LookupError("no dataset stored yet")
        return str(row["value"])

    def summary(self) -> DatasetSummary:
        """Headline numbers saved alongside the dataset."""
        with self._connect() as conn:
            return DatasetSummary.model_validate_json(self._meta(conn, "summary"))

    def scenario(self) -> ScenarioFacts:
        with self._connect() as conn:
            return ScenarioFacts.model_validate_json(self._meta(conn, "scenario"))

    def users(self) -> list[DirectoryEntry]:
        with self._connect() as conn:
            rows = conn.execute("SELECT raw_json FROM users ORDER BY seq").fetchall()
        return [DirectoryEntry.model_validate_json(r["raw_json"]) for r in rows]

    def attack_steps(self) -> list[AttackStep]:
        with self._connect() as conn:
            rows = conn.execute("SELECT raw_json FROM attack_steps ORDER BY step").fetchall()
        return [AttackStep.model_validate_json(r["raw_json"]) for r in rows]

    def load_dataset(self) -> LogDataset:
        """Load everything back into a :class:`LogDataset`."""
        with self._connect() as conn:
            seed = int(self._meta(conn, "seed"))
            window_start = datetime.fromisoformat(self._meta(conn, "window_start").replace("Z", "+00:00"))
            window_end = datetime.fromisoformat(self._meta(conn, "window_end").replace("Z", "+00:00"))
            scenario = ScenarioFacts.model_validate_json(self._meta(conn, "scenario"))
            events = [
                SystemLogEvent.model_validate_json(r["raw_json"])
                for r in conn.execute("SELECT raw_json FROM events ORDER BY seq")
            ]
            labels = {
                r["event_uuid"]: EventLabel(category=r["category"], scenario=r["scenario"], phase=r["phase"])
                for r in conn.execute("SELECT event_uuid, category, scenario, phase FROM labels")
            }
        return LogDataset(
            seed=seed,
            window_start=window_start,
            window_end=window_end,
            users=self.users(),
            events=events,
            labels=labels,
            attack_steps=self.attack_steps(),
            scenario=scenario,
        )

    def query_events(self, query: EventQuery) -> EventPage:
        """Filter and page through events, oldest first."""
        clauses: list[str] = []
        params: list[object] = []
        for column, value in (
            ("e.event_type", query.event_type),
            ("e.actor_login", query.actor),
            ("e.session_id", query.session_id),
            ("e.ip_address", query.ip_address),
            ("l.category", query.category.value if query.category else None),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")  # column names come from the fixed tuple above
                params.append(value)
        if query.since is not None:
            clauses.append("e.published >= ?")
            params.append(_timestamp(query.since))
        if query.until is not None:
            clauses.append("e.published < ?")
            params.append(_timestamp(query.until))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        limit = max(1, min(query.limit, MAX_PAGE_SIZE))
        offset = max(0, query.offset)
        base = f"FROM events e JOIN labels l ON l.event_uuid = e.uuid {where}"
        with self._connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT e.raw_json, l.category, l.scenario, l.phase {base} ORDER BY e.seq LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        items = [
            LabelledEvent(
                event=SystemLogEvent.model_validate_json(r["raw_json"]),
                label=EventLabel(category=r["category"], scenario=r["scenario"], phase=r["phase"]),
            )
            for r in rows
        ]
        return EventPage(total=int(total), limit=limit, offset=offset, items=items)

    # -- detection results -----------------------------------------------------
    def save_detection(self, result: DetectionResult, evaluation: EvaluationReport) -> None:
        """Replace the stored detection run (alerts, config, rules and evaluation)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM detection_run")
            conn.executemany(
                "INSERT INTO alerts (id, seq, rule_id, severity, first_seen, actor, raw_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (a.id, seq, a.rule_id, a.severity.value, _timestamp(a.first_seen), a.actor,
                     a.model_dump_json())
                    for seq, a in enumerate(result.alerts)
                ],
            )
            conn.execute(
                "INSERT INTO detection_run (id, config_json, rules_json, evaluation_json, events_analyzed)"
                " VALUES (1, ?, ?, ?, ?)",
                (
                    result.config.model_dump_json(),
                    "[" + ",".join(r.model_dump_json() for r in result.rules) + "]",
                    evaluation.model_dump_json(),
                    result.events_analyzed,
                ),
            )

    def has_detection(self) -> bool:
        """True once a detection run has been stored for the current dataset."""
        if not self.path.exists():
            return False
        with self._connect() as conn:
            return conn.execute("SELECT 1 FROM detection_run").fetchone() is not None

    def _detection_row(self, conn: sqlite3.Connection) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM detection_run WHERE id = 1").fetchone()
        if row is None:
            raise LookupError("no detection run stored yet")
        return row

    def evaluation(self) -> EvaluationReport:
        with self._connect() as conn:
            return EvaluationReport.model_validate_json(self._detection_row(conn)["evaluation_json"])

    def detection_config(self) -> DetectionConfig:
        with self._connect() as conn:
            return DetectionConfig.model_validate_json(self._detection_row(conn)["config_json"])

    def detection_result(self) -> DetectionResult:
        """The full stored run, including every alert."""
        with self._connect() as conn:
            row = self._detection_row(conn)
            alerts = [Alert.model_validate_json(r["raw_json"])
                      for r in conn.execute("SELECT raw_json FROM alerts ORDER BY seq")]
        return DetectionResult(
            config=DetectionConfig.model_validate_json(row["config_json"]),
            rules=[RuleInfo.model_validate(r) for r in json.loads(row["rules_json"])],
            alerts=alerts,
            events_analyzed=int(row["events_analyzed"]),
        )

    def query_alerts(self, query: AlertQuery) -> list[Alert]:
        """Filter stored alerts, oldest first."""
        clauses: list[str] = []
        params: list[object] = []
        for column, value in (
            ("rule_id", query.rule_id),
            ("severity", query.severity.value if query.severity else None),
            ("actor", query.actor),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")  # column names come from the fixed tuple above
                params.append(value)
        if query.since is not None:
            clauses.append("first_seen >= ?")
            params.append(_timestamp(query.since))
        if query.until is not None:
            clauses.append("first_seen < ?")
            params.append(_timestamp(query.until))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(f"SELECT raw_json FROM alerts {where} ORDER BY seq", params).fetchall()
        return [Alert.model_validate_json(r["raw_json"]) for r in rows]

    def get_alert(self, alert_id: str) -> Alert | None:
        with self._connect() as conn:
            row = conn.execute("SELECT raw_json FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return Alert.model_validate_json(row["raw_json"]) if row else None

    def events_by_uuid(self, uuids: list[str]) -> list[SystemLogEvent]:
        """Fetch specific events, in chronological order."""
        if not uuids:
            return []
        placeholders = ",".join("?" for _ in uuids)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT raw_json FROM events WHERE uuid IN ({placeholders}) ORDER BY seq", uuids
            ).fetchall()
        return [SystemLogEvent.model_validate_json(r["raw_json"]) for r in rows]
