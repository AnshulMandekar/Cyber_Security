"""Assemble the full synthetic dataset and check its invariants."""

from __future__ import annotations

from collections import Counter

from pydantic import BaseModel

from oktatrace.log_generator.attack import build_attack_scenario
from oktatrace.log_generator.benign import simulate_population
from oktatrace.log_generator.builder import Recorder
from oktatrace.log_generator.directory import build_directory
from oktatrace.log_generator.edge_cases import build_edge_cases
from oktatrace.log_generator.models import LabelCategory, LogDataset
from oktatrace.scenario import DEFAULT_SEED, LOG_WINDOW_END, LOG_WINDOW_START

MIN_EVENTS = 5000


class DatasetInvariantError(RuntimeError):
    """Raised when a generated dataset breaks one of its guarantees."""


class DatasetSummary(BaseModel):
    """Headline numbers for a dataset."""

    seed: int
    event_count: int
    user_count: int
    session_count: int
    events_by_type: dict[str, int]
    events_by_category: dict[str, int]
    attack_step_count: int
    victim_login: str
    victim_session_fingerprint: str


def validate_dataset(dataset: LogDataset) -> None:
    """Check ordering, labelling, window and attack-step consistency.

    Raises:
        DatasetInvariantError: Describing the first broken invariant.
    """
    events = dataset.events
    uuids = [e.uuid for e in events]
    if len(set(uuids)) != len(uuids):
        raise DatasetInvariantError("duplicate event UUIDs")
    if any(a.published > b.published for a, b in zip(events, events[1:])):
        raise DatasetInvariantError("events are not in chronological order")
    if set(dataset.labels) != set(uuids):
        raise DatasetInvariantError("every event needs exactly one label")
    outside = [e.uuid for e in events if not dataset.window_start <= e.published < dataset.window_end]
    if outside:
        raise DatasetInvariantError(f"{len(outside)} events fall outside the log window")
    attack_uuids = {u for u, label in dataset.labels.items() if label.category is LabelCategory.ATTACK}
    step_uuids = [s.event_uuid for s in dataset.attack_steps]
    if set(step_uuids) != attack_uuids or len(step_uuids) != len(attack_uuids):
        raise DatasetInvariantError("attack steps and attack labels disagree")


def generate_dataset(seed: int = DEFAULT_SEED) -> LogDataset:
    """Generate the deterministic synthetic System Log for ``seed``.

    Benign activity for ~50 principals is combined with five labelled edge cases
    and the labelled intrusion. The same seed always yields an identical dataset.
    """
    directory = build_directory(seed)
    recorder = Recorder()
    attack_steps, facts, attack_days = build_attack_scenario(directory, seed, recorder)
    edge_days = build_edge_cases(directory, seed, recorder)
    simulate_population(directory, seed, recorder, skip=attack_days | edge_days)

    in_window = [e for e in recorder.events if LOG_WINDOW_START <= e.published < LOG_WINDOW_END]
    in_window.sort(key=lambda e: (e.published, e.uuid))
    dataset = LogDataset(
        seed=seed,
        window_start=LOG_WINDOW_START,
        window_end=LOG_WINDOW_END,
        users=[u.to_entry() for u in directory.users],
        events=in_window,
        labels={e.uuid: recorder.labels[e.uuid] for e in in_window},
        attack_steps=attack_steps,
        scenario=facts,
    )
    validate_dataset(dataset)
    if len(dataset.events) < MIN_EVENTS:
        raise DatasetInvariantError(f"only {len(dataset.events)} events generated (< {MIN_EVENTS})")
    return dataset


def summarize_dataset(dataset: LogDataset) -> DatasetSummary:
    """Count events by type and label category."""
    return DatasetSummary(
        seed=dataset.seed,
        event_count=len(dataset.events),
        user_count=len(dataset.users),
        session_count=len({e.session_id for e in dataset.events if e.session_id}),
        events_by_type=dict(sorted(Counter(e.event_type for e in dataset.events).items())),
        events_by_category=dict(sorted(Counter(l.category.value for l in dataset.labels.values()).items())),
        attack_step_count=len(dataset.attack_steps),
        victim_login=dataset.scenario.victim_login,
        victim_session_fingerprint=dataset.scenario.victim_session_fingerprint,
    )
