"""Command-line entry point: ``python -m oktatrace.timeline_builder``.

Example (run from the ``backend`` directory)::

    python -m oktatrace.timeline_builder --scope incident --json ../data/generated/timeline.json
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from oktatrace import DISCLAIMER
from oktatrace.config import get_settings
from oktatrace.detection_engine.pipeline import run_on_store
from oktatrace.log_generator import generate_dataset
from oktatrace.storage import SqliteStore
from oktatrace.timeline_builder.evaluation import TimelineEvaluation
from oktatrace.timeline_builder.models import TimelineResult
from oktatrace.timeline_builder.pipeline import timeline_for_store


def format_timeline(result: TimelineResult, evaluation: TimelineEvaluation, *, collapse: bool = True) -> str:
    """Render the timeline as text; consecutive identical event rows are collapsed."""
    lines = [DISCLAIMER, "", f"Scope: {result.scope} | {len(result.entries)} entries | "
             f"incident alerts {len(result.incident_alerts)} | excluded {', '.join(result.excluded_alerts) or 'none'}",
             f"Pivots: fingerprints {result.pivots.matched_fingerprints}, actors {result.pivots.actors}, "
             f"ASNs {result.pivots.attacker_asns}", ""]
    previous_title, repeats = None, 0
    for entry in result.entries:
        key = (entry.kind, entry.title.split(":")[0], entry.actor, entry.source_ip, entry.suspicious)
        if collapse and entry.kind == "event" and key == previous_title:
            repeats += 1
            continue
        if repeats:
            lines.append(f"{'':>8} ... {repeats} more similar event(s)")
        previous_title, repeats = key, 0
        techniques = ",".join(t.technique_id for t in entry.mitre) or "-"
        marker = "!" if entry.suspicious else " "
        lines.append(f"{entry.id} {marker} {entry.timestamp:%m-%d %H:%M:%S}  {entry.kind:<11} "
                     f"{(entry.stage or '-'):<17} {techniques:<24} {entry.title[:80]}")
    if repeats:
        lines.append(f"{'':>8} ... {repeats} more similar event(s)")
    lines += ["", "ATT&CK techniques:"]
    lines += [f"  {r.technique_id:<10} {r.name:<60} {r.tactic:<17} x{r.entries:<3} first {r.first_seen:%m-%d %H:%M}"
              for r in result.mitre_summary]
    lines += ["", f"Attack events in timeline: {evaluation.attack_events_in_timeline}/{evaluation.attack_events}; "
              f"benign context entries: {evaluation.benign_event_entries} "
              f"(tagged with a technique: {evaluation.benign_entries_tagged_with_technique})"]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Build and print the timeline."""
    settings = get_settings()
    parser = argparse.ArgumentParser(prog="python -m oktatrace.timeline_builder", description=DISCLAIMER)
    parser.add_argument("--db", type=Path, default=settings.db_path)
    parser.add_argument("--scope", choices=("incident", "all_alerts"), default="incident")
    parser.add_argument("--json", type=Path, help="write the timeline as JSON")
    parser.add_argument("--full", action="store_true", help="do not collapse repeated events")
    args = parser.parse_args(argv)

    store = SqliteStore(args.db)
    if not store.has_dataset():
        store.save_dataset(generate_dataset(settings.seed))
    if not store.has_detection():
        run_on_store(store)
    result, evaluation = timeline_for_store(store, args.scope)
    print(format_timeline(result, evaluation, collapse=not args.full))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
