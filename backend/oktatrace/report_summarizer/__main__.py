"""Command-line entry point: ``python -m oktatrace.report_summarizer``.

Examples (run from the ``backend`` directory)::

    python -m oktatrace.report_summarizer --mode template --out ../data/generated/summary.md
    python -m oktatrace.report_summarizer --mode llm      # needs ANTHROPIC_API_KEY (makes one paid API call)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from oktatrace import DISCLAIMER
from oktatrace.config import get_settings
from oktatrace.detection_engine.pipeline import run_on_store
from oktatrace.log_generator import generate_dataset
from oktatrace.report_summarizer.pipeline import facts_for_store
from oktatrace.report_summarizer.summarizer import SummarizerError, summarize
from oktatrace.storage import SqliteStore


def main(argv: Sequence[str] | None = None) -> int:
    """Write the incident summary and return a process exit code."""
    settings = get_settings()
    parser = argparse.ArgumentParser(prog="python -m oktatrace.report_summarizer", description=DISCLAIMER)
    parser.add_argument("--db", type=Path, default=settings.db_path)
    parser.add_argument("--mode", choices=("auto", "llm", "template"), default=settings.summary_mode)
    parser.add_argument("--out", type=Path, help="write the Markdown summary here")
    parser.add_argument("--facts", type=Path, help="also write the input facts as JSON")
    args = parser.parse_args(argv)

    store = SqliteStore(args.db)
    if not store.has_dataset():
        store.save_dataset(generate_dataset(settings.seed))
    if not store.has_detection():
        run_on_store(store)
    facts = facts_for_store(store)
    try:
        summary = summarize(facts, mode=args.mode, settings=settings)
    except SummarizerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(summary.markdown)
    origin = f"llm ({summary.model})" if summary.mode == "llm" else "template"
    print(f"--\nwritten by: {origin}; cited IDs: {len(summary.cited_ids)}; unknown IDs: "
          f"{', '.join(summary.unknown_ids) or 'none'}", file=sys.stderr)
    if summary.fallback_reason:
        print(f"note: {summary.fallback_reason}", file=sys.stderr)
    for warning in summary.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(summary.markdown, encoding="utf-8")
    if args.facts:
        args.facts.parent.mkdir(parents=True, exist_ok=True)
        args.facts.write_text(json.dumps(facts.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
