"""Command-line entry point: ``python -m oktatrace.log_generator``.

Examples (run from the ``backend`` directory)::

    python -m oktatrace.log_generator
    python -m oktatrace.log_generator --seed 7 --out-dir ../data/generated --db ../data/generated/oktatrace.db
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from oktatrace import DISCLAIMER
from oktatrace.config import get_settings
from oktatrace.log_generator.export import export_dataset
from oktatrace.log_generator.generator import generate_dataset, summarize_dataset
from oktatrace.storage import SqliteStore


def main(argv: Sequence[str] | None = None) -> int:
    """Generate a dataset, store it in SQLite and optionally export files."""
    settings = get_settings()
    parser = argparse.ArgumentParser(prog="python -m oktatrace.log_generator", description=DISCLAIMER)
    parser.add_argument("--seed", type=int, default=settings.seed, help="random seed (default %(default)s)")
    parser.add_argument("--db", type=Path, default=settings.db_path, help="SQLite file to (over)write")
    parser.add_argument("--out-dir", type=Path, help="also write JSONL, ground truth and directory here")
    args = parser.parse_args(argv)

    dataset = generate_dataset(args.seed)
    SqliteStore(args.db).save_dataset(dataset)
    summary = summarize_dataset(dataset)

    print(DISCLAIMER)
    print(f"\nseed {summary.seed}: {summary.event_count} events, {summary.user_count} principals, "
          f"{summary.session_count} sessions")
    print("by label: " + ", ".join(f"{k} {v}" for k, v in summary.events_by_category.items()))
    print(f"attack steps: {summary.attack_step_count} | victim session fingerprint "
          f"{summary.victim_session_fingerprint}")
    print(f"stored in {args.db}")
    if args.out_dir:
        for path in export_dataset(dataset, args.out_dir):
            print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
