"""Write a dataset to plain files: Okta-style JSONL, ground truth and directory."""

from __future__ import annotations

import json
from pathlib import Path

from oktatrace import DISCLAIMER
from oktatrace.log_generator.models import LogDataset

LOG_FILENAME = "system_log.jsonl"
GROUND_TRUTH_FILENAME = "ground_truth.json"
DIRECTORY_FILENAME = "directory.json"


def _write_json(path: Path, payload: object) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def export_dataset(dataset: LogDataset, out_dir: Path) -> list[Path]:
    """Write the log, ground truth and directory files; returns the paths written.

    The log file contains events only. Labels and the attack script go in a
    separate ground-truth file, exactly as a detection engineer would receive
    an evaluation dataset.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / LOG_FILENAME
    with log_path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in dataset.events:
            handle.write(json.dumps(event.model_dump(mode="json", by_alias=True), separators=(",", ":")))
            handle.write("\n")

    truth_path = out_dir / GROUND_TRUTH_FILENAME
    _write_json(
        truth_path,
        {
            "disclaimer": DISCLAIMER,
            "seed": dataset.seed,
            "window_start": dataset.window_start.isoformat(),
            "window_end": dataset.window_end.isoformat(),
            "scenario": dataset.scenario.model_dump(mode="json"),
            "attack_steps": [s.model_dump(mode="json") for s in dataset.attack_steps],
            "labels": {uuid: label.model_dump(mode="json") for uuid, label in dataset.labels.items()},
        },
    )
    directory_path = out_dir / DIRECTORY_FILENAME
    _write_json(directory_path, [u.model_dump(mode="json") for u in dataset.users])
    return [log_path, truth_path, directory_path]
