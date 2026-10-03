"""Regenerate the bundled synthetic artefacts under ``data/samples/``.

Writes the sample HAR (plus redacted copy and findings), the synthetic System
Log (JSONL, ground truth, directory), its detection results, the incident timeline and an offline
(template) incident summary.

Usage (from the project root)::

    python scripts/generate_samples.py

Output is deterministic: the same seed always produces byte-identical files.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from oktatrace import DISCLAIMER  # noqa: E402
from oktatrace.detection_engine.pipeline import detect_and_evaluate  # noqa: E402
from oktatrace.har_analyzer import analyze_har, redact_har  # noqa: E402
from oktatrace.har_analyzer.__main__ import write_json  # noqa: E402
from oktatrace.har_analyzer.sample_har import SAMPLE_HAR_FILENAME, build_sample_har  # noqa: E402
from oktatrace.log_generator import generate_dataset  # noqa: E402
from oktatrace.log_generator.export import export_dataset  # noqa: E402
from oktatrace.report_summarizer import build_facts, summarize  # noqa: E402
from oktatrace.timeline_builder import build_timeline  # noqa: E402
from oktatrace.timeline_builder.pipeline import sample_har_evidence  # noqa: E402

SAMPLES_DIR = ROOT / "data" / "samples"
EIGHT_HOURS = 8 * 3600


def main() -> int:
    """Write the sample HAR artefacts, the synthetic System Log and its detections."""
    print(DISCLAIMER)
    har = build_sample_har()
    stem = Path(SAMPLE_HAR_FILENAME).stem
    outputs = {
        SAMPLES_DIR / SAMPLE_HAR_FILENAME: har,
        SAMPLES_DIR / f"{stem}.redacted.har": redact_har(har).har,
        SAMPLES_DIR / f"{stem}.findings.json": analyze_har(
            har, long_lived_threshold_seconds=EIGHT_HOURS
        ).model_dump(mode="json"),
    }
    for path, payload in outputs.items():
        write_json(path, payload)
        print(f"wrote {path.relative_to(ROOT)}")
    dataset = generate_dataset()
    for path in export_dataset(dataset, SAMPLES_DIR):
        print(f"wrote {path.relative_to(ROOT)}")
    result, evaluation = detect_and_evaluate(dataset)
    detections = SAMPLES_DIR / "detections.json"
    write_json(detections, {"result": result.model_dump(mode="json"),
                            "evaluation": evaluation.model_dump(mode="json")})
    print(f"wrote {detections.relative_to(ROOT)}")
    timeline = build_timeline(dataset.events, result.alerts, sample_har_evidence(dataset.seed, EIGHT_HOURS))
    timeline_path = SAMPLES_DIR / "timeline.json"
    write_json(timeline_path, timeline.model_dump(mode="json"))
    print(f"wrote {timeline_path.relative_to(ROOT)}")
    har_evidence = sample_har_evidence(dataset.seed, EIGHT_HOURS)
    facts = build_facts(har_evidence.analysis, result, evaluation, timeline, dataset.scenario)
    summary_path = SAMPLES_DIR / "incident_summary.template.md"
    summary_path.write_text(summarize(facts, mode="template").markdown, encoding="utf-8", newline="\n")
    print(f"wrote {summary_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
