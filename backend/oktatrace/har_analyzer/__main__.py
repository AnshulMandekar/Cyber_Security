"""Command-line entry point: ``python -m oktatrace.har_analyzer``.

Examples (run from the ``backend`` directory)::

    python -m oktatrace.har_analyzer analyze ../data/samples/support_case_00421.har
    python -m oktatrace.har_analyzer analyze in.har --json findings.json --redacted out.har
    python -m oktatrace.har_analyzer sample --out ../data/samples/support_case_00421.har
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from oktatrace import DISCLAIMER
from oktatrace.har_analyzer.analyzer import analyze_har
from oktatrace.har_analyzer.har_io import HarParseError, load_har
from oktatrace.har_analyzer.models import HarAnalysisResult, Severity
from oktatrace.har_analyzer.redactor import redact_har
from oktatrace.har_analyzer.sample_har import build_sample_har


def write_json(path: Path, payload: object) -> None:
    """Write JSON with stable formatting and Unix newlines."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def format_report(result: HarAnalysisResult, source: str) -> str:
    """Render analysis results as a plain-text table."""
    summary, stats = result.summary, result.stats
    severity_counts = ", ".join(f"{s.value} {stats.by_severity.get(s, 0)}" for s in Severity)
    overall = stats.overall_severity.value.upper() if stats.overall_severity else "NONE"
    lines = [
        DISCLAIMER,
        "",
        f"HAR: {source} | {summary.entry_count} entries | {len(summary.hosts)} hosts",
        f"Findings: {stats.total_findings} ({severity_counts}) | long-lived {stats.long_lived_count}"
        f" | overall {overall} ({stats.max_risk_score})",
        "",
        f"{'ID':<8} {'SEVERITY':<9} {'SCORE':>5}  {'KIND':<18} {'NAME':<20} {'SEEN':>4}  PREVIEW",
    ]
    for f in result.findings:
        lines.append(
            f"{f.id:<8} {f.severity.value:<9} {f.risk_score:>5}  {f.kind.value:<18} "
            f"{f.name[:20]:<20} {f.occurrence_count:>4}  {f.value_preview}"
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = argparse.ArgumentParser(prog="python -m oktatrace.har_analyzer", description=DISCLAIMER)
    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser("analyze", help="Analyse a HAR file for exposed secrets")
    analyze.add_argument("har", type=Path, help="Path to a .har file")
    analyze.add_argument("--json", type=Path, help="Write the full analysis as JSON")
    analyze.add_argument("--redacted", type=Path, help="Write a redacted copy of the HAR")

    sample = commands.add_parser("sample", help="Write the synthetic sample HAR")
    sample.add_argument("--out", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.command == "sample":
        write_json(args.out, build_sample_har())
        print(f"Wrote synthetic sample HAR to {args.out}")
        return 0

    try:
        har = load_har(args.har)
    except (OSError, HarParseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    result = analyze_har(har)
    print(format_report(result, str(args.har)))
    if args.json:
        write_json(args.json, result.model_dump(mode="json"))
        print(f"\nWrote analysis JSON to {args.json}")
    if args.redacted:
        redaction = redact_har(har)
        write_json(args.redacted, redaction.har)
        print(f"Wrote redacted HAR ({redaction.redaction_count} fields masked) to {args.redacted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
