"""Module 1 - HAR analyzer.

Parses HTTP Archive files, finds session cookies, Authorization headers, JWTs
(decoded, never verified) and long-lived tokens, scores each finding, and
produces a redacted copy with every secret masked.
"""

from oktatrace.har_analyzer.analyzer import analyze_har
from oktatrace.har_analyzer.har_io import HarParseError, load_har
from oktatrace.har_analyzer.models import (
    Finding,
    FindingKind,
    HarAnalysisResult,
    Occurrence,
    RiskFactor,
    Severity,
)
from oktatrace.har_analyzer.redactor import RedactionResult, redact_har, redact_url

__all__ = [
    "Finding",
    "FindingKind",
    "HarAnalysisResult",
    "HarParseError",
    "Occurrence",
    "RedactionResult",
    "RiskFactor",
    "Severity",
    "analyze_har",
    "load_har",
    "redact_har",
    "redact_url",
]
