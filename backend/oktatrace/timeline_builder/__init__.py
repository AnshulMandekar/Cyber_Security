"""Module 4 - timeline builder.

Merges HAR evidence, System Log events and alerts into one ordered incident
timeline, tags each entry with MITRE ATT&CK techniques and points every entry
at its evidence (event UUID, alert ID, HAR finding ID or HAR file).
"""

from oktatrace.timeline_builder.builder import HarEvidence, build_timeline
from oktatrace.timeline_builder.evaluation import TimelineEvaluation, evaluate_timeline
from oktatrace.timeline_builder.models import (
    EvidenceRef,
    MitreTag,
    TimelineEntry,
    TimelineResult,
)

__all__ = [
    "EvidenceRef",
    "HarEvidence",
    "MitreTag",
    "TimelineEntry",
    "TimelineEvaluation",
    "TimelineResult",
    "build_timeline",
    "evaluate_timeline",
]
