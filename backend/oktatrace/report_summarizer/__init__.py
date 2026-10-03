"""Module 6 (optional) - report summarizer.

Turns the deterministic findings of modules 1-4 into a plain-English incident
summary, either with an offline template or with one Claude API call. The LLM
only writes prose; Python decides every detection, severity and metric.
"""

from oktatrace.report_summarizer.facts import IncidentFacts, build_facts
from oktatrace.report_summarizer.summarizer import (
    IncidentSummary,
    SummarizerError,
    check_references,
    summarize,
    template_markdown,
)

__all__ = [
    "IncidentFacts",
    "IncidentSummary",
    "SummarizerError",
    "build_facts",
    "check_references",
    "summarize",
    "template_markdown",
]
