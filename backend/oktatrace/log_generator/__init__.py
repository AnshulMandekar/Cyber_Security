"""Module 2 - log generator.

Produces a deterministic, synthetic Okta-style System Log (5,000+ events for
~50 principals over 7 days) with ground-truth labels, benign edge cases and a
labelled intrusion modelled on the 2023 support-system breach.
"""

from oktatrace.log_generator.generator import (
    DatasetInvariantError,
    DatasetSummary,
    generate_dataset,
    summarize_dataset,
    validate_dataset,
)
from oktatrace.log_generator.models import (
    AttackPhase,
    AttackStep,
    EventLabel,
    LabelCategory,
    LogDataset,
    ScenarioFacts,
    SystemLogEvent,
)

__all__ = [
    "AttackPhase",
    "AttackStep",
    "DatasetInvariantError",
    "DatasetSummary",
    "EventLabel",
    "LabelCategory",
    "LogDataset",
    "ScenarioFacts",
    "SystemLogEvent",
    "generate_dataset",
    "summarize_dataset",
    "validate_dataset",
]
