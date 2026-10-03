"""Shared pytest fixtures."""

from __future__ import annotations

from typing import Any

import pytest

from oktatrace.har_analyzer import HarAnalysisResult, analyze_har
from oktatrace.har_analyzer.sample_har import build_sample_har, sample_secret_values
from oktatrace.log_generator import LogDataset, generate_dataset

EIGHT_HOURS = 8 * 3600


@pytest.fixture(scope="session")
def dataset() -> LogDataset:
    """The default synthetic log dataset (generated once per test run; treat as read-only)."""
    return generate_dataset()


@pytest.fixture
def sample_har() -> dict[str, Any]:
    """A fresh copy of the synthetic sample HAR."""
    return build_sample_har()


@pytest.fixture
def sample_analysis(sample_har: dict[str, Any]) -> HarAnalysisResult:
    """Analysis of the sample HAR with the default 8-hour long-lived threshold."""
    return analyze_har(sample_har, long_lived_threshold_seconds=EIGHT_HOURS)


@pytest.fixture
def sample_secrets() -> list[str]:
    """Every raw fake secret embedded in the sample HAR."""
    return sample_secret_values()
