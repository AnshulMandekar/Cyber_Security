"""Severity scale shared by HAR findings and detection alerts."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Severity bucket, most severe first."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """0 for critical up to 3 for low; handy for sorting."""
        return list(Severity).index(self)
