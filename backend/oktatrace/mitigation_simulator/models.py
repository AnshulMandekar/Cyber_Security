"""Models for the mitigation simulator."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from oktatrace.log_generator.models import AttackPhase


class MitigationConfig(BaseModel):
    """Which controls are switched on, and their parameters."""

    model_config = ConfigDict(frozen=True)

    har_redaction: bool = Field(False, description="HAR files are sanitised before upload")
    session_ttl: bool = Field(False, description="Sessions have a short maximum lifetime")
    session_ttl_minutes: int = Field(120, ge=5, le=1440)
    session_binding: bool = Field(False, description="Sessions are bound to the IP and device they started on")
    step_up_reauth: bool = Field(False, description="Admin actions require fresh MFA")
    step_up_window_minutes: int = Field(15, ge=1, le=240)

    def enabled(self) -> list[str]:
        """Names of the controls that are switched on."""
        return [name for name in ("har_redaction", "session_ttl", "session_binding", "step_up_reauth")
                if getattr(self, name)]


class StepResult(BaseModel):
    """One recorded attack step, before and after the controls."""

    step: int
    phase: AttackPhase
    event_type: str
    published: datetime
    credential: str
    baseline_outcome: str
    succeeded_before: bool
    succeeded_after: bool
    blocked_by: list[str]
    reasons: list[str]


class PhaseImpact(BaseModel):
    phase: AttackPhase
    steps: int
    succeeded_before: int
    succeeded_after: int


class ControlImpact(BaseModel):
    control: str
    steps_blocked: int = Field(description="Steps that succeeded at baseline and this control blocks")


class SimulationResult(BaseModel):
    """Before/after counts for one combination of controls."""

    config: MitigationConfig
    total_steps: int
    succeeded_before: int
    succeeded_after: int
    blocked: int
    by_phase: list[PhaseImpact]
    by_control: list[ControlImpact]
    steps: list[StepResult]


class ComparisonRow(BaseModel):
    """One line of the each-control-alone comparison."""

    label: str
    config: MitigationConfig
    succeeded_before: int
    succeeded_after: int
    reduction_pct: float
