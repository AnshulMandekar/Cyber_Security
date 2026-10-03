"""Okta-style System Log event models, ground-truth labels and the dataset container.

Field names are snake_case in Python and serialise to Okta's camelCase JSON
(``eventType``, ``authenticationContext.externalSessionId`` ...) via aliases.
Only the subset of the real schema that the demo needs is modelled.

Ground-truth labels live beside the events, never inside them, so detection
rules cannot accidentally read the answer.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

Outcome = Literal["SUCCESS", "FAILURE", "DENY"]


class OktaModel(BaseModel):
    """Base model: camelCase aliases and immutable instances."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, frozen=True)


class Actor(OktaModel):
    id: str
    type: str = "User"
    alternate_id: str
    display_name: str


class UserAgent(OktaModel):
    raw_user_agent: str
    os: str
    browser: str


class Geolocation(OktaModel):
    lat: float
    lon: float


class GeographicalContext(OktaModel):
    city: str
    state: str
    country: str
    geolocation: Geolocation


class Client(OktaModel):
    user_agent: UserAgent
    zone: str = "null"
    device: str
    ip_address: str
    geographical_context: GeographicalContext


class AuthenticationContext(OktaModel):
    authentication_provider: str = "OKTA_AUTHENTICATION_PROVIDER"
    credential_type: str | None = None
    external_session_id: str | None = None
    authentication_step: int = 0


class SecurityContext(OktaModel):
    as_number: int
    as_org: str
    isp: str
    domain: str
    is_proxy: bool = False


class EventOutcome(OktaModel):
    result: Outcome
    reason: str | None = None


class Target(OktaModel):
    id: str
    type: str
    alternate_id: str
    display_name: str


class Transaction(OktaModel):
    type: str = "WEB"
    id: str


class DebugContext(OktaModel):
    debug_data: dict[str, str]


class SystemLogEvent(OktaModel):
    """One Okta-style System Log event."""

    uuid: str
    published: datetime
    event_type: str
    version: str = "0"
    severity: Literal["INFO", "WARN", "ERROR"]
    display_message: str
    actor: Actor
    client: Client
    authentication_context: AuthenticationContext
    security_context: SecurityContext
    outcome: EventOutcome
    target: list[Target] = Field(default_factory=list)
    transaction: Transaction
    debug_context: DebugContext

    @property
    def session_id(self) -> str | None:
        """Shortcut for ``authenticationContext.externalSessionId``."""
        return self.authentication_context.external_session_id

    @property
    def ip_address(self) -> str:
        """Shortcut for ``client.ipAddress``."""
        return self.client.ip_address


class LabelCategory(StrEnum):
    """Ground-truth class of an event."""

    BENIGN = "benign"
    EDGE_CASE = "edge_case"  # benign but deliberately suspicious-looking
    CONTEXT = "context"  # benign, but part of the incident story (e.g. the HAR upload)
    ATTACK = "attack"


class AttackPhase(StrEnum):
    """Stages of the labelled intrusion."""

    INITIAL_ACCESS = "initial_access"
    HAR_EXFILTRATION = "har_exfiltration"
    SESSION_REPLAY = "session_replay"
    CASE_COLLECTION = "case_collection"
    ADMIN_ATTEMPT = "admin_attempt"


class EventLabel(BaseModel):
    """Ground truth for one event."""

    category: LabelCategory
    scenario: str = Field(description="Behaviour that produced the event, e.g. 'daily_work'")
    phase: AttackPhase | None = None

    @property
    def is_attack(self) -> bool:
        return self.category is LabelCategory.ATTACK


class AttackStep(BaseModel):
    """One attacker action, in order, with what it relied on."""

    step: int
    phase: AttackPhase
    event_uuid: str
    published: datetime
    event_type: str
    credential: Literal["service_account_password", "stolen_session_cookie"]
    outcome: Outcome
    sensitive: bool = Field(description="True for admin actions that warrant step-up re-auth")
    description: str


class DirectoryEntry(BaseModel):
    """A synthetic directory principal."""

    user_id: str
    login: str
    display_name: str
    role: Literal["employee", "admin", "support_engineer", "service_account"]
    department: str
    city: str
    utc_offset_hours: int
    network: str
    ip_address: str
    user_agent: str


class ScenarioFacts(BaseModel):
    """Facts about the planted incident, for timelines and evaluation only."""

    victim_login: str
    victim_user_id: str
    victim_session_id: str
    victim_session_fingerprint: str = Field(description="Matches the sid finding in the sample HAR")
    victim_device_fingerprint: str = Field(description="Matches the DT finding in the sample HAR")
    compromised_service_account: str
    support_case_id: str
    har_uploaded_at: datetime
    attacker_ips: list[str]
    attacker_asn: int
    org_utc_offset_hours: int


class LogDataset(BaseModel):
    """A complete generated dataset: directory, events, labels and the attack script."""

    seed: int
    window_start: datetime
    window_end: datetime
    users: list[DirectoryEntry]
    events: list[SystemLogEvent]
    labels: dict[str, EventLabel]
    attack_steps: list[AttackStep]
    scenario: ScenarioFacts
