"""The victim's day and the labelled intrusion, as synthetic log records.

Timeline (UTC; Acme is on PDT, UTC-7):

* 2023-10-02 14:30 - Jordan Rivera signs in (session ``sid`` = the cookie in the
  sample HAR), troubleshoots, opens CASE-00421 and uploads the HAR at 14:46.
* 19:52 - the vendor's CaseSync service account signs in from unfamiliar hosting
  infrastructure (stolen credential) and downloads HAR attachments, including
  Jordan's (initial access and HAR exfiltration).
* 22:04 - Jordan's session is used from that infrastructure with a different
  browser, while Jordan is still active in San Francisco (session replay). The
  replayed session opens 30 support cases in about 7 minutes (collection).
* 2023-10-03 09:41 (02:41 PDT) - the replayed session returns and makes admin
  changes: a new user, super-admin group membership, an API token and an MFA
  reset. One policy change is refused.

These are log records only: nothing here interacts with any real system.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from oktatrace.common.masking import fingerprint
from oktatrace.log_generator import catalog
from oktatrace.log_generator.builder import (
    EventFactory,
    Recorder,
    group_target,
    user_target,
)
from oktatrace.log_generator.directory import Directory, Endpoint
from oktatrace.log_generator.models import (
    AttackPhase,
    AttackStep,
    EventLabel,
    LabelCategory,
    ScenarioFacts,
    SystemLogEvent,
    Target,
)
from oktatrace.log_generator.sessions import SessionScript
from oktatrace.scenario import (
    ORG_UTC_OFFSET_HOURS,
    SUPPORT_CASE_COUNT,
    SUPPORT_CASE_ID,
    make_scenario_tokens,
    random_token,
)

VICTIM_DAY = date(2023, 10, 2)
SERVICE_ACCOUNT_IP = catalog.ATTACKER_VPS.address(207)
REPLAY_IP = catalog.ATTACKER_VPS.address(211)
HAR_FILENAME = "support_case_00421.har"
BACKDOOR_LOGIN = "it-helpdesk-svc@acme.example"


def _utc(day: date, hour: int, minute: int, second: float = 0.0) -> datetime:
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=timezone.utc) + timedelta(
        seconds=second
    )


@dataclass
class _StepLog:
    """Records attack steps in order as their events are emitted."""

    steps: list[AttackStep] = field(default_factory=list)

    def add(self, event: SystemLogEvent, phase: AttackPhase, credential: str, description: str,
            *, sensitive: bool = False) -> None:
        self.steps.append(
            AttackStep(
                step=len(self.steps) + 1,
                phase=phase,
                event_uuid=event.uuid,
                published=event.published,
                event_type=event.event_type,
                credential=credential,  # type: ignore[arg-type]
                outcome=event.outcome.result,
                sensitive=sensitive,
                description=description,
            )
        )


def _attack_label(phase: AttackPhase) -> EventLabel:
    return EventLabel(category=LabelCategory.ATTACK, scenario="okta_support_breach", phase=phase)


def _victim_day(directory: Directory, session_id: str, rng: random.Random, factory: EventFactory,
                recorder: Recorder) -> datetime:
    """Jordan's real working day in the session that later gets replayed; returns the HAR upload time."""
    victim = directory.victim
    daily = EventLabel(category=LabelCategory.BENIGN, scenario="victim_daily_work")
    context = EventLabel(category=LabelCategory.CONTEXT, scenario="har_capture_and_upload")
    script = SessionScript(factory, recorder, victim, victim.primary, daily, session_id=session_id)
    day = VICTIM_DAY

    script.emit(_utc(day, 14, 30, 0.6), catalog.SESSION_START, credential_type="PASSWORD", label=context)
    script.mfa(_utc(day, 14, 30, 5.2))
    script.sso(_utc(day, 14, 30, 9.1), catalog.ADMIN_CONSOLE)
    script.sso(_utc(day, 14, 30, 20.3), catalog.REPORTS)
    script.sso(_utc(day, 14, 44, 30), catalog.SUPPORT_PORTAL)
    script.emit(_utc(day, 14, 44, 58), catalog.SUPPORT_CASE_CREATE,
                targets=[Target(id=SUPPORT_CASE_ID, type="SupportCase", alternate_id=SUPPORT_CASE_ID,
                                display_name=f"Support case {SUPPORT_CASE_ID}")],
                label=context)
    script.label = context
    upload = script.attachment(_utc(day, 14, 46, 5), SUPPORT_CASE_ID, HAR_FILENAME, upload=True)
    script.label = daily

    # Routine work through the afternoon, including activity either side of the replay.
    fixed = [_utc(day, 21, 58, 30), _utc(day, 22, 13, 10)]
    spread = [_utc(day, 15, 0) + timedelta(minutes=rng.uniform(0, 520)) for _ in range(12)]
    for when in sorted(fixed + spread):
        script.sso(when, rng.choice(victim.apps[:4]))
    burst = _utc(day, 17, 20)
    script.sso(burst, catalog.ADMIN_CONSOLE)
    script.mfa(burst + timedelta(seconds=40))
    employee = directory.with_role("employee")[3]
    script.admin(burst + timedelta(minutes=2), "group.user_membership.add",
                 [user_target(employee.user_id, employee.login, employee.display_name),
                  group_target("VPN-Users")])
    script.admin(burst + timedelta(minutes=5), "application.user_membership.add",
                 [user_target(employee.user_id, employee.login, employee.display_name),
                  Target(id=catalog.JIRA.app_id, type="AppInstance", alternate_id="Jira", display_name="Jira")])
    # No logout: the laptop is closed with the session still alive.
    return upload.published


def build_attack_scenario(
    directory: Directory, seed: int, recorder: Recorder
) -> tuple[list[AttackStep], ScenarioFacts, set[tuple[str, date]]]:
    """Emit the victim's day and the labelled attack.

    Returns:
        The ordered attack steps, scenario facts, and the user-days this module owns.
    """
    rng = random.Random(f"{seed}-attack")
    factory = EventFactory(rng)
    tokens = make_scenario_tokens(seed)
    victim = directory.victim
    service = directory.service_account
    steps = _StepLog()

    uploaded_at = _victim_day(directory, tokens.session_id, rng, factory, recorder)

    # Phase 1-2: stolen service-account credential, HAR attachments downloaded.
    svc_endpoint = Endpoint(catalog.ATTACKER_VPS, SERVICE_ACCOUNT_IP, catalog.PYTHON_REQUESTS, "")
    svc = SessionScript(factory, recorder, service, svc_endpoint,
                        _attack_label(AttackPhase.INITIAL_ACCESS))
    login = svc.emit(_utc(VICTIM_DAY, 19, 52, 7), catalog.SESSION_START, credential_type="PASSWORD")
    steps.add(login, AttackPhase.INITIAL_ACCESS, "service_account_password",
              "CaseSync service account signs in from unfamiliar hosting infrastructure")

    svc.label = _attack_label(AttackPhase.HAR_EXFILTRATION)
    other_cases = [catalog.case_id(n) for n in rng.sample(range(300, SUPPORT_CASE_COUNT), 5)]
    when = _utc(VICTIM_DAY, 19, 53, 30)
    for case in [SUPPORT_CASE_ID, *other_cases]:
        filename = HAR_FILENAME if case == SUPPORT_CASE_ID else f"{case.lower()}_browser.har"
        viewed = svc.case_view(when, case)
        steps.add(viewed, AttackPhase.HAR_EXFILTRATION, "service_account_password",
                  f"Opens {case}, which has a HAR attachment")
        fetched = svc.attachment(when + timedelta(seconds=11), case, filename, upload=False)
        steps.add(fetched, AttackPhase.HAR_EXFILTRATION, "service_account_password",
                  f"Downloads {filename}")
        when += timedelta(seconds=rng.uniform(40, 55))

    # Phase 3: Jordan's session replayed from new infrastructure and a different browser.
    # The DT cookie was in the HAR too, so the replayed requests carry Jordan's dtHash.
    replay_endpoint = Endpoint(catalog.ATTACKER_VPS, REPLAY_IP, catalog.WIN_FIREFOX_118,
                               victim.primary.dt_hash)
    replay = SessionScript(factory, recorder, victim, replay_endpoint,
                           _attack_label(AttackPhase.SESSION_REPLAY), session_id=tokens.session_id)
    first_use = replay.sso(_utc(VICTIM_DAY, 22, 4, 10), catalog.ADMIN_CONSOLE)
    steps.add(first_use, AttackPhase.SESSION_REPLAY, "stolen_session_cookie",
              "Victim's session used from new IP, ASN and browser with no new sign-in")
    portal = replay.sso(_utc(VICTIM_DAY, 22, 4, 35), catalog.SUPPORT_PORTAL)
    steps.add(portal, AttackPhase.SESSION_REPLAY, "stolen_session_cookie",
              "Replayed session opens the support portal")

    # Phase 4: bulk support-case access.
    replay.label = _attack_label(AttackPhase.CASE_COLLECTION)
    cases = [catalog.case_id(n) for n in rng.sample(range(1, SUPPORT_CASE_COUNT + 1), 30)]
    start = _utc(VICTIM_DAY, 22, 5, 0)
    for i, case in enumerate(cases):
        viewed = replay.case_view(start + timedelta(seconds=i * 15 + rng.uniform(0, 3)), case)
        steps.add(viewed, AttackPhase.CASE_COLLECTION, "stolen_session_cookie", f"Views {case}")

    # Phase 5: off-hours admin changes through the same replayed session.
    next_day = VICTIM_DAY + timedelta(days=1)
    replay.label = _attack_label(AttackPhase.SESSION_REPLAY)
    returned = replay.sso(_utc(next_day, 9, 41, 12), catalog.ADMIN_CONSOLE)
    steps.add(returned, AttackPhase.SESSION_REPLAY, "stolen_session_cookie",
              "Replayed session returns to the admin console at 02:41 local time")

    replay.label = _attack_label(AttackPhase.ADMIN_ATTEMPT)
    backdoor_id = random_token(rng, "00uSYN", 14)
    backdoor = user_target(backdoor_id, BACKDOOR_LOGIN, "IT Helpdesk Service")
    other_admin = next(u for u in directory.with_role("admin") if u.login != victim.login)
    admin_actions: list[tuple[str, list[Target], str, str | None, str]] = [
        ("user.lifecycle.create", [backdoor], "SUCCESS", None,
         f"Creates a new user {BACKDOOR_LOGIN}"),
        ("group.user_membership.add", [backdoor, group_target("Acme-Super-Admins")], "SUCCESS", None,
         "Adds the new user to the super-admin group"),
        ("system.api_token.create", [Target(id=random_token(rng, "00TSYN", 14), type="Token",
                                            alternate_id="sync-helper", display_name="sync-helper")],
         "SUCCESS", None, "Creates an API token"),
        ("user.mfa.factor.deactivate",
         [user_target(other_admin.user_id, other_admin.login, other_admin.display_name)],
         "SUCCESS", None, f"Resets MFA factors for {other_admin.login}"),
        ("policy.rule.update", [Target(id="0prSYNdefaultRule1", type="PolicyRule",
                                       alternate_id="Default sign-on rule",
                                       display_name="Default sign-on rule")],
         "FAILURE", "Insufficient permissions: super administrator role required",
         "Tries to weaken the default sign-on rule (refused)"),
    ]
    when = _utc(next_day, 9, 42, 3)
    for event_type, targets, outcome, reason, description in admin_actions:
        event = replay.admin(when, event_type, targets, outcome=outcome, reason=reason)  # type: ignore[arg-type]
        steps.add(event, AttackPhase.ADMIN_ATTEMPT, "stolen_session_cookie", description, sensitive=True)
        when += timedelta(seconds=rng.uniform(35, 50))

    facts = ScenarioFacts(
        victim_login=victim.login,
        victim_user_id=victim.user_id,
        victim_session_id=tokens.session_id,
        victim_session_fingerprint=fingerprint(tokens.session_id),
        victim_device_fingerprint=fingerprint(tokens.device_token),
        compromised_service_account=service.login,
        support_case_id=SUPPORT_CASE_ID,
        har_uploaded_at=uploaded_at,
        attacker_ips=[SERVICE_ACCOUNT_IP, REPLAY_IP],
        attacker_asn=catalog.ATTACKER_VPS.as_number,
        org_utc_offset_hours=ORG_UTC_OFFSET_HOURS,
    )
    return steps.steps, facts, {(victim.login, VICTIM_DAY)}
