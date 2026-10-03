"""Everyday benign activity for the whole directory.

Each principal gets its own seeded RNG, so changing one user's behaviour never
reshuffles anyone else's events.
"""

from __future__ import annotations

import random
from datetime import date, datetime, timedelta

from oktatrace.log_generator import catalog
from oktatrace.log_generator.builder import EventFactory, Recorder, group_target, user_target
from oktatrace.log_generator.directory import Directory, DirectoryUser, Endpoint
from oktatrace.log_generator.models import EventLabel, LabelCategory, Target
from oktatrace.log_generator.sessions import (
    ATTACHMENT_NAMES,
    SessionScript,
    local_time,
    random_case,
    window_dates,
)
from oktatrace.scenario import LOG_WINDOW_DAYS, LOG_WINDOW_START, random_token

DAILY_WORK = EventLabel(category=LabelCategory.BENIGN, scenario="daily_work")
CASE_SYNC = EventLabel(category=LabelCategory.BENIGN, scenario="case_sync")

SUPPORT_ACTIVITY_PROBABILITY = {"employee": 0.08, "admin": 0.35}


def admin_targets(event_type: str, rng: random.Random, directory: Directory) -> list[Target]:
    """Plausible targets for a routine admin action."""
    employees = directory.with_role("employee")
    person = rng.choice(employees)
    who = user_target(person.user_id, person.login, person.display_name)
    groups = catalog.GROUPS[:-1]  # routine work never touches the super-admin group
    if event_type.startswith("group."):
        return [who, group_target(rng.choice(groups))]
    if event_type == "application.user_membership.add":
        app = rng.choice((catalog.SLACK, catalog.JIRA, catalog.GITHUB, catalog.SALESFORCE, catalog.AWS))
        return [who, Target(id=app.app_id, type="AppInstance", alternate_id=app.label,
                            display_name=app.label)]
    if event_type == "user.lifecycle.create":
        hire = random_token(rng, "", 4).lower()
        login = f"new.hire.{hire}@{person.login.split('@')[1]}"
        return [user_target(random_token(rng, "00uSYN", 14), login, f"New Hire {hire.upper()}")]
    if event_type == "system.api_token.create":
        return [Target(id=random_token(rng, "00TSYN", 14), type="Token",
                       alternate_id="terraform-ci", display_name="terraform-ci")]
    if event_type == "policy.rule.update":
        return [Target(id="0prSYNdefaultRule1", type="PolicyRule", alternate_id="Default sign-on rule",
                       display_name="Default sign-on rule")]
    return [who]


def _human_session(
    user: DirectoryUser,
    endpoint: Endpoint,
    day: date,
    start: float,
    end: float,
    *,
    weekend: bool,
    rng: random.Random,
    factory: EventFactory,
    recorder: Recorder,
    directory: Directory,
) -> None:
    """One browser session: login, MFA, app use, optional support and admin work, logout."""
    place = user.home
    script = SessionScript(factory, recorder, user, endpoint, DAILY_WORK)
    login_at = local_time(day, start, place)
    if rng.random() < 0.04:
        script.failed_login(login_at - timedelta(seconds=rng.randint(20, 90)))
    script.emit(login_at, catalog.SESSION_START, credential_type="PASSWORD")
    mfa_at = login_at + timedelta(seconds=rng.uniform(3, 20))
    if rng.random() < 0.015:
        script.mfa(mfa_at, outcome="FAILURE")
        mfa_at += timedelta(seconds=rng.uniform(15, 45))
    script.mfa(mfa_at)

    def at(hours: float) -> datetime:
        return local_time(day, hours, place)

    span = max(end - start, 0.5)
    sso_count = max(2, round(rng.randint(12, 21) * min(span / 8.5, 1.0)))
    for hours in sorted(rng.uniform(start + 0.02, end) for _ in range(sso_count)):
        script.sso(at(hours), rng.choice(user.apps))

    if user.role == "support_engineer":
        script.sso(at(start + 0.05), catalog.SUPPORT_PORTAL)
        for hours in sorted(rng.uniform(start + 0.1, end) for _ in range(rng.randint(8, 20))):
            case = random_case(rng)
            viewed = script.case_view(at(hours), case)
            if rng.random() < 0.3:
                filename = f"{case.lower()}_{rng.choice(ATTACHMENT_NAMES)}"
                script.attachment(viewed.published + timedelta(seconds=rng.uniform(5, 60)), case,
                                  filename, upload=False)
    elif rng.random() < SUPPORT_ACTIVITY_PROBABILITY.get(user.role, 0.0):
        visit = at(rng.uniform(start + 0.1, end))
        script.sso(visit, catalog.SUPPORT_PORTAL)
        if user.role == "admin" and rng.random() < 0.15:
            case = catalog.case_id(rng.randint(430, 479))  # new cases sort after CASE-00421
            script.case_create(visit + timedelta(seconds=40), case)
            script.attachment(visit + timedelta(seconds=95), case,
                              f"{case.lower()}_screenshot.png", upload=True)
        else:
            for k in range(rng.randint(1, 3)):
                script.case_view(visit + timedelta(seconds=30 + 70 * k + rng.uniform(0, 30)),
                                 random_case(rng))

    if user.role == "admin" and not weekend:
        for burst_hours in sorted(rng.uniform(start + 0.3, end - 0.2) for _ in range(rng.randint(1, 3))):
            burst = at(burst_hours)
            script.sso(burst, catalog.ADMIN_CONSOLE)
            script.mfa(burst + timedelta(seconds=rng.uniform(20, 60)))  # step-up before admin work
            action_at = burst + timedelta(seconds=90)
            for _ in range(rng.randint(1, 3)):
                event_type = rng.choices(
                    list(catalog.BENIGN_ADMIN_WEIGHTS), weights=list(catalog.BENIGN_ADMIN_WEIGHTS.values())
                )[0]
                script.admin(action_at, event_type, admin_targets(event_type, rng, directory))
                action_at += timedelta(seconds=rng.uniform(40, 200))

    if rng.random() < 0.55:
        script.logout(at(end + rng.uniform(0.01, 0.1)))


def simulate_human_day(
    user: DirectoryUser,
    day: date,
    *,
    rng: random.Random,
    factory: EventFactory,
    recorder: Recorder,
    directory: Directory,
) -> None:
    """Generate one local calendar day of activity for a human user."""
    weekend = day.weekday() >= 5
    p_active = 0.12 if weekend else (0.97 if user.role in ("admin", "support_engineer") else 0.93)
    if rng.random() >= p_active:
        return
    start = user.work_start_hour + rng.gauss(0, 0.4)
    length = rng.uniform(1.0, 3.0) if weekend else max(rng.gauss(8.6, 0.6), 6.0)
    end = start + length
    sessions: list[tuple[float, float, Endpoint]] = [(start, end, user.primary)]
    if not weekend and rng.random() < 0.22:
        split = start + length * rng.uniform(0.45, 0.6)
        evening = user.secondary or user.primary
        sessions = [(start, split, user.primary),
                    (split + rng.uniform(0.3, 1.0), end + rng.uniform(0.0, 1.5), evening)]
    for session_start, session_end, endpoint in sessions:
        _human_session(user, endpoint, day, session_start, session_end, weekend=weekend, rng=rng,
                       factory=factory, recorder=recorder, directory=directory)


def simulate_service_account(
    user: DirectoryUser, *, rng: random.Random, factory: EventFactory, recorder: Recorder
) -> None:
    """CaseSync: logs in every 6 hours and syncs a few cases every hour, around the clock."""
    for block in range(LOG_WINDOW_DAYS * 4):
        block_start = LOG_WINDOW_START + timedelta(hours=6 * block, minutes=5 + rng.uniform(0, 3))
        script = SessionScript(factory, recorder, user, user.primary, CASE_SYNC)
        script.login(block_start, mfa=False)
        for hour in range(6):
            sync = block_start + timedelta(hours=hour, minutes=rng.uniform(0.5, 4))
            for i in range(rng.randint(1, 3)):
                case = random_case(rng)
                viewed = script.case_view(sync + timedelta(seconds=i * rng.uniform(2, 10)), case)
                if rng.random() < 0.25:
                    script.attachment(viewed.published + timedelta(seconds=1.5), case,
                                      f"{case.lower()}_{rng.choice(ATTACHMENT_NAMES)}", upload=False)


def simulate_population(
    directory: Directory, seed: int, recorder: Recorder, skip: set[tuple[str, date]]
) -> None:
    """Generate benign activity for every principal, except user-days in ``skip``."""
    for user in directory.users:
        rng = random.Random(f"{seed}-benign-{user.login}")
        factory = EventFactory(rng)
        if user.role == "service_account":
            simulate_service_account(user, rng=rng, factory=factory, recorder=recorder)
            continue
        for day in window_dates():
            if (user.login, day) not in skip:
                simulate_human_day(user, day, rng=rng, factory=factory, recorder=recorder,
                                   directory=directory)
