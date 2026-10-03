"""Benign behaviour that deliberately looks suspicious.

These "edge cases" give the detection engine realistic false-positive pressure,
so its precision/recall numbers mean something. Each one is labelled
``edge_case`` and is NOT part of the attack.

| Scenario        | Looks like                         | Why it is benign                          |
|-----------------|------------------------------------|-------------------------------------------|
| vpn_switch      | one session, two IPs/ASNs          | laptop moves office -> home in one city   |
| browser_update  | new User-Agent on a session        | Chrome auto-updated 117 -> 118            |
| travel          | new city the next day              | a flight SF -> NYC, physically possible   |
| offhours_admin  | admin actions at 03:00 on Saturday | planned maintenance with fresh MFA        |
| support_bulk    | many support cases viewed quickly  | support engineer triaging a queue         |
"""

from __future__ import annotations

import random
from dataclasses import replace
from datetime import date, timedelta

from oktatrace.log_generator import catalog
from oktatrace.log_generator.benign import admin_targets
from oktatrace.log_generator.builder import EventFactory, Recorder
from oktatrace.log_generator.directory import Directory, DirectoryUser, Endpoint
from oktatrace.log_generator.models import EventLabel, LabelCategory
from oktatrace.log_generator.sessions import SessionScript, local_time, random_case

VPN_SWITCH_DAY = date(2023, 9, 29)
BROWSER_UPDATE_DAY = date(2023, 10, 3)
TRAVEL_DAYS = (date(2023, 10, 1), date(2023, 10, 2))
OFFHOURS_ADMIN_DAY = date(2023, 9, 30)
SUPPORT_BULK_DAY = date(2023, 10, 4)


def _label(scenario: str) -> EventLabel:
    return EventLabel(category=LabelCategory.EDGE_CASE, scenario=scenario)


def _sf_office_employees(directory: Directory) -> list[DirectoryUser]:
    return [u for u in directory.with_role("employee") if u.primary.network.key == catalog.CORP_SF.key]


def _apps_through_day(script: SessionScript, rng: random.Random, day: date, start: float, end: float,
                      count: int) -> None:
    place = script.endpoint.network.place
    for hours in sorted(rng.uniform(start, end) for _ in range(count)):
        script.sso(local_time(day, hours, place), rng.choice(script.user.apps))


def vpn_switch(user: DirectoryUser, rng: random.Random, factory: EventFactory, recorder: Recorder) -> None:
    home = user.secondary
    if home is None:
        raise ValueError("vpn_switch needs an office worker with a home network")
    script = SessionScript(factory, recorder, user, user.primary, _label("vpn_switch"))
    day = VPN_SWITCH_DAY
    script.login(local_time(day, 8.9, user.home))
    _apps_through_day(script, rng, day, 9.0, 11.0, 5)
    script.endpoint = home  # same session continues from the home ISP
    _apps_through_day(script, rng, day, 11.3, 12.2, 3)
    script.endpoint = user.primary
    _apps_through_day(script, rng, day, 13.0, 17.2, 6)
    script.logout(local_time(day, 17.4, user.home))


def browser_update(user: DirectoryUser, rng: random.Random, factory: EventFactory,
                   recorder: Recorder) -> None:
    before = replace(user.primary, user_agent=catalog.WIN_CHROME_117)
    after = replace(user.primary, user_agent=catalog.WIN_CHROME_118)
    script = SessionScript(factory, recorder, user, before, _label("browser_update"))
    day = BROWSER_UPDATE_DAY
    script.login(local_time(day, 8.7, user.home))
    _apps_through_day(script, rng, day, 8.8, 12.4, 6)
    script.endpoint = after  # browser restarted after auto-update; same session cookie
    _apps_through_day(script, rng, day, 12.6, 17.0, 6)
    script.logout(local_time(day, 17.1, user.home))


def travel(user: DirectoryUser, rng: random.Random, factory: EventFactory, recorder: Recorder) -> None:
    sunday, monday = TRAVEL_DAYS
    home = user.secondary or user.primary
    script = SessionScript(factory, recorder, user, home, _label("travel"))
    script.login(local_time(sunday, 10.0, user.home))
    _apps_through_day(script, rng, sunday, 10.1, 11.0, 3)
    script.logout(local_time(sunday, 11.1, user.home))
    # Flies overnight; works from the New York office on Monday (new session, new city).
    nyc = Endpoint(catalog.CORP_NYC, catalog.CORP_NYC.address(71), home.user_agent, home.dt_hash)
    script = SessionScript(factory, recorder, user, nyc, _label("travel"))
    script.login(local_time(monday, 9.0, catalog.NEW_YORK))
    _apps_through_day(script, rng, monday, 9.1, 17.0, 10)
    script.logout(local_time(monday, 17.2, catalog.NEW_YORK))


def offhours_admin(user: DirectoryUser, directory: Directory, rng: random.Random,
                   factory: EventFactory, recorder: Recorder) -> None:
    script = SessionScript(factory, recorder, user, user.primary, _label("offhours_admin"))
    day = OFFHOURS_ADMIN_DAY
    start = local_time(day, 3.15, user.home)
    script.login(start)
    script.sso(start + timedelta(seconds=40), catalog.ADMIN_CONSOLE)
    action_at = start + timedelta(minutes=2)
    for event_type in ("group.user_membership.remove", "group.user_membership.remove",
                       "application.user_membership.add"):
        script.admin(action_at, event_type, admin_targets(event_type, rng, directory))
        action_at += timedelta(minutes=rng.uniform(2, 6))
    script.logout(action_at + timedelta(minutes=3))


def support_bulk(user: DirectoryUser, rng: random.Random, factory: EventFactory,
                 recorder: Recorder) -> None:
    script = SessionScript(factory, recorder, user, user.primary, _label("support_bulk"))
    day = SUPPORT_BULK_DAY
    script.login(local_time(day, 8.8, user.home))
    script.sso(local_time(day, 8.9, user.home), catalog.SUPPORT_PORTAL)
    triage = local_time(day, 10.0, user.home)
    for i in range(28):  # a queue triage: 28 cases in about 50 minutes
        script.case_view(triage + timedelta(seconds=i * 105 + rng.uniform(0, 20)), random_case(rng))
    _apps_through_day(script, rng, day, 11.0, 16.5, 6)
    script.logout(local_time(day, 17.0, user.home))


def build_edge_cases(directory: Directory, seed: int, recorder: Recorder) -> set[tuple[str, date]]:
    """Emit all edge cases; returns the (login, local date) pairs they own."""
    rng = random.Random(f"{seed}-edge-cases")
    factory = EventFactory(rng)
    office = _sf_office_employees(directory)
    switcher = office[0]
    # Prefer someone who really uses Windows Chrome, so their other days look consistent.
    updater = next((u for u in office[1:] if u.primary.user_agent == catalog.WIN_CHROME_117), office[1])
    traveller = next(u for u in office if u not in (switcher, updater))
    admins = [u for u in directory.with_role("admin") if u.login != directory.victim.login]
    sf_admin = next(u for u in admins if u.primary.network.key == catalog.CORP_SF.key)
    support = directory.with_role("support_engineer")[0]

    vpn_switch(switcher, rng, factory, recorder)
    browser_update(updater, rng, factory, recorder)
    travel(traveller, rng, factory, recorder)
    offhours_admin(sf_admin, directory, rng, factory, recorder)
    support_bulk(support, rng, factory, recorder)
    return {
        (switcher.login, VPN_SWITCH_DAY),
        (updater.login, BROWSER_UPDATE_DAY),
        *((traveller.login, day) for day in TRAVEL_DAYS),
        (sf_admin.login, OFFHOURS_ADMIN_DAY),
        (support.login, SUPPORT_BULK_DAY),
    }
