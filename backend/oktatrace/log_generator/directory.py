"""Build the synthetic directory: ~50 principals with stable devices and networks."""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Final, Literal

from oktatrace.log_generator import catalog
from oktatrace.log_generator.catalog import Network, Place, UserAgentProfile
from oktatrace.log_generator.models import Actor, DirectoryEntry
from oktatrace.scenario import (
    ORG_DOMAIN,
    SERVICE_ACCOUNT_LOGIN,
    VENDOR_DOMAIN,
    VICTIM,
    make_scenario_tokens,
    random_token,
)

Role = Literal["employee", "admin", "support_engineer", "service_account"]

VICTIM_IP: Final = "192.0.2.11"

_FIRST_NAMES: Final = (
    "Alex", "Priya", "Sam", "Morgan", "Taylor", "Chris", "Dana", "Jamie", "Riley", "Casey",
    "Avery", "Quinn", "Noor", "Mateo", "Wei", "Aisha", "Diego", "Hana", "Ivan", "Leila",
    "Kofi", "Sofia", "Arjun", "Emma", "Lucas", "Mei", "Omar", "Nia", "Tomas", "Yuki",
    "Zara", "Ben", "Grace", "Hugo", "Ines", "Jonah", "Kira", "Liam", "Maya", "Nikhil",
)
_LAST_NAMES: Final = (
    "Chen", "Nair", "Patel", "Kim", "Garcia", "Okafor", "Novak", "Silva", "Haddad", "Larsen",
    "Tanaka", "Mensah", "Rossi", "Dubois", "Kowalski", "Ahmed", "Lopez", "Nguyen", "Schmidt",
    "Murphy", "Reyes", "Costa", "Ibrahim", "Moreau", "Fischer", "Sato", "Owusu", "Bianchi",
)
_DEPARTMENTS: Final = ("Engineering", "Sales", "Finance", "People", "Marketing")

# (count, city, office network or None for remote workers)
_EMPLOYEE_PLAN: Final = (
    (18, catalog.SAN_FRANCISCO, catalog.CORP_SF),
    (10, catalog.NEW_YORK, catalog.CORP_NYC),
    (5, catalog.SEATTLE, None),
    (5, catalog.AUSTIN, None),
    (4, catalog.DENVER, None),
)
_ADMIN_PLAN: Final = (
    (catalog.SAN_FRANCISCO, catalog.CORP_SF),
    (catalog.NEW_YORK, catalog.CORP_NYC),
    (catalog.SEATTLE, None),
)


@dataclass(frozen=True)
class Endpoint:
    """Where a user connects from: network, address, browser and device-token hash."""

    network: Network
    ip_address: str
    user_agent: UserAgentProfile
    dt_hash: str


@dataclass(frozen=True)
class DirectoryUser:
    """A principal plus the behaviour profile the generator needs."""

    user_id: str
    login: str
    display_name: str
    role: Role
    department: str
    home: Place
    primary: Endpoint
    secondary: Endpoint | None
    work_start_hour: float
    apps: tuple[catalog.App, ...] = field(default=())

    @property
    def actor(self) -> Actor:
        return Actor(id=self.user_id, alternate_id=self.login, display_name=self.display_name)

    @property
    def is_human(self) -> bool:
        return self.role != "service_account"

    def to_entry(self) -> DirectoryEntry:
        return DirectoryEntry(
            user_id=self.user_id,
            login=self.login,
            display_name=self.display_name,
            role=self.role,
            department=self.department,
            city=self.home.city,
            utc_offset_hours=self.home.utc_offset_hours,
            network=self.primary.network.key,
            ip_address=self.primary.ip_address,
            user_agent=self.primary.user_agent.raw,
        )


@dataclass
class Directory:
    """All principals, with lookups by role."""

    users: list[DirectoryUser]

    def by_login(self, login: str) -> DirectoryUser:
        return next(u for u in self.users if u.login == login)

    def with_role(self, role: Role) -> list[DirectoryUser]:
        return [u for u in self.users if u.role == role]

    @property
    def victim(self) -> DirectoryUser:
        return self.by_login(VICTIM.login)

    @property
    def service_account(self) -> DirectoryUser:
        return self.by_login(SERVICE_ACCOUNT_LOGIN)


def _dt_hash(rng: random.Random) -> str:
    return hashlib.sha256(rng.randbytes(32)).hexdigest()


class _AddressBook:
    """Hands out stable addresses: shared NAT egress for offices, one per home."""

    def __init__(self, rng: random.Random) -> None:
        self._rng = rng
        self._next_host: dict[str, int] = {}

    def office(self, network: Network) -> str:
        return network.random_address(self._rng)

    def home(self, network: Network) -> str:
        host = self._next_host.get(network.key, network.host_first)
        self._next_host[network.key] = host + 1
        return network.address(host)


def build_directory(seed: int) -> Directory:
    """Create the deterministic synthetic directory for ``seed``."""
    rng = random.Random(f"{seed}-directory")
    addresses = _AddressBook(rng)
    names = [(f, l) for f in _FIRST_NAMES for l in _LAST_NAMES]
    rng.shuffle(names)
    used_logins = {VICTIM.login}

    def next_name(domain: str) -> tuple[str, str]:
        while True:
            first, last = names.pop()
            login = f"{first.lower()}.{last.lower()}@{domain}"
            if login not in used_logins:
                used_logins.add(login)
                return login, f"{first} {last}"

    def person(role: Role, department: str, place: Place, office: Network | None,
               domain: str = ORG_DOMAIN, agent: UserAgentProfile | None = None) -> DirectoryUser:
        login, display = next_name(domain)
        agent = agent or rng.choice(catalog.EMPLOYEE_AGENTS)
        home_net = catalog.HOME_NETWORK_FOR.get(place.city)
        home = Endpoint(home_net, addresses.home(home_net), agent, _dt_hash(rng)) if home_net else None
        if office is not None:
            primary = Endpoint(office, addresses.office(office), agent, home.dt_hash if home else _dt_hash(rng))
            secondary = home
        else:
            if home is None:
                raise ValueError(f"no home network for {place.city}")
            primary, secondary = home, None
        return DirectoryUser(
            user_id=random_token(rng, "00uSYN", 14),
            login=login,
            display_name=display,
            role=role,
            department=department,
            home=place,
            primary=primary,
            secondary=secondary,
            work_start_hour=rng.uniform(7.5, 9.75),
            apps=catalog.DEPARTMENT_APPS[department],
        )

    users: list[DirectoryUser] = []
    tokens = make_scenario_tokens(seed)
    victim_endpoint = Endpoint(
        catalog.CORP_SF, VICTIM_IP, catalog.MAC_CHROME_117,
        # Okta logs dtHash = SHA-256 of the device token, i.e. the DT cookie in the sample HAR.
        hashlib.sha256(tokens.device_token.encode()).hexdigest(),
    )
    users.append(
        DirectoryUser(
            user_id=VICTIM.user_id,
            login=VICTIM.login,
            display_name=VICTIM.display_name,
            role="admin",
            department="IT",
            home=catalog.SAN_FRANCISCO,
            primary=victim_endpoint,
            secondary=Endpoint(catalog.HOME_SF, addresses.home(catalog.HOME_SF),
                               catalog.MAC_CHROME_117, victim_endpoint.dt_hash),
            work_start_hour=7.5,
            apps=catalog.DEPARTMENT_APPS["IT"],
        )
    )
    users += [person("admin", "IT", place, office) for place, office in _ADMIN_PLAN]
    users.append(person("admin", "IT", catalog.SAN_FRANCISCO, catalog.CORP_SF))
    for count, place, office in _EMPLOYEE_PLAN:
        users += [person("employee", rng.choice(_DEPARTMENTS), place, office) for _ in range(count)]

    for _ in range(3):
        login, display = next_name(VENDOR_DOMAIN)
        agent = rng.choice(catalog.EMPLOYEE_AGENTS)
        users.append(
            DirectoryUser(
                user_id=random_token(rng, "00uSYN", 14),
                login=login,
                display_name=display,
                role="support_engineer",
                department="Support",
                home=catalog.ASHBURN,
                primary=Endpoint(catalog.VENDOR_OFFICE, addresses.home(catalog.VENDOR_OFFICE),
                                 agent, _dt_hash(rng)),
                secondary=None,
                work_start_hour=rng.uniform(8.0, 9.5),
                apps=catalog.DEPARTMENT_APPS["Support"],
            )
        )
    users.append(
        DirectoryUser(
            user_id="00uSYNsvcCaseSync01",
            login=SERVICE_ACCOUNT_LOGIN,
            display_name="Case Sync Service",
            role="service_account",
            department="Support",
            home=catalog.ASHBURN,
            primary=Endpoint(catalog.VENDOR_DC, catalog.VENDOR_DC.address(15),
                             catalog.CASESYNC_AGENT, ""),
            secondary=None,
            work_start_hour=0.0,
            apps=(catalog.SUPPORT_PORTAL,),
        )
    )
    return Directory(users=users)
