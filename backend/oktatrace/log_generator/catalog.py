"""Static catalogues for the synthetic system log: places, networks, browsers, apps, events.

Networks use RFC 5737 documentation addresses and RFC 6996 private-use AS
numbers, so no address or ASN here belongs to a real organisation.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Final

from oktatrace.scenario import ORG_DOMAIN, VENDOR_DOMAIN, VICTIM_USER_AGENT


@dataclass(frozen=True)
class Place:
    """A city with coordinates and its UTC offset during the log window."""

    city: str
    state: str
    country: str
    lat: float
    lon: float
    utc_offset_hours: int


SAN_FRANCISCO: Final = Place("San Francisco", "California", "United States", 37.7749, -122.4194, -7)
NEW_YORK: Final = Place("New York", "New York", "United States", 40.7128, -74.0060, -4)
SEATTLE: Final = Place("Seattle", "Washington", "United States", 47.6062, -122.3321, -7)
AUSTIN: Final = Place("Austin", "Texas", "United States", 30.2672, -97.7431, -5)
DENVER: Final = Place("Denver", "Colorado", "United States", 39.7392, -104.9903, -6)
ASHBURN: Final = Place("Ashburn", "Virginia", "United States", 39.0438, -77.4874, -4)
FRANKFURT: Final = Place("Frankfurt am Main", "Hesse", "Germany", 50.1109, 8.6821, 2)


@dataclass(frozen=True)
class Network:
    """An autonomous system and the slice of documentation addresses it owns here."""

    key: str
    as_number: int
    as_org: str
    isp: str
    domain: str
    prefix: str
    host_first: int
    host_last: int
    place: Place
    is_proxy: bool = False

    def address(self, host: int) -> str:
        """Return the IP for ``host`` (must be inside this network's slice)."""
        if not self.host_first <= host <= self.host_last:
            raise ValueError(f"host {host} outside {self.key} range")
        return f"{self.prefix}{host}"

    def random_address(self, rng: random.Random) -> str:
        """Pick an address from this network."""
        return self.address(rng.randint(self.host_first, self.host_last))


CORP_SF: Final = Network("corp-sf", 64512, ORG_DOMAIN, "Acme Synthetic Corp", ORG_DOMAIN,
                         "192.0.2.", 10, 13, SAN_FRANCISCO)
CORP_NYC: Final = Network("corp-nyc", 64512, ORG_DOMAIN, "Acme Synthetic Corp", ORG_DOMAIN,
                          "192.0.2.", 70, 72, NEW_YORK)
HOME_SF: Final = Network("home-sf", 64600, "bayline-broadband.example", "Bayline Broadband",
                         "bayline-broadband.example", "198.51.100.", 10, 60, SAN_FRANCISCO)
HOME_NYC: Final = Network("home-nyc", 64610, "empire-fiber.example", "Empire Fiber",
                          "empire-fiber.example", "198.51.100.", 70, 100, NEW_YORK)
HOME_SEA: Final = Network("home-sea", 64620, "cascade-cable.example", "Cascade Cable",
                          "cascade-cable.example", "198.51.100.", 110, 130, SEATTLE)
HOME_AUS: Final = Network("home-aus", 64630, "longhorn-net.example", "Longhorn Net",
                          "longhorn-net.example", "198.51.100.", 140, 160, AUSTIN)
HOME_DEN: Final = Network("home-den", 64640, "front-range-isp.example", "Front Range ISP",
                          "front-range-isp.example", "198.51.100.", 170, 185, DENVER)
VENDOR_DC: Final = Network("vendor-dc", 64800, "vendor-cloud.example", "Vendor Cloud DC",
                           "vendor-cloud.example", "203.0.113.", 10, 20, ASHBURN)
VENDOR_OFFICE: Final = Network("vendor-office", 64801, VENDOR_DOMAIN, "Vendor Corp Office",
                               VENDOR_DOMAIN, "203.0.113.", 70, 90, ASHBURN)
ATTACKER_VPS: Final = Network("attacker-vps", 65066, "nightjar-hosting.example", "Nightjar Hosting Ltd",
                              "nightjar-hosting.example", "203.0.113.", 200, 220, FRANKFURT)

HOME_NETWORK_FOR: Final[dict[str, Network]] = {
    SAN_FRANCISCO.city: HOME_SF,
    NEW_YORK.city: HOME_NYC,
    SEATTLE.city: HOME_SEA,
    AUSTIN.city: HOME_AUS,
    DENVER.city: HOME_DEN,
}
ALL_NETWORKS: Final = (CORP_SF, CORP_NYC, HOME_SF, HOME_NYC, HOME_SEA, HOME_AUS, HOME_DEN,
                       VENDOR_DC, VENDOR_OFFICE, ATTACKER_VPS)


@dataclass(frozen=True)
class UserAgentProfile:
    """A raw User-Agent string with the parsed fields Okta reports."""

    raw: str
    os: str
    browser: str
    device: str = "Computer"


MAC_CHROME_117: Final = UserAgentProfile(VICTIM_USER_AGENT, "Mac OS X", "CHROME")
WIN_CHROME_117: Final = UserAgentProfile(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/117.0.0.0 Safari/537.36", "Windows 10", "CHROME")
WIN_CHROME_118: Final = UserAgentProfile(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/118.0.0.0 Safari/537.36", "Windows 10", "CHROME")
MAC_SAFARI_16: Final = UserAgentProfile(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/16.6 Safari/605.1.15", "Mac OS X", "SAFARI")
WIN_EDGE_117: Final = UserAgentProfile(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47", "Windows 10", "EDGE")
LINUX_FIREFOX_118: Final = UserAgentProfile(
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0", "Linux", "FIREFOX")
WIN_FIREFOX_118: Final = UserAgentProfile(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Windows 10", "FIREFOX")
CASESYNC_AGENT: Final = UserAgentProfile(
    f"CaseSync/4.2.1 (+https://{VENDOR_DOMAIN}/casesync)", "Unknown", "UNKNOWN", "Unknown")
PYTHON_REQUESTS: Final = UserAgentProfile("python-requests/2.31.0", "Unknown", "UNKNOWN", "Unknown")

EMPLOYEE_AGENTS: Final = (MAC_CHROME_117, WIN_CHROME_117, MAC_SAFARI_16, WIN_EDGE_117, LINUX_FIREFOX_118)


@dataclass(frozen=True)
class App:
    """An SSO application instance in the tenant."""

    app_id: str
    label: str
    slug: str


SLACK: Final = App("0oaSYNslack00001", "Slack", "slack")
GOOGLE: Final = App("0oaSYNgoogle0001", "Google Workspace", "google")
SALESFORCE: Final = App("0oaSYNsfdc000001", "Salesforce", "salesforce")
JIRA: Final = App("0oaSYNjira000001", "Jira", "jira")
GITHUB: Final = App("0oaSYNgithub0001", "GitHub", "github")
ZOOM: Final = App("0oaSYNzoom000001", "Zoom", "zoom")
WORKDAY: Final = App("0oaSYNworkday001", "Workday", "workday")
AWS: Final = App("0oaSYNaws0000001", "AWS Console", "amazon_aws")
ADMIN_CONSOLE: Final = App("0oaSYNadminConsole01", "Okta Admin Console", "saasure")
SUPPORT_PORTAL: Final = App("0oaSYNsupport001", "Vendor Support Portal", "vendor_support")
REPORTS: Final = App("0oaSYNreportsApp0001", "Acme Reports", "acme_reports")

DEPARTMENT_APPS: Final[dict[str, tuple[App, ...]]] = {
    "Engineering": (SLACK, GOOGLE, JIRA, GITHUB, ZOOM, AWS),
    "Sales": (SLACK, GOOGLE, SALESFORCE, ZOOM),
    "Finance": (SLACK, GOOGLE, WORKDAY, ZOOM, REPORTS),
    "People": (SLACK, GOOGLE, WORKDAY, ZOOM),
    "Marketing": (SLACK, GOOGLE, SALESFORCE, ZOOM, REPORTS),
    "IT": (SLACK, GOOGLE, JIRA, ZOOM, ADMIN_CONSOLE, SUPPORT_PORTAL, REPORTS),
    "Support": (SLACK, GOOGLE, ZOOM, SUPPORT_PORTAL),
}

GROUPS: Final = ("Engineering", "Sales", "Finance", "Contractors", "VPN-Users", "AWS-ReadOnly",
                 "Marketing", "Acme-Super-Admins")

# -- event types ---------------------------------------------------------------
SESSION_START: Final = "user.session.start"
SESSION_END: Final = "user.session.end"
MFA_VERIFY: Final = "user.authentication.auth_via_mfa"
APP_SSO: Final = "user.authentication.sso"
# Support-portal events are a fictional extension modelling the vendor's case
# system; Okta's real System Log has no such event types.
SUPPORT_CASE_CREATE: Final = "support.case.create"
SUPPORT_CASE_VIEW: Final = "support.case.view"
SUPPORT_ATTACHMENT_UPLOAD: Final = "support.case.attachment.upload"
SUPPORT_ATTACHMENT_DOWNLOAD: Final = "support.case.attachment.download"

ADMIN_EVENT_TYPES: Final[dict[str, str]] = {
    "user.lifecycle.create": "Create Okta user",
    "user.lifecycle.deactivate": "Deactivate Okta user",
    "user.account.reset_password": "Reset password for Okta user",
    "group.user_membership.add": "Add user to group membership",
    "group.user_membership.remove": "Remove user from group membership",
    "application.user_membership.add": "Add user to application membership",
    "user.mfa.factor.deactivate": "Reset factor for user",
    "system.api_token.create": "Create API token",
    "policy.rule.update": "Update policy rule",
}
BENIGN_ADMIN_WEIGHTS: Final[dict[str, int]] = {
    "group.user_membership.add": 30,
    "group.user_membership.remove": 14,
    "application.user_membership.add": 25,
    "user.lifecycle.create": 8,
    "user.lifecycle.deactivate": 8,
    "user.account.reset_password": 10,
    "policy.rule.update": 3,
    "system.api_token.create": 1,
}
SUPPORT_EVENT_TYPES: Final = frozenset(
    {SUPPORT_CASE_CREATE, SUPPORT_CASE_VIEW, SUPPORT_ATTACHMENT_UPLOAD, SUPPORT_ATTACHMENT_DOWNLOAD}
)
DISPLAY_MESSAGES: Final[dict[str, str]] = {
    SESSION_START: "User login to Okta",
    SESSION_END: "User logout from Okta",
    MFA_VERIFY: "Authentication of user via MFA",
    APP_SSO: "User single sign on to app",
    SUPPORT_CASE_CREATE: "Create support case",
    SUPPORT_CASE_VIEW: "View support case",
    SUPPORT_ATTACHMENT_UPLOAD: "Upload support case attachment",
    SUPPORT_ATTACHMENT_DOWNLOAD: "Download support case attachment",
    **ADMIN_EVENT_TYPES,
}
REQUEST_URIS: Final[dict[str, str]] = {
    SESSION_START: "/api/v1/authn",
    SESSION_END: "/login/signout",
    MFA_VERIFY: "/api/v1/authn/factors/verify",
    SUPPORT_CASE_CREATE: "/support/cases",
    SUPPORT_CASE_VIEW: "/support/cases/{case}",
    SUPPORT_ATTACHMENT_UPLOAD: "/support/cases/{case}/attachments",
    SUPPORT_ATTACHMENT_DOWNLOAD: "/support/cases/{case}/attachments/{file}",
    "user.lifecycle.create": "/api/v1/users",
    "user.lifecycle.deactivate": "/api/v1/users/{id}/lifecycle/deactivate",
    "user.account.reset_password": "/api/v1/users/{id}/lifecycle/reset_password",
    "group.user_membership.add": "/api/v1/groups/{id}/users",
    "group.user_membership.remove": "/api/v1/groups/{id}/users",
    "application.user_membership.add": "/api/v1/apps/{id}/users",
    "user.mfa.factor.deactivate": "/api/v1/users/{id}/factors",
    "system.api_token.create": "/api/internal/tokens",
    "policy.rule.update": "/api/v1/policies/{id}/rules",
}


def case_id(number: int) -> str:
    """Format a support case number, e.g. ``CASE-00421``."""
    return f"CASE-{number:05d}"
