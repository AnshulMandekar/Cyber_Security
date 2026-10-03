"""The MITRE ATT&CK techniques OktaTrace refers to (Enterprise matrix)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class Technique:
    """An ATT&CK technique and the tactic it most often represents in this scenario."""

    technique_id: str
    name: str
    primary_tactic: str
    tactics: tuple[str, ...]

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}/"


TECHNIQUES: Final[dict[str, Technique]] = {
    t.technique_id: t
    for t in (
        Technique("T1078", "Valid Accounts", "Initial Access",
                  ("Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion")),
        Technique("T1539", "Steal Web Session Cookie", "Credential Access", ("Credential Access",)),
        Technique("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access",
                  ("Credential Access",)),
        Technique("T1550.004", "Use Alternate Authentication Material: Web Session Cookie",
                  "Lateral Movement", ("Lateral Movement", "Defense Evasion")),
        Technique("T1213", "Data from Information Repositories", "Collection", ("Collection",)),
        Technique("T1098", "Account Manipulation", "Persistence", ("Persistence", "Privilege Escalation")),
        Technique("T1098.001", "Account Manipulation: Additional Cloud Credentials", "Persistence",
                  ("Persistence", "Privilege Escalation")),
        Technique("T1136.003", "Create Account: Cloud Account", "Persistence", ("Persistence",)),
        Technique("T1556.006", "Modify Authentication Process: Multi-Factor Authentication",
                  "Defense Evasion", ("Credential Access", "Defense Evasion", "Persistence")),
        Technique("T1484", "Domain or Tenant Policy Modification", "Defense Evasion",
                  ("Defense Evasion", "Privilege Escalation")),
    )
}

TACTIC_ORDER: Final = (
    "Initial Access", "Credential Access", "Lateral Movement", "Collection", "Persistence",
    "Privilege Escalation", "Defense Evasion",
)
