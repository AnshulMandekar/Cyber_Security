"""OktaTrace: a defensive forensic demo for the 2023 Okta support-system breach case study.

Every log event, token, user, IP address and HAR file produced or bundled by
this package is synthetic. Nothing here talks to real Okta tenants, replays
real credentials or scans real systems.
"""

__version__ = "0.1.0"

DISCLAIMER = (
    "SYNTHETIC DATA ONLY - OktaTrace is an educational forensic demo. All users, "
    "tokens, IP addresses, logs and HAR files are fabricated; no real systems, "
    "credentials or customer data are involved."
)
