# Incident summary: Acme Synthetic Corp, support case CASE-00421

> SYNTHETIC DATA ONLY - OktaTrace is an educational forensic demo. All users, tokens, IP addresses, logs and HAR files are fabricated; no real systems, credentials or customer data are involved.

## Executive summary

A browser HAR file attached to support case CASE-00421 contained 16 secrets (6 critical), including live session cookies. A session matching fingerprint c85dd9d19760 from that file later appeared in the identity provider's logs from a different network. The detection engine raised 11 alerts linked to this incident between 2023-10-02T14:30:00Z and 2023-10-03T15:15:05Z (UTC), spanning these ATT&CK stages: Credential Access, Initial Access, Collection, Lateral Movement, Persistence, Defense Evasion.

## What happened

- 2023-10-02T14:30:00Z: HAR captured: support_case_00421.har (TL-0001)
- 2023-10-02T14:30:00Z: HAR-013: device token 'DT' exposed in HAR (TL-0002) [T1539]
- 2023-10-02T14:30:01Z: HAR-011: session cookie 'sid' exposed in HAR (TL-0004) [T1539]
- 2023-10-02T19:52:07Z: OT-DET-002 Impossible travel (TL-0010) [T1078]
- 2023-10-02T19:52:07Z: OT-DET-007 Service account from a new network (TL-0011) [T1078]
- 2023-10-02T19:53:41Z: Download support case attachment: support_case_00421.har (TL-0013) [T1213, T1552.001, T1078]
- 2023-10-02T19:53:41Z: 'sid' cookie extracted from support_case_00421.har (inferred) (TL-0014) [T1539]
- 2023-10-02T19:54:33Z: Download support case attachment: case-00434_browser.har (TL-0016) [T1213, T1552.001, T1078]
- 2023-10-02T19:55:18Z: Download support case attachment: case-00412_browser.har (TL-0018) [T1213, T1552.001, T1078]
- 2023-10-02T19:55:59Z: Download support case attachment: case-00387_browser.har (TL-0020) [T1213, T1552.001, T1078]
- 2023-10-02T19:56:48Z: Download support case attachment: case-00357_browser.har (TL-0022) [T1213, T1552.001, T1078]
- 2023-10-02T19:57:41Z: Download support case attachment: case-00317_browser.har (TL-0024) [T1213, T1552.001, T1078]
- 2023-10-02T22:04:10Z: OT-DET-001 Session token reused from another IP (TL-0028) [T1550.004, T1539]
- 2023-10-02T22:04:10Z: OT-DET-002 Impossible travel (TL-0029) [T1078]
- 2023-10-02T22:04:10Z: OT-DET-003 New user agent on an existing session (TL-0030) [T1550.004]
- 2023-10-02T22:08:32Z: OT-DET-005 Bulk support-case access (TL-0047) [T1213]
- 2023-10-03T09:41:12Z: OT-DET-001 Session token reused from another IP (TL-0065) [T1550.004, T1539]
- 2023-10-03T09:41:12Z: OT-DET-003 New user agent on an existing session (TL-0066) [T1550.004]
- 2023-10-03T09:42:03Z: Create Okta user: it-helpdesk-svc@acme.example (TL-0067) [T1136.003, T1550.004]
- 2023-10-03T09:42:03Z: OT-DET-004 Admin action without recent MFA (TL-0068) [T1098, T1550.004]
- 2023-10-03T09:42:03Z: OT-DET-006 Off-hours admin action (TL-0069) [T1078]
- 2023-10-03T09:42:44Z: Add user to group membership: Acme-Super-Admins (TL-0070) [T1098, T1550.004]
- 2023-10-03T09:43:26Z: Create API token: sync-helper (TL-0071) [T1098.001, T1550.004]
- 2023-10-03T09:44:12Z: Reset factor for user: mei.ibrahim@acme.example (TL-0072) [T1556.006, T1550.004]
- 2023-10-03T09:44:59Z: Update policy rule: Default sign-on rule (FAILURE) (TL-0073) [T1484, T1550.004]
- 2023-10-03T15:15:05Z: OT-DET-002 Impossible travel (TL-0075) [T1078]

## Detection and evidence

- **ALR-0003** OT-DET-002 (high): svc-case-sync@support.vendor.example was seen in Frankfurt am Main 46m10s after Ashburn: 6,549 km, an implied 8,511 km/h (limit 900 km/h). 2 matches from 2023-10-02 19:52 to 20:06 UTC were merged into this alert.
- **ALR-0004** OT-DET-007 (high): Service account svc-case-sync@support.vendor.example signed in from 203.0.113.207 (AS65066 Nightjar Hosting Ltd, Frankfurt am Main), outside the networks seen in its first 24h (AS64800). 13 matches from 2023-10-02 19:52 to 19:57 UTC were merged into this alert.
- **ALR-0005** OT-DET-001 (high): session c85dd9d19760 for jordan.rivera@acme.example was established from 192.0.2.11 (AS64512 Acme Synthetic Corp, San Francisco) but was used from 203.0.113.211 (AS65066 Nightjar Hosting Ltd, Frankfurt am Main) 7h34m later, without a new sign-in. 32 matches from 2023-10-02 22:04 to 22:12 UTC were merged into this alert.
- **ALR-0006** OT-DET-002 (high): jordan.rivera@acme.example was seen in Frankfurt am Main 5m40s after San Francisco: 9,133 km, an implied 96,707 km/h (limit 900 km/h). 2 matches from 2023-10-02 22:04 to 22:13 UTC were merged into this alert.
- **ALR-0007** OT-DET-003 (medium): session c85dd9d19760 for jordan.rivera@acme.example started in CHROME on Mac OS X but continued in FIREFOX on Windows 10. 32 matches from 2023-10-02 22:04 to 22:12 UTC were merged into this alert.
- **ALR-0008** OT-DET-005 (medium): jordan.rivera@acme.example viewed 15 distinct support cases within 10 minutes (threshold 15). 16 matches from 2023-10-02 22:08 to 22:12 UTC were merged into this alert.
- **ALR-0009** OT-DET-001 (high): session c85dd9d19760 for jordan.rivera@acme.example was established from 192.0.2.11 (AS64512 Acme Synthetic Corp, San Francisco) but was used from 203.0.113.211 (AS65066 Nightjar Hosting Ltd, Frankfurt am Main) 19h11m later, without a new sign-in. 6 matches from 2023-10-03 09:41 to 09:44 UTC were merged into this alert.
- **ALR-0010** OT-DET-003 (medium): session c85dd9d19760 for jordan.rivera@acme.example started in CHROME on Mac OS X but continued in FIREFOX on Windows 10. 6 matches from 2023-10-03 09:41 to 09:44 UTC were merged into this alert.
- **ALR-0011** OT-DET-004 (high): user.lifecycle.create by jordan.rivera@acme.example on session c85dd9d19760: the last MFA was 16h21m earlier (limit 60 min). 5 matches from 2023-10-03 09:42 to 09:44 UTC were merged into this alert.
- **ALR-0012** OT-DET-006 (medium): user.lifecycle.create by jordan.rivera@acme.example at Tue 02:42 local time (UTC-7), outside business hours (07:00-20:00, Mon-Fri). 5 matches from 2023-10-03 09:42 to 09:44 UTC were merged into this alert.
- **ALR-0013** OT-DET-002 (high): jordan.rivera@acme.example was seen in San Francisco 5h30m after Frankfurt am Main: 9,133 km, an implied 1,660 km/h (limit 900 km/h).

## Impact

- Create Okta user: it-helpdesk-svc@acme.example (TL-0067)
- Add user to group membership: Acme-Super-Admins (TL-0070)
- Create API token: sync-helper (TL-0071)
- Reset factor for user: mei.ibrahim@acme.example (TL-0072)
- Update policy rule: Default sign-on rule (FAILURE) (TL-0073)

## Recommended actions

- Force a password reset and check for reuse. HAR captures of login flows record passwords in clear text.
- Rotate the client secret and move the client to private_key_jwt authentication.
- Terminate the session server-side and treat all activity after the capture time as suspect. Strip cookies from HAR files before sharing them.
- Revoke the API token now. API tokens inherit the creating admin's privileges; replace it with a narrowly scoped OAuth service app.
- Revoke the token and shorten access-token lifetimes; never pass tokens in URLs and prefer sender-constrained tokens (DPoP or mTLS).
- Revoke the refresh token (and its grant) immediately and enable refresh-token rotation.
- Rotate the account password and replace Basic authentication with token-based auth.
- One-time session tokens must be exchanged immediately and never placed in URLs that can be logged; revoke the resulting session.
- ID tokens describe a login and should not be used as API credentials; review the client and revoke the related session.

## Detection quality

- Alert precision 84.6%; event-level precision 85.0%, recall 100.0%, F1 91.9%.
- Attack steps missed: 0.
- Alerts judged unrelated (false positives): ALR-0001, ALR-0002; causes: offhours_admin (1), vpn_switch (1).
