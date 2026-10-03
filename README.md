# OktaTrace

A defensive forensic demo for a university case study of the **2023 Okta
support-system breach**. In that incident an attacker used a stolen
service-account credential to get into the support case system, downloaded
HAR files that customers had uploaded, pulled live session tokens out of them,
and replayed those tokens to hijack customer admin sessions.

OktaTrace shows how an analyst reconstructs that kind of breach from session
artefacts and logs, detects token replay, and evaluates mitigations.

> **SYNTHETIC DATA ONLY.** Every user, token, IP address, log event and HAR
> file in this project is fabricated. Domains use the reserved `.example` TLD
> (RFC 2606), IPs come from documentation ranges (RFC 5737), and every token
> carries a `SYN` marker. Nothing here performs exploitation, uses real
> credentials, or scans real systems.

## Status

| # | Module | Status |
|---|--------|--------|
| 1 | `har_analyzer`: HAR parsing, secret detection, risk scoring, redaction | **Done** |
| 2 | `log_generator`: 5,000+ Okta-style events with a labelled attack, SQLite storage | **Done** |
| 3 | `detection_engine`: 7 deterministic rules, alert aggregation, precision/recall | **Done** |
| 4 | `timeline_builder`: merged, ATT&CK-tagged incident timeline with evidence links | **Done** |
| 5 | `mitigation_simulator`: before/after attacker success | **Skipped** (only `models.py` exists) |
| 6 | `report_summarizer` (optional): LLM or template prose over computed findings | **Done** |
| – | Dashboard (React + Vite), JSON/PDF export, one-command run script | Planned |

## Quick start (backend)

Requires Python 3.11+.

```bash
python -m venv .venv
```

```bash
.venv\Scripts\activate
```
(on macOS/Linux: `source .venv/bin/activate`)

```bash
pip install -r requirements.txt
```

```bash
python -m pytest
```

```bash
python -m uvicorn oktatrace.api.app:app --app-dir backend --reload
```

Then open <http://127.0.0.1:8000/docs> for the interactive API.

## Project layout

```
oktatrace/
├── backend/
│   ├── oktatrace/
│   │   ├── __init__.py          # version and DISCLAIMER
│   │   ├── config.py            # settings from OKTATRACE_* env vars
│   │   ├── scenario.py          # shared fictional org, victim, timeline, seeded tokens
│   │   ├── common/              # masking/fingerprints, time parsing
│   │   ├── storage/             # SQLite store (events, labels, attack steps)
│   │   ├── har_analyzer/        # Module 1
│   │   │   ├── har_io.py        # load and validate HAR, walk bodies
│   │   │   ├── classify.py      # which cookies/headers/params are secrets
│   │   │   ├── cookies.py       # Cookie / Set-Cookie parsing
│   │   │   ├── jwt_utils.py     # decode-only JWT helpers
│   │   │   ├── scoring.py       # explainable 0-100 risk score
│   │   │   ├── analyzer.py      # analyze_har()
│   │   │   ├── redactor.py      # redact_har()
│   │   │   ├── sample_har.py    # deterministic synthetic HAR
│   │   │   └── __main__.py      # CLI
│   │   ├── log_generator/       # Module 2
│   │   │   ├── catalog.py       # places, networks, browsers, apps, event types
│   │   │   ├── directory.py     # 51 synthetic principals
│   │   │   ├── builder.py       # Okta-style event construction
│   │   │   ├── sessions.py      # per-session event scripting
│   │   │   ├── benign.py        # everyday activity
│   │   │   ├── edge_cases.py    # benign-but-suspicious behaviour
│   │   │   ├── attack.py        # victim's day + labelled intrusion
│   │   │   ├── generator.py     # generate_dataset() + invariants
│   │   │   ├── export.py        # JSONL / ground truth / directory files
│   │   │   └── __main__.py      # CLI
│   │   ├── detection_engine/    # Module 3
│   │   │   ├── context.py       # per-session / per-actor indexes
│   │   │   ├── rules.py         # OT-DET-001 ... OT-DET-007
│   │   │   ├── engine.py        # run rules, merge matches into alerts
│   │   │   ├── evaluation.py    # precision / recall vs ground truth
│   │   │   ├── pipeline.py      # detect + evaluate + store
│   │   │   └── __main__.py      # CLI
│   │   ├── timeline_builder/    # Module 4
│   │   │   ├── mapping.py       # deterministic ATT&CK tagging
│   │   │   ├── builder.py       # scoping, entries, inference
│   │   │   ├── evaluation.py    # coverage vs ground truth
│   │   │   └── __main__.py      # CLI
│   │   ├── report_summarizer/   # Module 6
│   │   │   ├── facts.py         # deterministic facts (no secrets)
│   │   │   ├── summarizer.py    # template + Claude writer, citation check
│   │   │   └── __main__.py      # CLI
│   │   └── api/                 # FastAPI app and routes
│   └── tests/
├── data/samples/                # sample HAR (+ redacted, findings), system log, ground truth, detections, timeline, summary
├── data/generated/              # SQLite database (git-ignored, rebuilt on demand)
├── scripts/generate_samples.py
├── requirements.txt
├── pyproject.toml               # pytest config
└── .env.example                 # documented settings (no secrets)
```

## Module 1: HAR analyzer

### What it detects

| Kind | Where it looks | Base score |
|------|----------------|-----------:|
| `password` | JSON/form bodies, query strings (`password`, `passcode`, ...) | 90 |
| `api_token` | `Authorization: SSWS ...` (Okta API token scheme), pasted curl commands | 80 |
| `client_secret` | OAuth token requests | 80 |
| `basic_credentials` | `Authorization: Basic ...` (only the username is shown) | 75 |
| `refresh_token`, `api_key` | bodies, `X-API-Key`-style headers | 70 |
| `session_cookie` | `sid`, `idx`, `JSESSIONID`, ... and session-like names | 60 |
| `access_token`, `bearer_token` | `Authorization: Bearer`, token responses, URLs | 55 |
| `session_token` | Okta `sessionToken`, `?token=` on `sessionCookieRedirect` | 50 |
| `jwt` | any JWT found anywhere, including inside HTML or scripts | 45 |
| `id_token` | token responses | 40 |
| `device_token` | `DT` device-trust cookie | 35 |
| `oauth_code` | `?code=` in URLs and redirects | 25 |
| `csrf_token` | `X-Okta-XsrfToken`, `XSRF-TOKEN` | 15 |

JWT headers and payloads are **decoded without signature verification**. That
is deliberate: an analyst needs to read the claims (issuer, subject, scopes,
expiry) but has no key and should never validate or reuse the token.

### Risk score

`score = base + modifiers`, clamped to 0–100. Each finding lists its factors,
so you can always see why it got its score.

| Modifier | Points |
|----------|-------:|
| Still valid when the HAR was captured | +10 |
| Already expired at capture time | −35 |
| Long-lived (lifetime > threshold, default 8h) or long-lived by design | +10 |
| Exposed in a URL (query string, Referer, redirect) | +10 |
| Cookie set without `HttpOnly` / without `Secure` | +5 each |
| Privileged scopes or admin group claims | +10 |
| Unsigned JWT (`alg=none`) | +5 |

Severity: **critical** ≥ 80, **high** ≥ 60, **medium** ≥ 35, otherwise **low**.

Each distinct secret becomes one finding, with every occurrence listed. For
example, the `sid` cookie is set in entry 1 and then replayed in entries 2 and 11.
Findings carry a 12-hex-char **SHA-256 fingerprint**, which lets you prove the
token in a HAR is the one replayed in the logs without ever showing the token.
Passwords and Basic credentials are never fingerprinted, because a short
password can be brute-forced from an unsalted hash.

### Redaction

`redact_har()` returns a deep copy (the input is never modified) where:

- every cookie value is masked, but cookie names and `Set-Cookie` attributes are kept;
- `Authorization`, API-key, CSRF and session headers are masked, keeping the scheme;
- sensitive query, form and JSON parameters are masked using the same rules as the analyzer;
- a final sweep masks any JWT or `Bearer`/`SSWS`/`Basic` credential anywhere,
  including bodies, `_custom` fields and comments; base64 bodies are decoded,
  redacted and re-encoded.

Masked values become `[REDACTED:sha256=<fingerprint>]`, or a bare
`[REDACTED]` for passwords. The tests check that re-analysing a redacted HAR
returns zero findings.

### The sample HAR

`data/samples/support_case_00421.har` is a fictional capture that an Acme
admin attached to support case CASE-00421. It has 12 entries that cover every
detector, plus a clean negative control (entry 9). It is generated
deterministically:

```bash
python scripts/generate_samples.py
```

That command also writes `support_case_00421.redacted.har` and
`support_case_00421.findings.json`.

### CLI

Run from the `backend/` directory:

```bash
python -m oktatrace.har_analyzer analyze ../data/samples/support_case_00421.har --json findings.json --redacted out.har
```

## Module 2: log generator

`generate_dataset(seed)` builds a deterministic, Okta-style System Log for a
fictional tenant covering **Thu 28 Sep – Wed 4 Oct 2023**. With the default
seed it has 5,788 events from 51 principals across 332 sessions; every seed
tested produced more than 5,500. Generating it takes about half a second.

### Population

| Role | Count | Behaviour |
|------|------:|-----------|
| Employees | 42 | SF and NYC offices (shared NAT egress) plus remote staff in Seattle, Austin and Denver |
| Admins | 5 | as employees, plus admin-console work, always preceded by step-up MFA |
| Support engineers | 3 | vendor office; view 8–20 support cases a day |
| Service account | 1 | `svc-case-sync`: signs in every 6 h, syncs cases hourly, around the clock |

Event types: `user.session.start` / `.end`, `user.authentication.auth_via_mfa`,
`user.authentication.sso`, and admin events (`user.lifecycle.create`,
`group.user_membership.add`, `system.api_token.create`,
`user.mfa.factor.deactivate`, `policy.rule.update`, ...). The vendor support
portal uses four **fictional** event types (`support.case.view`, `.create`,
`.attachment.upload`, `.attachment.download`); Okta's real System Log has no
equivalent. There is realistic noise too: failed passwords, occasional MFA
failures, second sessions from home, and quiet weekends.

All IPs are RFC 5737 documentation addresses, all ASNs are RFC 6996
private-use numbers, and every domain ends in `.example`. The tests check this
for every event.

### The labelled attack (51 events)

| Phase | When (UTC) | What the log shows |
|-------|-----------|--------------------|
| context | 02 Oct 14:30–14:46 | Jordan Rivera (admin) signs in. This is the session whose `sid` is in the sample HAR. Jordan opens CASE-00421 and uploads the HAR |
| `initial_access` | 19:52 | `svc-case-sync` signs in from a new hosting ASN (AS65066, Frankfurt) with a `python-requests` user agent |
| `har_exfiltration` | 19:53–19:58 | the service account downloads 6 HAR attachments, including Jordan's |
| `session_replay` | 22:04 | Jordan's session is used from AS65066 with Firefox on Windows. There is no sign-in, and Jordan was active in San Francisco 6 minutes earlier |
| `case_collection` | 22:05–22:12 | the replayed session views 30 support cases in about 7 minutes |
| `session_replay` + `admin_attempt` | 03 Oct 09:41–09:45 (02:41 PDT) | the replayed session creates a user, adds it to `Acme-Super-Admins`, creates an API token and resets another admin's MFA. A policy change is refused |

**Cross-module evidence:** the replayed `externalSessionId` hashes to the same
fingerprint (`c85dd9d19760`) as the `sid` finding from Module 1. The replayed
requests also carry the victim's `dtHash`, which matches the HAR's `DT`
finding, because the device cookie leaked as well. That shows why cookie-based
device trust does not stop HAR-based replay.

### Benign edge cases (96 events, labelled `edge_case`)

These give the detection engine realistic false-positive pressure:
`vpn_switch` (one session, office → home ISP), `browser_update` (Chrome
117 → 118 mid-session), `travel` (SF → NYC overnight, physically possible),
`offhours_admin` (Saturday 03:00 maintenance with fresh MFA) and
`support_bulk` (28 cases triaged in 50 minutes).

### Ground truth

Labels (`benign`, `edge_case`, `context`, `attack` plus phase) are stored
**separately** from events: a different SQLite table, and a separate
`ground_truth.json` next to `system_log.jsonl`. Detection rules never see them.

### CLI

Run from the `backend/` directory:

```bash
python -m oktatrace.log_generator --seed 20231020 --out-dir ../data/generated
```

This writes the SQLite database (default `data/generated/oktatrace.db`) and,
with `--out-dir`, `system_log.jsonl`, `ground_truth.json` and `directory.json`.

## Module 3: detection engine

Each rule reads only what is in the log (IP, ASN, geolocation, user agent,
event type, session ID) plus the directory, and returns one match per
offending event. The engine merges matches of the same rule and key that are
within 30 minutes of each other into a single alert. Every alert has an
explanation built from the actual values, its evidence events, and ATT&CK
technique IDs. Alerts refer to sessions by fingerprint only, never by the raw
replayable ID.

| ID | Rule | Severity | Fires when | ATT&CK |
|----|------|----------|-----------|--------|
| OT-DET-001 | Session token reused from another IP | high | a session is used from an IP on a different ASN than its first event, with no new sign-in | T1550.004, T1539 |
| OT-DET-002 | Impossible travel | high | consecutive events for a user imply more than 900 km/h over more than 500 km | T1078 |
| OT-DET-003 | New user agent on an existing session | medium | browser family or OS changes mid-session (version-only changes are ignored) | T1550.004 |
| OT-DET-004 | Admin action without recent MFA | high | an admin event happens on a session whose last successful MFA is more than 60 min old, or missing | T1098, T1550.004 |
| OT-DET-005 | Bulk support-case access | medium | at least 15 distinct support cases are viewed within 10 minutes | T1213 |
| OT-DET-006 | Off-hours admin action | medium | an admin event happens outside 07:00–20:00 or at a weekend, in the actor's home time zone | T1078 |
| OT-DET-007 | Service account from a new network | high | a service account signs in from an ASN outside its 24 h baseline (the whole session is flagged) | T1078 |

OT-DET-007 goes beyond the six rules in the brief. It covers the incident's
real first step, a stolen service-account credential, which none of the other
rules can see. Every threshold is configurable (`DetectionConfig`, or the
body of `POST /api/detections/run`).

### Results on the default dataset

| Metric | Value |
|--------|-------|
| Alerts | 13 (11 true positives, 2 false positives) |
| Alert-level precision | 84.6% |
| Event-level precision / recall / F1 | 85.0% / **100%** / 91.9% |
| Attack phases detected | 5 of 5 (every attack event flagged) |
| False positives | `vpn_switch` (OT-DET-001) and `offhours_admin` (OT-DET-006), both planted |

On six other seeds, recall stayed at 100% and the only false positives were
the planted edge cases. **How the metrics are defined** (`evaluation.py`):

- An alert is a true positive if any of its flagged or context events is an attack event.
- At the event level, the union of flagged events is the prediction set.
- Labels are only consulted after the engine has finished.

**Threshold sensitivity (report material):**

- Narrowing business hours to 08:00–18:00 adds 4 false positives from ordinary admin work.
- Comparing raw user-agent strings instead of browser family plus OS adds 6
  false positives from the `browser_update` case.
- The benign edge cases `travel` and `support_bulk` never alert at the defaults.

### CLI

Run from the `backend/` directory:

```bash
python -m oktatrace.detection_engine --json ../data/generated/detections.json
```

It prints the alert table, the metrics and per-rule precision, and stores the
alerts in SQLite.

## Module 4: timeline builder

`build_timeline(events, alerts, har)` merges HAR evidence, log events and
alerts into one chronological incident timeline. Every entry has an evidence
reference (event UUID, alert ID, HAR finding ID or HAR file) and, if
suspicious, MITRE ATT&CK techniques. The entry's *stage* is the tactic of its
first technique.

**Scoping pivots from the leaked token**, as an analyst would:

1. Seed with the alerts whose session fingerprint matches a secret in the HAR.
2. Pivot on their actor and on the networks of events that OT-DET-001 flagged.
3. Keep every alert linked to those pivots.

On the default data this keeps exactly the 11 true-positive alerts and
excludes the two false positives as unrelated. `scope=all_alerts` keeps
everything.

**Inferred step:** no log records the attacker pulling the cookie out of the
HAR. The timeline adds an `inference` entry (T1539) at the moment the
service account downloaded `support_case_00421.har`. Its evidence is the HAR
finding (`sid`, fingerprint `c85dd9d19760`), the download event and the first
replay alert. The leaked `DT` device cookie is linked in the same way, through
the `dtHash` on the replayed requests.

| Evidence | Technique |
|----------|-----------|
| HAR `sid` / `DT` cookies, inferred extraction | T1539 Steal Web Session Cookie |
| `.har` attachment downloads | T1213 + T1552.001 Credentials In Files |
| Service-account sign-in from new network | T1078 Valid Accounts |
| Anything done through the replayed session | T1550.004 Web Session Cookie |
| Support-case views | T1213 Data from Information Repositories |
| New user / group membership / API token | T1136.003 / T1098 / T1098.001 |
| MFA factor reset / policy change | T1556.006 / T1484 |

Benign context (the victim's own sign-in, last MFA, the HAR upload) is kept
but never tagged. For an impossible-travel pair, only the side on the
attacker's network is tagged. On the default data the timeline has 75
entries, covers all 51 attack events, and none of its 9 benign context
entries carries a technique.

Run from the `backend/` directory:

```bash
python -m oktatrace.timeline_builder --scope incident --json ../data/generated/timeline.json
```

## Module 6 (optional): report summarizer

`summarize(facts)` turns the outputs of modules 1–4 into a plain-English
incident summary with these sections: executive summary, what happened,
detection and evidence, impact, recommended actions, and detection quality.

- **Python decides, the LLM only writes.** `build_facts()` collects the HAR
  findings, alerts (each marked as part of the incident or not), metrics,
  key timeline entries and recommendations. All of these are computed
  deterministically and contain no secrets or raw session IDs. The model is told
  to use only these facts and to cite their IDs.
- **Citation check:** every ID in the output (`ALR-`, `TL-`, `HAR-`,
  `OT-DET-`, ATT&CK) is checked against the facts, and unknown IDs are
  reported as warnings.
- **Three modes:**
  - `template`: deterministic and offline.
  - `llm`: one Claude call; errors are raised.
  - `auto` (default): Claude when `ANTHROPIC_API_KEY` or
    `ANTHROPIC_AUTH_TOKEN` is set, otherwise the template. Any API error or
    refusal falls back to the template, with the reason recorded.
- **LLM call:** Anthropic Python SDK, model `claude-opus-5-5`
  (`OKTATRACE_LLM_MODEL`), effort `medium`, default adaptive thinking, a 120 s
  timeout and 2 SDK retries. Server-side refusal fallback is enabled
  (`fallbacks: "default"`), and `stop_reason` is checked before any text is
  read. API errors are mapped one class at a time (authentication, permission,
  not found, rate limit, bad request, status, timeout, connection). No key is
  ever hard-coded; the SDK reads it from the environment.
- **Cost:** `mode=llm` makes one paid API call per summary. The tests use a
  fake client and never touch the network.

Run from the `backend/` directory:

```bash
python -m oktatrace.report_summarizer --mode template --out ../data/generated/summary.md
```

`--mode llm` does the same through Claude and needs `ANTHROPIC_API_KEY`.

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | Liveness check plus disclaimer |
| POST | `/api/har/analyze` | Upload a `.har` and get findings (processed in memory, not stored) |
| POST | `/api/har/redact` | Upload a `.har` and download the redacted copy |
| GET | `/api/har/sample` | Download the synthetic sample HAR |
| GET | `/api/har/sample/analysis` | Findings for the sample HAR |
| GET | `/api/har/sample/redacted` | Redacted sample HAR |
| GET | `/api/logs/summary` | Dataset counts (auto-generates the default dataset on first use) |
| GET | `/api/logs/events` | Filter by `event_type`, `actor`, `session_id`, `ip_address`, `category`, `since`, `until`; paged (`limit` ≤ 500) |
| GET | `/api/logs/attack` | The labelled attack, step by step |
| GET | `/api/logs/scenario` | Victim, session fingerprint, attacker infrastructure |
| GET | `/api/logs/users` | Synthetic directory |
| POST | `/api/logs/generate` | Regenerate with `{"seed": N}` |
| GET | `/api/detections/rules` | Rule catalogue |
| GET | `/api/detections/summary` | Latest run: counts by rule/severity plus evaluation (runs on first use) |
| GET | `/api/detections/alerts` | Filter by `rule_id`, `severity`, `actor`, `since`, `until` |
| GET | `/api/detections/alerts/{id}` | One alert with its evidence and context events |
| GET | `/api/detections/evaluation` | Precision/recall, phase coverage, per-rule metrics |
| GET | `/api/detections/config` | Thresholds used by the latest run |
| POST | `/api/detections/run` | Re-run with new thresholds (JSON body, all fields optional) |
| GET | `/api/timeline` | Incident timeline (`scope=incident` or `all_alerts`) |
| GET | `/api/timeline/evaluation` | Attack-event coverage of the timeline |
| GET | `/api/report/facts` | The deterministic facts the summary is written from |
| POST | `/api/report/summary` | Write the summary (`mode=auto`, `llm` or `template`) |

Uploads are capped at `OKTATRACE_MAX_HAR_MB` (default 25 MB). Download
filenames are sanitised.

## Configuration

Set these as environment variables (see `.env.example`). No secrets are
hardcoded anywhere.

| Variable | Default | Meaning |
|----------|---------|---------|
| `OKTATRACE_LONG_LIVED_HOURS` | `8` | Lifetime above which a token is "long-lived" |
| `OKTATRACE_MAX_HAR_MB` | `25` | Largest accepted upload |
| `OKTATRACE_CORS_ORIGINS` | Vite dev server | Allowed browser origins |
| `OKTATRACE_DATA_DIR` | `./data` | Artefact directory |
| `OKTATRACE_DB_PATH` | `data/generated/oktatrace.db` | SQLite database |
| `OKTATRACE_SEED` | `20231020` | Seed for the auto-generated dataset |
| `OKTATRACE_SUMMARY_MODE` | `auto` | `auto`, `llm` or `template` |
| `OKTATRACE_LLM_MODEL` | `claude-opus-5-5` | Model for LLM summaries |
| `OKTATRACE_LLM_TIMEOUT_SECONDS` | `120` | Summarizer API timeout |
| `ANTHROPIC_API_KEY` | unset | Read by the Anthropic SDK (only needed for `llm` mode) |

## How this maps to the report chapters

The full mapping will be finished with the last module. So far:

| Report chapter | OktaTrace evidence |
|----------------|--------------------|
| Incident background: why HAR files are dangerous | Sample HAR: live `sid`/`idx` cookies, an API token and a password captured during routine troubleshooting |
| Forensic analysis: artefact examination | `har_analyzer` findings, decoded JWT claims, risk factors |
| Lessons learned: data handling | Redaction rules; "re-analysis finds nothing" test |
| Attack narrative and timeline | `attack.py` phases and `ground_truth.json` attack steps |
| Methodology: dataset design | Seeded generation, documentation-only IPs/ASNs, edge cases for false-positive pressure |
| Forensic analysis: linking artefacts | `sid`/`DT` fingerprints shared by the HAR findings and the replayed log events |
| Detection and analysis | Rule table, alert explanations, `detections.json` |
| Incident reconstruction / timeline | `timeline.json`, ATT&CK technique summary, the inferred cookie-extraction step |
| Executive summary / conclusion | `incident_summary.template.md` (or an LLM-written version), with every claim citing an evidence ID |
| Evaluation | Precision/recall/F1, phase coverage, per-rule precision, false-positive causes, threshold sensitivity |
