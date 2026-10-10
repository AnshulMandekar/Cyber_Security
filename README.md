# [OktaTrace] [GitHub](https://github.com/AnshulMandekar/Cyber_Security) 

A defensive forensic demo for a university case study of the **2023 Okta
support-system breach**. In that incident an attacker used a stolen
service-account credential to get into the support case system, downloaded
HAR files that customers had uploaded, pulled live session tokens out of them,
and replayed those tokens to hijack customer admin sessions.

OktaTrace shows how an analyst reconstructs that kind of breach from session
artefacts and logs, and how token replay can be detected. (The mitigation
simulator from the original brief is not implemented; see section 1.)

> **SYNTHETIC DATA ONLY.** Every user, token, IP address, log event and HAR
> file in this project is fabricated. Domains use the reserved `.example` TLD
> (RFC 2606), IPs come from documentation ranges (RFC 5737), and every token
> carries a `SYN` marker. Nothing here performs exploitation, uses real
> credentials, or scans real systems.

## Contents

1. [What works today](#1-what-works-today)
2. [Setup](#2-setup)
3. [Using the project](#3-using-the-project)
4. [Reading the results](#4-reading-the-results)
5. [Troubleshooting](#5-troubleshooting)
6. Reference: [layout](#project-layout), [modules](#module-1-har-analyzer), [API](#api), [configuration](#configuration)
7. [How this maps to the report](#how-this-maps-to-the-report)

## 1. What works today

| # | Module | What it gives you | Status |
|---|--------|-------------------|--------|
| 1 | HAR analyzer | Finds secrets in a HAR file, scores each one, writes a redacted copy | Done |
| 2 | Log generator | 5,788 synthetic Okta-style log events with a labelled attack, stored in SQLite | Done |
| 3 | Detection engine | 7 deterministic rules that raise alerts with explanations, plus precision/recall against the labelled attack | Done |
| 4 | Timeline builder | One ordered, MITRE ATT&CK-tagged incident timeline linking the HAR, the logs and the alerts | Done |
| 5 | Mitigation simulator | Before/after attacker success with controls switched on | **Not implemented** (only `models.py` exists) |
| 6 | Report summarizer | Plain-English incident summary, from an offline template or from Claude | Done |
| – | Web dashboard (React + Vite), PDF export | | **Not built** |

**How you use it today.** There are two ways in, and both work offline:

- **Command line.** One small program per module (section 3.1).
- **API explorer in your browser.** Start the server and open
  <http://127.0.0.1:8000/docs>: every endpoint has a form, and you can upload a
  HAR file from there (section 3.2).

There is no custom dashboard yet, and no one-click "run everything and show me
a web page" script. `python scripts/generate_samples.py` is the closest thing:
it rebuilds every sample data file in one go.

## 2. Setup

**You need:** Python 3.11 or newer (developed on 3.14), Git, and internet access for
`pip install`. You do **not** need Node.js (there is no front end yet), a database
server (SQLite is built in) or an API key (the LLM summary is optional).

> **Which folder do I run from?** Two folders matter.
>
> - **Project root** (the folder that contains this README): `pip`, `pytest`,
>   `uvicorn` and `scripts/generate_samples.py`.
> - **`backend/`**: every `python -m oktatrace.<module>` command-line tool.
>
> Running a command from the wrong folder gives
> `ModuleNotFoundError: No module named 'oktatrace'`.

**Step 1. Get the code.** The repository root is the project root.

```bash
git clone https://github.com/AnshulMandekar/Cyber_Security.git
cd Cyber_Security
```

**Step 2. Create an isolated Python environment** (once).

Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

The prompt now starts with `(.venv)`. Repeat only the activation line each time you
open a new terminal. If PowerShell says running scripts is disabled, open Command
Prompt instead and run `.venv\Scripts\activate.bat`.

**Step 3. Install the dependencies.**

```bash
pip install -r requirements.txt
```

**Step 4. Check that everything works.**

```bash
python -m pytest
```

You should see `204 passed` (the first run takes under a minute).

## 3. Using the project

### 3.1 Command-line tour

Run these from the **`backend/`** folder, in this order (`cd backend` first). Each
step stands alone: anything it needs from an earlier step is generated
automatically. The `../data/generated/...` paths are created for you and are
git-ignored.

**Step 1: find the secrets in a HAR file (Module 1).**

```bash
python -m oktatrace.har_analyzer analyze ../data/samples/support_case_00421.har --json ../data/generated/findings.json --redacted ../data/generated/redacted.har
```

You should see a table of **16 findings** (6 critical, 6 high, 2 medium, 2 low),
highest risk first: a clear-text password, a client secret, a 30-day `JSESSIONID`
cookie, an Okta `SSWS` API token, and so on. The `sid` session cookie is
`HAR-011`. The command also writes `findings.json` and a copy of the HAR with
**47 values masked** (`redacted.har`). Open both to compare.

**Step 2: generate the synthetic log (Module 2).**

```bash
python -m oktatrace.log_generator --out-dir ../data/generated
```

You should see `seed 20231020: 5788 events, 51 principals, 332 sessions` and
`attack 51, benign 5638, context 3, edge_case 96`. The line
`victim session fingerprint c85dd9d19760` is the same fingerprint as the `sid`
finding in step 1: that match is how the HAR and the logs are linked. Files
written: `oktatrace.db` (SQLite), `system_log.jsonl` (the events, one JSON object
per line), `ground_truth.json` (the answer key) and `directory.json` (the users).

**Step 3: run the detection rules (Module 3).**

```bash
python -m oktatrace.detection_engine --json ../data/generated/detections.json
```

You should see **13 alerts** and the scores: `11 TP / 2 FP`, alert precision
84.6%, event-level recall **100%**, precision 85.0%, F1 91.9%. The two false
positives are deliberately planted look-alikes (a VPN switch and Saturday-night
maintenance); the per-rule table at the bottom shows which rule raised which.

**Step 4: build the incident timeline (Module 4).**

```bash
python -m oktatrace.timeline_builder --json ../data/generated/timeline.json
```

You should see **75 entries**, one per line (`!` marks suspicious rows) with the
ATT&CK tactic and technique IDs. `TL-0014` is the *inferred* step where the `sid`
cookie was extracted from the HAR. The table at the end lists the ATT&CK
techniques, and the last line reads `Attack events in timeline: 51/51`. Add
`--scope all_alerts` to include the two unrelated false-positive alerts, and
`--full` to stop similar rows being collapsed.

**Step 5: write the incident summary (Module 6).**

```bash
python -m oktatrace.report_summarizer --mode template --out ../data/generated/summary.md
```

You get a Markdown report (executive summary, what happened, detection and
evidence, impact, recommended actions, detection quality). Every ID in it is checked
against the real findings. `--mode template` is fully offline; for the Claude
version see section 3.5.

**Rebuild all the sample data in one command** (from the **project root**):

```bash
python scripts/generate_samples.py
```

This rewrites the 9 files in `data/samples/` (sample HAR, redacted HAR, findings,
system log, ground truth, directory, detections, timeline, template summary). The
output is deterministic: running it again gives byte-identical content. If `git status`
then lists those files as modified, it is only line endings (LF vs CRLF), not content.

### 3.2 The API explorer in your browser

From the **project root**, with the environment activated:

```bash
python -m uvicorn oktatrace.api.app:app --app-dir backend --reload
```

Leave it running and open <http://127.0.0.1:8000/docs>. Press `Ctrl+C` in the
terminal to stop it. If port 8000 is busy, add `--port 8001` and use
`http://127.0.0.1:8001/docs`.

On the docs page, click an endpoint, then **Try it out**, then **Execute**. A good
first walkthrough, in order:

| # | Endpoint | What you should see |
|---|----------|---------------------|
| 1 | `GET /api/health` | `status: ok` and the synthetic-data disclaimer |
| 2 | `GET /api/har/sample/analysis` | 16 findings in the sample HAR |
| 3 | `POST /api/har/analyze` | Choose a `.har` file, then Execute: findings for **your** file (section 3.3) |
| 4 | `POST /api/har/redact` | Same upload; the response is the redacted HAR to download |
| 5 | `GET /api/logs/summary` | The first call generates the dataset (about a second): 5,788 events |
| 6 | `GET /api/logs/events` | Filter by `category=attack` (51 events), `ip_address=203.0.113.211`, `actor`, `event_type`, `since` / `until`; at most 500 per page |
| 7 | `GET /api/detections/alerts` | Filter by `severity`, `rule_id`, `actor`. Then `GET /api/detections/alerts/ALR-0005` for the evidence behind one alert |
| 8 | `GET /api/detections/evaluation` | Precision, recall, F1, per-phase and per-rule results |
| 9 | `GET /api/timeline` | The 75-entry timeline (`scope=all_alerts` keeps every alert) |
| 10 | `POST /api/report/summary?mode=template` | The incident summary as Markdown inside JSON |

The full endpoint list is in the [API](#api) section below.

**Calling the API from a terminal** instead (the server must be running).

Windows PowerShell: use `curl.exe` (not `curl`, which is an alias for something else)
for file uploads, and `Invoke-RestMethod` for anything that sends JSON:

```powershell
curl.exe -F "file=@data/samples/support_case_00421.har" http://127.0.0.1:8000/api/har/analyze -o analysis.json
curl.exe -F "file=@data/samples/support_case_00421.har" http://127.0.0.1:8000/api/har/redact -o redacted.har
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/detections/run -ContentType "application/json" -Body '{"ignore_user_agent_version": false}'
Invoke-RestMethod http://127.0.0.1:8000/api/detections/summary
```

macOS / Linux / Git Bash:

```bash
curl -F "file=@data/samples/support_case_00421.har" http://127.0.0.1:8000/api/har/analyze -o analysis.json
curl -X POST -H "Content-Type: application/json" -d '{"ignore_user_agent_version": false}' http://127.0.0.1:8000/api/detections/run
```

(`curl.exe` with inline JSON fails in Windows PowerShell 5.1 because of how it
handles quotes; that is why `Invoke-RestMethod` is used there.)

### 3.3 Analysing your own HAR file

Use the upload endpoint (section 3.2, step 3) or the command line:

```bash
python -m oktatrace.har_analyzer analyze path/to/your.har --redacted path/to/your.redacted.har
```

To capture a HAR, open your browser's developer tools, go to the **Network** tab
and export as HAR. Newer browsers may strip cookies and auth headers on export, so
a fresh export can show fewer findings than the sample. Things to know:

- The file is read **in memory only**; the API does not store uploads. Limit 25 MB
  (`OKTATRACE_MAX_HAR_MB`). Bad JSON returns `400`, an oversized file `413`.
- A real HAR from a real signed-in session contains **real credentials**. Do not
  commit it, do not post it, and do not upload it to anyone else's server. Share
  the redacted copy instead. The report shows only masked previews and
  fingerprints, never full values.
- Redaction keeps the structure and replaces each secret with
  `[REDACTED:sha256=<fingerprint>]` (a bare `[REDACTED]` for passwords).

### 3.4 Changing the scenario and the detection thresholds

**A different random scenario (seed).** Same seed, same data; a new seed gives a
different but equally structured dataset and a matching HAR for the timeline.

```bash
python -m oktatrace.log_generator --seed 7
```

Or call `POST /api/logs/generate` with `{"seed": 7}` (stored detections are
recalculated on the next request). Seed 7 gives 5,728 events. The `/api/har/sample*`
endpoints and the files in `data/samples/` always use the default seed; the timeline
and summary build the HAR that matches whichever seed is stored.

**Different detection thresholds.** Use `POST /api/detections/run` with only the
fields you want to change; `{}` restores the defaults. The command-line
detection tool does not take thresholds.

| Field | Default | Meaning |
|-------|---------|---------|
| `require_asn_change` | `true` | OT-DET-001: ignore IP changes inside the same network (NAT pools) |
| `max_travel_speed_kmh` / `min_travel_distance_km` | 900 / 500 | OT-DET-002 impossible travel |
| `ignore_user_agent_version` | `true` | OT-DET-003: compare browser family + OS, not version |
| `mfa_freshness_minutes` | 60 | OT-DET-004: how recent MFA must be before an admin action |
| `bulk_case_threshold` / `bulk_case_window_minutes` | 15 / 10 | OT-DET-005 bulk case access |
| `business_hours_start` / `business_hours_end` | 7 / 20 | OT-DET-006 (weekends always count as off-hours) |
| `service_baseline_hours` | 24 | OT-DET-007: learning period for a service account's networks |
| `suppression_minutes` | 30 | Matches this close together merge into one alert |

Try `{"ignore_user_agent_version": false}` (19 alerts instead of 13: browser
auto-updates now look suspicious) or
`{"business_hours_start": 8, "business_hours_end": 18}` (17 alerts: ordinary admin
work now looks off-hours). Check `GET /api/detections/evaluation` after each run to
see precision fall.

### 3.5 Optional: an LLM-written summary

The offline template needs nothing. To have Claude write the prose instead, set an
API key **in the terminal you run the command from** (never in a file you commit):

```powershell
$env:ANTHROPIC_API_KEY = "your-key-here"
```

```bash
export ANTHROPIC_API_KEY="your-key-here"
```

Then, from `backend/`:

```bash
python -m oktatrace.report_summarizer --mode llm --out ../data/generated/summary_llm.md
```

Each run is **one paid API call**. The default `--mode auto` uses Claude only if a key
is set and quietly falls back to the template on any error (the reason is printed).
`--mode llm` shows the error instead. Claude only receives the computed findings
and is told to cite their IDs; the program warns about any ID that does not exist.
The test suite covers this path with a fake client, so a live call needs your own key.

### 3.6 A five-minute demo script

1. **The leak.** Run step 1 of 3.1. Point at `HAR-001` (clear-text password), `HAR-004`
   (API token) and `HAR-011` (the `sid` session cookie, fingerprint `c85dd9d19760`). Show
   that `redacted.har` has no secrets left.
2. **The attack in the logs.** In `/docs`, run `GET /api/logs/attack`: 51 steps from
   the stolen service-account sign-in to the refused policy change. Stress that the
   rules never see these labels.
3. **The detection.** Run `GET /api/detections/alerts/ALR-0005`. Its explanation says
   session `c85dd9d19760` was set up from San Francisco and used from Frankfurt 7h34m
   later with no new sign-in. That is the HAR's cookie, replayed.
4. **The score.** `GET /api/detections/evaluation`: recall 100%, precision 85%. Name
   the two false positives and why they happen.
5. **The experiment.** `POST /api/detections/run` with
   `{"ignore_user_agent_version": false}`, then `GET /api/detections/evaluation`:
   more alerts, lower precision.
6. **The story.** `GET /api/timeline`: follow the ATT&CK stages from Credential
   Access to Persistence, and show the inferred entry `TL-0014`.
7. **The write-up.** `POST /api/report/summary?mode=template`.

### 3.7 Where the outputs go

| Location | Contents | In Git? |
|----------|----------|---------|
| `data/samples/` | The 9 ready-made sample files (default seed) | Yes |
| `data/generated/oktatrace.db` | SQLite database: events, labels, attack steps, alerts | No |
| `data/generated/*.json`, `.jsonl`, `.har`, `.md` | Whatever the command-line tools write when you pass `--json`, `--out`, `--redacted` or `--out-dir` | No |

The `data/generated/` folder is rebuilt automatically, so deleting it is always safe.
The server and the command-line tools share the same database, so what you generate
in one shows up in the other.

## 4. Reading the results

| You see | What it is |
|---------|-----------|
| `HAR-001`, `HAR-002`, ... | A secret found in a HAR file, numbered from highest to lowest risk (Module 1) |
| `ALR-0005` | An alert: nearby matches of one rule merged into one (Module 3) |
| `OT-DET-001` ... `OT-DET-007` | A detection rule (the table is in the Module 3 section) |
| `TL-0014` | One row of the incident timeline (Module 4) |
| `T1550.004` and similar | A MITRE ATT&CK technique ID |
| `c85dd9d19760` | A fingerprint: the first 12 hex characters of the SHA-256 of a secret or session ID. Identical fingerprints mean the same secret, without ever printing it |
| `attack`, `benign`, `edge_case`, `context` | Ground-truth labels. They are only used to score results, never by the rules |

**Following one story through the IDs:** `HAR-011` (the `sid` cookie, fingerprint
`c85dd9d19760`) is the session in `ALR-0005` and `ALR-0009` (reused from another
network), which is why `TL-0014` infers the cookie was extracted from the HAR at the
moment the service account downloaded it. `ALR-0011` then shows an admin action with
no recent MFA.

**Severity.** HAR findings use a 0 to 100 risk score (critical at 80 or more, high
at 60, medium at 35). Alerts take the severity of their rule. **Precision** is the share
of alerts (or flagged events) that really were part of the attack; **recall** is the
share of attack events that were flagged. Both are defined in the Module 3 section.

## 5. Troubleshooting

| Problem | Fix |
|---------|-----|
| `python` is not found, or `python --version` is below 3.11 | Install Python 3.11+ and reopen the terminal. On Windows try `py -3` instead of `python`; on macOS/Linux use `python3` |
| `ModuleNotFoundError: No module named 'oktatrace'` | Wrong folder. Command-line tools run from `backend/`; the server, `pytest` and `scripts/` run from the project root (with `--app-dir backend` for the server) |
| `pip` fails with `OSError: [Errno 2] No such file or directory` and a hint about **Long Path** support | The folder path is too long for Windows (260 characters). Clone to a short path such as `C:\dev\Cyber_Security`, or create the environment elsewhere (`python -m venv C:\venvs\oktatrace`, then activate that one) |
| Slow `pip` or sync errors when the project is inside OneDrive | Keep `.venv` outside OneDrive as above. If SQLite reports a locked database, point the database elsewhere with `OKTATRACE_DB_PATH` |
| PowerShell: "running scripts is disabled" when activating | Use Command Prompt and `.venv\Scripts\activate.bat`, or call `.venv\Scripts\python` directly |
| `Address already in use` when starting the server | Another program uses port 8000. Add `--port 8001` |
| Results look stale after you changed the code or a setting | Delete `data/generated/` (or call `POST /api/logs/generate`). Data is rebuilt on the next request |
| I put settings in a `.env` file and nothing changed | OktaTrace does not read `.env`. Set variables in your terminal (see [Configuration](#configuration)) |
| API returns `422` | A parameter is invalid, for example `limit` above 500 or an unknown `category` |
| API returns `502` from `/api/report/summary?mode=llm` | No key, a rejected key, or an API problem. The `detail` field says which. Use `mode=template` or `auto` |
| `git status` shows sample files as modified after `generate_samples.py` | Only line endings; the content is identical |

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
│   │   ├── mitigation_simulator/ # Module 5: models.py only (simulator not implemented)
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

Set these as environment variables in the terminal where you run the command.
`.env.example` only documents the names: OktaTrace does **not** read a `.env`
file. No secrets are hardcoded anywhere.

```powershell
$env:OKTATRACE_SEED = "7"
```

```bash
export OKTATRACE_SEED=7
```

A variable set this way lasts until you close that terminal.

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

## How this maps to the report

Section numbers refer to the Group 61 case-study report. "Supported" means the
project produces the evidence for that section; the notes say where the report text
and the project differ.

| Report section | What OktaTrace provides | Status |
|----------------|------------------------|--------|
| 3.6 Laboratory design principles | Synthetic data only, seeded randomness, deterministic rules, every alert carries evidence, the LLM confined to Module 6 | Supported |
| 4.1 / 4.2 System overview, technology stack | Python 3.11+, FastAPI, SQLite, pytest. The React dashboard is not built | Partly |
| 4.3 / 4.4 HAR anatomy, Module 1 | `data/samples/support_case_00421.har` (12 requests, 16 secrets), the scoring tables in the Module 1 section, redaction | Supported; redaction uses fingerprinted markers, not length-preserving ones |
| 4.5 Module 2 | Log generator, 51 principals, 5,788 events, labelled attack, edge cases | Supported; field names and the attack steps differ from the report text |
| 4.6 Module 3 | `OT-DET-001` to `OT-DET-007`, per-rule unit tests, precision/recall | Supported; two rules differ from the report's R6 and R7 |
| 4.7 Module 4 | `timeline.json`, ATT&CK tags, evidence references, the inferred extraction step | Supported; entries are chronological, not grouped by session |
| 4.8 Module 5 | | **Not implemented** |
| 4.9 Module 6 | Template or Claude summary with an ID check | Supported |
| 4.10 Dashboard | Only the API explorer at `/docs`; JSON available through the API, no PDF export | **Not built** |
| 4.11 Testing and reproducibility | 204 tests, seeded generation, `scripts/generate_samples.py` | Supported |
| 5.4 ATT&CK mapping | The timeline's technique table for the synthetic scenario | Supported (lab mapping, wider than the real-incident table) |
| 5.7 Dataset, HAR and detection tables | Counts and metrics from the commands in section 3.1 | Supported; per-rule recall/F1 and time-to-detect are not produced by the tool |
| 5.7 Mitigation table and figure | | **Not available** |
