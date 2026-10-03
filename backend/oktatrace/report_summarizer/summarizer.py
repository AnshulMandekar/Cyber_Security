"""Turn :class:`IncidentFacts` into a plain-English incident summary.

Two writers produce the same sections:

* **template** - deterministic Python, works offline, used by default when no
  Anthropic credentials are configured;
* **llm** - one Claude Messages API call that rephrases the facts as prose.

The LLM is a writer, not an analyst: detections, severities, metrics and
recommendations all come from the facts. Every evidence ID the output cites is
checked against the facts afterwards and anything unknown is reported.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Literal

from pydantic import BaseModel, Field

from oktatrace.config import Settings, get_settings
from oktatrace.report_summarizer.facts import IncidentFacts

SummaryMode = Literal["auto", "llm", "template"]

REFERENCE_PATTERN = re.compile(r"\b(?:ALR-\d{4}|TL-\d{4}|HAR-\d{3}|OT-DET-\d{3}|T\d{4}(?:\.\d{3})?)\b")
FALLBACK_BETA = "server-side-fallback-2026-07-01"

SYSTEM_PROMPT = """\
You write incident summaries for a university cyber-security case study. All data is synthetic.

The user message contains a JSON object of findings that were computed deterministically by \
analysis code (HAR analysis, detection rules, an incident timeline). Your job is to explain those \
findings clearly to a reader who has not seen the data.

Ground rules:
- Use only the facts in the JSON. Do not add, drop, merge or re-rate alerts, findings, severities \
or metrics, and do not speculate about who the attacker is.
- Cite evidence by the IDs used in the facts (for example ALR-0005, TL-0014, HAR-011, OT-DET-001, \
T1539) so a reader can trace each statement. Never invent an ID.
- Alerts with "in_incident": false were judged unrelated; mention them only as false positives in \
the detection-quality section.
- Keep any secret values out of the text; fingerprints may be quoted.

Write Markdown with these sections: a title line, Executive summary (3-4 sentences), What happened \
(chronological bullet points with UTC times), Detection and evidence, Impact, Recommended actions \
(use the recommendations in the facts), Detection quality. Aim for 400-650 words. Start the \
document with the disclaimer from the facts as a block quote."""


class SummarizerError(RuntimeError):
    """The LLM summary could not be produced."""


class IncidentSummary(BaseModel):
    """A written summary plus how it was produced and whether its citations check out."""

    mode: Literal["llm", "template"]
    model: str | None = Field(None, description="Model that served the request (LLM mode only)")
    markdown: str
    cited_ids: list[str]
    unknown_ids: list[str] = Field(description="IDs cited in the text that do not exist in the facts")
    fallback_reason: str | None = None
    warnings: list[str] = Field(default_factory=list)
    usage: dict[str, int] | None = None


def check_references(text: str, facts: IncidentFacts) -> tuple[list[str], list[str]]:
    """Return (cited IDs, cited IDs that are not in the facts), each sorted and de-duplicated."""
    cited = sorted(set(REFERENCE_PATTERN.findall(text)))
    known = facts.known_ids()
    return cited, [i for i in cited if i not in known]


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


# -- template writer -----------------------------------------------------------
def template_markdown(facts: IncidentFacts) -> str:
    """Deterministic summary with the same sections the LLM is asked for."""
    har, det, tl = facts.har, facts.detections, facts.timeline
    incident_alerts = [a for a in det["alerts"] if a["in_incident"]]
    other_alerts = [a for a in det["alerts"] if not a["in_incident"]]
    stages = ", ".join(tl["entries_by_stage"]) or "none"
    fingerprints = ", ".join(tl["matched_fingerprints"]) or "none"
    critical = har["by_severity"].get("critical", 0)
    ev = det["evaluation"]

    lines = [
        f"# Incident summary: {facts.organisation}, support case {facts.case_id}",
        "",
        f"> {facts.disclaimer}",
        "",
        "## Executive summary",
        "",
        f"A browser HAR file attached to support case {facts.case_id} contained {har['total_findings']} "
        f"secrets ({critical} critical), including live session cookies. A session matching fingerprint "
        f"{fingerprints} from that file later appeared in the identity provider's logs from a different "
        f"network. The detection engine raised {len(incident_alerts)} alerts linked to this incident "
        f"between {tl['first']} and {tl['last']} (UTC), spanning these ATT&CK stages: {stages}.",
        "",
        "## What happened",
        "",
    ]
    for entry in tl["key_entries"]:
        techniques = f" [{', '.join(entry['techniques'])}]" if entry["techniques"] else ""
        lines.append(f"- {entry['time']}: {entry['title']} ({entry['id']}){techniques}")
    lines += ["", "## Detection and evidence", ""]
    for alert in incident_alerts:
        lines.append(f"- **{alert['id']}** {alert['rule_id']} ({alert['severity']}): {alert['explanation']}")
    impact = [e for e in tl["key_entries"] if e["kind"] == "event" and e["stage"] in ("Persistence", "Defense Evasion")]
    lines += ["", "## Impact", ""]
    if impact:
        lines += [f"- {e['title']} ({e['id']})" for e in impact]
    else:
        lines.append("- No privileged changes were recorded.")
    lines += ["", "## Recommended actions", ""]
    lines += [f"- {r}" for r in facts.recommendations] or ["- None recorded."]
    lines += [
        "",
        "## Detection quality",
        "",
        f"- Alert precision {_pct(ev['alert_precision'])}; event-level precision {_pct(ev['event_precision'])}, "
        f"recall {_pct(ev['event_recall'])}, F1 {_pct(ev['event_f1'])}.",
        f"- Attack steps missed: {ev['missed_attack_steps']}.",
    ]
    if other_alerts:
        causes = ", ".join(f"{k} ({v})" for k, v in ev["false_positive_causes"].items()) or "unknown"
        lines.append(
            f"- Alerts judged unrelated (false positives): {', '.join(a['id'] for a in other_alerts)}; "
            f"causes: {causes}."
        )
    return "\n".join(lines) + "\n"


def _template_summary(facts: IncidentFacts, fallback_reason: str | None = None) -> IncidentSummary:
    markdown = template_markdown(facts)
    cited, unknown = check_references(markdown, facts)
    return IncidentSummary(mode="template", markdown=markdown, cited_ids=cited, unknown_ids=unknown,
                           fallback_reason=fallback_reason)


# -- LLM writer ----------------------------------------------------------------
def _has_env_credentials() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN"))


def _default_client(settings: Settings) -> Any:
    try:
        import anthropic
    except ImportError as exc:
        raise SummarizerError("The 'anthropic' package is not installed") from exc
    return anthropic.Anthropic(timeout=float(settings.llm_timeout_seconds), max_retries=2)


def _user_message(facts: IncidentFacts) -> str:
    payload = json.dumps(facts.model_dump(mode="json"), indent=2, sort_keys=True)
    return f"<facts>\n{payload}\n</facts>\n\nWrite the incident summary from these facts."


def _llm_summary(facts: IncidentFacts, client: Any, model: str) -> IncidentSummary:
    import anthropic

    try:
        response = client.beta.messages.create(
            model=model,
            max_tokens=16000,
            betas=[FALLBACK_BETA],
            fallbacks="default",  # if the model declines, the API retries on its recommended fallback
            output_config={"effort": "medium"},
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _user_message(facts)}],
        )
    except anthropic.AuthenticationError as exc:
        raise SummarizerError("Anthropic credentials were rejected") from exc
    except anthropic.PermissionDeniedError as exc:
        raise SummarizerError("The API key is not allowed to use this model or feature") from exc
    except anthropic.NotFoundError as exc:
        raise SummarizerError(f"Model {model!r} was not found") from exc
    except anthropic.RateLimitError as exc:
        raise SummarizerError("Rate limited by the Anthropic API; try again shortly") from exc
    except anthropic.BadRequestError as exc:
        raise SummarizerError(f"The API rejected the request: {exc.message}") from exc
    except anthropic.APIStatusError as exc:
        raise SummarizerError(f"Anthropic API error {exc.status_code}") from exc
    except anthropic.APITimeoutError as exc:
        raise SummarizerError("The Anthropic API request timed out") from exc
    except anthropic.APIConnectionError as exc:
        raise SummarizerError("Could not reach the Anthropic API") from exc

    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        category = getattr(details, "category", None) if details else None
        raise SummarizerError(f"The model declined to write the summary (category: {category})")
    text = "".join(block.text for block in response.content if block.type == "text").strip()
    if not text:
        raise SummarizerError("The model returned no text")
    warnings = []
    if response.stop_reason == "max_tokens":
        warnings.append("The summary hit the output limit and may be cut short.")
    cited, unknown = check_references(text, facts)
    if unknown:
        warnings.append(f"Cited IDs not present in the facts: {', '.join(unknown)}")
    usage = getattr(response, "usage", None)
    return IncidentSummary(
        mode="llm",
        model=getattr(response, "model", model),
        markdown=text + "\n",
        cited_ids=cited,
        unknown_ids=unknown,
        warnings=warnings,
        usage={"input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens} if usage else None,
    )


def summarize(
    facts: IncidentFacts,
    *,
    mode: SummaryMode | None = None,
    client: Any = None,
    settings: Settings | None = None,
) -> IncidentSummary:
    """Write the summary.

    Args:
        facts: Output of :func:`build_facts`.
        mode: ``template`` (offline), ``llm`` (errors are raised) or ``auto``
            (LLM when credentials are set or a client is given, falling back to
            the template on any error). Defaults to ``OKTATRACE_SUMMARY_MODE``.
        client: An Anthropic client (injected in tests); created on demand otherwise.
        settings: Overrides :func:`get_settings`.

    Raises:
        SummarizerError: In ``llm`` mode, when the API call fails or is declined.
    """
    settings = settings or get_settings()
    mode = mode or settings.summary_mode  # type: ignore[assignment]
    if mode == "template":
        return _template_summary(facts)
    if mode == "auto" and client is None and not _has_env_credentials():
        return _template_summary(
            facts, "No ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN set, so the offline template was used."
        )
    try:
        return _llm_summary(facts, client or _default_client(settings), settings.llm_model)
    except SummarizerError as exc:
        if mode == "llm":
            raise
        return _template_summary(facts, f"LLM summary unavailable ({exc}); used the offline template.")
