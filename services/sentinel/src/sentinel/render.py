"""Message rendering — Slack blocks, plain text, and the daily digest.

The acceptance bar for a ping is a list of five things, so the renderer is
written against that list and the test asserts on it: **severity, a
plain-English explanation, the affected resource, an evidence link, and a
concrete remediation snippet.** If any of the five is missing the message says
so explicitly (`no vetted remediation for this finding type`, `evidence link
unavailable`) rather than omitting the section — a reader must be able to tell
"nothing to say" from "the code forgot".

Evidence links are the one place a bus field becomes a URL, which makes them
the one place a compromised or buggy publisher could aim a human at an
attacker's page. Two controls: the contract's ``source_uri`` pattern already
rejects absolute URIs, traversal and the characters that break out of a query
value, and ``resolve_evidence`` additionally allowlists the scheme (D3.1 §3.4)
so an unknown pillar prefix renders as inert text instead of a clickable link.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

# scheme -> gateway subdomain. The launcher serves pillars as <pillar>.<host>
# (stack.yaml gateway.host), so resolution is a host rewrite, not a path join.
SCHEME_HOSTS = {
    "cnapp": "cnapp",
    "cloudsentry": "cnapp",
    "aim": "aim",
    "guardrail": "aim",
    "gatehouse": "gatehouse",
    "sentinel": "sentinel",
}

SEVERITY_EMOJI = {
    "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "informational": "⚪",
}
VERDICT_TEXT = {
    "likely_real": "likely real",
    "needs_verification": "needs verification",
    "likely_noise": "likely noise",
}

_SOURCE_URI = re.compile(r"^([a-z][a-z0-9-]{0,31}):(/.*)$")


def resolve_evidence(source_uri: str, gateway_base_url: str) -> str:
    """`pillar:/path?q` -> an absolute gateway URL, or "" if not resolvable.

    Returning "" is a real answer, not a failure to handle one: the caller
    renders "evidence link unavailable (<raw ref>)", which is honest, whereas
    guessing a host would produce a link that 404s or, worse, points somewhere
    that is not the finding.
    """
    match = _SOURCE_URI.match(source_uri or "")
    if not match:
        return ""
    scheme, rest = match.group(1), match.group(2)
    subdomain = SCHEME_HOSTS.get(scheme)
    if not subdomain:
        return ""
    parts = urlsplit(gateway_base_url or "")
    if not parts.scheme or not parts.hostname:
        return ""
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{subdomain}.{parts.hostname}{port}{rest}"


def _snippet_block(proposal) -> tuple[str, str]:
    """(language, snippet) for the first concrete artefact we have."""
    if proposal.cli:
        return "bash", proposal.cli
    if proposal.terraform:
        return "hcl", proposal.terraform
    return "", ""


def _pr_line(pr) -> str:
    """One sentence about the draft PR, in every state including the ones where
    there isn't one. `None` means the finding names no repository at all — a
    public S3 bucket has no file to patch, and printing "no draft PR" on those
    would teach readers to skip the line on the findings where it matters."""
    if pr is None:
        return ""
    prefix = "✅" if pr.is_pr else ("⚠️" if pr.state == "failed" else "ℹ️")
    return f"{prefix} {pr.note}"


def _short_ref(value: str, *, keep: int = 8) -> str:
    """Truncated pseudonym/id for human-facing lines; empty stays empty."""
    if not value:
        return ""
    return value if len(value) <= keep else f"{value[:keep]}…"


def format_child_links(children: list[dict] | None, *, gateway_base_url: str,
                       limit: int = 8) -> list[str]:
    """Plain-text lines for AIM-700 parent→child links under a parent incident.

    Returns [] when there is nothing to show (no children, or a single child
    that is just the paged alert with no cross-tool/user fan-out). Multi-child
    incidents always list children so the SOC can open each finding.
    """
    children = children or []
    if len(children) <= 1:
        return []
    tools = {c.get("tool") or "" for c in children if c.get("tool")}
    users = {c.get("user_ref") or "" for c in children if c.get("user_ref")}
    summary_bits = [f"{len(children)} findings"]
    if tools:
        summary_bits.append(f"{len(tools)} tool(s)")
    if users:
        summary_bits.append(f"{len(users)} user(s)")
    lines = [f"Child findings ({', '.join(summary_bits)}):"]
    for child in children[:limit]:
        tool = child.get("tool") or "unknown-tool"
        user = _short_ref(child.get("user_ref") or "")
        resource = _short_ref(child.get("resource_ref") or "", keep=24) or "resource?"
        child_link = resolve_evidence(child.get("source_uri") or "", gateway_base_url)
        parts = [tool]
        if user:
            parts.append(f"user:{user}")
        parts.append(resource)
        if child_link:
            parts.append(child_link)
        elif child.get("source_uri"):
            parts.append(child["source_uri"])
        lines.append(f"  • {' · '.join(parts)}")
    if len(children) > limit:
        lines.append(f"  • …and {len(children) - limit} more")
    return lines


def incident_text(*, alert: dict, triage, proposal, incident, cfg,
                  resources: list[str] | None = None,
                  children: list[dict] | None = None, pr=None) -> str:
    """The plain-text rendering. Also the Slack fallback text and the email body."""
    resource = alert.get("resource") or {}
    severity = alert.get("severity", "unknown")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    link = resolve_evidence((alert.get("evidence") or {}).get("source_uri", ""),
                            cfg.gateway_base_url)
    resources = resources or []
    lines = [
        f"{emoji} {severity.upper()} — {alert.get('title', 'security alert')}",
        "",
        triage.what_happened,
        "",
        f"Blast radius: {triage.blast_radius}",
        f"Assessment: {VERDICT_TEXT.get(triage.is_real, triage.is_real)} "
        f"(confidence {triage.confidence}) — {triage.why}",
        "",
        f"Affected resource: {resource.get('display') or resource.get('ref') or 'unknown'}"
        + (f"  [{resource.get('ref')}]" if resource.get("ref") != resource.get("display") else ""),
    ]
    scope = ", ".join(x for x in (resource.get("provider"), resource.get("account_ref"),
                                  resource.get("region")) if x)
    if scope:
        lines.append(f"Scope: {scope}")
    if len(resources) > 1:
        shown = ", ".join(resources[:5])
        extra = f" (+{len(resources) - 5} more)" if len(resources) > 5 else ""
        lines.append(f"Also in this incident ({len(resources)} resources): {shown}{extra}")
    child_lines = format_child_links(children, gateway_base_url=cfg.gateway_base_url)
    if child_lines:
        lines += [""] + child_lines
    lines.append(f"Evidence: {link}" if link else
                 "Evidence: link unavailable — raw ref "
                 f"{(alert.get('evidence') or {}).get('source_uri', 'none')}")
    lines += ["", f"Remediation — {proposal.title}"]
    if proposal.explanation:
        lines.append(proposal.explanation)
    if proposal.caution:
        lines.append(f"CAUTION: {proposal.caution}")
    _, snippet = _snippet_block(proposal)
    if snippet:
        lines += ["", snippet]
    if proposal.console:
        lines.append(f"Console: {proposal.console}")
    if proposal.docs:
        lines.append(f"Docs: {proposal.docs}")
    pr_line = _pr_line(pr)
    if pr_line:
        lines += ["", pr_line]
    lines += ["",
              f"Incident {incident['incident_id']} · alert {alert.get('alert_id')} · "
              f"pillar {alert.get('pillar')} · type {alert.get('finding_type')}"]
    if triage.degraded:
        lines.insert(1, f"⚠️ Automated triage unavailable ({triage.degraded}) — "
                        f"this is the raw alert, not an assessment.")
    lines.append(_closing(pr))
    return "\n".join(lines)


def _closing(pr) -> str:
    """The standing footer, adjusted when a draft PR exists.

    The v1 footer — "no change has been made, sentinel holds no write
    credentials" — becomes false the moment a branch is pushed, and a footer
    that contradicts the line above it costs the channel more credibility than
    it ever bought. What stays true in both worlds is the part that matters: no
    infrastructure changed, and nothing merges without a human.
    """
    if pr is not None and pr.is_pr:
        return ("Nothing has been applied. A DRAFT pull request is open for review — "
                "sentinel cannot merge it, approve it, or touch your cloud accounts.")
    return ("No change has been made. Sentinel holds no cloud write credentials; "
            "a human applies the fix.")


def incident_slack(*, alert: dict, triage, proposal, incident, cfg,
                   resources: list[str] | None = None,
                   children: list[dict] | None = None, pr=None) -> dict:
    """Slack Block Kit payload. `text` is populated for notifications and for
    clients that do not render blocks — an empty `text` is how a Slack message
    arrives as a silent, contentless push."""
    resource = alert.get("resource") or {}
    severity = alert.get("severity", "unknown")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    link = resolve_evidence((alert.get("evidence") or {}).get("source_uri", ""),
                            cfg.gateway_base_url)
    resources = resources or []
    fallback = incident_text(alert=alert, triage=triage, proposal=proposal,
                             incident=incident, cfg=cfg, resources=resources,
                             children=children, pr=pr)

    blocks: list[dict] = [
        {"type": "header",
         "text": {"type": "plain_text",
                  "text": f"{emoji} {severity.upper()}: {alert.get('title', 'Security alert')}"[:150]}},
    ]
    if triage.degraded:
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn",
             "text": f"⚠️ *Automated triage unavailable* (`{triage.degraded}`) — raw alert below."}]})
    blocks.append({"type": "section",
                   "text": {"type": "mrkdwn", "text": triage.what_happened[:2900]}})

    fields = [
        {"type": "mrkdwn", "text": f"*Resource*\n{resource.get('display') or resource.get('ref') or 'unknown'}"},
        {"type": "mrkdwn", "text": f"*Assessment*\n{VERDICT_TEXT.get(triage.is_real, triage.is_real)} "
                                   f"(confidence {triage.confidence})"},
        {"type": "mrkdwn", "text": f"*Blast radius*\n{triage.blast_radius[:280]}"},
        {"type": "mrkdwn", "text": f"*Pillar*\n{alert.get('pillar')} / `{alert.get('finding_type')}`"},
    ]
    if len(resources) > 1:
        fields.append({"type": "mrkdwn",
                       "text": f"*Affected resources*\n{len(resources)} in this incident"})
    if children and len(children) > 1:
        tools = {c.get("tool") for c in children if c.get("tool")}
        users = {c.get("user_ref") for c in children if c.get("user_ref")}
        fanout = f"{len(children)} children"
        if tools:
            fanout += f" · {len(tools)} tools"
        if users:
            fanout += f" · {len(users)} users"
        fields.append({"type": "mrkdwn", "text": f"*Correlated*\n{fanout}"})
    blocks.append({"type": "section", "fields": fields[:10]})

    if link:
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Open evidence"},
             "url": link, "style": "primary"}]})
    else:
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn",
             "text": "Evidence link unavailable — raw ref "
                     f"`{(alert.get('evidence') or {}).get('source_uri', 'none')}`"}]})

    child_lines = format_child_links(children, gateway_base_url=cfg.gateway_base_url)
    if child_lines:
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": "\n".join(child_lines)[:2900]}})

    remediation = [f"*Remediation — {proposal.title}*"]
    if proposal.explanation:
        remediation.append(proposal.explanation)
    if proposal.caution:
        remediation.append(f":warning: {proposal.caution}")
    blocks.append({"type": "section",
                   "text": {"type": "mrkdwn", "text": "\n".join(remediation)[:2900]}})
    _, snippet = _snippet_block(proposal)
    if snippet:
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn", "text": f"```\n{snippet[:2800]}\n```"}})
    pr_line = _pr_line(pr)
    if pr_line:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": pr_line[:2900]}})
        if pr.is_pr and pr.url:
            blocks.append({"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "Review draft PR"},
                 "url": pr.url}]})
    tail = [f"Incident `{incident['incident_id']}` · alert `{alert.get('alert_id')}`",
            _closing(pr)]
    if proposal.docs:
        tail.insert(1, f"<{proposal.docs}|Vendor docs>")
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": " · ".join(tail)}]})

    return {"text": fallback[:2900], "blocks": blocks}


def digest_text(items: list[dict], *, day: str) -> str:
    """Medium/low rollup. One message a day, grouped so it is skimmable."""
    if not items:
        return f"Sentinel daily digest {day}: no medium or low findings in the last 24h."
    by_type: dict[tuple[str, str, str], list[dict]] = {}
    for item in items:
        by_type.setdefault((item["severity"], item["pillar"], item["finding_type"]), []).append(item)
    counts = {}
    for item in items:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    header = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items()))
    lines = [f"📋 Sentinel daily digest — {day}",
             f"{len(items)} finding(s) below the paging threshold: {header}.", ""]
    for (severity, pillar, finding_type), group in sorted(by_type.items()):
        emoji = SEVERITY_EMOJI.get(severity, "⚪")
        lines.append(f"{emoji} {severity} · {pillar} · `{finding_type}` — {len(group)}")
        for entry in group[:5]:
            lines.append(f"    • {entry['title']} — {entry['resource']}")
        if len(group) > 5:
            lines.append(f"    • …and {len(group) - 5} more")
    lines += ["", "Nothing here paged. Raise or lower the bar with `page_from` in sentinel.yml."]
    return "\n".join(lines)


def self_alert_text(*, kind: str, detail: str) -> str:
    """The agent reporting on itself. The stack going quiet must be loud."""
    return ("🛑 Sentinel degraded — the security stack may be blind\n\n"
            f"{kind}: {detail}\n\n"
            "Alerts published while this is true are NOT being triaged or delivered. "
            "They stay on the bus and will be processed once it clears — but until then, "
            "an absence of pings is not evidence of an absence of findings.")
