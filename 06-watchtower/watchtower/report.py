"""Report writers: Markdown, JSON and a self-contained HTML page.

Every string that reaches a report came from an attacker-controlled log line
(paths, user agents, referrers). A report that renders those verbatim is itself
a stored-XSS or markdown-injection vector against the analyst, so each format
neutralises its own metacharacters: html.escape for HTML, pipe/backtick
neutralisation for Markdown tables and adaptive code fences for evidence.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

from .models import SEVERITIES, Alert, Incident, ScanResult

_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_TITLE = "WATCHTOWER Threat Detection Report"


# ---------------------------------------------------------------- shared helpers

def technique_url(technique: str) -> str | None:
    """ATT&CK URL for a technique id; sub-techniques use a slash (T1595/002)."""
    if not isinstance(technique, str) or not _TECH_RE.match(technique):
        return None
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def _fmt_dt(dt) -> str:
    try:
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except AttributeError:
        return str(dt) if dt else "n/a"


def _fmt_stat_time(value) -> str:
    return str(value) if value else "n/a"


def _sev(value: str) -> str:
    return value if value in SEVERITIES else "low"


def recommended_actions(incident: Incident) -> list[str]:
    """Analyst next steps derived from the kill-chain stages and rules seen."""
    rules = {a.rule_id for a in incident.alerts}
    stages = set(incident.stages)
    actions = [f"Block or rate-limit {incident.client_ip} at the WAF or firewall."]
    if "BEH-BRUTE-SUCCESS" in rules:
        actions.append("Brute force succeeded: reset the affected account's credentials, "
                       "revoke active sessions and review what the session did after login.")
    elif "credential-access" in stages:
        actions.append("Enforce account lockout or MFA on the targeted login endpoint "
                       "and check for any successful logins from this client.")
    if "exploit" in stages:
        if any("2xx" in (a.detail or "") for a in incident.alerts):
            actions.append("An exploit attempt got a 2xx answer: investigate the targeted "
                           "endpoint for compromise and patch or disable it.")
        else:
            actions.append("Confirm the targeted endpoints reject the exploit payloads "
                           "and are patched.")
    if "recon" in stages:
        actions.append("Make sure sensitive files and paths probed during recon "
                       "are not exposed.")
    if "impact" in stages:
        actions.append("Check service availability and consider rate limiting to absorb "
                       "the request spike.")
    return actions


# ---------------------------------------------------------------- markdown

_MD_CONTROL = re.compile(r"([\\`*_\[\]()!#<>|])")
_CTRL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def _md_text(value) -> str:
    """Neutralise a log-derived value for markdown outside a code fence.

    Log fields are attacker-controlled: unescaped, `[x](https://evil)` becomes
    a live phishing link and `![t](https://evil/px.png)` an image beacon in the
    analyst's viewer. Control characters (including newlines) become a space so
    a value can never open a new heading, list item or table row.
    """
    s = _CTRL_CHARS.sub(" ", str(value))
    s = re.sub(r" {2,}", " ", s).strip()
    return _MD_CONTROL.sub(r"\\\1", s)


def _md_cell(value) -> str:
    """Same neutralisation for table cells (pipes are escaped as well)."""
    return _md_text(value)


def _fence(lines: list[str]) -> str:
    """A backtick fence longer than any backtick run in the content."""
    longest = max((len(m) for ln in lines for m in re.findall(r"`+", ln)), default=0)
    return "`" * max(3, longest + 1)


def _md_technique(technique: str) -> str:
    url = technique_url(technique)
    if url:
        return f"[{technique}]({url})"
    return _md_cell(technique)


def to_markdown(result: ScanResult) -> str:
    s = result.stats or {}
    out = [f"# {_TITLE}", "", f"Generated: {_fmt_dt(result.generated_at)}", "",
           "## Scan summary", "",
           f"- Files: {_md_text(', '.join(map(str, s.get('files') or [])) or 'n/a')}",
           f"- Time range: {_md_text(_fmt_stat_time(s.get('time_start')))} to "
           f"{_md_text(_fmt_stat_time(s.get('time_end')))}",
           f"- Lines read: {s.get('lines_read', 0)}",
           f"- Lines parsed: {s.get('lines_parsed', 0)}",
           f"- Lines malformed: {s.get('lines_malformed', 0)}",
           f"- Unique clients: {s.get('unique_clients', 0)}",
           f"- Alerts: {len(result.alerts)}", "",
           "## Incidents by severity", "",
           "| Severity | Incidents |", "|---|---|"]
    by_sev = s.get("incidents_by_severity") or {}
    for sev in reversed(SEVERITIES):
        out.append(f"| {sev} | {by_sev.get(sev, 0)} |")
    out.append("")

    if not result.incidents:
        out += ["No incidents were detected in this scan.", ""]
        return "\n".join(out)

    out += ["## Incidents", ""]
    for n, inc in enumerate(result.incidents, 1):
        out += [f"### {n}. {_md_text(inc.client_ip)} ({_sev(inc.severity)}, score {inc.score})", "",
                f"- Client: {_md_text(inc.client_ip)}",
                f"- Score: {inc.score}/100",
                f"- Severity: {_md_text(inc.severity)}",
                f"- Stages: {_md_text(', '.join(inc.stages) or 'none')}",
                f"- Window: {_fmt_dt(inc.first_seen)} to {_fmt_dt(inc.last_seen)}",
                f"- Summary: {_md_text(inc.summary)}", "",
                "| Rule | Severity | ATT&CK | Count | First seen | Last seen |",
                "|---|---|---|---|---|---|"]
        for a in inc.alerts:
            out.append(f"| {_md_cell(a.rule_id)} | {_md_cell(a.severity)} | "
                       f"{_md_technique(a.technique)} | {a.event_count} | "
                       f"{_md_cell(_fmt_dt(a.first_seen))} | {_md_cell(_fmt_dt(a.last_seen))} |")
        out.append("")
        for a in inc.alerts:
            out += [f"**{_md_text(a.rule_id)}**: {_md_text(a.title)}"
                    + (f" ({_md_text(a.detail)})" if a.detail else ""), ""]
            if a.evidence:
                fence = _fence(a.evidence)
                out += [fence + "text", *a.evidence, fence, ""]
        out += ["Recommended actions:", ""]
        out += [f"- {_md_text(act)}" for act in recommended_actions(inc)]
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------- json

def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


# ---------------------------------------------------------------- html

_CSS = """
:root{--bg:#f6f7f9;--fg:#1b1f24;--muted:#5b6570;--card:#fff;--border:#d5dae0;--code:#eef1f4;
--low:#2f6f4f;--medium:#8a5a00;--high:#b5381c;--critical:#8e1b3f;--badge-fg:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#0f1317;--fg:#e6e9ed;--muted:#9aa5b1;--card:#171c22;
--border:#2b333c;--code:#0b0e11;--low:#3f9d6f;--medium:#c28a1c;--high:#e0623f;--critical:#d9467a;
--badge-fg:#0b0e11}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:960px;margin:0 auto;padding:16px}
h1{font-size:1.5rem}h2{font-size:1.2rem;margin-top:1.5rem}
a{color:inherit}
.card,details{background:var(--card);border:1px solid var(--border);border-radius:8px;
padding:12px 16px;margin:12px 0}
summary{cursor:pointer;font-weight:600;overflow-wrap:anywhere}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.8rem;font-weight:700;
color:var(--badge-fg);text-transform:uppercase}
.sev-low{background:var(--low)}.sev-medium{background:var(--medium)}
.sev-high{background:var(--high)}.sev-critical{background:var(--critical)}
.tablewrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{border:1px solid var(--border);padding:4px 8px;text-align:left;overflow-wrap:anywhere}
pre{background:var(--code);padding:8px;border-radius:6px;overflow-x:auto;font-size:.8rem;
white-space:pre-wrap;overflow-wrap:anywhere}
.muted{color:var(--muted)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:0}
dd{margin:0;overflow-wrap:anywhere}
"""


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _badge(sev: str) -> str:
    s = _sev(sev)
    return f'<span class="badge sev-{s}">{_e(s)}</span>'


def _html_technique(technique: str) -> str:
    url = technique_url(technique)
    if url:
        return f'<a href="{_e(url)}" rel="noopener noreferrer">{_e(technique)}</a>'
    return _e(technique)


def _html_alerts(alerts: list[Alert]) -> str:
    rows = "".join(
        f"<tr><td>{_e(a.rule_id)}</td><td>{_badge(a.severity)}</td>"
        f"<td>{_html_technique(a.technique)}</td><td>{a.event_count}</td>"
        f"<td>{_e(_fmt_dt(a.first_seen))}</td><td>{_e(_fmt_dt(a.last_seen))}</td></tr>"
        for a in alerts)
    return ('<div class="tablewrap"><table><thead><tr><th>Rule</th><th>Severity</th>'
            '<th>ATT&amp;CK</th><th>Count</th><th>First seen</th><th>Last seen</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div>")


def _html_incident(n: int, inc: Incident) -> str:
    parts = [
        f"<details{' open' if n == 1 else ''}><summary>{n}. {_e(inc.client_ip)} "
        f"{_badge(inc.severity)} <span class=\"muted\">score {inc.score}</span></summary>",
        "<dl>"
        f"<dt>Client</dt><dd>{_e(inc.client_ip)}</dd>"
        f"<dt>Score</dt><dd>{inc.score}/100</dd>"
        f"<dt>Stages</dt><dd>{_e(', '.join(inc.stages) or 'none')}</dd>"
        f"<dt>Window</dt><dd>{_e(_fmt_dt(inc.first_seen))} to {_e(_fmt_dt(inc.last_seen))}</dd>"
        f"<dt>Summary</dt><dd>{_e(inc.summary)}</dd></dl>",
        _html_alerts(inc.alerts),
    ]
    for a in inc.alerts:
        parts.append(f"<p><strong>{_e(a.rule_id)}</strong>: {_e(a.title)}"
                     + (f' <span class="muted">({_e(a.detail)})</span>' if a.detail else "")
                     + "</p>")
        if a.evidence:
            parts.append("<pre>" + _e("\n".join(a.evidence)) + "</pre>")
    parts.append("<h3>Recommended actions</h3><ul>"
                 + "".join(f"<li>{_e(x)}</li>" for x in recommended_actions(inc))
                 + "</ul></details>")
    return "".join(parts)


def to_html(result: ScanResult) -> str:
    s = result.stats or {}
    by_sev = s.get("incidents_by_severity") or {}
    summary = [
        ("Files", ", ".join(map(str, s.get("files") or [])) or "n/a"),
        ("Time range", f"{_fmt_stat_time(s.get('time_start'))} to {_fmt_stat_time(s.get('time_end'))}"),
        ("Lines read", s.get("lines_read", 0)),
        ("Lines parsed", s.get("lines_parsed", 0)),
        ("Lines malformed", s.get("lines_malformed", 0)),
        ("Unique clients", s.get("unique_clients", 0)),
        ("Alerts", len(result.alerts)),
    ]
    dl = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in summary)
    sev_rows = "".join(f"<tr><td>{_badge(sv)}</td><td>{_e(by_sev.get(sv, 0))}</td></tr>"
                       for sv in reversed(SEVERITIES))
    if result.incidents:
        body = "".join(_html_incident(i, inc) for i, inc in enumerate(result.incidents, 1))
    else:
        body = '<p class="card">No incidents were detected in this scan.</p>'
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_e(_TITLE)}</title><style>{_CSS}</style></head><body><main>"
        f"<h1>{_e(_TITLE)}</h1>"
        f'<p class="muted">Generated: {_e(_fmt_dt(result.generated_at))}</p>'
        f'<h2>Scan summary</h2><div class="card"><dl>{dl}</dl></div>'
        '<h2>Incidents by severity</h2><div class="card tablewrap"><table>'
        f"<thead><tr><th>Severity</th><th>Incidents</th></tr></thead><tbody>{sev_rows}</tbody>"
        "</table></div>"
        f"<h2>Incidents</h2>{body}</main></body></html>\n"
    )


# ---------------------------------------------------------------- files

def write_reports(result: ScanResult, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {"md": out / "report.md", "json": out / "report.json", "html": out / "report.html"}
    paths["md"].write_text(to_markdown(result), encoding="utf-8")
    paths["json"].write_text(to_json(result), encoding="utf-8")
    paths["html"].write_text(to_html(result), encoding="utf-8")
    return paths
