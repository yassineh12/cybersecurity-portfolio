"""Correlation: turn a pile of per-rule alerts into one story per client.

A single alert is a data point; the sequence is what tells an analyst whether
to act. A scanner user agent alone is background noise on the Internet. The
same client running nikto, then sending SQL injection, then getting a 200 back
is an intrusion in progress. Grouping by client and ordering by time exposes
that kill chain, and the score ranks incidents so the worst is read first.

Scoring formula (weights come from ``Config.scoring``; defaults in brackets)::

    base        = severity_points[max alert severity]
                  [low 15, medium 35, high 60, critical 85]
    breadth     = min(extra_rule * (distinct rules - 1), extra_rule_cap)   [5, cap 15]
    campaign    = extra_stage * (distinct kill-chain stages - 1)            [10]
    sequence    = recon_then_exploit  if a recon alert began no later than
                  the first exploit alert                                   [10]
    success     = exploit_success     if an exploit attempt was answered 2xx [15]
                + brute_success       if BEH-BRUTE-SUCCESS fired             [15]
    score       = clamp(base + breadth + campaign + sequence + success, 0, 100)

Severity comes from the score: >= severity_cutoffs.critical [80] is critical,
>= high [55] is high, >= medium [30] is medium, otherwise low. With the default
weights a lone alert keeps its own severity, and only combinations escalate:
a nikto scan followed by SQL injection (60 + 5 + 10 + 10 = 85) is critical.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .config import DEFAULT_SCORING
from .models import SEVERITY_RANK, Alert, Incident

STAGE_ORDER = ("recon", "exploit", "credential-access", "impact")

RULE_STAGE = {
    "SIG-UA-SCANNER": "recon",
    "SIG-SENSITIVE-PATH": "recon",
    "BEH-404-BURST": "recon",
    "SIG-SQLI": "exploit",
    "SIG-XSS": "exploit",
    "SIG-TRAVERSAL": "exploit",
    "SIG-CMDI": "exploit",
    "SIG-LOG4SHELL": "exploit",
    "BEH-BRUTE-FORCE": "credential-access",
    "BEH-BRUTE-SUCCESS": "credential-access",
    "BEH-RATE-SPIKE": "impact",
}

# Tie-break when alerts start at the same second: tell the story in kill-chain
# order (the scanner user agent before the payload it carried).
_RULE_ORDER = {rule: n for n, rule in enumerate(RULE_STAGE)}

# Fallback for rule ids we do not know yet: classify by ATT&CK technique.
TECHNIQUE_STAGE = {
    "T1595": "recon", "T1592": "recon", "T1590": "recon",
    "T1190": "exploit", "T1203": "exploit",
    "T1110": "credential-access",
    "T1499": "impact", "T1498": "impact",
}

# Base severities from the brief. An exploit alert above its base severity
# means the signature detector saw a 2xx answer and escalated it.
EXPLOIT_BASE_SEVERITY = {
    "SIG-SQLI": "high", "SIG-XSS": "medium", "SIG-TRAVERSAL": "high",
    "SIG-CMDI": "high", "SIG-LOG4SHELL": "critical",
}

PHRASES = {
    "SIG-SENSITIVE-PATH": "probed for sensitive files",
    "SIG-SQLI": "attempted SQL injection",
    "SIG-XSS": "attempted cross-site scripting",
    "SIG-TRAVERSAL": "attempted path traversal",
    "SIG-CMDI": "attempted command injection",
    "SIG-LOG4SHELL": "sent a Log4Shell (JNDI lookup) payload",
}

SCANNER_NAMES = (
    "nikto", "sqlmap", "nmap", "nuclei", "gobuster", "dirbuster", "dirb",
    "wpscan", "masscan", "zgrab", "acunetix", "nessus", "openvas", "ffuf",
    "wfuzz", "feroxbuster", "whatweb", "arachni", "w3af", "skipfish", "burp",
    "zap", "netsparker", "qualys", "hydra", "commix", "jaeles",
)

_NUMBER_WORDS = ("no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine")

# Status code in a combined/common log line ('"GET / HTTP/1.1" 200 512') or JSON line.
_STATUS_RE = re.compile(r'"\s+(\d{3})\s+(?:\d+|-)|"status"\s*:\s*"?(\d{3})')
# User agent: last quoted field of a combined line, or the JSON key.
_UA_RE = re.compile(r'"http_user_agent"\s*:\s*"((?:[^"\\]|\\.)*)"|"([^"]*)"\s*$')
# "3 request(s) were answered with HTTP 2xx": the true count, evidence is capped.
_DETAIL_COUNT_RE = re.compile(r"(\d+)[^.\d]*\b2xx\b", re.IGNORECASE)
# A detail that reports a 2xx answer ("got a 2xx", "answered 200"), not any 2nn number.
_DETAIL_2XX_RE = re.compile(r"\b2xx\b|(?:status|answered|returned|response|code)\D{0,3}2\d\d\b",
                            re.IGNORECASE)


# ---------------------------------------------------------------- public ---

def correlate(alerts: list[Alert], scoring: dict[str, Any] | None = None) -> list[Incident]:
    """Group alerts by client into incidents, sorted by score (highest first).

    Ties are broken by severity, then earliest first_seen, then client IP, so
    the output is deterministic for the same input.
    """
    weights = _merge_weights(scoring)
    by_client: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        by_client[alert.client_ip].append(alert)
    incidents = [_build_incident(ip, group, weights) for ip, group in by_client.items()]
    incidents.sort(key=lambda i: (-i.score, -SEVERITY_RANK.get(i.severity, 0),
                                  i.first_seen, i.client_ip))
    return incidents


def stage_of(alert: Alert) -> str | None:
    """Kill-chain stage for an alert, or None when we cannot classify it."""
    if alert.rule_id in RULE_STAGE:
        return RULE_STAGE[alert.rule_id]
    technique = (alert.technique or "").split(".")[0]
    return TECHNIQUE_STAGE.get(technique)


def score_alerts(alerts: list[Alert], scoring: dict[str, Any] | None = None) -> int:
    """The 0-100 score for one client's alerts (formula in the module docstring)."""
    w = _merge_weights(scoring)
    if not alerts:
        return 0
    points = w["severity_points"]
    base = max(points.get(a.severity, 0) for a in alerts)
    rules = {a.rule_id for a in alerts}
    breadth = min(w["extra_rule"] * (len(rules) - 1), w["extra_rule_cap"])
    stages = {s for s in map(stage_of, alerts) if s}
    campaign = w["extra_stage"] * max(len(stages) - 1, 0)
    sequence = w["recon_then_exploit"] if _recon_before_exploit(alerts) else 0
    success = 0
    if any(exploit_succeeded(a) for a in alerts):
        success += w["exploit_success"]
    if "BEH-BRUTE-SUCCESS" in rules:
        success += w["brute_success"]
    return max(0, min(100, base + breadth + campaign + sequence + success))


def severity_for_score(score: int, scoring: dict[str, Any] | None = None) -> str:
    cut = _merge_weights(scoring)["severity_cutoffs"]
    if score >= cut["critical"]:
        return "critical"
    if score >= cut["high"]:
        return "high"
    if score >= cut["medium"]:
        return "medium"
    return "low"


def exploit_succeeded(alert: Alert) -> bool:
    """Did an exploit-class attempt get a 2xx answer?

    A 2xx to an injection payload does not prove compromise, but it means the
    application processed the request instead of rejecting it, so a human has
    to look. Signals, any of which counts: the detector raised the alert above
    its base severity, the detail mentions a 2xx, or the evidence shows one.
    """
    if stage_of(alert) != "exploit":
        return False
    base = EXPLOIT_BASE_SEVERITY.get(alert.rule_id)
    if base and SEVERITY_RANK.get(alert.severity, 0) > SEVERITY_RANK[base]:
        return True
    if _DETAIL_2XX_RE.search(alert.detail or ""):
        return True
    return bool(success_statuses(alert))


def success_statuses(alert: Alert) -> list[int]:
    """2xx status codes visible in an alert's evidence lines."""
    found = []
    for line in alert.evidence:
        m = _STATUS_RE.search(line or "")
        if m:
            code = int(m.group(1) or m.group(2))
            if 200 <= code < 300:
                found.append(code)
    return found


# --------------------------------------------------------------- helpers ---

def _merge_weights(scoring: dict[str, Any] | None) -> dict[str, Any]:
    if not scoring:
        return DEFAULT_SCORING
    merged = {**DEFAULT_SCORING, **scoring}
    for key in ("severity_points", "severity_cutoffs"):
        merged[key] = {**DEFAULT_SCORING[key], **scoring.get(key, {})}
    return merged


def _chrono(a: Alert) -> tuple:
    return (a.first_seen, _RULE_ORDER.get(a.rule_id, len(_RULE_ORDER)), a.rule_id)


def _recon_before_exploit(alerts: list[Alert]) -> bool:
    recon = [a.first_seen for a in alerts if stage_of(a) == "recon"]
    exploit = [a.first_seen for a in alerts if stage_of(a) == "exploit"]
    return bool(recon and exploit and min(recon) <= min(exploit))


def _ordered_stages(alerts: list[Alert]) -> list[str]:
    """Stages in the order the client first reached them (ties: kill-chain order)."""
    first: dict[str, Any] = {}
    for a in alerts:
        s = stage_of(a)
        if s and (s not in first or a.first_seen < first[s]):
            first[s] = a.first_seen
    return sorted(first, key=lambda s: (first[s], STAGE_ORDER.index(s)))


def _build_incident(ip: str, alerts: list[Alert], weights: dict[str, Any]) -> Incident:
    ordered = sorted(alerts, key=_chrono)
    score = score_alerts(ordered, weights)
    return Incident(
        client_ip=ip,
        alerts=ordered,
        score=score,
        severity=severity_for_score(score, weights),
        stages=_ordered_stages(ordered),
        first_seen=min(a.first_seen for a in ordered),
        last_seen=max(a.last_seen for a in ordered),
        summary=summarize(ip, ordered),
    )


# --------------------------------------------------------------- summary ---

def summarize(ip: str, alerts: list[Alert]) -> str:
    """One plain-English sentence an analyst can paste into a ticket.

    e.g. "203.0.113.5 ran a nikto scan, then attempted SQL injection; one
    attempt returned 200."
    """
    ordered = sorted(alerts, key=_chrono)
    rules = {a.rule_id for a in ordered}
    phrases: list[str] = []
    for alert in ordered:
        if alert.rule_id == "BEH-BRUTE-SUCCESS" and "BEH-BRUTE-FORCE" in rules:
            continue                         # told as a consequence clause below
        phrase = _phrase(alert)
        if phrase not in phrases:
            phrases.append(phrase)
    if not phrases:
        return f"{ip} triggered no alerts."
    sentence = f"{ip} {_join_then(phrases)}"

    tails = []
    success = _success_clause(ordered)
    if success:
        tails.append(success)
    if "BEH-BRUTE-SUCCESS" in rules and "BEH-BRUTE-FORCE" in rules:
        tails.append("the brute force ended in a successful login")
    if tails:
        sentence += "; " + "; ".join(tails)
    return sentence + "."


def _phrase(alert: Alert) -> str:
    rule = alert.rule_id
    if rule == "SIG-UA-SCANNER":
        tool = _scanner_name(alert)
        return f"ran {_article(tool)} {tool} scan" if tool else "ran an automated scanner"
    if rule == "BEH-404-BURST":
        return f"enumerated paths ({_count(alert.event_count, 'request')} answered 404)"
    if rule == "BEH-BRUTE-FORCE":
        return f"brute-forced a login ({_count(alert.event_count, 'failed attempt')})"
    if rule == "BEH-BRUTE-SUCCESS":
        return "logged in after repeated failed attempts"
    if rule == "BEH-RATE-SPIKE":
        return f"flooded the site with {_count(alert.event_count, 'request')}"
    if rule in PHRASES:
        return PHRASES[rule]
    title = (alert.title or rule).strip()
    return f"triggered {title[0].lower() + title[1:]}" if title else f"triggered {rule}"


def _scanner_name(alert: Alert) -> str | None:
    """Name the tool from the evidence; only known names, never raw log text."""
    agents = []
    for line in alert.evidence:
        m = _UA_RE.search(line or "")
        agents.append((m.group(1) or m.group(2)) if m else (line or ""))
    haystack = " ".join([alert.detail or "", alert.title or "", *agents]).lower()
    best = None
    for name in SCANNER_NAMES:
        m = re.search(rf"\b{re.escape(name)}\b", haystack)
        if m and (best is None or m.start() < best[0]):
            best = (m.start(), name)
    return best[1] if best else None


def _success_clause(alerts: list[Alert]) -> str:
    winners = [a for a in alerts if exploit_succeeded(a)]
    if not winners:
        return ""
    codes = [c for a in winners for c in success_statuses(a)]
    reported = 0
    for a in winners:
        m = _DETAIL_COUNT_RE.search(a.detail or "")
        reported += max(int(m.group(1)) if m else 0, len(success_statuses(a)))
    n = max(reported, len(codes))
    if not n:
        return "at least one attempt got a 2xx answer"
    status = str(codes[0]) if codes and len(set(codes)) == 1 else "2xx"
    verb_subject = "one attempt" if n == 1 else f"{_word(n)} attempts"
    return f"{verb_subject} returned {status}"


def _join_then(phrases: list[str]) -> str:
    if len(phrases) == 1:
        return phrases[0]
    return ", ".join(phrases[:-1]) + ", then " + phrases[-1]


def _word(n: int) -> str:
    return _NUMBER_WORDS[n] if 0 <= n < len(_NUMBER_WORDS) else str(n)


def _count(n: int, noun: str) -> str:
    return f"{_word(n)} {noun}{'' if n == 1 else 's'}"


def _article(word: str) -> str:
    return "an" if word[:1].lower() in "aeiou" or word == "nmap" else "a"

