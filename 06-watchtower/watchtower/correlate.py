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
    success     = exploit_success     if an exploit attempt was answered 2xx
                                      and its alert was NOT already escalated
                                      a step by the detector for that 2xx  [15]
                + brute_success       if BEH-BRUTE-SUCCESS fired             [15]
    score       = clamp(base + breadth + campaign + sequence + success, 0, 100)

Severity comes from the score: >= severity_cutoffs.critical [80] is critical,
>= high [55] is high, >= medium [30] is medium, otherwise low. With the default
weights a lone alert keeps its own severity, and only combinations escalate:
a nikto scan followed by SQL injection (60 + 5 + 10 + 10 = 85) is critical.
A 2xx answer is counted once: a lone SQL injection answered 200 arrives already
escalated to critical by the detector and scores 85, not 85 + 15; a Log4Shell
answered 200 (critical before and after) gets the bonus instead and scores 100.
"""

from __future__ import annotations

import ipaddress
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
    "BEH-LOW-AND-SLOW": "recon",
    "BEH-ID-ENUM": "recon",
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
_DETAIL_COUNT_RE = re.compile(r"(\d+) request\(s\) were answered with HTTP 2xx")
# Long-horizon detectors' details (parsed defensively; absent numbers are omitted).
_HOURS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(?:h\b|hours?\b)", re.IGNORECASE)
_MISSES_RE = re.compile(r"(\d+)\s+(?:miss(?:es)?|not[- ]found|404s?)\b", re.IGNORECASE)
_PATHS_RE = re.compile(r"(\d+)\s+(?:distinct\s+|different\s+|unique\s+)?paths?\b", re.IGNORECASE)
_IDS_RE = re.compile(r"(\d+)\s+(?:distinct\s+|sequential\s+|unique\s+)?ids?\b", re.IGNORECASE)
_RANGE_RE = re.compile(r"(?:range|from|ids?)\s*:?\s*\(?\s*(\d+)\s*(?:-|–|\.\.|to)\s*(\d+)", re.IGNORECASE)
_TEMPLATE_RE = re.compile(r"(/[^\s\"']*(?:\{[^}\s]*\}|<[^>\s]*>|:id\b)[^\s\"']*)")

# Network-channel alerts: "distributed across 6 addresses in 2001:db8::/64: ..."
_DISTRIBUTED_RE = re.compile(r"distributed across (\d+) addresses", re.IGNORECASE)
# Exact phrases from signatures.py: the detector decides whether a 2xx was informative.
_INFORMATIVE_2XX = "were answered with HTTP 2xx"
_DECLINED_2XX = "not treated as success"


# ---------------------------------------------------------------- public ---

def correlate(alerts: list[Alert], scoring: dict[str, Any] | None = None) -> list[Incident]:
    """Group alerts by client into incidents, sorted by score (highest first).

    A "client" is usually one address, but the behaviour detectors' network
    channel reports a whole network ("2001:db8:abcd:12::/64") when an attacker
    spreads activity across many addresses in it. Network incidents are kept
    separate from per-address incidents inside them: merging would inflate the
    single address with its neighbours' activity (or hide it). Instead the
    per-address summary points at the network incident.

    Ties are broken by severity, then earliest first_seen, then client IP, so
    the output is deterministic for the same input.
    """
    weights = _merge_weights(scoring)
    by_client: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        by_client[alert.client_ip].append(alert)
    incidents = [_build_incident(ip, group, weights) for ip, group in by_client.items()]
    _link_to_networks(incidents)
    incidents.sort(key=lambda i: (-i.score, -SEVERITY_RANK.get(i.severity, 0),
                                  i.first_seen, i.client_ip))
    return incidents


def as_network(client: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """The network a network-level incident covers; None for a single address."""
    if "/" not in client:
        return None
    try:
        return ipaddress.ip_network(client.strip(), strict=False)
    except ValueError:
        return None


def is_network(client: str) -> bool:
    return as_network(client) is not None


def _link_to_networks(incidents: list[Incident]) -> None:
    """Point per-address incidents at network incidents whose range holds them."""
    networks = [(as_network(i.client_ip), i.client_ip) for i in incidents]
    networks = [(net, label) for net, label in networks if net is not None]
    if not networks:
        return
    for inc in incidents:
        if is_network(inc.client_ip):
            continue
        try:
            addr = ipaddress.ip_address(inc.client_ip.strip())
        except ValueError:
            continue
        related = sorted(label for net, label in networks if addr in net)
        if related:
            inc.summary = (inc.summary[:-1] + "; related to network incident "
                           + ", ".join(related) + ".")


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
    # The signature detector already raises an alert one severity step for a
    # 2xx answer; that escalation *is* the success penalty, so the bonus only
    # applies to a success it could not express (Log4Shell is already critical).
    if any(exploit_succeeded(a) and not _escalated(a) for a in alerts):
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
    """Did an exploit-class attempt get an *informative* 2xx answer?

    A 2xx to an injection payload does not prove compromise, but it means the
    application processed the request instead of rejecting it, so a human has
    to look. Many endpoints (search pages, SPAs, soft-404s) answer 2xx to
    everything, though, and there a 2xx says nothing. The signature detector
    compares against the endpoint's baseline and is the sole authority: it
    raises the alert above its rule's base severity and writes "were answered
    with HTTP 2xx" when the 2xx was informative, and writes "not treated as
    success" when it was not. Raw status codes in evidence are deliberately
    not consulted: they would overrule that judgement.
    """
    if stage_of(alert) != "exploit":
        return False
    return _escalated(alert) or _INFORMATIVE_2XX in (alert.detail or "")


def _escalated(alert: Alert) -> bool:
    """True when the detector already raised this alert above its rule's base severity."""
    base = EXPLOIT_BASE_SEVERITY.get(alert.rule_id)
    return bool(base) and SEVERITY_RANK.get(alert.severity, 0) > SEVERITY_RANK[base]


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
        if alert.rule_id == "BEH-LOW-AND-SLOW" and "BEH-404-BURST" in rules:
            continue                         # same misses; the burst already tells it
        phrase = _phrase(alert)
        if phrase not in phrases:
            phrases.append(phrase)
    subject = _subject(ip, ordered)
    if not phrases:
        return f"{subject} triggered no alerts."
    sentence = f"{subject} {_join_then(phrases)}"

    tails = []
    success = _success_clause(ordered)
    if success:
        tails.append(success)
    if "BEH-BRUTE-SUCCESS" in rules and "BEH-BRUTE-FORCE" in rules:
        tails.append("the brute force ended in a successful login")
    if tails:
        sentence += "; " + "; ".join(tails)
    return sentence + "."


def _subject(client: str, alerts: list[Alert]) -> str:
    """ "203.0.113.5", or "Clients in 2001:db8::/64 (6 addresses)" for a network."""
    if not is_network(client):
        return client
    counts = [int(m.group(1)) for a in alerts
              if (m := _DISTRIBUTED_RE.search(a.detail or ""))]
    return f"Clients in {client} ({max(counts)} addresses)" if counts else f"Clients in {client}"


def _phrase(alert: Alert) -> str:
    rule = alert.rule_id
    if rule == "SIG-UA-SCANNER":
        tool = _scanner_name(alert)
        return f"ran {_article(tool)} {tool} scan" if tool else "ran an automated scanner"
    if rule == "BEH-404-BURST":
        return f"enumerated paths ({_count(alert.event_count, 'request')} answered 404/403/410)"
    if rule == "BEH-LOW-AND-SLOW":
        return _low_and_slow_phrase(alert)
    if rule == "BEH-ID-ENUM":
        return _id_enum_phrase(alert)
    if rule == "BEH-BRUTE-FORCE":
        noun = "failed attempt" if _explicit_failures(alert) else "login attempt"
        return f"brute-forced a login ({_count(alert.event_count, noun)})"
    if rule == "BEH-BRUTE-SUCCESS":
        return "logged in after repeated failed attempts"
    if rule == "BEH-RATE-SPIKE":
        return f"flooded the site with {_count(alert.event_count, 'request')}"
    if rule in PHRASES:
        return PHRASES[rule]
    title = (alert.title or rule).strip()
    return f"triggered {title[0].lower() + title[1:]}" if title else f"triggered {rule}"


def _num(pattern: re.Pattern, text: str) -> int | None:
    m = pattern.search(text)
    return int(m.group(1)) if m else None


def _low_and_slow_phrase(alert: Alert) -> str:
    """ "probed slowly over 5 hours (62 misses across 41 paths)".

    Numbers come from the detail when it states them, else from the alert's
    own fields; whatever cannot be established is left out, never guessed.
    """
    detail = alert.detail or ""
    m = _HOURS_RE.search(detail)
    if m:
        duration = _count(max(1, round(float(m.group(1)))), "hour")
    else:                      # longhorizon.py states the window, not the span seen
        span = (alert.last_seen - alert.first_seen).total_seconds()
        if span >= 3600:
            duration = _count(round(span / 3600), "hour")
        elif span >= 60:
            duration = _count(round(span / 60), "minute")
        else:
            duration = ""
    misses = _num(_MISSES_RE, detail)
    if misses is None:
        misses = alert.event_count or None
    paths = _num(_PATHS_RE, detail)
    # The detector also fires on fast scanners (their misses pile up too);
    # only call it "slow" when the activity really spanned an hour or more.
    if duration and "hour" in duration:
        phrase = f"probed slowly over {duration}"
    elif duration:
        phrase = f"probed many missing paths over {duration}"
    else:
        phrase = "probed many missing paths"
    facts = []
    if misses:
        facts.append(f"{_word(misses)} miss{'' if misses == 1 else 'es'}")
    if paths:
        facts.append(f"across {_count(paths, 'path')}")
    return phrase + (f" ({' '.join(facts)})" if facts else "")


def _id_enum_phrase(alert: Alert) -> str:
    """ "walked sequential IDs on /api/users/{id} (40 IDs, range 1000-1039)"."""
    detail = alert.detail or ""
    m = _TEMPLATE_RE.search(detail)
    template = m.group(1).rstrip(".,;:)")[:80] if m else ""
    ids = _num(_IDS_RE, detail)
    rng = _RANGE_RE.search(detail)
    phrase = "walked sequential IDs" + (f" on {template}" if template else "")
    facts = []
    if ids:
        facts.append(f"{ids} ID" + ("" if ids == 1 else "s"))
    elif alert.event_count:                  # count of requests, not IDs: say so
        facts.append(_count(alert.event_count, "request"))
    if rng:
        facts.append(f"range {rng.group(1)}-{rng.group(2)}")
    return phrase + (f" ({', '.join(facts)})" if facts else "")


def _explicit_failures(alert: Alert) -> bool:
    """Only call attempts "failed" when the detector saw explicit 401/403 answers.

    Some apps answer a wrong password 200 with an error page, so the brute-force
    detector may count every login POST ("status-agnostic"). Calling those
    "failed attempts" would overstate what the log proves.
    """
    detail = (alert.detail or "").lower()
    return bool(re.search(r"\b40[13]\b", detail)) and "agnostic" not in detail


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
    """ "one attempt returned 200"; empty when no 2xx was informative.

    The count is the detector's informative count from the detail (evidence is
    capped at five lines). The status is named from evidence only when the
    detector declined no 2xx for that alert, since otherwise the evidence may
    show the uninformative ones.
    """
    winners = [a for a in alerts if exploit_succeeded(a)]
    if not winners:
        return ""
    n = 0
    codes: list[int] = []
    for a in winners:
        m = _DETAIL_COUNT_RE.search(a.detail or "")
        n += int(m.group(1)) if m else 0
        if _DECLINED_2XX not in (a.detail or ""):
            codes.extend(success_statuses(a))
        else:
            codes.append(0)                    # unknown code: forces "2xx"
    if not n:
        return "at least one attempt got a 2xx answer"
    status = str(codes[0]) if codes and len(set(codes)) == 1 and codes[0] else "2xx"
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

