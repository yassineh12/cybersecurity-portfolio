"""Signature detection: known-bad strings in requests that are already logged.

Attackers rarely type a request by hand. Scanners and exploit kits send the
same recognisable payloads again and again: a scanner announces itself in the
User-Agent, a probe asks for ``/.env``, an injection carries ``union select``.
This module recognises those payloads in access logs (detection only; it never
sends traffic) and emits one alert per (client, rule).

Each rule is a small ``Rule`` record so adding a new one means adding one entry
to ``RULES``. Two cross-cutting ideas matter more than any single regex:

* Normalise first. Attackers hide payloads behind URL encoding (often twice,
  to slip past a filter that decodes once), ``+`` for spaces and mixed case.
  We decode twice, turn ``+`` into a space and lower-case before matching.
* Stay quiet on benign look-alikes. A search for "select a plan" is not SQL
  injection; every SQLI pattern therefore needs real SQL structure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import unquote_plus

from watchtower.models import SEVERITIES, Alert, LogEvent

MAX_FIELD_LEN = 8192  # bound regex work on hostile, enormous request lines


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------

def normalize(text: str) -> str:
    """URL-decode until stable (max 4 passes), '+' to space, lower-case.

    Repeated decoding catches ``%252e%252e%252f`` and deeper nesting
    (``../`` encoded two or three times), which a naive single-pass filter
    would let through. Stopping at 4 passes bounds the work.
    """
    try:
        text = str(text)[:MAX_FIELD_LEN]
        for _ in range(4):
            new = unquote_plus(text)
            if new == text:
                break
            text = new
        return text.lower().replace("\x00", "")
    except Exception:
        return ""


_LOOKUP_DEFAULT = re.compile(r"\$\{[^{}$]*?:-([^{}$]*)\}")
_LOOKUP_CASE = re.compile(r"\$\{(?:lower|upper):([^{}$]*)\}")


def deobfuscate_lookups(text: str) -> str:
    """Collapse Log4j string lookups so ``${${lower:j}ndi:`` becomes ``${jndi:``.

    Log4Shell payloads were routinely obfuscated with ``${lower:x}``,
    ``${upper:x}`` and ``${::-x}`` to defeat plain ``${jndi:`` filters. The
    logging library evaluates these, so we evaluate them too, innermost first.
    """
    for _ in range(10):
        new = _LOOKUP_CASE.sub(r"\1", text)
        new = _LOOKUP_DEFAULT.sub(r"\1", new)
        if new == text:
            break
        text = new
    return text


# --------------------------------------------------------------------------
# Rule definitions
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern
    path_only: bool = False   # match the path, ignore the query string


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    technique: str
    severity: str
    patterns: tuple[Pattern, ...]
    fields: tuple[str, ...] = ("target",)   # target | user_agent | referrer
    exploit: bool = False                    # eligible for 2xx escalation
    deobfuscate: bool = False                # apply Log4j lookup collapsing


def _p(name: str, rx: str, path_only: bool = False) -> Pattern:
    return Pattern(name, re.compile(rx, re.IGNORECASE | re.DOTALL), path_only)


SCANNER_NAMES = (
    "nikto|sqlmap|nmap|nuclei|gobuster|dirbuster|dirb|wpscan|masscan|zgrab|"
    "acunetix|nessus|openvas|netsparker|arachni|w3af|wfuzz|ffuf|feroxbuster|"
    "havij|skipfish|whatweb|burpcollaborator"
)

# A command only counts with a real argument ("cat /etc", "wget http"), so
# ordinary searches such as "dog && cat toys" or "amazon | echo dot" stay quiet.
_CMD_ARGS = (
    r"(?:cat\s+(?:/|~|\.\./|-)|ls\s+(?:-\w|/)|uname\s+-|"
    r"(?:wget|curl)\s+(?:-\S+\s+)*(?:https?:|ftp:|/)|nc\s+-\w|ncat\s+-\w|netcat\s+-\w|"
    r"(?:ba|z|da)?sh\s+-c|bash\s+-i|python3?\s+-c|perl\s+-e|php\s+-r|ruby\s+-e|"
    r"ping\s+-[nc]\s*\d|sleep\s+\d|chmod\s+(?:[+0-7]|-)|rm\s+-\w|echo\s+[`$]|"
    r"powershell\s+-|cmd(?:\.exe)?\s+/c|net\s+user\s|"
    r"(?:whoami|ifconfig|ipconfig)(?![a-z0-9_-])|id\s*(?=[;|&`]))"
)
# Inside $( ) or backticks the shell runs the content, so bare words suffice.
_CMD_BARE = (
    r"(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|netcat|bash|sh|zsh|python3?|"
    r"perl|php|ruby|ping|nslookup|rm|chmod|echo|sleep|powershell|cmd|tftp|"
    r"ifconfig|ipconfig)(?![a-z0-9_-])"
)

RULES: tuple[Rule, ...] = (
    Rule(
        "SIG-UA-SCANNER", "Known scanner user agent", "T1595.002", "medium",
        # Automated scanners usually keep their default tool name in the UA.
        (_p("scanner-ua", rf"(?<![a-z])(?:{SCANNER_NAMES})(?![a-z])"),),
        fields=("user_agent",),
    ),
    Rule(
        "SIG-SENSITIVE-PATH", "Probe for sensitive file or path", "T1595.003", "medium",
        # Attackers look for leaked secrets and admin leftovers: env files,
        # exposed git repos, config backups, cloud credential files.
        (
            _p("dotenv", r"/\.env(?:\.[a-z0-9_-]+)?(?:[/#]|$)", True),
            _p("git-dir", r"/\.git(?:/|$)", True),
            _p("wp-config", r"/wp-config\.php", True),
            _p("server-status", r"/server-(?:status|info)(?:[/#]|$)", True),
            _p("phpinfo", r"/(?:phpinfo|info)\.php$", True),
            _p("actuator", r"/actuator/(?:env|heapdump|threaddump|configprops|mappings|beans|httptrace|jolokia)\b", True),
            _p("web-config", r"/web\.config$", True),
            _p("db-admin", r"/(?:phpmyadmin|pma|adminer)(?:/|\.php|$)", True),
            _p("ssh-key", r"/id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$", True),
            _p("cgi-bin", r"/cgi-bin/(?:test-cgi|printenv|php|bash|admin)|/cgi-bin/[^/]*\.(?:sh|pl|cgi)$", True),
            # Backup archives only for well-known names at web root or one
            # well-known directory; "/downloads/db.zip" is a normal file.
            _p("backup-file", r"^/(?:(?:backups?|old|bak|admin|sql|dump|db)/)?"
               r"(?:backup|db|database|dump|site|www|web|config|wp-config)"
               r"(?:\.(?:php|json|yml|yaml|ini|conf))?\.(?:bak|old|orig|save|zip|sql|tar\.gz|tgz|tar|gz|rar|7z)$", True),
            _p("cloud-creds", r"/\.(?:aws/credentials|ssh/id_[a-z0-9]+|htpasswd|htaccess|npmrc|docker/config\.json)", True),
            _p("ds-store", r"/\.ds_store$", True),
        ),
    ),
    Rule(
        "SIG-SQLI", "SQL injection pattern", "T1190", "high",
        # Injection changes the query's logic: UNION to read other tables,
        # tautologies to bypass logins, SLEEP() for blind timing probes.
        # Every pattern needs SQL structure, so plain words never match.
        (
            _p("union-select", r"\bunion(?:\s|/\*.*?\*/)+(?:all(?:\s|/\*.*?\*/)+)?select\b"),
            _p("tautology", r"\b(?:or|and)\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\1\b"),
            _p("numeric-compare", r"\b(?:or|and)\s+\d+\s*(?:=|<>|<=|>=|<|>)\s*\d+\b"),
            _p("sql-variable", r"@@(?:version|servername|hostname|datadir|basedir)\b|\bconvert\s*\(\s*int\b"),
            _p("order-by", r"\border\s+by\s+\d+\s*(?:--|#|/\*|$)"),
            _p("quote-or-cmp", r"['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*(?:=|<|>|like\b)"),
            _p("quote-comment", r"['\")]\s*(?:--|#)[\s-]*(?:&|$)"),
            _p("time-based", r"\b(?:pg_)?sleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|waitfor\s+delay\s+'"),
            _p("info-schema", r"\binformation_schema\b|\bsysobjects\b|\bpg_catalog\b"),
            _p("select-fn", r"\bselect\s+(?:\*|null\b|concat\(|group_concat|version\(|user\(|database\(|@@|count\(|char\()"),
            _p("stacked", r";\s*(?:drop|alter|truncate|insert|update|delete)\s+(?:table|database|into|from|\w+\s+set)\b"),
            _p("db-funcs", r"\b(?:load_file|extractvalue|updatexml|xp_cmdshell)\s*\(|into\s+(?:out|dump)file\b"),
        ),
        exploit=True,
    ),
    Rule(
        "SIG-XSS", "Script injection (XSS) pattern", "T1190", "medium",
        # Reflected XSS probes put script or event handlers into parameters.
        (
            _p("script-tag", r"<\s*/?\s*script\b"),
            _p("html-injection", r"<\s*(?:iframe|svg|img|body|object|embed|video|details)\b[^>]*(?:on\w+\s*=|src\s*=|data\s*=)"),
            _p("js-uri", r"javascript\s*:"),
            _p("event-handler", r"[\s\"'/<]on(?:error|load|click|mouseover|focus|toggle|start)\s*="),
            _p("js-payload", r"document\.(?:cookie|domain)|\b(?:alert|prompt|confirm)\s*\(\s*(?:1|document|['\"])"),
        ),
        exploit=True,
    ),
    Rule(
        "SIG-TRAVERSAL", "Path traversal pattern", "T1190", "high",
        # Traversal climbs out of the web root to read system files. A lone
        # "../" can be a harmless relative link, so it must repeat or point
        # at a known target; known target files alone are enough.
        (
            _p("repeated-dotdot", r"(?:\.\.[/\\]){2,}"),
            _p("dotdot-target", r"\.\.[/\\]+(?:etc|proc|windows|winnt|boot\.ini|var|root|home|\.ssh|\.git|web-inf)\b"),
            _p("etc-passwd", r"/etc/(?:passwd|shadow|hosts)\b"),
            _p("win-ini", r"[/\\](?:win\.ini|boot\.ini)\b|windows[/\\]system32"),
            _p("proc-self", r"/proc/self/"),
            _p("nested-dotdot", r"\.\.\.\.[/\\]{2}|\.\.;/"),
        ),
        exploit=True,
    ),
    Rule(
        "SIG-CMDI", "Shell command injection pattern", "T1190", "high",
        # A shell metacharacter followed by a command lets an attacker chain
        # their own command onto the one the application intended to run.
        (
            _p("chained-cmd", rf"(?:;|\|\||&&|\||\n)\s*{_CMD_ARGS}"),
            _p("subshell", rf"\$\(\s*{_CMD_BARE}|`\s*{_CMD_BARE}[^`]*`"),
            _p("shell-path", r"/bin/(?:ba|z|da|k)?sh\b|\bcmd(?:\.exe)?\s+/c\b|powershell(?:\.exe)?\s+-"),
        ),
        exploit=True,
    ),
    Rule(
        "SIG-LOG4SHELL", "Log4Shell JNDI injection (CVE-2021-44228)", "T1190", "critical",
        # Log4j expands ${jndi:ldap://...} found anywhere it logs, including
        # headers, then fetches attacker code. Headers are checked too.
        (_p("jndi-lookup", r"\$\{\s*jndi\s*:"),),
        fields=("target", "user_agent", "referrer"),
        exploit=True,
        deobfuscate=True,
    ),
)

RULE_IDS = tuple(r.rule_id for r in RULES)


# --------------------------------------------------------------------------
# Matching helpers (pure)
# --------------------------------------------------------------------------

def _field_value(event: LogEvent, name: str) -> str:
    return str(getattr(event, name, "") or "")


def match_rule(rule: Rule, event: LogEvent) -> list[str]:
    """Return names of the rule's patterns that match this event."""
    hits: list[str] = []
    for fname in rule.fields:
        text = normalize(_field_value(event, fname))
        if rule.deobfuscate:
            text = deobfuscate_lookups(text)
        path_text = text.partition("?")[0]
        for pat in rule.patterns:
            if pat.name in hits:
                continue
            if pat.regex.search(path_text if pat.path_only else text):
                hits.append(pat.name)
    return hits


def escalate(severity: str) -> str:
    """One step up the severity ladder, capped at critical."""
    idx = SEVERITIES.index(severity) if severity in SEVERITIES else 0
    return SEVERITIES[min(idx + 1, len(SEVERITIES) - 1)]


@dataclass
class _State:
    first: datetime
    last: datetime
    count: int = 0
    evidence: list[str] = field(default_factory=list)
    patterns: list[str] = field(default_factory=list)
    success_2xx: int = 0


class SignatureDetector:
    """Match each request against every rule; aggregate per (client, rule).

    Aggregating keeps a scanner that sends 5,000 probes down to one alert
    with a count, which is what an analyst wants to read.
    """

    rule_ids = RULE_IDS

    def __init__(self, max_evidence: int = 5):
        self.max_evidence = max(0, int(max_evidence))
        self._states: dict[tuple[str, str], _State] = {}

    def feed(self, event: LogEvent) -> list[Alert]:
        try:
            self._ingest(event)
        except Exception:
            pass  # a detector must never raise on odd input
        return []

    def _ingest(self, event: LogEvent) -> None:
        for rule in RULES:
            hits = match_rule(rule, event)
            if not hits:
                continue
            key = (event.client_ip, rule.rule_id)
            st = self._states.get(key)
            if st is None:
                st = self._states[key] = _State(event.timestamp, event.timestamp)
            st.first = min(st.first, event.timestamp)
            st.last = max(st.last, event.timestamp)
            st.count += 1
            if len(st.evidence) < self.max_evidence:
                st.evidence.append(event.raw or self._synth_line(event))
            for h in hits:
                if h not in st.patterns:
                    st.patterns.append(h)
            if rule.exploit and isinstance(event.status, int) and 200 <= event.status < 300:
                st.success_2xx += 1

    @staticmethod
    def _synth_line(event: LogEvent) -> str:
        return f"{event.client_ip} {event.method} {event.target} {event.status}"

    def flush(self) -> list[Alert]:
        by_id = {r.rule_id: r for r in RULES}
        alerts: list[Alert] = []
        for (ip, rule_id), st in self._states.items():
            rule = by_id[rule_id]
            severity = rule.severity
            detail = f"{st.count} matching request(s); patterns: {', '.join(st.patterns)}."
            if st.success_2xx:
                severity = escalate(severity)
                detail += (
                    f" {st.success_2xx} request(s) were answered with HTTP 2xx, so the "
                    f"attempt may have succeeded; severity raised to {severity}."
                )
            alerts.append(Alert(
                rule_id=rule_id, title=rule.title, severity=severity, client_ip=ip,
                first_seen=st.first, last_seen=st.last, event_count=st.count,
                technique=rule.technique, evidence=list(st.evidence), detail=detail,
            ))
        self._states.clear()
        alerts.sort(key=lambda a: (a.first_seen, a.rule_id, a.client_ip))
        return alerts
