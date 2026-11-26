"""The shared contract. Every module in WATCHTOWER speaks these types.

Do not change field names or types without updating TEAM_BRIEF.md: eight
people build against this file at once.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class LogEvent:
    """One parsed access-log line."""
    timestamp: datetime          # always timezone-aware, converted to UTC
    client_ip: str
    method: str                  # upper-case, "-" if unknown
    path: str                    # URL-decoded path, no query string
    query: str                   # raw query string without "?", "" if none
    status: int
    bytes_sent: int              # 0 when the log shows "-"
    referrer: str                # "" when the log shows "-"
    user_agent: str              # "" when the log shows "-"
    source: str = ""             # file name the line came from
    line_no: int = 0             # 1-based line number in that file
    raw: str = ""                # the original line, for evidence

    @property
    def target(self) -> str:
        return f"{self.path}?{self.query}" if self.query else self.path


@dataclass
class Alert:
    """A detector's verdict about one client."""
    rule_id: str                 # e.g. "SIG-UA-SCANNER", "BEH-404-BURST"
    title: str
    severity: str                # one of SEVERITIES
    client_ip: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    technique: str               # MITRE ATT&CK id, e.g. "T1595.002"
    evidence: list[str] = field(default_factory=list)   # at most 5 raw lines
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "title": self.title, "severity": self.severity,
            "client_ip": self.client_ip,
            "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
            "event_count": self.event_count, "technique": self.technique,
            "evidence": list(self.evidence), "detail": self.detail,
        }


@dataclass
class Incident:
    """All alerts for one client, correlated into a single story."""
    client_ip: str
    alerts: list[Alert]
    score: int                   # 0-100 risk score
    severity: str                # one of SEVERITIES
    stages: list[str]            # kill-chain stages seen, in order, e.g. ["recon", "exploit"]
    first_seen: datetime
    last_seen: datetime
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "client_ip": self.client_ip, "score": self.score, "severity": self.severity,
            "stages": list(self.stages),
            "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
            "summary": self.summary, "alerts": [a.to_dict() for a in self.alerts],
        }


class Detector(Protocol):
    """Every detector is a streaming state machine.

    feed() sees events in timestamp order and may return alerts immediately.
    flush() is called once at end of input and returns anything still pending.
    A detector must never raise on odd input; skip what it cannot use.
    """
    rule_ids: tuple[str, ...]

    def feed(self, event: LogEvent) -> list[Alert]: ...

    def flush(self) -> list[Alert]: ...


@dataclass
class ScanResult:
    """Everything the engine produced. The report writers consume only this."""
    incidents: list[Incident]            # sorted by score, highest first
    alerts: list[Alert]                  # every alert, sorted by first_seen
    stats: dict                          # see TEAM_BRIEF.md, "ScanResult.stats"
    generated_at: datetime

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at.isoformat(),
            "stats": dict(self.stats),
            "incidents": [i.to_dict() for i in self.incidents],
            "alerts": [a.to_dict() for a in self.alerts],
        }
