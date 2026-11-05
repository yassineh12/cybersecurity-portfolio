"""Behaviour detectors: judge a client by how much and how fast it asks,
not by what the request strings contain.

Signature rules miss attackers who send perfectly ordinary-looking requests
in abnormal volume. These three detectors use per-client sliding windows (a
deque of timestamps per client IP). Each client gets at most one alert per
rule: once the threshold is crossed the alert stays open and is extended
while the client keeps going. Alerts are emitted on flush().

Memory is bounded: a client's state is dropped as soon as its window is
empty, and idle clients are swept periodically, so a million one-off
visitors do not accumulate.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta

from watchtower.models import Alert, LogEvent

MAX_EVIDENCE = 5
_SWEEP_EVERY = 1024  # events between idle-client sweeps


def _line(event: LogEvent) -> str:
    """Evidence text for an event: the raw log line, or a rebuilt summary."""
    if event.raw:
        return event.raw
    return (f"{event.timestamp.isoformat()} {event.client_ip} {event.method} "
            f"{event.target} {event.status}")


def normalise_path(path: str) -> str:
    """Lower-case a path and strip trailing slashes ("/Login/" -> "/login")."""
    p = (path or "").lower()
    if len(p) > 1:
        p = p.rstrip("/") or "/"
    return p


def is_login_path(path: str, login_paths: tuple[str, ...]) -> bool:
    """True if path equals a login path or sits under it ("/admin/x", "/admin?x")."""
    p = normalise_path(path)
    for lp in login_paths:
        lp = normalise_path(lp)
        if p == lp or p.startswith(lp + "/") or p.startswith(lp + "?"):
            return True
    return False


class _Window:
    """Per-client sliding window plus the evidence kept for it."""
    __slots__ = ("times", "evidence")

    def __init__(self) -> None:
        self.times: deque[datetime] = deque()
        self.evidence: deque[str] = deque(maxlen=MAX_EVIDENCE)


class _WindowDetector:
    """Shared machinery: per-client windows, eviction, open-alert tracking."""
    rule_ids: tuple[str, ...] = ()

    def __init__(self, threshold: int, window_seconds: int) -> None:
        self.threshold = max(1, int(threshold))
        self.window = timedelta(seconds=max(0, window_seconds))
        self._windows: dict[str, _Window] = {}
        self._alerts: dict[tuple[str, str], Alert] = {}
        self._seen = 0
        self._last_ts: datetime | None = None

    # -- helpers -----------------------------------------------------------
    def _evict(self, win: _Window, now: datetime) -> None:
        while win.times and now - win.times[0] > self.window:
            win.times.popleft()

    def _sweep(self, now: datetime) -> None:
        """Drop clients whose window has emptied (called now and then)."""
        for ip in list(self._windows):
            win = self._windows[ip]
            self._evict(win, now)
            if not win.times:
                del self._windows[ip]

    def _tick(self, now: datetime) -> None:
        self._seen += 1
        self._last_ts = now
        if self._seen % _SWEEP_EVERY == 0:
            self._sweep(now)

    def _record(self, rule: str, event: LogEvent, win: _Window, build) -> None:
        """Update the open alert for (client, rule), or open one at threshold."""
        key = (event.client_ip, rule)
        alert = self._alerts.get(key)
        if alert is not None:
            alert.last_seen = max(alert.last_seen, event.timestamp)
            alert.event_count += 1
            if len(alert.evidence) < MAX_EVIDENCE:
                alert.evidence.append(_line(event))
            return
        if len(win.times) >= self.threshold:
            alert = build(win.times[0], event.timestamp, len(win.times))
            alert.evidence = list(win.evidence)
            self._alerts[key] = alert

    def _add(self, event: LogEvent) -> _Window:
        win = self._windows.get(event.client_ip)
        if win is None:
            win = self._windows[event.client_ip] = _Window()
        self._evict(win, event.timestamp)
        win.times.append(event.timestamp)
        win.evidence.append(_line(event))
        return win

    def feed(self, event: LogEvent) -> list[Alert]:
        try:
            self._feed(event)
        except Exception:  # odd input must never break a scan
            pass
        return []

    def _feed(self, event: LogEvent) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def flush(self) -> list[Alert]:
        out = sorted(self._alerts.values(), key=lambda a: (a.first_seen, a.client_ip))
        self._alerts = {}
        self._windows = {}
        return out


class EnumerationDetector(_WindowDetector):
    """BEH-404-BURST (T1595.003, medium): many 404s from one client.

    Attacker behaviour: forced browsing (gobuster, dirb, ffuf) guesses
    thousands of paths and almost all of them miss, so the client generates a
    burst of 404 responses in seconds. Normal users rarely see more than a
    couple.

    False-positive risk: a single-page app or broken front end that requests
    missing assets in a loop, a crawler walking stale links, or many users
    behind one NAT gateway / corporate proxy sharing an IP. Tune the
    threshold per site and allowlist known proxies.
    """
    rule_ids = ("BEH-404-BURST",)

    def __init__(self, threshold: int = 20, window_seconds: int = 60):
        super().__init__(threshold, window_seconds)

    def _feed(self, event: LogEvent) -> None:
        if event.status != 404:
            return
        self._tick(event.timestamp)
        win = self._add(event)
        self._record("BEH-404-BURST", event, win, lambda first, last, n: Alert(
            rule_id="BEH-404-BURST", title="Burst of 404 responses (path enumeration)",
            severity="medium", client_ip=event.client_ip, first_seen=first,
            last_seen=last, event_count=n, technique="T1595.003",
            detail=(f"{n} 404 responses within {int(self.window.total_seconds())}s "
                    f"(threshold {self.threshold}); consistent with directory guessing.")))


class RateDetector(_WindowDetector):
    """BEH-RATE-SPIKE (T1499, low): request volume far above human speed.

    Attacker behaviour: application-layer denial of service, aggressive
    scraping or credential stuffing floods the server with requests from one
    address, hundreds a minute.

    False-positive risk: a shared NAT gateway or corporate proxy, a load
    balancer or monitoring probe logging its own IP, legitimate API clients
    and search-engine crawlers. Severity is low for that reason; treat it as
    context for other alerts.
    """
    rule_ids = ("BEH-RATE-SPIKE",)

    def __init__(self, threshold: int = 300, window_seconds: int = 60):
        super().__init__(threshold, window_seconds)

    def _feed(self, event: LogEvent) -> None:
        self._tick(event.timestamp)
        win = self._add(event)
        self._record("BEH-RATE-SPIKE", event, win, lambda first, last, n: Alert(
            rule_id="BEH-RATE-SPIKE", title="Request rate spike",
            severity="low", client_ip=event.client_ip, first_seen=first,
            last_seen=last, event_count=n, technique="T1499",
            detail=(f"{n} requests within {int(self.window.total_seconds())}s "
                    f"(threshold {self.threshold}).")))


class BruteForceDetector(_WindowDetector):
    """BEH-BRUTE-FORCE (T1110, high) and BEH-BRUTE-SUCCESS (T1110, critical).

    Attacker behaviour: password guessing or credential stuffing sends many
    POSTs to a login endpoint that answer 401/403. If the attacker then gets
    a 2xx or 302 the guessing worked, which is far worse than the guessing
    itself, hence the separate critical rule.

    False-positive risk: many real users behind one NAT gateway or corporate
    proxy share an IP, and a user who forgot a password plus an automated
    client with a stale token can also fail repeatedly. A success after
    failures from a shared IP may be an innocent user; verify against the
    account's own authentication log.
    """
    rule_ids = ("BEH-BRUTE-FORCE", "BEH-BRUTE-SUCCESS")

    def __init__(self, threshold: int = 10, window_seconds: int = 300,
                 login_paths: tuple[str, ...] = ("/login", "/signin", "/wp-login.php",
                                                 "/admin", "/api/auth", "/user/login")):
        super().__init__(threshold, window_seconds)
        self.login_paths = tuple(login_paths)

    def _feed(self, event: LogEvent) -> None:
        if event.method != "POST" or not is_login_path(event.path, self.login_paths):
            return
        status = event.status
        if status in (401, 403):
            self._tick(event.timestamp)
            win = self._add(event)
            self._record("BEH-BRUTE-FORCE", event, win, lambda first, last, n: Alert(
                rule_id="BEH-BRUTE-FORCE", title="Login brute force",
                severity="high", client_ip=event.client_ip, first_seen=first,
                last_seen=last, event_count=n, technique="T1110",
                detail=(f"{n} failed logins within {int(self.window.total_seconds())}s "
                        f"(threshold {self.threshold}).")))
        elif 200 <= status < 300 or status == 302:
            self._success(event)

    def _success(self, event: LogEvent) -> None:
        win = self._windows.get(event.client_ip)
        if win is None:
            return
        self._evict(win, event.timestamp)
        failures = len(win.times)
        if failures < self.threshold:
            if not win.times:
                self._windows.pop(event.client_ip, None)
            return
        key = (event.client_ip, "BEH-BRUTE-SUCCESS")
        alert = self._alerts.get(key)
        if alert is not None:
            alert.last_seen = max(alert.last_seen, event.timestamp)
            alert.event_count += 1
            if len(alert.evidence) < MAX_EVIDENCE:
                alert.evidence.append(_line(event))
            return
        evidence = list(win.evidence)[-(MAX_EVIDENCE - 1):] + [_line(event)]
        self._alerts[key] = Alert(
            rule_id="BEH-BRUTE-SUCCESS", title="Successful login after brute force",
            severity="critical", client_ip=event.client_ip, first_seen=win.times[0],
            last_seen=event.timestamp, event_count=failures + 1, technique="T1110",
            evidence=evidence,
            detail=(f"Login succeeded (HTTP {event.status}) after {failures} failed "
                    f"attempts within {int(self.window.total_seconds())}s; "
                    f"credentials may be compromised."))
