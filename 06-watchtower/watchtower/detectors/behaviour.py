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

Each detector also has a network-level channel. An attacker holding an IPv6
/64 can rotate through billions of source addresses, each sending only a few
requests, so no single address ever crosses a threshold. The network channel
groups events by prefix (IPv6 /64 by default; IPv4 grouping is off by default
because a /24 merges unrelated users of shared ISPs) and alerts when the
network crosses the same threshold across at least `min_distinct` addresses
and no single address already did (that case is a per-client alert).
"""

from __future__ import annotations

import ipaddress
from collections import deque
from datetime import datetime, timedelta

from watchtower.models import Alert, LogEvent

MAX_EVIDENCE = 5
BOUNCE_SECONDS = 10  # max gap between a 302 login POST and the GET back to the form
_SWEEP_EVERY = 1024  # events between idle-client sweeps
NET_ADDR_CAP = 10_000  # distinct addresses remembered per network window


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
    """True if path equals a login path, optionally followed by "?query".

    Exact matching only: "/admin" must not swallow every page under /admin
    (a busy admin UI saving records would look like a brute force).
    """
    p = normalise_path(path)
    base = p.split("?", 1)[0]
    base = base.rstrip("/") or "/" if len(base) > 1 else base
    return any(base == normalise_path(lp) for lp in login_paths)


class _Window:
    """Per-client sliding window plus the evidence kept for it."""
    __slots__ = ("times", "evidence")

    def __init__(self) -> None:
        self.times: deque[datetime] = deque()
        self.evidence: deque[str] = deque(maxlen=MAX_EVIDENCE)


class _Chan:
    """One threshold/window pair tracked per client."""

    def __init__(self, threshold: int, window_seconds: int) -> None:
        self.threshold = max(1, int(threshold))
        self.window = timedelta(seconds=max(0, window_seconds))
        self.wins: dict[str, _Window] = {}

    def _evict(self, win: _Window, now: datetime) -> None:
        while win.times and now - win.times[0] > self.window:
            win.times.popleft()

    def peek(self, ip: str, now: datetime) -> _Window | None:
        """Window for ip after eviction, without creating or adding."""
        win = self.wins.get(ip)
        if win is not None:
            self._evict(win, now)
            if not win.times:
                del self.wins[ip]
                return None
        return win

    def add(self, event: LogEvent) -> _Window:
        win = self.wins.get(event.client_ip)
        if win is None:
            win = self.wins[event.client_ip] = _Window()
        self._evict(win, event.timestamp)
        win.times.append(event.timestamp)
        win.evidence.append(_line(event))
        return win

    def hit(self, win: _Window) -> bool:
        return len(win.times) >= self.threshold

    def sweep(self, now: datetime) -> None:
        for ip in list(self.wins):
            self.peek(ip, now)

    @property
    def seconds(self) -> int:
        return int(self.window.total_seconds())


class _NetWin:
    """One network's sliding window plus per-address bookkeeping."""
    __slots__ = ("q", "evidence", "counts", "overflow", "big")

    def __init__(self) -> None:
        self.q: deque[tuple[datetime, str | None]] = deque()
        self.evidence: deque[str] = deque(maxlen=MAX_EVIDENCE)
        self.counts: dict[str, int] = {}
        self.overflow = 0          # addresses beyond NET_ADDR_CAP, counted not stored
        self.big: set[str] = set()  # addresses at/over the threshold on their own

    @property
    def distinct(self) -> int:
        return len(self.counts) + self.overflow


class _NetChan:
    """Threshold/window pair tracked per network (IPv6 /64, optional IPv4 /N)."""

    def __init__(self, threshold: int, window_seconds: int, ipv4_prefix: int | None,
                 ipv6_prefix: int | None, min_distinct: int) -> None:
        self.threshold = max(1, int(threshold))
        self.window = timedelta(seconds=max(0, window_seconds))
        self.v4, self.v6 = ipv4_prefix, ipv6_prefix
        self.min_distinct = max(1, int(min_distinct))
        self.wins: dict[str, _NetWin] = {}

    def key(self, ip: str) -> str | None:
        """Network string for ip, or None when grouping is off or ip is odd.
        IPv4-mapped IPv6 (::ffff:a.b.c.d) is treated as IPv4."""
        if not ip or (":" not in ip and self.v4 is None):
            return None
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 6 and addr.ipv4_mapped is not None:
                addr = addr.ipv4_mapped
            prefix = self.v4 if addr.version == 4 else self.v6
            if prefix is None:
                return None
            return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
        except ValueError:
            return None

    def _evict(self, nw: _NetWin, now: datetime) -> None:
        while nw.q and now - nw.q[0][0] > self.window:
            _, addr = nw.q.popleft()
            if addr is None:
                nw.overflow -= 1
                continue
            nw.counts[addr] -= 1
            if nw.counts[addr] < self.threshold:
                nw.big.discard(addr)
            if nw.counts[addr] <= 0:
                del nw.counts[addr]

    def peek(self, key: str, now: datetime) -> _NetWin | None:
        nw = self.wins.get(key)
        if nw is not None:
            self._evict(nw, now)
            if not nw.q:
                del self.wins[key]
                return None
        return nw

    def add(self, event: LogEvent) -> tuple[str, _NetWin] | None:
        key = self.key(event.client_ip)
        if key is None:
            return None
        nw = self.wins.get(key)
        if nw is None:
            nw = self.wins[key] = _NetWin()
        self._evict(nw, event.timestamp)
        addr: str | None = event.client_ip
        if addr in nw.counts:
            nw.counts[addr] += 1
        elif len(nw.counts) < NET_ADDR_CAP:
            nw.counts[addr] = 1
        else:
            addr = None
            nw.overflow += 1
        if addr is not None and nw.counts[addr] >= self.threshold:
            nw.big.add(addr)
        nw.q.append((event.timestamp, addr))
        nw.evidence.append(_line(event))
        return key, nw

    def active(self, nw: _NetWin) -> bool:
        return len(nw.q) >= self.threshold

    def hit(self, nw: _NetWin) -> bool:
        """Distributed crossing: network over threshold, enough distinct
        addresses, and no lone address already over it (per-client alert)."""
        return self.active(nw) and nw.distinct >= self.min_distinct and not nw.big

    def sweep(self, now: datetime) -> None:
        for key in list(self.wins):
            self.peek(key, now)

    @property
    def seconds(self) -> int:
        return int(self.window.total_seconds())


def _spread(net: str, nw: _NetWin) -> str:
    return f"distributed across {nw.distinct} addresses in {net}: "


class _WindowDetector:
    """Shared machinery: sweeping, open-alert tracking, safe feed/flush."""
    rule_ids: tuple[str, ...] = ()

    def __init__(self, *chans: _Chan) -> None:
        self._chans = chans
        self._alerts: dict[tuple[str, str], Alert] = {}
        self._seen = 0

    @property
    def _windows(self) -> dict[str, _Window]:  # primary channel, for inspection
        return self._chans[0].wins

    def _tick(self, now: datetime) -> None:
        self._seen += 1
        if self._seen % _SWEEP_EVERY == 0:
            for ch in self._chans:
                ch.sweep(now)

    def _extend(self, alert: Alert, event: LogEvent) -> None:
        alert.last_seen = max(alert.last_seen, event.timestamp)
        alert.event_count += 1
        if len(alert.evidence) < MAX_EVIDENCE:
            alert.evidence.append(_line(event))

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
        for ch in self._chans:
            ch.wins = {}
        return out


class EnumerationDetector(_WindowDetector):
    """BEH-404-BURST (T1595.003, medium): many misses from one client.

    Attacker behaviour: forced browsing (gobuster, dirb, ffuf) guesses
    thousands of paths and almost all of them miss. 404 is the classic miss,
    but a WAF often answers 403 and some apps 410, so all three count. A fast
    window catches loud bursts; a second slow window (default 100 per 15
    minutes) catches low-and-slow enumeration that stays under the fast one.

    False-positive risk: a single-page app or broken front end that requests
    missing assets in a loop, a crawler walking stale links, or many users
    behind one NAT gateway / corporate proxy sharing an IP. Tune thresholds
    per site and allowlist known proxies.
    """
    rule_ids = ("BEH-404-BURST",)
    MISS_STATUSES = (403, 404, 410)

    def __init__(self, threshold: int = 20, window_seconds: int = 60,
                 slow_threshold: int = 100, slow_window_seconds: int = 900,
                 ipv6_prefix: int | None = 64, ipv4_prefix: int | None = None,
                 min_distinct: int = 4):
        self._fast = _Chan(threshold, window_seconds)
        self._slow = _Chan(slow_threshold, slow_window_seconds)
        self._nfast = _NetChan(threshold, window_seconds, ipv4_prefix, ipv6_prefix, min_distinct)
        self._nslow = _NetChan(slow_threshold, slow_window_seconds, ipv4_prefix,
                               ipv6_prefix, min_distinct)
        super().__init__(self._fast, self._slow, self._nfast, self._nslow)
        self.threshold = self._fast.threshold
        self.slow_threshold = self._slow.threshold

    def _feed(self, event: LogEvent) -> None:
        if event.status not in self.MISS_STATUSES:
            return
        self._tick(event.timestamp)
        self._client(event)
        self._network(event)

    def _network(self, event: LogEvent) -> None:
        nf, ns = self._nfast.add(event), self._nslow.add(event)
        if nf is None or ns is None:
            return
        net, fw = nf
        sw = ns[1]
        key = (net, "BEH-404-BURST")
        alert = self._alerts.get(key)
        if alert is not None:
            if self._nfast.active(fw) or self._nslow.active(sw):
                self._extend(alert, event)
            return
        fast, slow = self._nfast.hit(fw), self._nslow.hit(sw)
        if not (fast or slow):
            return
        nw, ch = (fw, self._nfast) if fast else (sw, self._nslow)
        n = len(nw.q)
        kind = "" if fast else "slow enumeration: "
        self._alerts[key] = Alert(
            rule_id="BEH-404-BURST", title="Burst of 404/403/410 responses (path enumeration)",
            severity="medium", client_ip=net, first_seen=nw.q[0][0],
            last_seen=event.timestamp, event_count=n, technique="T1595.003",
            evidence=list(nw.evidence),
            detail=(f"{_spread(net, nw)}{kind}{n} miss responses (404/403/410) within "
                    f"{ch.seconds}s (threshold {ch.threshold}); consistent with directory "
                    f"guessing."))

    def _client(self, event: LogEvent) -> None:
        fw, sw = self._fast.add(event), self._slow.add(event)
        fast, slow = self._fast.hit(fw), self._slow.hit(sw)
        alert = self._alerts.get((event.client_ip, "BEH-404-BURST"))
        if alert is not None:
            # extend only while the client is still above a threshold
            if fast or slow:
                self._extend(alert, event)
            return
        if not (fast or slow):
            return
        win, ch = (fw, self._fast) if fast else (sw, self._slow)
        n = len(win.times)
        kind = "" if fast else "slow enumeration: "
        self._alerts[(event.client_ip, "BEH-404-BURST")] = Alert(
            rule_id="BEH-404-BURST", title="Burst of 404/403/410 responses (path enumeration)",
            severity="medium", client_ip=event.client_ip, first_seen=win.times[0],
            last_seen=event.timestamp, event_count=n, technique="T1595.003",
            evidence=list(win.evidence),
            detail=(f"{kind}{n} miss responses (404/403/410) within {ch.seconds}s "
                    f"(threshold {ch.threshold}); consistent with directory guessing."))


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

    def __init__(self, threshold: int = 300, window_seconds: int = 60,
                 ipv6_prefix: int | None = 64, ipv4_prefix: int | None = None,
                 min_distinct: int = 4):
        self._ch = _Chan(threshold, window_seconds)
        self._nch = _NetChan(threshold, window_seconds, ipv4_prefix, ipv6_prefix, min_distinct)
        super().__init__(self._ch, self._nch)
        self.threshold = self._ch.threshold

    def _feed(self, event: LogEvent) -> None:
        self._tick(event.timestamp)
        self._client(event)
        self._network(event)

    def _network(self, event: LogEvent) -> None:
        added = self._nch.add(event)
        if added is None:
            return
        net, nw = added
        key = (net, "BEH-RATE-SPIKE")
        alert = self._alerts.get(key)
        if alert is not None:
            if self._nch.active(nw):
                self._extend(alert, event)
        elif self._nch.hit(nw):
            n = len(nw.q)
            self._alerts[key] = Alert(
                rule_id="BEH-RATE-SPIKE", title="Request rate spike",
                severity="low", client_ip=net, first_seen=nw.q[0][0],
                last_seen=event.timestamp, event_count=n, technique="T1499",
                evidence=list(nw.evidence),
                detail=(f"{_spread(net, nw)}{n} requests within {self._nch.seconds}s "
                        f"(threshold {self.threshold})."))

    def _client(self, event: LogEvent) -> None:
        win = self._ch.add(event)
        alert = self._alerts.get((event.client_ip, "BEH-RATE-SPIKE"))
        if alert is not None:
            self._extend(alert, event)
        elif self._ch.hit(win):
            n = len(win.times)
            self._alerts[(event.client_ip, "BEH-RATE-SPIKE")] = Alert(
                rule_id="BEH-RATE-SPIKE", title="Request rate spike",
                severity="low", client_ip=event.client_ip, first_seen=win.times[0],
                last_seen=event.timestamp, event_count=n, technique="T1499",
                evidence=list(win.evidence),
                detail=f"{n} requests within {self._ch.seconds}s (threshold {self.threshold}).")


class BruteForceDetector(_WindowDetector):
    """BEH-BRUTE-FORCE (T1110, high) and BEH-BRUTE-SUCCESS (T1110, critical).

    Attacker behaviour: password guessing or credential stuffing sends many
    POSTs to a login endpoint. Well-behaved apps answer failures 401/403, but
    WordPress answers a failed login 200 and many apps redirect (302) back to
    the form. So when explicit failures are absent, POSTs answered 200 count
    toward volume (302/303 and other 2xx are normal successes and do not, so
    a login monitor that logs in every 30s stays quiet), at medium severity
    (flagged "status-agnostic; lower confidence" when the failures
    were not explicit 401/403). If the client then gets a 2xx or 302 after
    explicit failures, the guessing probably worked, which is worse than the
    guessing itself, hence the separate critical rule. A success is not
    declared for status-agnostic volume alone, since a 200 or 302 is then
    indistinguishable from a failure.

    Login paths match exactly (or with ?query); "/admin" does not cover
    every page under /admin.

    False-positive risk: many real users behind one NAT gateway or corporate
    proxy share an IP, and a user who forgot a password or an automated
    client with a stale token can fail repeatedly. A success after failures
    from a shared IP may be an innocent user; verify against the account's
    own authentication log.
    """
    rule_ids = ("BEH-BRUTE-FORCE", "BEH-BRUTE-SUCCESS")

    def __init__(self, threshold: int = 10, window_seconds: int = 300,
                 login_paths: tuple[str, ...] = ("/login", "/signin", "/wp-login.php",
                                                 "/admin", "/admin/login", "/api/auth",
                                                 "/api/login", "/user/login", "/xmlrpc.php"),
                 ipv6_prefix: int | None = 64, ipv4_prefix: int | None = None,
                 min_distinct: int = 4):
        self._posts = _Chan(threshold, window_seconds)
        self._fails = _Chan(threshold, window_seconds)
        self._nposts = _NetChan(threshold, window_seconds, ipv4_prefix, ipv6_prefix, min_distinct)
        self._nfails = _NetChan(threshold, window_seconds, ipv4_prefix, ipv6_prefix, min_distinct)
        super().__init__(self._posts, self._fails, self._nposts, self._nfails)
        self.threshold = self._posts.threshold
        self.login_paths = tuple(login_paths)
        self._totals: dict[str, int] = {}   # explicit failures seen, per alerted client
        self._pending: dict[str, LogEvent] = {}   # 302/303 login POSTs awaiting the next request
        self._inferred: set[str] = set()          # clients with redirect-bounce failures

    def _tick(self, now: datetime) -> None:
        super()._tick(now)
        if self._seen % _SWEEP_EVERY == 0:
            self._pending = {ip: p for ip, p in self._pending.items()
                             if abs((now - p.timestamp).total_seconds()) <= BOUNCE_SECONDS}
            self._inferred &= set(self._posts.wins)

    @staticmethod
    def _base(path: str) -> str:
        return normalise_path(path).split("?", 1)[0].rstrip("/") or "/"

    def _resolve_pending(self, event: LogEvent) -> None:
        """A 302/303 login POST is a failure only if the same client's very
        next request is a GET of the same login page, or another POST to it
        (an immediate retry: nobody re-submits a login that just succeeded),
        within BOUNCE_SECONDS. A slow monitor re-posting every 30s is not."""
        pend = self._pending.pop(event.client_ip, None)
        if (pend is None or event.method not in ("GET", "POST")
                or self._base(event.path) != self._base(pend.path)
                or not is_login_path(event.path, self.login_paths)
                or (event.timestamp - pend.timestamp).total_seconds() > BOUNCE_SECONDS):
            return
        self._inferred.add(event.client_ip)
        self._count_post(pend, explicit=False)

    def _feed(self, event: LogEvent) -> None:
        self._resolve_pending(event)
        if event.method != "POST" or not is_login_path(event.path, self.login_paths):
            return
        self._tick(event.timestamp)
        status = event.status
        explicit = status in (401, 403)
        success = 200 <= status < 300 or status == 302
        if success:
            self._maybe_success(event)
        if status in (302, 303):
            self._pending[event.client_ip] = event
            return
        if not (explicit or status == 200):
            return  # other 2xx are normal successes, not volume
        self._count_post(event, explicit)

    def _count_post(self, event: LogEvent, explicit: bool) -> None:
        self._client_post(event, explicit)
        self._network_post(event, explicit)

    def _network_post(self, event: LogEvent, explicit: bool) -> None:
        added = self._nposts.add(event)
        if added is None:
            return
        net, nw = added
        if explicit:
            self._nfails.add(event)
        key = (net, "BEH-BRUTE-FORCE")
        note = "302 redirects back to the login page counted as failures"
        alert = self._alerts.get(key)
        if alert is not None:
            if self._nposts.active(nw):
                self._extend(alert, event)
                if explicit:
                    alert.severity = "high"
                if event.client_ip in self._inferred and note not in alert.detail:
                    alert.detail += " " + note + "."
            return
        if not self._nposts.hit(nw):
            return
        fw = self._nfails.peek(net, event.timestamp)
        nfail = len(fw.q) if fw else 0
        n = len(nw.q)
        detail = (f"{_spread(net, nw)}{n} login POSTs within {self._nposts.seconds}s "
                  f"(threshold {self.threshold}); {nfail} explicit 401/403 failures")
        if nfail < self.threshold:
            detail += "; status-agnostic; lower confidence"
        if event.client_ip in self._inferred:
            detail += "; " + note
        self._alerts[key] = Alert(
            rule_id="BEH-BRUTE-FORCE", title="Login brute force",
            severity="high" if nfail else "medium", client_ip=net,
            first_seen=nw.q[0][0], last_seen=event.timestamp, event_count=n,
            technique="T1110", evidence=list(nw.evidence), detail=detail + ".")

    def _client_post(self, event: LogEvent, explicit: bool) -> None:
        pw = self._posts.add(event)
        if explicit:
            self._fails.add(event)
        key = (event.client_ip, "BEH-BRUTE-FORCE")
        alert = self._alerts.get(key)
        note = "302 redirects back to the login page counted as failures"
        if alert is not None:
            self._extend(alert, event)
            if explicit:
                self._totals[event.client_ip] = self._totals.get(event.client_ip, 0) + 1
                alert.severity = "high"  # explicit failures confirm the guessing
            if event.client_ip in self._inferred and note not in alert.detail:
                alert.detail += " " + note + "."
            return
        if not self._posts.hit(pw):
            return
        fw = self._fails.peek(event.client_ip, event.timestamp)
        nfail = len(fw.times) if fw else 0
        n = len(pw.times)
        detail = f"{n} login POSTs within {self._posts.seconds}s (threshold {self.threshold})"
        if nfail < self.threshold:
            detail += f"; {nfail} explicit 401/403 failures; status-agnostic; lower confidence"
        else:
            detail += f"; {nfail} explicit 401/403 failures"
        if event.client_ip in self._inferred:
            detail += "; " + note
        self._totals[event.client_ip] = nfail
        self._alerts[key] = Alert(
            rule_id="BEH-BRUTE-FORCE", title="Login brute force",
            severity="high" if nfail else "medium",
            client_ip=event.client_ip, first_seen=pw.times[0], last_seen=event.timestamp,
            event_count=n, technique="T1110", evidence=list(pw.evidence),
            detail=detail + ".")

    def _maybe_success(self, event: LogEvent) -> None:
        ip = event.client_ip
        fw = self._fails.peek(ip, event.timestamp)
        in_window = len(fw.times) if fw else 0
        open_total = self._totals.get(ip, 0) if (ip, "BEH-BRUTE-FORCE") in self._alerts else 0
        failures = max(in_window if in_window >= self.threshold else 0, open_total)
        if failures <= 0:
            return
        key = (ip, "BEH-BRUTE-SUCCESS")
        alert = self._alerts.get(key)
        if alert is not None:
            self._extend(alert, event)
            return
        pw = self._posts.peek(ip, event.timestamp)
        prior = list(pw.evidence)[-(MAX_EVIDENCE - 1):] if pw else []
        first = pw.times[0] if pw else event.timestamp
        self._alerts[key] = Alert(
            rule_id="BEH-BRUTE-SUCCESS", title="Successful login after brute force",
            severity="critical", client_ip=ip, first_seen=first,
            last_seen=event.timestamp, event_count=failures + 1, technique="T1110",
            evidence=prior + [_line(event)],
            detail=(f"Login succeeded (HTTP {event.status}) after {failures} failed "
                    f"attempts (401/403); credentials may be compromised."))

    def flush(self) -> list[Alert]:
        self._totals = {}
        self._pending = {}  # unresolved 302s are not failures
        self._inferred = set()
        return super().flush()
