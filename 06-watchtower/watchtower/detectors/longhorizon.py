"""Long-horizon behaviour detectors: attackers who pace themselves.

The fast windows in behaviour.py (seconds to 15 minutes) are beaten by an
attacker who sends a few requests per ten minutes for hours, or who spreads
the same slow walk over an IPv6 /64 so no single address is busy. These two
detectors look at hours, not minutes, and keep memory bounded by storing
5-minute counter buckets rather than every timestamp.

Both detectors track two keys per event: the client address and (when
grouping is on) its network, with the same semantics as behaviour.py: IPv6
/64 by default, IPv4 grouping off by default, and a network alert needs at
least `min_distinct` addresses and is suppressed when one address already
alerted on its own. One alert per key per rule, extended while the pattern
continues, emitted on flush(). feed() never raises.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import deque
from datetime import datetime
from functools import lru_cache

from watchtower.detectors.behaviour import MAX_EVIDENCE, NET_ADDR_CAP, _SWEEP_EVERY, _line
from watchtower.models import Alert, LogEvent

BUCKET_SECONDS = 300
PATH_CAP = 2000          # distinct miss paths remembered per key; beyond it, count only
ID_CAP = 5000            # distinct IDs remembered per (key, template)
TEMPLATES_PER_KEY = 50   # templates tracked per key; more are ignored
MISS_STATUSES = (401, 403, 404, 410)


@lru_cache(maxsize=65536)
def _net_key(ip: str, v4: int | None, v6: int | None) -> str | None:
    """Network string for ip, or None when grouping is off or ip is odd.
    IPv4-mapped IPv6 is treated as IPv4."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        prefix = v4 if addr.version == 4 else v6
        if prefix is None:
            return None
        return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
    except ValueError:
        return None


def _keys(ip: str, v4: int | None, v6: int | None) -> list[tuple[str, bool]]:
    keys = [(ip, False)]
    net = _net_key(ip, v4, v6)
    if net is not None:
        keys.append((net, True))
    return keys


class _Bucket:
    __slots__ = ("idx", "total", "misses", "first_ts", "overflow")

    def __init__(self, idx: int) -> None:
        self.idx = idx
        self.total = 0
        self.misses = 0
        self.first_ts: datetime | None = None
        self.overflow = 0


class _SlowState:
    """Counters for one key over the long window, in 5-minute buckets."""

    def __init__(self) -> None:
        self.buckets: deque[_Bucket] = deque()
        self.total = 0
        self.misses = 0
        self.overflow = 0
        self.paths: dict[str, int] = {}
        self.addrs: dict[str, int] = {}
        self.evidence: deque[str] = deque(maxlen=MAX_EVIDENCE)
        self.last_idx = 0

    def advance(self, idx: int, nbuckets: int) -> None:
        cutoff = idx - nbuckets
        purged = False
        while self.buckets and self.buckets[0].idx <= cutoff:
            b = self.buckets.popleft()
            self.total -= b.total
            self.misses -= b.misses
            self.overflow -= b.overflow
            purged = True
        if purged:
            self.paths = {p: i for p, i in self.paths.items() if i > cutoff}
            self.addrs = {a: i for a, i in self.addrs.items() if i > cutoff}
            if not self.buckets:
                self.evidence.clear()

    def add(self, ev: LogEvent, idx: int, nbuckets: int, miss: bool) -> None:
        idx = max(idx, self.last_idx)   # out-of-order events fold into the newest bucket
        self.last_idx = idx
        self.advance(idx, nbuckets)
        if not self.buckets or self.buckets[-1].idx != idx:
            self.buckets.append(_Bucket(idx))
        b = self.buckets[-1]
        b.total += 1
        self.total += 1
        if not miss:
            return
        b.misses += 1
        self.misses += 1
        if b.first_ts is None:
            b.first_ts = ev.timestamp
        self.evidence.append(_line(ev))
        path = ev.path or "(none)"
        if path in self.paths:
            self.paths[path] = idx
        elif len(self.paths) < PATH_CAP:
            self.paths[path] = idx
        else:
            b.overflow += 1
            self.overflow += 1
        if ev.client_ip in self.addrs or len(self.addrs) < NET_ADDR_CAP:
            self.addrs[ev.client_ip] = idx

    @property
    def distinct_paths(self) -> int:
        return len(self.paths) + self.overflow

    def first_miss(self) -> datetime | None:
        for b in self.buckets:
            if b.first_ts is not None:
                return b.first_ts
        return None


class LowAndSlowDetector:
    """BEH-LOW-AND-SLOW (T1595.003, medium): patient forced browsing.

    Attacker behaviour: a scanner throttled to a few requests per ten minutes
    for hours (or rotated across an IPv6 /64) never fills the 60-second or
    15-minute windows of BEH-404-BURST, yet still probes hundreds of paths.
    Over a 6 hour window we require all three of: many misses (401/403/404/
    410), a high share of the client's traffic being misses, and many
    distinct missed paths. The three together separate it from noise.

    False-positive risk: a crawler walking stale links has many distinct
    misses but a tiny miss ratio, so the ratio test keeps it quiet. A user
    with a few broken images has too few misses. A health check hammering
    one missing URL has few distinct paths. A shared NAT or proxy can still
    trip it; allowlist known proxies.
    """
    rule_ids = ("BEH-LOW-AND-SLOW",)

    def __init__(self, window_seconds: int = 21600, min_misses: int = 40,
                 min_miss_ratio: float = 0.3, min_distinct_paths: int = 20,
                 ipv6_prefix: int | None = 64, ipv4_prefix: int | None = None,
                 min_distinct: int = 4):
        self.window_seconds = max(BUCKET_SECONDS, int(window_seconds))
        self.nbuckets = math.ceil(self.window_seconds / BUCKET_SECONDS)
        self.min_misses = max(1, int(min_misses))
        self.min_miss_ratio = float(min_miss_ratio)
        self.min_distinct_paths = max(1, int(min_distinct_paths))
        self.v6, self.v4 = ipv6_prefix, ipv4_prefix
        self.min_distinct = max(1, int(min_distinct))
        self._states: dict[tuple[str, bool], _SlowState] = {}
        self._alerts: dict[tuple[str, bool], Alert] = {}
        self._client_nets: set[str] = set()
        self._seen = 0

    def _hit(self, st: _SlowState, is_net: bool, key: str) -> bool:
        if (st.misses < self.min_misses or st.total <= 0
                or st.misses / st.total < self.min_miss_ratio
                or st.distinct_paths < self.min_distinct_paths):
            return False
        if is_net:
            return len(st.addrs) >= self.min_distinct and key not in self._client_nets
        return True

    def _sweep(self, now_idx: int) -> None:
        for k in list(self._states):
            st = self._states[k]
            st.advance(max(now_idx, st.last_idx), self.nbuckets)
            if not st.buckets:
                del self._states[k]

    def feed(self, event: LogEvent) -> list[Alert]:
        try:
            self._feed(event)
        except Exception:  # odd input must never break a scan
            pass
        return []

    def _feed(self, ev: LogEvent) -> None:
        idx = int(ev.timestamp.timestamp() // BUCKET_SECONDS)
        self._seen += 1
        if self._seen % _SWEEP_EVERY == 0:
            self._sweep(idx)
        miss = ev.status in MISS_STATUSES
        # client key first so a lone noisy address claims its network
        for key, is_net in _keys(ev.client_ip, self.v4, self.v6):
            sk = (key, is_net)
            st = self._states.get(sk)
            if st is None:
                st = self._states[sk] = _SlowState()
            st.add(ev, idx, self.nbuckets, miss)
            if not miss:
                continue
            hit = self._hit(st, is_net, key)
            alert = self._alerts.get(sk)
            if alert is not None:
                if hit:
                    alert.last_seen = max(alert.last_seen, ev.timestamp)
                    alert.event_count += 1
                    if len(alert.evidence) < MAX_EVIDENCE:
                        alert.evidence.append(_line(ev))
            elif hit:
                self._open(sk, st, ev)

    def _open(self, sk: tuple[str, bool], st: _SlowState, ev: LogEvent) -> None:
        key, is_net = sk
        if not is_net:
            net = _net_key(ev.client_ip, self.v4, self.v6)
            if net is not None:
                self._client_nets.add(net)
        scope = f"distributed across {len(st.addrs)} addresses in {key}: " if is_net else ""
        self._alerts[sk] = Alert(
            rule_id="BEH-LOW-AND-SLOW", title="Low-and-slow path enumeration",
            severity="medium", client_ip=key, first_seen=st.first_miss() or ev.timestamp,
            last_seen=ev.timestamp, event_count=st.misses, technique="T1595.003",
            evidence=list(st.evidence),
            detail=(f"{scope}{st.misses} miss responses (401/403/404/410) of {st.total} "
                    f"requests ({st.misses / st.total:.0%}) across {st.distinct_paths} "
                    f"distinct paths within {self.window_seconds}s; patient forced "
                    f"browsing that stays under the short-window rules."))

    def flush(self) -> list[Alert]:
        out = sorted(self._alerts.values(), key=lambda a: (a.first_seen, a.client_ip))
        self._alerts, self._states, self._client_nets = {}, {}, set()
        return out


# ---------------------------------------------------------------------------

_INT_SEG = re.compile(r"^\d{1,18}$")
_PREFIXED_SEG = re.compile(r"^([A-Za-z][A-Za-z_-]*?)(\d{3,18})$")


def templatise(path: str) -> tuple[str, int] | None:
    """Replace ID-like segments with "{id}"; return (template, last id value).

    A segment is ID-like if it is all digits, or letters (optionally ending
    in "-"/"_") followed by at least 3 digits (SKU10234, INV-00042). The
    alphabetic prefix is kept in the template ("INV-{id}") so different
    families of IDs do not merge. None when the path has no ID segment.
    """
    if not path or "{id}" in path:
        return None
    value: int | None = None
    parts = path.split("/")
    for i, seg in enumerate(parts):
        if _INT_SEG.match(seg):
            parts[i], value = "{id}", int(seg)
            continue
        m = _PREFIXED_SEG.match(seg)
        if m:
            parts[i], value = m.group(1) + "{id}", int(m.group(2))
    if value is None:
        return None
    return "/".join(parts).lower(), value


class _IdState:
    """Distinct IDs requested for one template by one key, within the window."""

    def __init__(self) -> None:
        self.ids: dict[int, tuple[datetime, bool, str]] = {}  # id -> (ts, non2xx, addr)
        self.order: deque[tuple[datetime, int]] = deque()
        self.evidence: deque[str] = deque(maxlen=MAX_EVIDENCE)

    def evict(self, now: datetime, window: float) -> None:
        while self.order and (now - self.order[0][0]).total_seconds() > window:
            ts, i = self.order.popleft()
            rec = self.ids.get(i)
            if rec is not None and rec[0] == ts:
                del self.ids[i]
        if not self.ids:
            self.evidence.clear()

    def add(self, ev: LogEvent, ident: int) -> bool:
        """Record ident; True if it is a new distinct ID."""
        non2xx = not (200 <= ev.status < 300)
        old = self.ids.get(ident)
        if old is None and len(self.ids) >= ID_CAP:
            return False
        self.ids[ident] = (ev.timestamp, non2xx or (old[1] if old else False), ev.client_ip)
        self.order.append((ev.timestamp, ident))
        self.evidence.append(_line(ev))
        return old is None


class IdEnumerationDetector:
    """BEH-ID-ENUM (T1595.003, medium): walking sequential object IDs.

    Attacker behaviour: insecure direct object reference (IDOR) hunting and
    scraping. The attacker requests /invoice/1000, /invoice/1001, ... to
    harvest other users' records, slowly enough to dodge rate rules. Each
    path is templatised ("/invoice/{id}") and we alert when one template saw
    at least `min_ids` distinct IDs inside `window_seconds` and at least 70%
    of consecutive sorted IDs differ by <= `max_step` (a walk, not a random
    sample). Detail gives the template, ID range, count and how many IDs
    were answered non-2xx.

    False-positive risk: a user paging through their own orders or a crawler
    following "next" links also walks sequential IDs. min_ids (25) and the
    6 hour window keep ordinary sessions quiet; raise min_ids for sites with
    legitimately long sequential listings, or allowlist known crawlers.
    """
    rule_ids = ("BEH-ID-ENUM",)

    def __init__(self, min_ids: int = 25, window_seconds: int = 21600, max_step: int = 3,
                 min_sequential: float = 0.7, ipv6_prefix: int | None = 64,
                 ipv4_prefix: int | None = None, min_distinct: int = 4):
        self.min_ids = max(2, int(min_ids))
        self.window_seconds = max(1, int(window_seconds))
        self.max_step = max(1, int(max_step))
        self.min_sequential = float(min_sequential)
        self.v6, self.v4 = ipv6_prefix, ipv4_prefix
        self.min_distinct = max(1, int(min_distinct))
        self._states: dict[tuple[str, bool], dict[str, _IdState]] = {}
        self._alerts: dict[tuple[str, bool, str], Alert] = {}
        self._client_nets: set[tuple[str, str]] = set()
        self._seen = 0

    def feed(self, event: LogEvent) -> list[Alert]:
        try:
            self._feed(event)
        except Exception:  # odd input must never break a scan
            pass
        return []

    def _sweep(self, now: datetime) -> None:
        for sk in list(self._states):
            tmpl = self._states[sk]
            for t in list(tmpl):
                tmpl[t].evict(now, self.window_seconds)
                if not tmpl[t].ids:
                    del tmpl[t]
            if not tmpl:
                del self._states[sk]

    def _feed(self, ev: LogEvent) -> None:
        self._seen += 1
        if self._seen % _SWEEP_EVERY == 0:
            self._sweep(ev.timestamp)
        tv = templatise(ev.path)
        if tv is None:
            return
        template, ident = tv
        for key, is_net in _keys(ev.client_ip, self.v4, self.v6):
            sk = (key, is_net)
            per = self._states.setdefault(sk, {})
            st = per.get(template)
            if st is None:
                if len(per) >= TEMPLATES_PER_KEY:
                    continue
                st = per[template] = _IdState()
            st.evict(ev.timestamp, self.window_seconds)
            new = st.add(ev, ident)
            ak = (key, is_net, template)
            alert = self._alerts.get(ak)
            if alert is not None:
                alert.last_seen = max(alert.last_seen, ev.timestamp)
                alert.event_count += 1
                if len(alert.evidence) < MAX_EVIDENCE:
                    alert.evidence.append(_line(ev))
                continue
            n = len(st.ids)
            if not new or n < self.min_ids or not (n <= 2 * self.min_ids or n % 8 == 0):
                continue
            if self._walk(st, is_net, key, template):
                self._open(ak, st, template, ev)

    def _walk(self, st: _IdState, is_net: bool, key: str, template: str) -> bool:
        if is_net:
            if (key, template) in self._client_nets:
                return False
            if len({r[2] for r in st.ids.values()}) < self.min_distinct:
                return False
        ids = sorted(st.ids)
        steps = [b - a for a, b in zip(ids, ids[1:])]
        close = sum(1 for s in steps if s <= self.max_step)
        return bool(steps) and close / len(steps) >= self.min_sequential

    def _open(self, ak: tuple[str, bool, str], st: _IdState, template: str, ev: LogEvent) -> None:
        key, is_net, _ = ak
        if not is_net:
            net = _net_key(ev.client_ip, self.v4, self.v6)
            if net is not None:
                self._client_nets.add((net, template))
        ids = sorted(st.ids)
        bad = sum(1 for r in st.ids.values() if r[1])
        scope = (f"distributed across {len({r[2] for r in st.ids.values()})} addresses "
                 f"in {key}: " if is_net else "")
        first = min(r[0] for r in st.ids.values())
        self._alerts[ak] = Alert(
            rule_id="BEH-ID-ENUM", title="Sequential ID enumeration",
            severity="medium", client_ip=key, first_seen=first, last_seen=ev.timestamp,
            event_count=len(st.order), technique="T1595.003", evidence=list(st.evidence),
            detail=(f"{scope}template {template}: {len(ids)} distinct IDs "
                    f"({ids[0]}..{ids[-1]}) within {self.window_seconds}s forming a "
                    f"sequential walk; {bad} answered non-2xx."))

    def flush(self) -> list[Alert]:
        out = sorted(self._alerts.values(), key=lambda a: (a.first_seen, a.client_ip))
        self._alerts, self._states, self._client_nets = {}, {}, set()
        return out
