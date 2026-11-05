"""The scan pipeline: parse -> allowlist -> merge by time -> detect -> correlate.

Detectors are streaming state machines with sliding windows, so they must see
events in timestamp order: a brute-force run split across two load-balanced
servers' logs only shows up as one burst once both files are interleaved by
time. Files are streamed, never loaded whole, so memory stays proportional to
the number of active clients (plus a small reorder buffer), not to log size.
"""

from __future__ import annotations

import heapq
import warnings
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from .config import Config, load_config
from .correlate import correlate
from .models import SEVERITIES, SEVERITY_RANK, Alert, Detector, LogEvent, ScanResult

# Events a file may be displaced from timestamp order and still be sorted.
# Web servers log on request *completion*, so a slow request is written after
# faster ones that started later; a few thousand lines of slack covers that.
REORDER_WINDOW = 5000


def _parse_file(path: str | Path, fmt: str):
    """Indirection so tests can swap the parser; imported lazily."""
    from .parsers import parse_file
    return parse_file(path, fmt)


def _reorder(events: Iterable[LogEvent], window: int = REORDER_WINDOW) -> Iterator[LogEvent]:
    """Yield events sorted by timestamp, tolerating local disorder.

    A bounded min-heap: an event displaced by fewer than ``window`` lines comes
    out in order. Anything further out of place is yielded late rather than
    buffering the whole file; detectors tolerate that, they just see it late.
    """
    heap: list[tuple[datetime, int, LogEvent]] = []
    for seq, event in enumerate(events):
        heapq.heappush(heap, (event.timestamp, seq, event))
        if len(heap) > window:
            yield heapq.heappop(heap)[2]
    while heap:
        yield heapq.heappop(heap)[2]


def _safe_call(detector: Detector, method: str, *args) -> list[Alert]:
    """Call feed/flush, containing a buggy detector so the rest of the scan survives."""
    try:
        return list(getattr(detector, method)(*args) or [])
    except Exception as exc:                       # noqa: BLE001 - defence in depth
        warnings.warn(f"detector {detector!r} raised in {method}(): {exc!r}; "
                      f"its result for this call was skipped", RuntimeWarning, stacklevel=2)
        return []


def run(paths: list[str | Path], config: Config | None = None, fmt: str = "auto",
        detectors: list[Detector] | None = None) -> ScanResult:
    """Scan log files and return incidents, alerts and stats.

    ``detectors`` overrides the stock set (default: ``default_detectors(config)``),
    which is how tests inject fakes. Stats semantics:

    - ``lines_*`` sum the parser's counters over all files;
    - ``events_allowlisted`` counts parsed events dropped by the allowlist;
    - ``unique_clients`` counts distinct client IPs that reached the detectors
      (allowlisted clients excluded);
    - ``time_start``/``time_end`` span every parsed event, allowlisted or not,
      so they describe the period the logs cover.
    """
    if config is None:
        config = load_config(None)
    if detectors is None:
        from .detectors import default_detectors
        detectors = default_detectors(config)
    paths = [Path(p) for p in paths]
    for p in paths:
        if not p.is_file():
            raise FileNotFoundError(f"log file not found: {p}")

    streams, parse_stats = [], []
    for p in paths:
        events, pstats = _parse_file(p, fmt)
        streams.append(_reorder(events))
        parse_stats.append(pstats)

    allow_cache: dict[str, bool] = {}
    clients: set[str] = set()
    allowlisted = 0
    t_start = t_end = None
    alerts: list[Alert] = []

    for event in heapq.merge(*streams, key=lambda e: e.timestamp):
        ts = event.timestamp
        if t_start is None or ts < t_start:
            t_start = ts
        if t_end is None or ts > t_end:
            t_end = ts
        ip = event.client_ip
        if ip not in allow_cache:
            allow_cache[ip] = config.is_allowlisted(ip)
        if allow_cache[ip]:
            allowlisted += 1
            continue
        clients.add(ip)
        for det in detectors:
            alerts.extend(_safe_call(det, "feed", event))
    for det in detectors:
        alerts.extend(_safe_call(det, "flush"))

    # Belt and braces: injected detectors are not wrapped in RuleFilter.
    alerts = [a for a in alerts if config.rule_enabled(a.rule_id)]
    alerts.sort(key=lambda a: (a.first_seen, a.rule_id, a.client_ip))
    incidents = correlate(alerts, config.scoring)

    stats = {
        "lines_read": sum(s.lines_read for s in parse_stats),
        "lines_parsed": sum(s.lines_parsed for s in parse_stats),
        "lines_malformed": sum(s.lines_malformed for s in parse_stats),
        "events_allowlisted": allowlisted,
        "unique_clients": len(clients),
        "time_start": t_start.isoformat() if t_start else None,
        "time_end": t_end.isoformat() if t_end else None,
        "files": [str(p) for p in paths],
        "alerts_by_rule": _alerts_by_rule(alerts),
        "incidents_by_severity": _incidents_by_severity(incidents),
    }
    return ScanResult(incidents=incidents, alerts=alerts, stats=stats,
                      generated_at=datetime.now(timezone.utc))


def _alerts_by_rule(alerts: list[Alert]) -> dict[str, int]:
    return dict(sorted(Counter(a.rule_id for a in alerts).items()))


def _incidents_by_severity(incidents) -> dict[str, int]:
    counts = Counter(i.severity for i in incidents)
    return {sev: counts.get(sev, 0) for sev in SEVERITIES}


def filter_min_severity(result: ScanResult, min_severity: str) -> ScanResult:
    """A copy of ``result`` keeping only incidents at or above ``min_severity``.

    Alerts are trimmed to the clients still shown and the per-rule and
    per-severity counts recomputed, so the report stays self-consistent.
    Parse and traffic stats are unchanged: they describe the whole scan.
    """
    floor = SEVERITY_RANK[min_severity]
    incidents = [i for i in result.incidents if SEVERITY_RANK.get(i.severity, 0) >= floor]
    kept = {i.client_ip for i in incidents}
    alerts = [a for a in result.alerts if a.client_ip in kept]
    stats = dict(result.stats)
    stats["alerts_by_rule"] = _alerts_by_rule(alerts)
    stats["incidents_by_severity"] = _incidents_by_severity(incidents)
    return ScanResult(incidents=incidents, alerts=alerts, stats=stats,
                      generated_at=result.generated_at)
