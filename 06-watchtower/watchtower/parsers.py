"""Access-log parsers: turn raw text lines into LogEvent objects.

Why this matters: every detector trusts the parser. Attackers control the
request line, user agent and referrer, so the parser must survive escaped
quotes, binary junk and garbage requests without raising, and must normalise
paths (URL-decode once) so signature matching is not dodged by encoding.
Scanners routinely send non-HTTP bytes; those lines are counted as malformed
rather than crashing the pipeline.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import re
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import unquote

from .models import LogEvent

_Q = r'"((?:[^"\\]++|\\.)*+)"'  # quoted field allowing backslash-escaped chars
_COMMON = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] ' + _Q.replace("(", "(?P<request>", 1)
    + r' (?P<status>\d{3}|-) (?P<bytes>\d+|-)\s*$'
)
_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] ' + _Q.replace("(", "(?P<request>", 1)
    + r' (?P<status>\d{3}|-) (?P<bytes>\d+|-)'
    + r' ' + _Q.replace("(", "(?P<referrer>", 1)
    + r' ' + _Q.replace("(", "(?P<agent>", 1) + r'(?:\s.*)?\s*$'
)
# Lines longer than this are scanner junk or a DoS attempt on the parser.
MAX_LINE_BYTES = 65536
_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
_FORMATS = ("auto", "combined", "common", "jsonl")


@dataclass
class ParseStats:
    lines_read: int = 0
    lines_parsed: int = 0
    lines_malformed: int = 0
    read_error: str = ""   # set when a file was cut short (corrupt/truncated gzip, bad bytes)


def _unescape(s: str) -> str:
    """Undo the \\" and \\\\ escaping that Apache/nginx apply to quoted fields."""
    return s.replace('\\"', '"').replace("\\\\", "\\") if "\\" in s else s


def _dash(s: str) -> str:
    return "" if s == "-" else s


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _split_request(request: str) -> tuple[str, str, str]:
    """Return (method, path, query). Garbage or "-" gives ("-", "", "")."""
    parts = request.split()
    if len(parts) < 2 or not re.fullmatch(r"[A-Za-z]{1,20}", parts[0]):
        return "-", "", ""
    target = parts[1]
    path, _, query = target.partition("?")
    path = path.split("#", 1)[0]
    return parts[0].upper(), unquote(path), query


def _clean_ip(value) -> str | None:
    """Return a canonical client IP or None.

    The client string flows into reports and the terminal, and in JSON logs
    the attacker controls it: markup or ANSI escapes there would attack the
    analyst. Anything that is not a literal IP is rejected. (Servers logging
    hostnames via HostnameLookups On must turn that off.)
    """
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v.startswith("[") and v.endswith("]"):
        v = v[1:-1]
    v = v.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


def _int(s, default: int = 0) -> int:
    try:
        return int(s)
    except (TypeError, ValueError):
        return default


def _from_regex(m: re.Match, combined: bool, source: str, line_no: int, raw: str) -> LogEvent | None:
    try:
        ts = _to_utc(datetime.strptime(m["time"], _TIME_FORMAT))
    except ValueError:
        return None
    ip = _clean_ip(m["ip"])
    if ip is None:
        return None
    method, path, query = _split_request(_unescape(m["request"]))
    return LogEvent(
        timestamp=ts, client_ip=ip, method=method, path=path, query=query,
        status=_int(m["status"]), bytes_sent=_int(m["bytes"]),
        referrer=_dash(_unescape(m["referrer"])) if combined else "",
        user_agent=_dash(_unescape(m["agent"])) if combined else "",
        source=source, line_no=line_no, raw=raw,
    )


def _parse_json_time(rec: dict) -> datetime | None:
    t = rec.get("time")
    if isinstance(t, (int, float)):
        return datetime.fromtimestamp(t, timezone.utc)
    if isinstance(t, str) and t:
        try:
            return _to_utc(datetime.fromisoformat(t.replace("Z", "+00:00")))
        except ValueError:
            pass
    tl = rec.get("time_local")
    if isinstance(tl, str):
        try:
            return _to_utc(datetime.strptime(tl, _TIME_FORMAT))
        except ValueError:
            pass
    return None


def _from_json(raw: str, source: str, line_no: int) -> LogEvent | None:
    try:
        rec = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(rec, dict):
        return None
    ts = _parse_json_time(rec)
    ip = _clean_ip(rec.get("remote_addr"))
    if ts is None or ip is None:
        return None
    request = rec.get("request")
    if isinstance(request, str):
        method, path, query = _split_request(request)
    elif rec.get("uri") is not None:
        uri = str(rec.get("uri"))
        path, _, query = uri.partition("?")
        path = unquote(path)
        method = str(rec.get("method") or "-").upper()
    else:
        method, path, query = "-", "", ""
    return LogEvent(
        timestamp=ts, client_ip=ip, method=method, path=path, query=query,
        status=_int(rec.get("status")), bytes_sent=_int(rec.get("body_bytes_sent")),
        referrer=_dash(str(rec.get("http_referer") or "")),
        user_agent=_dash(str(rec.get("http_user_agent") or "")),
        source=source, line_no=line_no, raw=raw,
    )


def parse_line(line: str, fmt: str = "auto", source: str = "", line_no: int = 0) -> LogEvent | None:
    """Parse one line; return None (never raise) if it does not fit the format."""
    try:
        if len(line) > MAX_LINE_BYTES:
            return None
        raw = line.rstrip("\r\n")
        text = raw.strip()
        if not text:
            return None
        if fmt == "auto":
            fmt = "jsonl" if text.startswith("{") else "combined+common"
        if fmt == "jsonl":
            return _from_json(raw, source, line_no)
        if fmt in ("combined", "combined+common"):
            m = _COMBINED.match(text)
            if m:
                return _from_regex(m, True, source, line_no, raw)
            if fmt == "combined":
                return None
        m = _COMMON.match(text)
        return _from_regex(m, False, source, line_no, raw) if m else None
    except Exception:
        return None


def _open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="\n")
    return open(path, "rt", encoding="utf-8", errors="replace", newline="\n")


def parse_file(path: str | Path, fmt: str = "auto") -> tuple[Iterator[LogEvent], ParseStats]:
    """Stream events from a (possibly gzipped) log; stats fill as it is consumed."""
    path = Path(path)
    stats = ParseStats()

    def gen() -> Iterator[LogEvent]:
        try:
            with _open_text(path) as fh:
                for n, line in enumerate(fh, 1):
                    if not line.strip():
                        continue
                    stats.lines_read += 1
                    ev = parse_line(line, fmt, path.name, n)
                    if ev is None:
                        stats.lines_malformed += 1
                    else:
                        stats.lines_parsed += 1
                        yield ev
        except (OSError, EOFError, UnicodeError) as exc:
            stats.read_error = f"{path.name}: {type(exc).__name__}: {exc}"[:200]
            warnings.warn(f"watchtower: stopped reading {stats.read_error}", RuntimeWarning)

    return gen(), stats
