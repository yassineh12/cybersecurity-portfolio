"""Command-line interface: ``python -m watchtower scan LOG [LOG ...]``.

Exit codes are designed for CI gating:

- 0: no incident at or above ``--fail-on`` (default high);
- 2: at least one incident at or above ``--fail-on``;
- 1: the scan could not run (missing file, bad config, bad arguments).

Bad arguments exit 1 rather than argparse's usual 2 so that "your command
line is wrong" is never mistaken for "an attack was found".
"""

from __future__ import annotations

import argparse
import sys
import warnings
from pathlib import Path
from typing import Sequence, TextIO

from . import __version__
from .config import ConfigError, load_config
from .engine import filter_min_severity, run
from .models import SEVERITIES, SEVERITY_RANK, ScanResult

EXIT_OK, EXIT_ERROR, EXIT_INCIDENTS = 0, 1, 2
FORMATS = ("auto", "combined", "common", "jsonl")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):              # exit 1, not 2 (see module docstring)
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="watchtower",
                     description="Detect scanners, exploit attempts and brute force in web access logs.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    scan = sub.add_parser("scan", help="scan one or more access logs and write reports")
    scan.add_argument("logs", nargs="+", metavar="LOG", help="access log files (.gz is fine)")
    scan.add_argument("--config", metavar="FILE", help="YAML config (default: rules/default.yaml)")
    scan.add_argument("--format", choices=FORMATS, default="auto", dest="fmt",
                      help="log format (default: auto-detect per line)")
    scan.add_argument("--out", metavar="DIR", default=".",
                      help="directory for report.md/.json/.html (default: .)")
    scan.add_argument("--min-severity", choices=SEVERITIES, default="low",
                      help="leave incidents below this out of the reports (default: low)")
    scan.add_argument("--fail-on", choices=(*SEVERITIES, "never"), default="high",
                      help="exit 2 if any incident is at or above this severity, judged on "
                           "the full scan regardless of --min-severity (default: high)")
    scan.add_argument("--top", type=int, default=10, metavar="N",
                      help="incidents shown in the terminal summary (default: 10)")
    return parser


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None) -> int:
    args = build_parser().parse_args(argv)
    out = stdout or sys.stdout
    if args.command == "scan":
        return _scan(args, out)
    return EXIT_ERROR                                  # pragma: no cover


def _scan(args: argparse.Namespace, out: TextIO) -> int:
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"watchtower: config error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    with warnings.catch_warnings():
        warnings.simplefilter("always")
        warnings.showwarning = _show_warning
        try:
            result = run(args.logs, config=config, fmt=args.fmt)
        except (FileNotFoundError, IsADirectoryError, PermissionError) as exc:
            print(f"watchtower: {exc}", file=sys.stderr)
            return EXIT_ERROR

    shown = filter_min_severity(result, args.min_severity)
    try:
        from .report import write_reports
        written = write_reports(shown, Path(args.out))
    except OSError as exc:
        print(f"watchtower: cannot write reports to {args.out}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    out.write(format_summary(shown, top=args.top, written=written))
    return exit_code(result, args.fail_on)


def _show_warning(message, category, filename, lineno, file=None, line=None):
    print(f"watchtower: warning: {message}", file=sys.stderr)


def exit_code(result: ScanResult, fail_on: str) -> int:
    """2 when any incident reaches ``fail_on`` (``never`` disables gating)."""
    if fail_on == "never":
        return EXIT_OK
    floor = SEVERITY_RANK[fail_on]
    hit = any(SEVERITY_RANK.get(i.severity, 0) >= floor for i in result.incidents)
    return EXIT_INCIDENTS if hit else EXIT_OK


# --------------------------------------------------------------- summary ---

def _safe(text: object, width: int | None = None) -> str:
    """Strip control characters before printing log-derived text.

    Log lines are attacker-controlled; an ANSI escape sequence in a user agent
    could otherwise rewrite the analyst's terminal (hide lines, fake output).
    """
    s = "".join(ch if ch.isprintable() else "?" for ch in str(text))
    if width is not None and len(s) > width:
        s = s[: max(width - 3, 0)] + "..."
    return s


def format_summary(result: ScanResult, top: int = 10, written: dict | None = None) -> str:
    st = result.stats
    sev = st.get("incidents_by_severity", {})
    lines = [
        "WATCHTOWER scan summary",
        f"  files      {len(st.get('files', []))}   lines {st.get('lines_read', 0)} read, "
        f"{st.get('lines_parsed', 0)} parsed, {st.get('lines_malformed', 0)} malformed",
        f"  clients    {st.get('unique_clients', 0)}   allowlisted events "
        f"{st.get('events_allowlisted', 0)}",
        f"  period     {st.get('time_start') or '-'} .. {st.get('time_end') or '-'}",
        f"  alerts     {len(result.alerts)}   incidents {len(result.incidents)} ("
        + ", ".join(f"{sev.get(s, 0)} {s}" for s in reversed(SEVERITIES)) + ")",
        "",
    ]
    if result.incidents:
        rows = result.incidents[:max(top, 0)]
        ip_w = max([6] + [len(_safe(i.client_ip, 39)) for i in rows])
        st_w = max([6] + [len(_safe(">".join(i.stages), 30)) for i in rows])
        lines.append(f"  {'SCORE':>5}  {'SEVERITY':<8}  {'CLIENT':<{ip_w}}  {'STAGES':<{st_w}}  SUMMARY")
        for inc in rows:
            lines.append(
                f"  {inc.score:>5}  {inc.severity:<8}  {_safe(inc.client_ip, 39):<{ip_w}}  "
                f"{_safe('>'.join(inc.stages) or '-', 30):<{st_w}}  {_safe(inc.summary, 110)}")
        hidden = len(result.incidents) - max(top, 0)
        if hidden > 0:
            lines.append(f"  ... and {hidden} more in the reports")
    else:
        lines.append("  No incidents.")
    if written:
        lines.append("")
        lines.append("  reports    " + "  ".join(str(p) for p in written.values()))
    return "\n".join(lines) + "\n"
