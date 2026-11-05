"""Measure how well WATCHTOWER separates attackers from ordinary visitors.

Why this tool exists
--------------------
A detection engine is only useful if analysts can trust it. Two numbers
tell you whether they can:

* **Precision**: of the clients we raised an incident for, how many were
  really malicious? Low precision means analysts spend their shift closing
  alerts on harmless users. That is *alert fatigue*: after the fiftieth
  false alarm people stop reading closely, and the real attack scrolls past
  unnoticed. Every false positive also costs triage minutes a small SOC
  does not have.

* **Recall**: of the clients that really were malicious, how many did we
  catch? Low recall means *missed breaches*. A brute force that ends in a
  successful login, or a SQL injection that got a 200 back, is exactly the
  event the engine exists to surface. Missing it is far worse than a noisy
  alert, because nobody goes looking for what was never raised.

The two pull against each other. Lower the thresholds and recall rises while
precision falls; raise them and the reverse happens. **F1** is their harmonic
mean: a single number that only stays high when both do. Use ``--min-severity``
to see the trade-off for yourself: counting only ``high`` and above usually
drops the scanners (recall falls) but also drops the noisy-but-benign users
(precision rises).

How it scores
-------------
The unit is the client IP, because that is what an analyst triages. A client
counts as *flagged* when the engine produced at least one incident for it
(at or above ``--min-severity`` if given). Every IP in the labels file is
then one of:

* TP: labelled malicious and flagged
* FN: labelled malicious and not flagged (including when the IP never
  appears in the log at all: a scenario the generator promised but the
  log does not contain is still a miss)
* FP: labelled benign and flagged
* TN: labelled benign and not flagged

Flagged IPs absent from the labels are reported as *unlabelled* and kept out
of the maths, since we cannot say whether they were right.

Usage::

    python tools/evaluate.py examples/sample_access.log examples/sample_labels.csv
    python tools/evaluate.py LOG LABELS --min-severity high
    python tools/evaluate.py LOG LABELS --min-recall 0.9      # exit 1 below 90 %

Exit codes: 0 on success, 1 when recall is below ``--min-recall`` (so CI can
gate on detection quality), 2 on bad input such as a missing file.
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from watchtower.models import SEVERITIES, SEVERITY_RANK, ScanResult  # noqa: E402

MALICIOUS = "malicious"
BENIGN = "benign"
VALID_LABELS = (BENIGN, MALICIOUS)


@dataclass
class Label:
    """Ground truth for one client from the labels CSV."""
    client_ip: str
    label: str          # "benign" or "malicious"
    scenario: str


@dataclass
class EvalResult:
    """Confusion matrix and the detail an analyst needs to act on it."""
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    # scenario -> {"clients": int, "detected": int, "label": str}
    per_scenario: dict[str, dict] = field(default_factory=dict)
    # (ip, scenario, rule_ids) for benign clients we flagged
    false_positives: list[tuple[str, str, tuple[str, ...]]] = field(default_factory=list)
    # (ip, scenario) for malicious clients we did not flag
    missed: list[tuple[str, str]] = field(default_factory=list)
    # flagged clients absent from the labels: (ip, rule_ids)
    unlabelled_flagged: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)
    min_severity: str | None = None
    labels_skipped: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn


# --------------------------------------------------------------------------
# Pure helpers (unit tested directly)
# --------------------------------------------------------------------------

def safe_div(num: float, den: float) -> float:
    """Divide, returning 0.0 instead of raising when the denominator is 0.

    No flags at all gives precision 0/0. We report 0.0 rather than crash:
    an engine that flags nobody has not earned a perfect precision score.
    """
    return num / den if den else 0.0


def compute_metrics(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    """Return (precision, recall, f1) for the given confusion counts."""
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    return precision, recall, f1


def load_labels(path: str | Path) -> tuple[dict[str, Label], int]:
    """Read ``client_ip,label,scenario`` rows. Returns (labels by ip, rows skipped).

    Tolerant of the things hand-edited CSVs pick up: surrounding whitespace,
    upper-case labels, blank lines, a missing scenario column. Rows with no
    IP or an unknown label are skipped and counted, not fatal. If one IP is
    listed twice with conflicting labels, ``malicious`` wins: scoring a real
    attacker as benign would hide a miss, which is the costlier mistake.
    """
    labels: dict[str, Label] = {}
    skipped = 0
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            return labels, 0
        reader.fieldnames = [(name or "").strip().lower() for name in reader.fieldnames]
        if "client_ip" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError(
                f"{path}: labels CSV needs columns client_ip,label,scenario; "
                f"got {','.join(reader.fieldnames)}"
            )
        for row in reader:
            ip = (row.get("client_ip") or "").strip()
            label = (row.get("label") or "").strip().lower()
            scenario = (row.get("scenario") or "").strip() or "unspecified"
            if not ip and not label:
                continue                      # blank line
            if not ip or label not in VALID_LABELS:
                skipped += 1
                continue
            existing = labels.get(ip)
            if existing is not None and existing.label == MALICIOUS and label == BENIGN:
                continue
            labels[ip] = Label(ip, label, scenario)
    return labels, skipped


def flagged_clients(result: ScanResult, min_severity: str | None = None) -> dict[str, tuple[str, ...]]:
    """Map each flagged client IP to the sorted rule ids behind its incidents.

    Only incidents at or above ``min_severity`` count. A client with several
    incidents (should not happen after correlation, but cheap to handle) has
    its rule ids merged.
    """
    floor = SEVERITY_RANK[min_severity] if min_severity else 0
    rules: dict[str, set[str]] = {}
    for incident in result.incidents:
        if SEVERITY_RANK.get(incident.severity, 0) < floor:
            continue
        bucket = rules.setdefault(incident.client_ip, set())
        bucket.update(alert.rule_id for alert in incident.alerts)
    return {ip: tuple(sorted(ids)) for ip, ids in rules.items()}


def score(labels: dict[str, Label], flagged: dict[str, tuple[str, ...]],
          min_severity: str | None = None) -> EvalResult:
    """Build the confusion matrix from ground truth and the flagged set."""
    res = EvalResult(min_severity=min_severity)
    for ip in sorted(labels):
        lab = labels[ip]
        hit = ip in flagged
        bucket = res.per_scenario.setdefault(
            lab.scenario, {"clients": 0, "detected": 0, "label": lab.label})
        if bucket["label"] != lab.label:
            bucket["label"] = "mixed"
        bucket["clients"] += 1
        bucket["detected"] += int(hit)
        if lab.label == MALICIOUS:
            if hit:
                res.tp += 1
            else:
                res.fn += 1
                res.missed.append((ip, lab.scenario))
        else:
            if hit:
                res.fp += 1
                res.false_positives.append((ip, lab.scenario, flagged[ip]))
            else:
                res.tn += 1
    res.unlabelled_flagged = [(ip, flagged[ip]) for ip in sorted(flagged) if ip not in labels]
    res.precision, res.recall, res.f1 = compute_metrics(res.tp, res.fp, res.fn)
    return res


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def _default_run() -> Callable[..., ScanResult]:
    from watchtower.engine import run   # lazy: lets tests run without the engine
    return run


def _resolve_config(config):
    """Accept a Config object, a path to a YAML file, or None."""
    if isinstance(config, (str, Path)):
        from watchtower.config import load_config
        return load_config(config)
    return config


def evaluate(log_path: str | Path, labels_path: str | Path, config=None, *,
             min_severity: str | None = None,
             run_fn: Callable[..., ScanResult] | None = None,
             fmt: str = "auto") -> EvalResult:
    """Run the engine over ``log_path`` and score it against ``labels_path``.

    ``config`` may be a Config, a path to a rules YAML, or None (defaults).
    ``run_fn`` replaces ``watchtower.engine.run``; tests pass a fake engine.
    """
    if min_severity is not None and min_severity not in SEVERITY_RANK:
        raise ValueError(f"min_severity must be one of {', '.join(SEVERITIES)}")
    labels, skipped = load_labels(labels_path)
    run = run_fn or _default_run()
    result = run([str(log_path)], config=_resolve_config(config), fmt=fmt)
    res = score(labels, flagged_clients(result, min_severity), min_severity)
    res.labels_skipped = skipped
    return res


# --------------------------------------------------------------------------
# Presentation
# --------------------------------------------------------------------------

def safe_text(value: object) -> str:
    """Replace control characters in log-derived text with '?' before printing.

    Client IPs (from JSON logs or X-Forwarded-For setups), scenario names and
    CSV headers are not trusted. An ANSI escape such as ``\x1b[2J`` would
    otherwise clear the analyst's terminal and could paint a fake "all clear"
    over the real result.
    """
    return "".join(ch if ch.isprintable() else "?" for ch in str(value))


def _rules(rules) -> str:
    return ", ".join(safe_text(r) for r in rules)


def _pct(x: float) -> str:
    return f"{x * 100:5.1f}%"


def format_table(res: EvalResult) -> str:
    """Render the result as plain text an analyst can paste into a ticket."""
    lines: list[str] = []
    floor = res.min_severity or "low"
    lines.append(f"WATCHTOWER evaluation (incidents counted at severity >= {floor})")
    lines.append("")
    width = max([len("Scenario")] + [len(safe_text(s)) for s in res.per_scenario])
    lines.append(f"{'Scenario':<{width}}  {'Label':<9}  {'Clients':>7}  {'Flagged':>7}  Result")
    lines.append(f"{'-' * width}  {'-' * 9}  {'-' * 7}  {'-' * 7}  {'-' * 6}")
    order = sorted(res.per_scenario.items(), key=lambda kv: (kv[1]["label"] != MALICIOUS, kv[0]))
    for name, b in order:
        if b["label"] == MALICIOUS:
            outcome = "ok" if b["detected"] == b["clients"] else "MISSED"
        elif b["label"] == BENIGN:
            outcome = "ok" if b["detected"] == 0 else "FALSE POS"
        else:
            outcome = "mixed"
        lines.append(f"{safe_text(name):<{width}}  {b['label']:<9}  {b['clients']:>7}  {b['detected']:>7}  {outcome}")
    lines.append("")
    lines.append(f"TP {res.tp}   FP {res.fp}   FN {res.fn}   TN {res.tn}   (clients: {res.total})")
    lines.append(f"Precision {_pct(res.precision)}   Recall {_pct(res.recall)}   F1 {_pct(res.f1)}")
    if res.false_positives:
        lines.append("")
        lines.append("False positives (benign clients flagged):")
        for ip, scenario, rules in res.false_positives:
            lines.append(f"  {safe_text(ip):<16} {safe_text(scenario):<24} "
                         f"rules: {_rules(rules) or '(none)'}")
    if res.missed:
        lines.append("")
        lines.append("Missed (malicious clients not flagged):")
        for ip, scenario in res.missed:
            lines.append(f"  {safe_text(ip):<16} {safe_text(scenario)}")
    if res.unlabelled_flagged:
        lines.append("")
        lines.append("Flagged but not in labels (excluded from metrics):")
        for ip, rules in res.unlabelled_flagged:
            lines.append(f"  {safe_text(ip):<16} rules: {_rules(rules)}")
    if res.labels_skipped:
        lines.append("")
        lines.append(f"Note: {res.labels_skipped} label row(s) skipped (no IP or unknown label).")
    return "\n".join(lines)


def verdict(res: EvalResult, min_recall: float) -> str:
    """One line: PASS/FAIL against the recall gate, plus the headline numbers."""
    status = "PASS" if res.recall >= min_recall else "FAIL"
    return (f"VERDICT: {status} - caught {res.tp}/{res.tp + res.fn} malicious clients "
            f"(recall {res.recall:.2f}, gate {min_recall:.2f}), "
            f"{res.fp} false positive(s), precision {res.precision:.2f}, F1 {res.f1:.2f}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="evaluate.py",
        description="Score WATCHTOWER detections against a labels CSV (client_ip,label,scenario).")
    p.add_argument("log", help="access log to scan")
    p.add_argument("labels", help="labels CSV with columns client_ip,label,scenario")
    p.add_argument("--config", default=None, help="rules YAML (default: rules/default.yaml)")
    p.add_argument("--format", dest="fmt", default="auto",
                   choices=("auto", "combined", "common", "jsonl"))
    p.add_argument("--min-severity", choices=SEVERITIES, default=None,
                   help="count only incidents at or above this severity as flags")
    p.add_argument("--min-recall", type=float, default=0.0,
                   help="exit 1 if recall falls below this (0.0-1.0, default 0.0)")
    return p


def main(argv: list[str] | None = None, run_fn: Callable[..., ScanResult] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 0.0 <= args.min_recall <= 1.0:
        print("error: --min-recall must be between 0.0 and 1.0", file=sys.stderr)
        return 2
    for path in (args.log, args.labels):
        if not Path(path).is_file():
            print(f"error: no such file: {safe_text(path)}", file=sys.stderr)
            return 2
    try:
        res = evaluate(args.log, args.labels, args.config, min_severity=args.min_severity,
                       run_fn=run_fn, fmt=args.fmt)
    except ValueError as exc:
        print(f"error: {safe_text(exc)}", file=sys.stderr)
        return 2
    print(format_table(res))
    print()
    print(verdict(res, args.min_recall))
    return 0 if res.recall >= args.min_recall else 1


if __name__ == "__main__":
    sys.exit(main())
