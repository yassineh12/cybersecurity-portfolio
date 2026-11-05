# WATCHTOWER team brief

**Mission:** a defensive detection engine. It reads web access logs, spots scanners, exploit attempts and brute force, correlates them per client into incidents, maps each to MITRE ATT&CK, and writes a report a SOC analyst can act on. This is roadmap project 6: the blue-team half of the purple-team story.

**Defensive only.** WATCHTOWER never sends network traffic. Attack strings appear only as detection signatures and inside synthetic log lines used as test data.

## Ground rules

1. `watchtower/models.py` is the contract. Do not edit it. If you need a change, say so in your final report.
2. Touch only the files you own (table below). Other people are editing the rest right now.
3. Python 3.11+, standard library plus `PyYAML`, `requests`, `beautifulsoup4`, `pytest`. No new dependencies.
4. Test files are named `tests/test_wt_<area>.py` (unique basenames: pytest runs the whole repo from its root). Each test file begins with:
   ```python
   import sys
   from pathlib import Path
   sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
   ```
   then `from watchtower.<module> import ...`.
5. Run your tests with `python -m pytest 06-watchtower/tests/test_wt_<area>.py -q` from the repo root. Do not run git commit, push, or reset. The supervisor commits.
6. Docstrings explain *why* a check matters (the attacker behaviour), the way project 1 does. Keep functions small and pure where possible.
7. Detectors must never raise on odd input. Skip what you cannot use.

## File ownership

| Agent | Role | Owns |
|---|---|---|
| Supervisor | Architecture, integration, commits | `models.py`, `TEAM_BRIEF.md`, `README.md` |
| Senior A (Opus) | Core engine | `engine.py`, `correlate.py`, `config.py`, `cli.py`, `__main__.py`, `detectors/__init__.py`, `rules/default.yaml`, `tests/test_wt_engine.py`, `tests/test_wt_correlate.py`, `tests/test_wt_cli.py` |
| Senior B (Opus) | Quality and evaluation | `tools/evaluate.py`, `tests/test_wt_evaluate.py`; review pass in phase 2 |
| Worker 1 (Sonnet) | Parsers | `parsers.py`, `tests/test_wt_parsers.py` |
| Worker 2 (Sonnet) | Signature detectors | `detectors/signatures.py`, `tests/test_wt_signatures.py` |
| Worker 3 (Sonnet) | Behaviour detectors | `detectors/behaviour.py`, `tests/test_wt_behaviour.py` |
| Worker 4 (Sonnet) | Reporting | `report.py`, `tests/test_wt_report.py` |
| Worker 5 (Sonnet) | Test data and CI | `tools/generate_logs.py`, `tests/test_wt_generate.py`, `/.github/workflows/tests.yml` |

## Interfaces (build exactly to these)

### parsers.py (Worker 1)
```python
def parse_line(line: str, fmt: str = "auto", source: str = "", line_no: int = 0) -> LogEvent | None
def parse_file(path: str | Path, fmt: str = "auto") -> tuple[Iterator[LogEvent], ParseStats]
@dataclass class ParseStats: lines_read: int = 0; lines_parsed: int = 0; lines_malformed: int = 0
```
`fmt` is `"combined"` (Apache/nginx default), `"common"`, `"jsonl"` or `"auto"` (detect per line). `ParseStats` is filled in as the iterator is consumed. `.gz` files are read transparently. Malformed lines return `None` / are counted, never raise.
JSON lines use nginx-style keys: `time` (ISO 8601) or `time_local`, `remote_addr`, `request` or (`method` + `uri`), `status`, `body_bytes_sent`, `http_referer`, `http_user_agent`.

### detectors/signatures.py (Worker 2)
```python
class SignatureDetector:            # implements Detector
    def __init__(self, max_evidence: int = 5): ...
```
Rule ids, all emitted from `flush()` as one alert per (client_ip, rule_id):

| rule_id | Catches | ATT&CK | Base severity |
|---|---|---|---|
| `SIG-UA-SCANNER` | Known scanner user agents (nikto, sqlmap, nmap, nuclei, gobuster, dirbuster, wpscan, masscan, zgrab, acunetix, nessus, ...) | T1595.002 | medium |
| `SIG-SENSITIVE-PATH` | Probes for `/.env`, `/.git/`, `/wp-config.php*`, `/server-status`, `/phpinfo.php`, backup files, `/.aws/credentials`, ... | T1595.003 | medium |
| `SIG-SQLI` | SQL injection patterns in path or query | T1190 | high |
| `SIG-XSS` | Script injection patterns | T1190 | medium |
| `SIG-TRAVERSAL` | `../` and encoded variants, `/etc/passwd`, `win.ini` | T1190 | high |
| `SIG-CMDI` | Shell metacharacter command injection | T1190 | high |
| `SIG-LOG4SHELL` | `${jndi:` and obfuscated variants, also in user agent and referrer | T1190 | critical |

Decode the target (URL-decode twice, `+` to space) before matching. Raise severity one step when an exploit-class attempt (SQLI/XSS/TRAVERSAL/CMDI/LOG4SHELL) got a 2xx answer, and say so in `detail`.

### detectors/behaviour.py (Worker 3)
```python
class EnumerationDetector:   # BEH-404-BURST,   T1595.003, medium
    def __init__(self, threshold: int = 20, window_seconds: int = 60): ...
class BruteForceDetector:    # BEH-BRUTE-FORCE, T1110,     high
                             # BEH-BRUTE-SUCCESS, T1110,   critical (failures then a success)
    def __init__(self, threshold: int = 10, window_seconds: int = 300,
                 login_paths: tuple[str, ...] = ("/login", "/signin", "/wp-login.php", "/admin", "/api/auth", "/user/login")): ...
class RateDetector:          # BEH-RATE-SPIKE,  T1499,     low
    def __init__(self, threshold: int = 300, window_seconds: int = 60): ...
```
Sliding windows per client IP (deque of timestamps). One alert per client per rule: extend `last_seen`/`event_count` while the client keeps going, emit on `flush()`. A failed login is a POST to a login path answered 401, 403, or 200 with the same path re-requested (keep it simple: 401/403 are failures; 2xx/302 after ≥ threshold failures is BEH-BRUTE-SUCCESS).

### correlate.py, engine.py, config.py, cli.py (Senior A)
```python
def correlate(alerts: list[Alert]) -> list[Incident]
def run(paths: list[str | Path], config: Config | None = None, fmt: str = "auto") -> ScanResult
def load_config(path: str | Path | None) -> Config     # None -> rules/default.yaml
def default_detectors(config: Config) -> list[Detector]  # in detectors/__init__.py
```
Kill-chain stages: `recon` (UA scanner, sensitive path, 404 burst), `exploit` (SQLI/XSS/TRAVERSAL/CMDI/LOG4SHELL), `credential-access` (brute force), `impact` (rate spike). An exploit attempt answered 2xx, a brute-force success, or recon followed by exploit raises the score. Allowlisted IPs/CIDRs in config are dropped before detection.
CLI: `python -m watchtower scan LOG [LOG ...] [--config FILE] [--format auto|combined|common|jsonl] [--out DIR] [--min-severity low|medium|high|critical]` writes `report.md`, `report.json`, `report.html` to `--out` (default `.`) and prints a one-screen summary. Exit code 0 if no incidents at or above `--fail-on` (default `high`), 2 otherwise, so it can gate CI.

### ScanResult.stats
Keys: `lines_read`, `lines_parsed`, `lines_malformed`, `events_allowlisted`, `unique_clients`, `time_start`, `time_end` (ISO strings or None), `files` (list of str), `alerts_by_rule` (dict rule_id -> count), `incidents_by_severity` (dict severity -> count).

### report.py (Worker 4)
```python
def to_markdown(result: ScanResult) -> str
def to_json(result: ScanResult) -> str
def to_html(result: ScanResult) -> str      # one self-contained file, inline CSS, no JS libraries, no external requests
def write_reports(result: ScanResult, out_dir: str | Path) -> dict[str, Path]   # keys "md", "json", "html"
```
Escape every log-derived string in HTML (log lines are attacker-controlled: a report that renders `<script>` from a log is itself an XSS). Markdown must neutralise pipes and backticks in table cells.

### tools/generate_logs.py (Worker 5)
```
python tools/generate_logs.py --out examples/sample_access.log --labels examples/sample_labels.csv --seed 7 --hours 6
```
Deterministic for a given seed. Combined log format. Writes nothing to the network. Labels CSV columns: `client_ip,label,scenario` where `label` is `benign` or `malicious`. Use RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) for every IP.
Scenarios: benign browsing users, a polite search-engine crawler, a monitoring health-check, nikto-style scanner, directory enumeration burst, login brute force ending in success, sqlmap-style SQL injection probing, log4shell probe, path-traversal probe, and one "noisy but benign" user who hits several 404s (a false-positive trap).

### tools/evaluate.py (Senior B)
```
python tools/evaluate.py examples/sample_access.log examples/sample_labels.csv
```
Runs the engine, compares flagged clients (any incident) with labels, prints per-scenario detection, precision, recall, F1 and the false positives. Exposes `evaluate(log_path, labels_path, config=None) -> EvalResult` for tests.
