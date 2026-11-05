# Project 6: WATCHTOWER, a web-log threat detection engine

WATCHTOWER reads web server access logs and finds the attackers in them. It catches scanners, exploit attempts and brute-force logins. It groups everything one client did into a single scored incident, maps each finding to MITRE ATT&CK and writes a report a SOC analyst can act on.

It is the blue-team half of this portfolio's purple-team story. Project 3 attacks a lab, and WATCHTOWER catches the attack in the logs.

```bash
cd 06-watchtower
python -m watchtower scan examples/hard_access.log --out examples
# writes report.md, report.json and report.html, prints a summary,
# exits 2 if any incident is high or critical
```

See [`examples/report.md`](examples/report.md) for the output, or open `examples/report.html` in a browser.

## What it detects

| Rule | Attacker behaviour | ATT&CK |
|---|---|---|
| `SIG-UA-SCANNER` | Tools that announce themselves: nikto, sqlmap, gobuster, nuclei and others | T1595.002 |
| `SIG-SENSITIVE-PATH` | Probes for `/.env`, `/.git/config`, backups, `/actuator/env` and similar secrets | T1595.003 |
| `SIG-SQLI` | Union, boolean, error-based and time-based SQL injection | T1190 |
| `SIG-XSS` | Script injection in parameters | T1190 |
| `SIG-TRAVERSAL` | `../` in up to four layers of URL encoding, aimed at `/etc/passwd` or `win.ini` | T1190 |
| `SIG-CMDI` | Shell command injection with a real command and argument | T1190 |
| `SIG-LOG4SHELL` | `${jndi:` lookups, including obfuscated forms, in the URL, user agent or referrer | T1190 |
| `BEH-404-BURST` | Path guessing: bursts of 404, 403 or 410, plus a slow window for patient scans | T1595.003 |
| `BEH-BRUTE-FORCE` | Many login POSTs in a window, whatever status the app returns | T1110 |
| `BEH-BRUTE-SUCCESS` | A successful login after a run of failures. The account is probably compromised | T1110 |
| `BEH-RATE-SPIKE` | Request floods from one client | T1499 |

An exploit attempt that the server answered with a 2xx is raised one severity step. A request that reached the application matters more than one that bounced off.

## How it works

```
access logs ─► parsers ─► time-ordered merge ─► allowlist ─► detectors ─► correlate ─► reports
 (combined,                (many files,                     (signature,    (one incident
  common, JSON,             bounded memory)                  behaviour)     per client,
  .gz)                                                                      kill-chain
                                                                            score 0-100)
```

- **Parsers** handle Apache and nginx combined and common formats, nginx JSON lines and gzip. They never crash on junk: scanners send binary, so logs contain it.
- **Detectors** are streaming state machines with per-client sliding windows. State for idle clients is dropped, so a million one-off visitors do not exhaust memory.
- **Correlation** orders each client's alerts into kill-chain stages: recon, exploit, credential access and impact. Recon followed by exploitation, a 2xx answer to an exploit, or a brute-force success raises the score. The formula is in the docstring of `watchtower/correlate.py`.
- **Hostile input** is expected everywhere. Lines over 64 KB are skipped, client fields must be real IP addresses, a truncated `.gz` keeps the events read so far, and every signature regex runs in linear time. A timing test feeds each rule pathological input, because one crafted request that hangs the scanner would blind it.
- **Reports** treat every log string as hostile. Log lines are attacker-controlled, so a report that rendered a logged `<script>` would itself be an XSS. HTML is escaped, Markdown fences cannot be broken out of, and the terminal summary strips ANSI escape codes.

## Tuning

Every threshold lives in [`rules/default.yaml`](rules/default.yaml), with a comment on the trade-off each one makes. Copy it, edit it and pass it with `--config`. Unknown keys are rejected, so a typo cannot silently switch a detector off. Keep the allowlist short: every entry is a blind spot.

## Using it in a pipeline

| Exit code | Meaning |
|---|---|
| 0 | No incident at or above `--fail-on` (default `high`) |
| 1 | The scan cannot be trusted: missing file, invalid config or arguments, nothing parsed, more than `--max-malformed` of the lines malformed (default 0.5), or a file that could not be read to the end |
| 2 | At least one incident at or above `--fail-on` |

An untrustworthy scan beats a finding, so a partial scan exits 1 even when it found something. A silent "all clear" from a log in the wrong format is the failure a pipeline must never miss. Reports are still written when some lines parsed, and `stats.read_errors` names each file that broke.

`--fail-on` is judged on the whole scan. `--min-severity` only trims the report, so it cannot hide a failure from CI.

## Measuring detection quality

A detector nobody measures is a guess. `tools/generate_logs.py` writes deterministic, labelled synthetic logs. It never touches the network and uses only RFC 5737 documentation addresses. `tools/evaluate.py` runs the engine over them and reports precision and recall.

```bash
python tools/generate_logs.py --profile hard --out /tmp/hard.log --labels /tmp/hard.csv --seed 7 --hours 6
python tools/evaluate.py /tmp/hard.log /tmp/hard.csv --min-recall 0.9
```

| Dataset | Before the review round | After |
|---|---|---|
| Easy profile: 6 attackers with textbook signatures | 100% precision, 100% recall | 100%, 100% |
| Adversarial set: 8 evasive attackers, 7 benign look-alikes | 12.5% precision, 12.5% recall | 100%, 100% |
| Hard profile: 11 attackers, including evasive ones, plus benign traps | not yet built | 100%, 100% |

CI runs all three on every push and fails if recall drops below 90%.

**Read the 100% with care.** The adversarial set was built to expose weaknesses, and the fixes were written against it, so it is now a regression test, not an unbiased benchmark. Real traffic will be messier. The next honest step is a fresh holdout set nobody tuned against.

## Known limitations

- **One client, one IP.** An attacker rotating through an IPv6 /64, or a botnet, spreads its traffic below every per-client threshold. Grouping behaviour by network prefix is the next step.
- **No hostnames.** Servers logging resolved hostnames (`HostnameLookups On`) must switch it off, because non-IP client fields are treated as malformed.
- **Huge fields.** Fields over 32 KB are inspected at the head and tail only, so a payload buried in the middle of one is missed.
- **Logs only show requests.** A response body or a `Location` header is not in an access log, so a successful login is inferred from status codes and what the client does next.

## Files

| Path | What it is |
|---|---|
| `watchtower/models.py` | The shared data contract: `LogEvent`, `Alert`, `Incident`, `ScanResult` |
| `watchtower/parsers.py` | Log parsing |
| `watchtower/detectors/` | Signature and behaviour detectors, plus the registry |
| `watchtower/correlate.py` | Incident grouping and scoring |
| `watchtower/engine.py` | The pipeline |
| `watchtower/config.py`, `rules/default.yaml` | Configuration and validation |
| `watchtower/report.py` | Markdown, JSON and HTML reports |
| `watchtower/cli.py` | `python -m watchtower scan` |
| `tools/` | Synthetic log generator and evaluation harness |
| `tests/` | Unit tests and the adversarial regression fixture |
| `TEAM_BRIEF.md` | The build plan: interfaces and file ownership |

## How it was built

WATCHTOWER was built in one hackathon-style session by eight AI agents: one supervisor, two senior developers and five workers. The supervisor wrote the data contract and brief first, so everyone could build at the same time without editing each other's files. Each worker owned one module and its tests. One senior built the engine. The other built the evaluation harness, then attacked the result with hand-made evasive traffic. That review found that the first version scored 12.5% on realistic traffic, and drove the second round of fixes.

## What I learned

- **A perfect score on your own test data proves little.** The first version caught 100% of the generated attacks, because the generator's attackers announced themselves. Precision and recall only mean something on data built to break the detector.
- **False positives are the expensive failure in a SOC.** A search for "dog && cat toys" flagged as command injection trains analysts to ignore the report. Detection rules need structure, not keywords.
- **Attackers adapt to thresholds.** A scan at one request every four seconds walks under a 20-per-minute rule. A second, slower window catches it.
- **Logs are attacker-controlled input.** Every tool that displays them, including your own report, has to escape them.
- **A detector is an attack surface too.** The review found one 268-byte request that hung the scanner for minutes through regex backtracking. An attacker who can blind your detection does not need to evade it.

## Ethics and scope

WATCHTOWER is defensive and passive. It reads log files and sends no traffic. The attack strings in this project are detection signatures and synthetic test data. Analyse only logs you are authorised to handle: server logs contain visitors' IP addresses, which are personal data under GDPR.
