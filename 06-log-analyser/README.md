# Project 6: Web log analyser (detection engineering)

Parses Apache/nginx access logs, identifies suspicious behaviour, and produces an incident report. The purple-team keystone: attack your own lab with project 3's scanner, then feed the logs into this analyser and watch it catch you.

```bash
cd 06-log-analyser
python analyser.py /var/log/nginx/access.log --out incident-report
```

## Detection rules

| Rule | Severity | What it catches |
|---|---|---|
| Scanner user-agent | High | Known tools: Nikto, Nmap, SQLMap, WPScan, DirBuster, Gobuster, Nuclei, Burp Suite, ZAP, Acunetix, Nessus |
| Brute-force | Critical | 10+ failed POST requests to login endpoints from one IP |
| SQL injection | Critical | UNION SELECT, OR 1=1, SLEEP(), BENCHMARK() patterns in request paths |
| XSS attempt | High | `<script>`, `javascript:`, event handler patterns in request paths |
| Path traversal | High | `../`, `/etc/passwd`, `/proc/self` patterns |
| Sensitive probing | Medium | 3+ requests to admin panels, .env, .git, phpMyAdmin, server-status |
| Directory scan | Medium | 50+ 404 responses from one IP (automated path guessing) |

## The purple-team story

1. Run project 3's vulnerability scanner against your local Juice Shop
2. Collect the access logs from the Juice Shop container
3. Feed them into this analyser
4. The report shows exactly what you did: the scanner user-agent, the paths you probed, the injection patterns you tested

Offence and defence in one portfolio. That is what "purple team" means, and it is rare in junior portfolios.

## How it processes logs

1. **Parse** — regex extracts IP, timestamp, method, path, status, user-agent from each line (combined log format)
2. **Group** — entries are grouped by source IP
3. **Detect** — each detection rule runs against every IP's request history
4. **Report** — alerts are sorted by severity, with top IPs, status distribution, and evidence

## Safety

This tool reads log files. It sends no network traffic. The logs must come from systems you own or are authorised to investigate.

## What I learned

- Detection engineering is pattern matching under uncertainty. Every rule is a trade-off between catching real attacks (true positives) and not flooding analysts with noise (false positives).
- URL-decoding matters: attackers encode payloads (`%27` for `'`, `%3C` for `<`) to bypass naive string matching. The analyser decodes before matching.
- Brute-force detection needs a threshold, and the right threshold depends on the application. Ten failed logins in a minute is suspicious; ten in a day might be forgetful users.
- The same scanner that looks suspicious in logs is the same tool a penetration tester uses with permission. Context — who authorised it, when, against what scope — separates attack from assessment.
