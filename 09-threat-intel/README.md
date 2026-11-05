# Project 9: Threat intelligence enricher

Takes raw indicators of compromise (IOCs) from project 8's incident response output and enriches them with context: IP classification, reputation scoring, DNS records, MITRE ATT&CK mappings, and related-IOC linking. No API keys required — all analysis runs locally using RFC-based IP classification and heuristic scoring.

```bash
cd 09-threat-intel

# From project 8's response package:
python enricher.py ../08-incident-responder/response.json --out enriched-report

# Quick lookup of individual IPs:
python enricher.py --ip 198.51.100.7 --ip 203.0.113.42 --out quick-check
```

## What it produces

| Output | Purpose |
|---|---|
| Reputation scores (0–100) | Prioritise which IOCs need immediate action |
| MITRE ATT&CK mapping | Link observed behaviour to the framework SOC teams speak |
| IP classification | Bogon detection, private range flagging, regional registry identification |
| Related IOC linking | Connect payloads back to the IPs that sent them |
| Tags | Machine-readable labels (sqli, xss, scanner, bogon, internal) for downstream tooling |

## How it builds on the portfolio

| Connection | What it reuses |
|---|---|
| Project 8 (incident responder) | Consumes the IOC list directly from the response package |
| Project 6 (log analyser) | The detection rules that produced the original alerts |
| Project 3 (vuln scanner) | The attack traffic that started the chain |

The full cycle: **attack** (project 3) → **detect** (project 6) → **respond** (project 8) → **enrich** (project 9).

## Reputation scoring

The scorer assigns 0–100 based on observable indicators, not third-party databases:

| Signal | Score contribution |
|---|---|
| Known scanner user-agent (Nikto, SQLMap, etc.) | +40 |
| SQL injection payload | +50 |
| XSS payload | +40 |
| Brute-force behaviour | +50 |
| Bogon/reserved IP range | +30 |
| Private IP in external context | +20 |
| Associated with critical-severity alert | +10 |

Confidence is derived from score: high (70+), medium (40–69), low (below 40).

## MITRE ATT&CK coverage

The enricher maps IOC categories to MITRE techniques:

| Category | Techniques |
|---|---|
| Scanner | T1595 (Active Scanning), T1046 (Network Service Discovery) |
| Bruteforcer | T1110 (Brute Force), T1078 (Valid Accounts) |
| Injector | T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter) |

## Safety

This tool processes data locally. DNS resolution (optional, via `--resolve-dns`) sends standard DNS lookups only. No data is sent to third-party services.

## What I learned

- Threat intelligence is enrichment, not collection. Raw IOCs are addresses and strings. Context — what category of threat they represent, which MITRE technique they map to, whether the IP is even routable — turns data into intelligence.
- MITRE ATT&CK is the common language between security teams. Mapping IOCs to techniques lets the SOC analyst, the threat hunter, and the incident commander talk about the same attack in the same terms.
- Bogon detection catches a specific class of spoofing: packets from reserved IP ranges should never arrive from the internet. Their presence in logs means either spoofing or misconfigured internal routing.
- Reputation scoring without external APIs is limited but not useless. Observable behaviour (scanner user-agents, injection payloads, brute-force patterns) carries strong signal on its own.
