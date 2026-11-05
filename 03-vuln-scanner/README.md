# Project 3: Passive vulnerability scanner

Maps a web application's attack surface, identifies the software it runs, matches versions against known CVEs, and runs safe non-destructive checks.

A miniature version of what tools like Burp Suite, Nuclei or Nikto do. Building one from scratch teaches you what those tools are actually doing underneath.

```bash
cd 03-vuln-scanner
python scanner.py http://testphp.vulnweb.com --max-pages 15
# writes report.md and report.json
```

## What it does

| Phase | What happens | Why it matters |
|---|---|---|
| Attack-surface mapping | Crawls pages, records forms, input names, query parameters, JS files | The "recon" phase: you cannot test what you have not found |
| Fingerprinting | Identifies software from headers, HTML meta tags, JS library banners | A known version is a searchable version |
| CVE matching | Queries the NIST NVD API with CPE names from fingerprints | Turns a version number into a list of known vulnerabilities |
| Safe active checks | Reflected-XSS probes (harmless marker only), open-redirect checks, directory listing, sensitive file detection | Finds real issues without sending destructive payloads |
| Reporting | Markdown + JSON report, findings sorted by severity | Mirrors how a real pentest report is structured |

## Lesson plan

| Lesson | Topic | What you learn |
|---|---|---|
| 1 | Lab setup | Running Juice Shop / DVWA in Docker; why scanning happens in a lab |
| 2 | Attack-surface mapping | Extending the crawler to record forms, inputs, query params and JS files |
| 3 | Fingerprinting | Identifying software from headers, HTML meta tags, JS library banners |
| 4 | CVE matching | Querying NIST NVD with CPE names; understanding CVSS scores |
| 5 | Safe active checks | Reflected-XSS probes, open-redirect checks; why we never send destructive payloads |
| 6 | Reporting | Severity triage and writing findings the way a pentest report does |

## Safety

Only scan targets you own or that explicitly invite testing:
- `testphp.vulnweb.com` (Acunetix's public test site)
- OWASP Juice Shop running locally in Docker
- DVWA running locally in Docker

The scanner obeys `robots.txt`, waits between requests, and never sends destructive payloads. The XSS check uses a harmless alphanumeric marker (`xsscanary7v9k2`), not an actual script tag.

## What I learned

- Fingerprinting is shockingly effective: a single `Server` header or `<meta generator>` tag reveals exact software versions, which map directly to CVE databases.
- The NIST NVD API uses CPE (Common Platform Enumeration) names — a structured naming scheme that turns "Apache 2.4.51" into a searchable identifier.
- Most real-world vulnerabilities are found through version matching, not through active exploitation. A scanner that never sends a payload can still find critical issues.
- The difference between a "safe" check and a "destructive" one is the difference between looking and touching. Reflected XSS detection only requires checking whether input appears in the response — no actual script execution needed.
