# Cybersecurity portfolio

[![Tests](https://github.com/yassineh12/cybersecurity-portfolio/actions/workflows/tests.yml/badge.svg)](https://github.com/yassineh12/cybersecurity-portfolio/actions/workflows/tests.yml)

Seven projects that build on each other. Together they cover the defensive, analytical and offensive sides of web security — from headers auditing through machine-learning classification to purple-team detection engineering.

| # | Project | Status | Skills shown |
|---|---|---|---|
| 1 | [Security headers & TLS auditor](01-headers-auditor/) | Complete | HTTP, TLS, OWASP secure-configuration, polite crawling |
| 2 | [Phishing site detector](02-phishing-detector/) | Complete | Threat intel data, feature engineering, ML classification |
| 3 | [Passive vulnerability scanner](03-vuln-scanner/) | Complete | Recon, fingerprinting, CVE matching, safe XSS checks |
| 4 | [Subdomain & CT recon](04-subdomain-recon/) | Complete | Certificate transparency, attack-surface management, passive recon |
| 5 | [Secrets scanner for JS bundles](05-secrets-scanner/) | Complete | AppSec, regex-based detection, cloud security |
| 6 | [Web log analyser](06-log-analyser/) | Complete | SOC analysis, detection engineering, incident response |
| 7 | [Phishing detector API](07-phishing-api/) | Complete | Security engineering, Docker, MLOps, REST APIs |

What comes next: see [ROADMAP.md](ROADMAP.md).

Project 1's `crawler.py` is shared: projects 2, 3, and 5 reuse it. Project 6 detects what project 3 does — offence and defence in one portfolio.

## Setup

```bash
pip install -r requirements.txt
python -m pytest
```

## Ethics and scope

Only crawl or scan sites you own, sites that invite testing (for example `testphp.vulnweb.com`, OWASP Juice Shop or DVWA running locally), or assets inside a bug-bounty programme's stated scope. The crawler obeys `robots.txt` and waits between requests by default. Keep those defaults.
