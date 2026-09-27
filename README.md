# Cybersecurity portfolio

Three projects that build on each other. Together they cover the defensive, analytical and offensive sides of web security.

| # | Project | Status | Skills shown |
|---|---|---|---|
| 1 | [Security headers & TLS auditor](01-headers-auditor/) | Complete | HTTP, TLS, OWASP secure-configuration, polite crawling |
| 2 | [Phishing site detector](02-phishing-detector/) | Lesson 1 of 4 | Threat intel data, feature engineering, ML classification |
| 3 | [Passive vulnerability scanner](03-vuln-scanner/) | Planned | Recon, fingerprinting, CVE matching, safe XSS checks |

Project 1's `crawler.py` is shared: project 2 uses it to collect legitimate URLs, and project 3 will use it to map a target.

## Setup

```bash
pip install -r requirements.txt
python -m pytest
```

## Ethics and scope

Only crawl or scan sites you own, sites that invite testing (for example `testphp.vulnweb.com`, OWASP Juice Shop or DVWA running locally), or assets inside a bug-bounty programme's stated scope. The crawler obeys `robots.txt` and waits between requests by default. Keep those defaults.
