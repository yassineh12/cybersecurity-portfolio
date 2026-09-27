# Project 3: Passive vulnerability scanner (guided, planned)

**Goal:** map a web application, identify the software it runs, and match those versions against known vulnerabilities (CVEs). Add a few *safe*, non-destructive checks on top.

It is a miniature version of the first stage of tools like Burp Suite, Nuclei or Nikto. Building one yourself is the best way to understand what those tools are actually doing.

**Targets:** only [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) or [DVWA](https://github.com/digininja/DVWA), running locally in Docker, and `testphp.vulnweb.com`. Sending test payloads to a site without permission is illegal in most countries, even "harmless" ones.

## Lesson plan

| Lesson | Topic | What you'll learn |
|---|---|---|
| 1 | Lab setup | Running Juice Shop / DVWA in Docker; why scanning happens in a lab |
| 2 | Attack-surface mapping | Extending the project 1 crawler to record forms, input names, query parameters and JS files. This is the "recon" phase of a pentest |
| 3 | Fingerprinting | Identifying software and versions from headers, HTML meta tags, JS library banners and file hashes |
| 4 | CVE matching | Querying the NIST NVD API with CPE names; understanding CVSS scores |
| 5 | Safe active checks | Reflected-XSS probes with a harmless unique marker, open-redirect checks, and why we never send destructive payloads |
| 6 | Reporting | Severity triage and writing findings the way a pentest report does |

We start this after project 2's lesson 2.
