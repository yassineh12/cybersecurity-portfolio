# Project 1: Security headers & TLS auditor

Crawls a website and grades its security configuration from A to F, with a concrete fix for every finding.

```bash
cd 01-headers-auditor
python auditor.py http://testphp.vulnweb.com --max-pages 20
# writes report.md (for people) and report.json (for other tools)
```

## What it checks

| Area | Check | Why it matters |
|---|---|---|
| Transport | Page served over HTTP | Anyone on the network can read or alter the traffic |
| | `Strict-Transport-Security` missing or short | Without it, a first visit can be downgraded to HTTP |
| | TLS version below 1.2, certificate untrusted or expiring | Broken or soon-to-break encryption |
| Headers | `Content-Security-Policy` missing, or `unsafe-inline` | CSP is the main defence-in-depth against XSS |
| | No `X-Frame-Options` / `frame-ancestors` | Clickjacking: the site can be framed invisibly |
| | `X-Content-Type-Options: nosniff` missing | Browsers may treat uploads as scripts |
| | `Referrer-Policy` missing | Full URLs, sometimes with tokens, leak to other sites |
| | `Server` / `X-Powered-By` shows a version | Tells attackers exactly which CVEs to try |
| Cookies | Missing `Secure`, `HttpOnly`, `SameSite` | Session theft over HTTP, via XSS, or through CSRF |
| Page | HTTPS page loading `http://` resources | Mixed content undoes HTTPS |
| | Forms posting over HTTP | Passwords sent in clear text |

## Scoring

The score starts at 100. Each distinct issue type costs points once (high −15, medium −8, low −3), however many pages repeat it. A missing header on 50 pages is one misconfiguration, not fifty.

## Files

- `crawler.py`: polite, same-host, breadth-first crawler (robots.txt, delay, page cap)
- `checks.py`: the checks, as pure functions that are easy to test
- `auditor.py`: the command-line tool, scoring and report writing
- `tests/`: unit tests (`python -m pytest tests`)

## Ideas to extend it

- Compare two scans and report what changed (for example, a regression after a deploy)
- Add `Permissions-Policy` and `Cross-Origin-Opener-Policy` checks
- Test whether the server still *accepts* TLS 1.0/1.1, not just which version it negotiates
