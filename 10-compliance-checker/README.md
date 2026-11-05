# Project 10: Security compliance checker

Maps a web application's security posture against the OWASP Top 10 (2021) and CIS-style controls. Can run live checks against a URL or consume scan results from earlier projects to produce a unified compliance matrix.

```bash
cd 10-compliance-checker

# Live check against a URL:
python checker.py https://testphp.vulnweb.com --out compliance

# From existing scan reports:
python checker.py --from-reports ../01-headers-auditor/report.json ../03-vuln-scanner/report.json --out compliance
```

## Frameworks covered

### OWASP Top 10 (2021)

| ID | Control | Automated check |
|---|---|---|
| A01 | Broken Access Control | Manual review |
| A02 | Cryptographic Failures | TLS version, certificate validity |
| A03 | Injection | Consumes vuln scanner results |
| A04 | Insecure Design | Manual review |
| A05 | Security Misconfiguration | Security headers, server disclosure |
| A06 | Vulnerable and Outdated Components | Consumes CVE match results |
| A07 | Identification and Authentication Failures | Manual review |
| A08 | Software and Data Integrity Failures | Manual review |
| A09 | Security Logging and Monitoring Failures | Manual review |
| A10 | Server-Side Request Forgery (SSRF) | Manual review |

### CIS-style controls

| ID | Control | Automated check |
|---|---|---|
| CIS-TLS | Transport Layer Security | TLS version, protocol support |
| CIS-HDR | Security Headers | CSP, HSTS, X-Frame-Options, etc. |
| CIS-COOKIE | Cookie Security | Secure, HttpOnly, SameSite flags |
| CIS-DISC | Information Disclosure | Server/X-Powered-By version leaks |
| CIS-CERT | Certificate Management | Certificate validity and expiration |

## How it builds on the portfolio

This is the capstone: it consumes output from projects 1, 3, 6, and 8 and maps their findings to a compliance framework. A headers scan that found missing CSP becomes an A05 failure. A CVE match from the vulnerability scanner becomes an A06 failure.

| Input source | Controls it feeds |
|---|---|
| Project 1 (headers auditor) | A05, CIS-HDR, CIS-COOKIE, CIS-DISC |
| Project 3 (vuln scanner) | A03, A06 |
| Project 6 (log analyser) | A09 |
| Project 8 (incident responder) | A01 (access patterns) |

## Safety

Live checks send standard HTTP/TLS requests to the target — the same traffic a browser sends. No exploitation, no fuzzing, no authentication bypass. Only check targets you own or that invite testing.

## What I learned

- Compliance is a map, not a destination. Passing every automated check does not mean the application is secure — it means the measurable controls are in place. The unmeasured ones (A01, A04, A07) need manual review.
- The OWASP Top 10 changes over time. "Injection" dropped from A01 to A03 in 2021 because access control failures became more common. The ranking reflects the threat landscape, not the severity of individual attacks.
- Mapping tool output to framework controls is the real skill. Any scanner can find a missing header. Knowing that a missing CSP maps to A05 (Security Misconfiguration) and that the remediation is specific, not generic, is what makes a report useful.
- Automated compliance checking covers about 40% of controls. The rest need human judgment: code review, architecture review, threat modelling. The checker's "not-tested" status is honest, not a gap.
