# Security compliance report

**Target:** testphp.vulnweb.com
**Generated:** 2026-10-28T05:30:00Z
**Frameworks:** CIS, OWASP

## Summary

**Compliance score: 20%**

| Status | Count |
|---|---|
| PASS | 2 |
| FAIL | 8 |
| WARN | 0 |
| N/T | 5 |

## OWASP controls

| ID | Control | Status | Severity | Findings |
|---|---|---|---|---|
| A01 | Broken Access Control | N/T | critical | Requires manual review or specialised scanning |
| A02 | Cryptographic Failures | FAIL | critical | Site does not use HTTPS |
| A03 | Injection | FAIL | critical | SQL injection in /products?id=; XSS in /search |
| A04 | Insecure Design | N/T | high | Requires manual review or specialised scanning |
| A05 | Security Misconfiguration | FAIL | high | Missing CSP; Missing HSTS; Server reveals nginx/1.19.0 |
| A06 | Vulnerable and Outdated Components | FAIL | high | CVE-2019-11043 in PHP 5.6.40 (CVSS 9.8) |
| A07 | Identification and Authentication Failures | N/T | high | Requires manual review or specialised scanning |
| A08 | Software and Data Integrity Failures | N/T | high | Requires manual review or specialised scanning |
| A09 | Security Logging and Monitoring Failures | N/T | high | Requires manual review or specialised scanning |
| A10 | Server-Side Request Forgery (SSRF) | FAIL | high | Requires manual review or specialised scanning |

## CIS controls

| ID | Control | Status | Severity | Findings |
|---|---|---|---|---|
| CIS-TLS | Transport Layer Security | FAIL | critical | Site does not use HTTPS |
| CIS-HDR | Security Headers | FAIL | high | Missing CSP; Missing HSTS; Missing X-Frame-Options |
| CIS-COOKIE | Cookie Security | FAIL | high | Cookie 'login' missing Secure; Cookie 'login' missing HttpOnly |
| CIS-DISC | Information Disclosure | PASS | medium | Server header reveals nginx/1.19.0 but no internal paths |
| CIS-CERT | Certificate Management | PASS | critical | No HTTPS — certificate check not applicable |

## Remediation plan

Priority order (critical first):

1. **A02 — Cryptographic Failures** (critical)
   Use TLS 1.2+ everywhere; encrypt data at rest; avoid deprecated algorithms

2. **A03 — Injection** (critical)
   Use parameterised queries; validate and sanitise all input; use ORMs

3. **CIS-TLS — Transport Layer Security** (critical)
   Configure TLS 1.2+ on all endpoints; disable TLS 1.0/1.1; use HSTS

4. **A05 — Security Misconfiguration** (high)
   Harden all environments; remove defaults; disable directory listing; review cloud permissions

5. **A06 — Vulnerable and Outdated Components** (high)
   Maintain a software inventory; monitor CVE databases; automate dependency updates

6. **CIS-HDR — Security Headers** (high)
   Add CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy

7. **CIS-COOKIE — Cookie Security** (high)
   Set Secure, HttpOnly, and SameSite=Strict on all session cookies
