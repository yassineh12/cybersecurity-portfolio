# Security audit: testphp.vulnweb.com

**Score: 22 / 100 (F)**

Scanned 12 pages on 2026-10-28.

## Findings

### High severity

| Finding | Pages affected | Fix |
|---|---|---|
| Page served over plain HTTP | 12 | Configure TLS and redirect all HTTP to HTTPS |
| `Content-Security-Policy` header missing | 12 | Add a CSP that restricts script sources to your own origin |
| `Strict-Transport-Security` header missing | 12 | Add `Strict-Transport-Security: max-age=63072000; includeSubDomains` |

### Medium severity

| Finding | Pages affected | Fix |
|---|---|---|
| `X-Frame-Options` header missing | 12 | Add `X-Frame-Options: DENY` or use CSP `frame-ancestors 'none'` |
| `X-Content-Type-Options` header missing | 12 | Add `X-Content-Type-Options: nosniff` |
| `Server` header reveals software version: `nginx/1.19.0` | 12 | Remove the version from the `Server` header |
| Cookie `login` missing `Secure` flag | 3 | Set the `Secure` attribute on all cookies |
| Cookie `login` missing `HttpOnly` flag | 3 | Set `HttpOnly` to prevent JavaScript access |

### Low severity

| Finding | Pages affected | Fix |
|---|---|---|
| `Referrer-Policy` header missing | 12 | Add `Referrer-Policy: strict-origin-when-cross-origin` |
| Form on `/login.php` posts over HTTP | 1 | Change the form action to HTTPS |

## Summary

This site fails basic transport security (no TLS, no HSTS) and is missing every recommended security header. An attacker on the same network can read all traffic, including credentials submitted through the login form. Priority: enable HTTPS and add the missing headers before doing anything else.
