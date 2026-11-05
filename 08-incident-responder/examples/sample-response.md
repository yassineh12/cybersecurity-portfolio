# Incident response report

Generated: 2026-10-28T03:15:42Z

## Summary

- **Total alerts:** 8
- **Unique source IPs:** 3
- **IOCs extracted:** 6
- **Firewall rules generated:** 2

| Severity | Count |
|---|---|
| Critical | 3 |
| High | 4 |
| Medium | 1 |

## Timeline

| Time | Source IP | Event | Severity | Detail |
|---|---|---|---|---|
| 27/Oct/2026:22:14:03 +0000 | 203.0.113.42 | brute-force | critical | 87 failed login attempts |
| 27/Oct/2026:23:38:00 +0000 | 198.51.100.7 | scanner-detected | high | Scanner user-agent: Nikto/2.1.6 |
| 27/Oct/2026:23:38:52 +0000 | 198.51.100.7 | xss-attempt | high | XSS pattern in /search?q=%3Cscript%3Ealert(1)%3C/script%3E |
| 27/Oct/2026:23:39:44 +0000 | 198.51.100.7 | path-traversal | high | Path traversal in /download?file=../../../../etc/passwd |
| 27/Oct/2026:23:41:08 +0000 | 198.51.100.7 | sqli-attempt | critical | UNION SELECT in /products?id=1 |
| 27/Oct/2026:23:41:15 +0000 | 198.51.100.7 | sqli-attempt | critical | OR 1=1 in /login?user= |
| 27/Oct/2026:14:30:00 +0000 | 10.0.0.5 | directory-scan | medium | 247 requests returned 404 |

## Indicators of compromise

| Type | Value | Severity | Context |
|---|---|---|---|
| ip | `203.0.113.42` | critical | Triggered brute-force: 87 failed login attempts |
| ip | `198.51.100.7` | critical | Triggered sqli-attempt: UNION SELECT in /products |
| user_agent | `Nikto/2.1.6` | high | Known scanner tool |
| payload | `UNION SELECT` | critical | Attack pattern from 198.51.100.7 |
| payload | `<script>` | high | Attack pattern from 198.51.100.7 |
| payload | `../../../../` | high | Attack pattern from 198.51.100.7 |

## Firewall rules

```bash
#!/bin/bash
# Auto-generated firewall rules — review before applying

iptables -A INPUT -s 203.0.113.42 -j DROP  # Block 203.0.113.42: brute-force attack
iptables -A INPUT -s 198.51.100.7 -j DROP  # Block 198.51.100.7: SQLi, XSS, traversal
```

## YARA rules

```yara
rule detect_sqli_patterns {
    meta:
        description = "SQL injection patterns observed in incident"
        generated = "auto"
    strings:
        $sqli_0 = "UNION SELECT" nocase
        $sqli_1 = "OR 1=1" nocase
    condition:
        any of them
}

rule detect_xss_patterns {
    meta:
        description = "XSS patterns observed in incident"
        generated = "auto"
    strings:
        $xss_0 = "<script" nocase
    condition:
        any of them
}

rule detect_traversal_patterns {
    meta:
        description = "Path traversal patterns observed in incident"
        generated = "auto"
    strings:
        $trav_0 = "../../../../" nocase
    condition:
        any of them
}
```

## Recommendations

1. Block the following IPs at the firewall immediately: 198.51.100.7, 203.0.113.42
2. Implement rate limiting on authentication endpoints (max 5 attempts per minute per IP)
3. Enable account lockout after 10 consecutive failed attempts
4. Deploy MFA on all user-facing login pages
5. Audit all database queries for parameterised statements — replace string concatenation with bound parameters
6. Deploy a WAF rule to block common SQL injection patterns
7. Check database logs for successful data exfiltration during the attack window
8. Implement output encoding on all user-controlled input rendered in HTML
9. Add Content-Security-Policy header to restrict inline script execution
10. Validate file paths against an allowlist; reject any path containing '..'
11. Run the application with minimal filesystem permissions
12. Review the full request log from scanner IPs for any successful exploitation (HTTP 200 on sensitive endpoints)
