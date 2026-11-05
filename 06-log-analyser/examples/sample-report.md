# Incident report: access.log

Analysed 12,847 log entries spanning 2026-10-27 14:00 to 2026-10-28 02:00.

## Alert summary

| Severity | Count |
|---|---|
| Critical | 2 |
| High | 3 |
| Medium | 1 |

## Alerts

### Critical: Brute-force attack from 203.0.113.42

- **Detections:** 87 failed POST requests to `/login` in 12 minutes
- **Time window:** 2026-10-27 22:14 – 22:26
- **Status codes:** 87× 401
- **Evidence (first 5):**
  ```
  203.0.113.42 - - [27/Oct/2026:22:14:03 +0000] "POST /login HTTP/1.1" 401 0
  203.0.113.42 - - [27/Oct/2026:22:14:11 +0000] "POST /login HTTP/1.1" 401 0
  203.0.113.42 - - [27/Oct/2026:22:14:18 +0000] "POST /login HTTP/1.1" 401 0
  203.0.113.42 - - [27/Oct/2026:22:14:24 +0000] "POST /login HTTP/1.1" 401 0
  203.0.113.42 - - [27/Oct/2026:22:14:31 +0000] "POST /login HTTP/1.1" 401 0
  ```

### Critical: SQL injection attempts from 198.51.100.7

- **Detections:** 14 requests containing SQL injection patterns
- **Patterns matched:** `UNION SELECT`, `OR 1=1`, `' OR ''='`
- **Evidence:**
  ```
  198.51.100.7 - - [27/Oct/2026:23:41:08 +0000] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 4891
  198.51.100.7 - - [27/Oct/2026:23:41:15 +0000] "GET /login?user=admin%27%20OR%20%271%27=%271 HTTP/1.1" 200 2103
  ```

### High: Scanner user-agent detected from 198.51.100.7

- **User-agent:** `Nikto/2.1.6`
- **Requests:** 342 over 18 minutes
- **Note:** same IP as the SQL injection attempts — likely the same attacker

### High: XSS attempts from 198.51.100.7

- **Detections:** 8 requests containing XSS patterns
- **Evidence:**
  ```
  198.51.100.7 - - [27/Oct/2026:23:38:52 +0000] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 3204
  ```

### High: Path traversal attempts from 198.51.100.7

- **Detections:** 6 requests containing traversal patterns
- **Evidence:**
  ```
  198.51.100.7 - - [27/Oct/2026:23:39:44 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 400 0
  ```

### Medium: Directory scanning from 10.0.0.5

- **Detections:** 247 requests returning 404
- **Time window:** 2026-10-27 14:30 – 15:10
- **Note:** internal IP — likely an authorised security scan

## Top source IPs

| IP | Requests | Alerts |
|---|---|---|
| 198.51.100.7 | 370 | 4 (scanner, SQLi, XSS, traversal) |
| 203.0.113.42 | 91 | 1 (brute-force) |
| 10.0.0.5 | 312 | 1 (directory scan, likely authorised) |

## Status code distribution

| Code | Count | Percentage |
|---|---|---|
| 200 | 10,482 | 81.6% |
| 404 | 1,547 | 12.0% |
| 401 | 412 | 3.2% |
| 301 | 289 | 2.2% |
| 500 | 117 | 0.9% |

## Recommendations

1. **Block** 198.51.100.7 and 203.0.113.42 at the WAF or firewall
2. **Investigate** whether the SQL injection at 23:41 returned real data (status 200 suggests the query executed)
3. **Implement** rate limiting on `/login` to cap failed attempts
4. **Confirm** that the scan from 10.0.0.5 was authorised internal testing
