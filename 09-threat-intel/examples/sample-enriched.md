# Threat intelligence report

Generated: 2026-10-28T04:22:15Z
IOCs analysed: 6

## Attack profile

**Threat categories:** bruteforcer, injector, scanner
**High-risk IOCs:** 4

| Severity | Count |
|---|---|
| Critical | 3 |
| High | 2 |
| Medium | 1 |

## MITRE ATT&CK mapping

| Tactic | Technique | Name |
|---|---|---|
| Reconnaissance | T1595 | Active Scanning |
| Discovery | T1046 | Network Service Discovery |
| Credential Access | T1110 | Brute Force |
| Initial Access | T1078 | Valid Accounts |
| Initial Access | T1190 | Exploit Public-Facing Application |
| Execution | T1059 | Command and Scripting Interpreter |

## Enriched IOCs

### `203.0.113.42` (ip)

- **Original severity:** critical
- **Context:** Triggered brute-force: 87 failed login attempts
- **Reputation score:** 80/100 (high confidence)
- **Category:** bruteforcer
  - Bogon/reserved IP range — should never appear in external traffic
  - Brute-force behaviour detected
  - Associated with SQL injection activity
- **Tags:** bogon
- **Registry:** unknown

### `198.51.100.7` (ip)

- **Original severity:** critical
- **Context:** Triggered sqli-attempt: UNION SELECT in /products
- **Reputation score:** 60/100 (medium confidence)
- **Category:** injector
  - Bogon/reserved IP range — should never appear in external traffic
  - Associated with SQL injection activity
- **Tags:** bogon
- **Registry:** unknown

### `Nikto/2.1.6` (user_agent)

- **Original severity:** high
- **Context:** Known scanner tool
- **Reputation score:** 55/100 (medium confidence)
- **Category:** scanner
  - Known scanner tool: nikto
  - Associated with automated scanning
- **Tags:** tool-signature

### `UNION SELECT` (payload)

- **Original severity:** critical
- **Context:** Attack pattern from 198.51.100.7
- **Reputation score:** 70/100 (high confidence)
- **Category:** injector
  - SQL injection pattern: union select
- **Tags:** sqli
- **Related IPs:** 198.51.100.7

### `<script>` (payload)

- **Original severity:** high
- **Context:** Attack pattern from 198.51.100.7
- **Reputation score:** 40/100 (medium confidence)
- **Category:** injector
  - XSS pattern: <script
- **Tags:** xss
- **Related IPs:** 198.51.100.7

### `../../../../` (payload)

- **Original severity:** medium
- **Context:** Path traversal from 198.51.100.7
- **Reputation score:** 10/100 (low confidence)
- **Category:** unknown
  - No specific malicious indicators — review manually
- **Related IPs:** 198.51.100.7
