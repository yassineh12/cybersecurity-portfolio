# Vulnerability scan: testphp.vulnweb.com

Scanned 15 pages on 2026-10-28.

## Software fingerprints

| Software | Version | Source | CPE |
|---|---|---|---|
| nginx | 1.19.0 | `Server` header | cpe:2.3:a:f5:nginx:1.19.0 |
| PHP | 5.6.40 | `X-Powered-By` header | cpe:2.3:a:php:php:5.6.40 |

## CVE matches

| CVE | CVSS | Software | Summary |
|---|---|---|---|
| CVE-2021-23017 | 7.7 | nginx 1.19.0 | Off-by-one in DNS resolver allows crash or code execution |
| CVE-2019-11043 | 9.8 | PHP 5.6.40 | Buffer underflow in FPM allows remote code execution |
| CVE-2020-7068 | 3.6 | PHP 5.6.40 | Use-after-free in phar extension |

## Active checks

### Reflected XSS

| URL | Parameter | Evidence |
|---|---|---|
| `/search.php?test=` | `test` | Marker `xsscanary7v9k2` reflected unescaped in response body |
| `/listproducts.php?cat=` | `cat` | Marker reflected inside an unquoted HTML attribute |

### Open redirect

No open redirects found.

### Directory listing

| URL | Files exposed |
|---|---|
| `/admin/` | `index.bak`, `config.old`, `users.sql` |

### Sensitive files

| URL | Status | Risk |
|---|---|---|
| `/.git/HEAD` | 200 | Git repository exposed — full source code can be reconstructed |
| `/phpinfo.php` | 200 | Server configuration exposed including file paths and loaded modules |

## Attack surface

- **Forms found:** 4 (login, search, contact, file upload)
- **Query parameters observed:** 7
- **JavaScript files:** 3

## Summary

Critical findings: PHP 5.6.40 has a known RCE (CVE-2019-11043), two reflected XSS vectors exist, and a `.git` directory is publicly accessible. Recommended priority: upgrade PHP, sanitise reflected input, and block access to `.git` and `phpinfo.php`.
