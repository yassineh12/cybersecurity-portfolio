"""The individual security checks.

Every check is a plain function that takes data (headers, cookies, HTML) and
returns Findings. None of them touch the network except check_tls, which keeps
them easy to unit-test.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from bs4 import BeautifulSoup

SEVERITY_POINTS = {"high": 15, "medium": 8, "low": 3}


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str        # high / medium / low
    title: str
    fix: str
    url: str
    detail: str = ""


# ---------------------------------------------------------------- headers ---

def check_headers(url: str, headers: dict[str, str]) -> list[Finding]:
    """`headers` must have lower-case names."""
    findings = []
    https = urlparse(url).scheme == "https"
    csp = headers.get("content-security-policy", "")

    def add(id_, sev, title, fix, detail=""):
        findings.append(Finding(id_, sev, title, fix, url, detail))

    if not https:
        add("no-https", "high", "Page served over plain HTTP",
            "Serve every page over HTTPS and redirect HTTP to HTTPS.")

    if https:
        hsts = headers.get("strict-transport-security")
        if not hsts:
            add("hsts-missing", "high", "Strict-Transport-Security header missing",
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.")
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if not m or int(m.group(1)) < 15552000:          # under 180 days
                add("hsts-short", "low", "HSTS max-age shorter than 180 days",
                    "Raise max-age to at least 31536000 (one year).", hsts)

    if not csp:
        add("csp-missing", "medium", "Content-Security-Policy header missing",
            "Define a CSP, starting with \"default-src 'self'\", to limit where scripts can load from.")
    elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
        add("csp-unsafe", "low", "CSP allows 'unsafe-inline' or 'unsafe-eval'",
            "Remove unsafe-* keywords; use nonces or hashes for inline scripts.", csp)

    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        add("clickjacking", "medium", "No clickjacking protection",
            "Add 'X-Frame-Options: DENY' or CSP \"frame-ancestors 'none'\".")

    if headers.get("x-content-type-options", "").lower() != "nosniff":
        add("nosniff-missing", "low", "X-Content-Type-Options is not 'nosniff'",
            "Add 'X-Content-Type-Options: nosniff'.")

    if "referrer-policy" not in headers:
        add("referrer-missing", "low", "Referrer-Policy header missing",
            "Add 'Referrer-Policy: strict-origin-when-cross-origin'.")

    for name in ("server", "x-powered-by", "x-aspnet-version"):
        value = headers.get(name, "")
        if re.search(r"\d", value):                        # a version number leaks
            add("version-leak", "low", f"'{name}' header reveals software version",
                "Strip version numbers from server banners.", f"{name}: {value}")

    return findings


# ---------------------------------------------------------------- cookies ---

def check_cookies(url: str, set_cookie_lines: list[str]) -> list[Finding]:
    findings = []
    https = urlparse(url).scheme == "https"
    for line in set_cookie_lines:
        name = line.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower() for a in line.split(";")[1:]}
        if https and "secure" not in attrs:
            findings.append(Finding("cookie-secure", "medium", f"Cookie '{name}' lacks Secure flag",
                                    "Add the Secure attribute so it is never sent over HTTP.", url))
        if "httponly" not in attrs:
            findings.append(Finding("cookie-httponly", "medium", f"Cookie '{name}' lacks HttpOnly flag",
                                    "Add HttpOnly so JavaScript (and XSS payloads) cannot read it.", url))
        if "samesite" not in attrs:
            findings.append(Finding("cookie-samesite", "low", f"Cookie '{name}' lacks SameSite",
                                    "Add 'SameSite=Lax' (or Strict) to reduce CSRF risk.", url))
    return findings


# ----------------------------------------------------------------- HTML -----

def check_html(url: str, html: str) -> list[Finding]:
    if not html:
        return []
    findings = []
    https = urlparse(url).scheme == "https"
    soup = BeautifulSoup(html, "html.parser")

    if https:
        insecure = [
            tag.get(attr) for tag, attr in
            [(t, "src") for t in soup.find_all(["script", "img", "iframe", "audio", "video", "source"])]
            + [(t, "href") for t in soup.find_all("link")]
            if (tag.get(attr) or "").startswith("http://")
        ]
        if insecure:
            findings.append(Finding("mixed-content", "medium", "HTTPS page loads resources over HTTP",
                                    "Load every resource over HTTPS.", url,
                                    ", ".join(insecure[:3])))

    for form in soup.find_all("form"):
        action = form.get("action", "")
        has_password = form.find("input", {"type": "password"}) is not None
        if action.startswith("http://") or (not https and has_password):
            findings.append(Finding("insecure-form", "high", "Form submits data over plain HTTP",
                                    "Make the form action HTTPS.", url, action or "(same page)"))
    return findings


# ------------------------------------------------------------------ TLS -----

def check_tls(hostname: str, port: int = 443, timeout: float = 10.0) -> tuple[dict, list[Finding]]:
    """Connect once and inspect the TLS version and the certificate."""
    url = f"https://{hostname}"
    info: dict = {"host": hostname}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                info["version"] = tls.version()
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return info, [Finding("cert-invalid", "high", "TLS certificate is not trusted",
                              "Install a valid certificate (e.g. free from Let's Encrypt).",
                              url, exc.verify_message)]
    except (OSError, ssl.SSLError) as exc:
        info["error"] = str(exc)
        return info, []                                  # could not test; not a finding

    findings = []
    if info["version"] in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(Finding("tls-old", "high", f"Server negotiated outdated {info['version']}",
                                "Disable everything below TLS 1.2.", url))

    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    days_left = (expires - datetime.now(timezone.utc)).days
    info["cert_expires"] = expires.date().isoformat()
    info["days_left"] = days_left
    if days_left < 30:
        findings.append(Finding("cert-expiring", "medium", f"Certificate expires in {days_left} days",
                                "Renew it, ideally with automatic renewal.", url))
    return info, findings
