"""Security compliance checker.

Maps a web application's security posture against the OWASP Top 10 (2021)
and basic CIS-style controls. Takes scan results from earlier projects
(or runs its own checks) and produces a compliance matrix showing which
controls pass, fail, or need manual review.

Usage:
    python checker.py https://testphp.vulnweb.com --out compliance-report
    python checker.py --from-reports headers.json vuln.json --out compliance-report
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import ssl
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

VERSION = "1.1.0"

log = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Control:
    """A single compliance control."""
    framework: str  # OWASP, CIS
    control_id: str  # e.g. A01, A03, CIS-1.1
    name: str
    description: str
    status: str = "not-tested"  # pass, fail, warning, not-tested
    severity: str = "medium"  # critical, high, medium, low, info
    findings: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class ComplianceReport:
    """The full compliance report."""
    target: str
    generated_at: str
    frameworks: list[str] = field(default_factory=list)
    controls: list[Control] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) control definitions
# ---------------------------------------------------------------------------

OWASP_CONTROLS = [
    Control(
        framework="OWASP",
        control_id="A01",
        name="Broken Access Control",
        description="Restrictions on authenticated users are not properly enforced",
        severity="critical",
        remediation="Implement server-side access control; deny by default; enforce record ownership",
    ),
    Control(
        framework="OWASP",
        control_id="A02",
        name="Cryptographic Failures",
        description="Sensitive data exposure through weak or missing encryption",
        severity="critical",
        remediation="Use TLS 1.2+ everywhere; encrypt data at rest; avoid deprecated algorithms",
    ),
    Control(
        framework="OWASP",
        control_id="A03",
        name="Injection",
        description="SQL, NoSQL, OS, and LDAP injection flaws",
        severity="critical",
        remediation="Use parameterised queries; validate and sanitise all input; use ORMs",
    ),
    Control(
        framework="OWASP",
        control_id="A04",
        name="Insecure Design",
        description="Missing or ineffective security controls in the design",
        severity="high",
        remediation="Use threat modelling; implement security design patterns; establish secure development lifecycle",
    ),
    Control(
        framework="OWASP",
        control_id="A05",
        name="Security Misconfiguration",
        description="Missing security hardening, default configurations, verbose errors",
        severity="high",
        remediation="Harden all environments; remove defaults; disable directory listing; review cloud permissions",
    ),
    Control(
        framework="OWASP",
        control_id="A06",
        name="Vulnerable and Outdated Components",
        description="Using components with known vulnerabilities",
        severity="high",
        remediation="Maintain a software inventory; monitor CVE databases; automate dependency updates",
    ),
    Control(
        framework="OWASP",
        control_id="A07",
        name="Identification and Authentication Failures",
        description="Weak authentication mechanisms, credential stuffing, session management",
        severity="high",
        remediation="Implement MFA; enforce strong passwords; rate-limit login attempts",
    ),
    Control(
        framework="OWASP",
        control_id="A08",
        name="Software and Data Integrity Failures",
        description="Code and infrastructure without integrity verification",
        severity="high",
        remediation="Verify digital signatures; use SRI for CDN resources; secure CI/CD pipelines",
    ),
    Control(
        framework="OWASP",
        control_id="A09",
        name="Security Logging and Monitoring Failures",
        description="Insufficient logging and monitoring to detect breaches",
        severity="high",
        remediation="Log authentication events; set up alerting; ensure logs cannot be tampered with",
    ),
    Control(
        framework="OWASP",
        control_id="A10",
        name="Server-Side Request Forgery (SSRF)",
        description="Application fetches remote resources without validating user-supplied URLs",
        severity="high",
        remediation="Validate and sanitise all client-supplied URLs; use allowlists for outbound requests",
    ),
]

NIST_CSF_CONTROLS = [
    Control(
        framework="NIST-CSF",
        control_id="ID.AM",
        name="Asset Management",
        description="Physical devices, software, and data flows are inventoried",
        severity="high",
        remediation="Maintain an accurate inventory of all hardware and software assets",
    ),
    Control(
        framework="NIST-CSF",
        control_id="PR.AC",
        name="Access Control",
        description="Access to assets and associated facilities is limited",
        severity="critical",
        remediation="Implement least-privilege access; use MFA; review permissions regularly",
    ),
    Control(
        framework="NIST-CSF",
        control_id="PR.DS",
        name="Data Security",
        description="Data is managed consistent with risk strategy to protect confidentiality, integrity, and availability",
        severity="critical",
        remediation="Encrypt data in transit and at rest; implement DLP controls",
    ),
    Control(
        framework="NIST-CSF",
        control_id="DE.CM",
        name="Security Continuous Monitoring",
        description="Information system and assets are monitored to identify cybersecurity events",
        severity="high",
        remediation="Deploy SIEM; monitor network traffic; enable audit logging",
    ),
    Control(
        framework="NIST-CSF",
        control_id="RS.RP",
        name="Response Planning",
        description="Response processes and procedures are executed and maintained",
        severity="high",
        remediation="Develop and test incident response plan; conduct tabletop exercises",
    ),
]

CIS_CONTROLS = [
    Control(
        framework="CIS",
        control_id="CIS-TLS",
        name="Transport Layer Security",
        description="All traffic encrypted with TLS 1.2 or higher",
        severity="critical",
        remediation="Configure TLS 1.2+ on all endpoints; disable TLS 1.0/1.1; use HSTS",
    ),
    Control(
        framework="CIS",
        control_id="CIS-HDR",
        name="Security Headers",
        description="All recommended security headers present and correctly configured",
        severity="high",
        remediation="Add CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy",
    ),
    Control(
        framework="CIS",
        control_id="CIS-COOKIE",
        name="Cookie Security",
        description="Session cookies use Secure, HttpOnly, and SameSite attributes",
        severity="high",
        remediation="Set Secure, HttpOnly, and SameSite=Strict on all session cookies",
    ),
    Control(
        framework="CIS",
        control_id="CIS-DISC",
        name="Information Disclosure",
        description="Server does not reveal software versions or internal paths",
        severity="medium",
        remediation="Remove Server/X-Powered-By version info; disable error details in production",
    ),
    Control(
        framework="CIS",
        control_id="CIS-CERT",
        name="Certificate Management",
        description="Valid, unexpired certificates from trusted CAs with proper chain",
        severity="critical",
        remediation="Automate certificate renewal; monitor expiration; use trusted CAs",
    ),
]


# ---------------------------------------------------------------------------
# Live checks (when given a URL, not pre-existing reports)
# ---------------------------------------------------------------------------

REQUIRED_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}


def check_tls(url: str) -> list[str]:
    """Check TLS configuration. Returns a list of findings."""
    findings: list[str] = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        findings.append("Site does not use HTTPS")
        return findings

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, port))
            cert = s.getpeercert()
            version = s.version()

            if version and version < "TLSv1.2":
                findings.append(f"TLS version {version} is below minimum (TLS 1.2)")

            not_after = cert.get("notAfter", "")
            if not_after:
                from email.utils import parsedate_to_datetime
                expiry = parsedate_to_datetime(not_after)
                days_left = (expiry - datetime.now(tz=timezone.utc)).days
                if days_left < 0:
                    findings.append("Certificate has expired")
                elif days_left < 30:
                    findings.append(f"Certificate expires in {days_left} days")
    except Exception as e:
        findings.append(f"TLS check failed: {e}")

    return findings


def check_headers_live(url: str) -> tuple[list[str], dict[str, str]]:
    """Check security headers against a live URL. Returns (findings, raw_headers)."""
    if not HAS_REQUESTS:
        return ["requests library not available — skipping live header check"], {}

    findings: list[str] = []
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=True)
    except Exception as e:
        return [f"Could not fetch {url}: {e}"], {}

    headers = {k.lower(): v for k, v in resp.headers.items()}

    for header, label in REQUIRED_HEADERS.items():
        if header not in headers:
            findings.append(f"Missing {label} header ({header})")

    csp = headers.get("content-security-policy", "")
    if "unsafe-inline" in csp:
        findings.append("CSP contains 'unsafe-inline' which weakens XSS protection")
    if "unsafe-eval" in csp:
        findings.append("CSP contains 'unsafe-eval' which allows dynamic code execution")

    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if re.search(r"[\d.]+", server):
        findings.append(f"Server header reveals version: {server}")
    if powered:
        findings.append(f"X-Powered-By header reveals technology: {powered}")

    return findings, headers


def check_cookies_live(url: str) -> list[str]:
    """Check cookie security attributes."""
    if not HAS_REQUESTS:
        return []

    findings: list[str] = []
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=True)
    except Exception:
        return []

    for cookie in resp.cookies:
        name = cookie.name
        if not cookie.secure:
            findings.append(f"Cookie '{name}' missing Secure flag")
        if "httponly" not in cookie._rest:
            findings.append(f"Cookie '{name}' missing HttpOnly flag")

    return findings


# ---------------------------------------------------------------------------
# Map findings to controls
# ---------------------------------------------------------------------------

import socket


def run_live_checks(url: str, frameworks: list[str] | None = None) -> ComplianceReport:
    """Run all live checks against a URL and produce a compliance report."""
    all_defs = OWASP_CONTROLS + CIS_CONTROLS + NIST_CSF_CONTROLS
    if frameworks:
        fw_set = {f.upper() for f in frameworks}
        all_defs = [c for c in all_defs if c.framework.upper() in fw_set]
    controls = [Control(**{k: v for k, v in asdict(c).items()})
                for c in all_defs]

    header_findings, headers = check_headers_live(url)
    tls_findings = check_tls(url)
    cookie_findings = check_cookies_live(url)

    for ctrl in controls:
        if ctrl.control_id == "A02":
            if tls_findings:
                ctrl.status = "fail"
                ctrl.findings = tls_findings
            elif urlparse(url).scheme == "https":
                ctrl.status = "pass"
                ctrl.findings = ["TLS configured correctly"]
            else:
                ctrl.status = "fail"
                ctrl.findings = ["No HTTPS"]

        elif ctrl.control_id == "A05":
            misconfig = [f for f in header_findings if "Missing" in f or "reveals" in f.lower()]
            if misconfig:
                ctrl.status = "fail"
                ctrl.findings = misconfig
            elif header_findings:
                ctrl.status = "warning"
                ctrl.findings = header_findings
            else:
                ctrl.status = "pass"
                ctrl.findings = ["Security headers properly configured"]

        elif ctrl.control_id == "CIS-TLS":
            if tls_findings:
                ctrl.status = "fail"
                ctrl.findings = tls_findings
            elif urlparse(url).scheme == "https":
                ctrl.status = "pass"
                ctrl.findings = ["TLS 1.2+ in use"]
            else:
                ctrl.status = "fail"
                ctrl.findings = ["Site does not use HTTPS"]

        elif ctrl.control_id == "CIS-HDR":
            missing = [f for f in header_findings if "Missing" in f]
            if missing:
                ctrl.status = "fail"
                ctrl.findings = missing
            else:
                ctrl.status = "pass"
                ctrl.findings = ["All required security headers present"]

        elif ctrl.control_id == "CIS-COOKIE":
            if cookie_findings:
                ctrl.status = "fail"
                ctrl.findings = cookie_findings
            else:
                ctrl.status = "pass"
                ctrl.findings = ["Cookie security attributes set correctly"]

        elif ctrl.control_id == "CIS-DISC":
            disclosure = [f for f in header_findings if "reveals" in f.lower()]
            if disclosure:
                ctrl.status = "fail"
                ctrl.findings = disclosure
            else:
                ctrl.status = "pass"
                ctrl.findings = ["No information disclosure detected"]

        elif ctrl.control_id == "CIS-CERT":
            cert_issues = [f for f in tls_findings if "certificate" in f.lower() or "expired" in f.lower()]
            if cert_issues:
                ctrl.status = "fail"
                ctrl.findings = cert_issues
            elif urlparse(url).scheme == "https":
                ctrl.status = "pass"
                ctrl.findings = ["Certificate valid and trusted"]
            else:
                ctrl.status = "not-tested"
                ctrl.findings = ["No HTTPS — certificate check not applicable"]

        elif ctrl.control_id in ("A01", "A03", "A04", "A06", "A07", "A08", "A09", "A10"):
            ctrl.status = "not-tested"
            ctrl.findings = ["Requires manual review or specialised scanning"]

        elif ctrl.framework == "NIST-CSF":
            if ctrl.control_id == "PR.DS":
                if tls_findings:
                    ctrl.status = "fail"
                    ctrl.findings = tls_findings
                elif urlparse(url).scheme == "https":
                    ctrl.status = "pass"
                    ctrl.findings = ["Data encrypted in transit via TLS"]
                else:
                    ctrl.status = "fail"
                    ctrl.findings = ["No HTTPS — data transmitted in clear text"]
            else:
                ctrl.status = "not-tested"
                ctrl.findings = ["Requires organisational assessment"]

    return _build_report(url, controls)


def from_reports(report_files: list[str], frameworks: list[str] | None = None) -> ComplianceReport:
    """Build compliance report from previously generated scan results."""
    all_defs = OWASP_CONTROLS + CIS_CONTROLS + NIST_CSF_CONTROLS
    if frameworks:
        fw_set = {f.upper() for f in frameworks}
        all_defs = [c for c in all_defs if c.framework.upper() in fw_set]
    controls = [Control(**{k: v for k, v in asdict(c).items()})
                for c in all_defs]

    all_findings: dict[str, list[str]] = {}
    target = "multiple-sources"

    for path_str in report_files:
        path = Path(path_str)
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

        if isinstance(data, dict):
            if "target" in data or "url" in data:
                target = data.get("target", data.get("url", target))

            for finding in data.get("findings", []):
                category = finding.get("category", finding.get("rule", "unknown"))
                desc = finding.get("description", finding.get("detail", str(finding)))
                all_findings.setdefault(category, []).append(desc)

            for alert in data.get("alerts", []):
                rule = alert.get("rule", "unknown")
                detail = alert.get("detail", str(alert))
                all_findings.setdefault(rule, []).append(detail)

    header_keys = {"missing-header", "server-disclosure", "headers", "security-headers"}
    tls_keys = {"tls", "https", "certificate", "transport"}
    injection_keys = {"sqli", "xss", "injection", "sqli-attempt", "xss-attempt"}
    vuln_keys = {"cve", "vulnerability", "outdated", "fingerprint"}

    for ctrl in controls:
        if ctrl.control_id == "A02":
            matched = [f for k, fs in all_findings.items()
                       if any(t in k.lower() for t in tls_keys)
                       for f in fs]
            if matched:
                ctrl.status = "fail"
                ctrl.findings = matched[:5]
            elif all_findings:
                ctrl.status = "pass"
                ctrl.findings = ["No TLS issues found in scan results"]

        elif ctrl.control_id == "A03":
            matched = [f for k, fs in all_findings.items()
                       if any(t in k.lower() for t in injection_keys)
                       for f in fs]
            if matched:
                ctrl.status = "fail"
                ctrl.findings = matched[:5]
            elif all_findings:
                ctrl.status = "pass"

        elif ctrl.control_id == "A05":
            matched = [f for k, fs in all_findings.items()
                       if any(t in k.lower() for t in header_keys)
                       for f in fs]
            if matched:
                ctrl.status = "fail"
                ctrl.findings = matched[:5]
            elif all_findings:
                ctrl.status = "pass"

        elif ctrl.control_id == "A06":
            matched = [f for k, fs in all_findings.items()
                       if any(t in k.lower() for t in vuln_keys)
                       for f in fs]
            if matched:
                ctrl.status = "fail"
                ctrl.findings = matched[:5]
            elif all_findings:
                ctrl.status = "pass"

        elif ctrl.control_id == "CIS-HDR":
            matched = [f for k, fs in all_findings.items()
                       if any(t in k.lower() for t in header_keys)
                       for f in fs]
            if matched:
                ctrl.status = "fail"
                ctrl.findings = matched[:5]

        elif ctrl.control_id == "CIS-TLS":
            matched = [f for k, fs in all_findings.items()
                       if any(t in k.lower() for t in tls_keys)
                       for f in fs]
            if matched:
                ctrl.status = "fail"
                ctrl.findings = matched[:5]

    return _build_report(target, controls)


def grade(pct: int) -> str:
    """Convert a compliance percentage to a letter grade."""
    if pct >= 90:
        return "A"
    if pct >= 80:
        return "B"
    if pct >= 70:
        return "C"
    if pct >= 60:
        return "D"
    return "F"


def _build_report(target: str, controls: list[Control]) -> ComplianceReport:
    """Build the final report with summary statistics."""
    status_counts: dict[str, int] = {"pass": 0, "fail": 0, "warning": 0, "not-tested": 0}
    framework_scores: dict[str, dict[str, int]] = {}

    for ctrl in controls:
        status_counts[ctrl.status] = status_counts.get(ctrl.status, 0) + 1
        fw = ctrl.framework
        if fw not in framework_scores:
            framework_scores[fw] = {"pass": 0, "fail": 0, "warning": 0, "not-tested": 0, "total": 0}
        framework_scores[fw][ctrl.status] += 1
        framework_scores[fw]["total"] += 1

    frameworks = sorted(set(c.framework for c in controls))
    total_testable = status_counts["pass"] + status_counts["fail"] + status_counts["warning"]
    compliance_pct = round(status_counts["pass"] / total_testable * 100) if total_testable else 0

    return ComplianceReport(
        target=target,
        generated_at=datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        frameworks=frameworks,
        controls=controls,
        summary={
            "status_counts": status_counts,
            "framework_scores": framework_scores,
            "compliance_percentage": compliance_pct,
            "grade": grade(compliance_pct),
        },
    )


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

STATUS_ICON = {"pass": "PASS", "fail": "FAIL", "warning": "WARN", "not-tested": "N/T"}


def to_markdown(report: ComplianceReport) -> str:
    """Render the compliance report as markdown."""
    lines = ["# Security compliance report", ""]
    lines.append(f"**Target:** {report.target}")
    lines.append(f"**Generated:** {report.generated_at}")
    lines.append(f"**Frameworks:** {', '.join(report.frameworks)}")
    lines.append("")

    s = report.summary
    pct = s.get("compliance_percentage", 0)
    sc = s.get("status_counts", {})
    lines.append("## Summary")
    lines.append("")
    lines.append(f"**Compliance score: {pct}% (Grade: {s.get('grade', 'N/A')})**")
    lines.append("")
    lines.append(f"| Status | Count |")
    lines.append("|---|---|")
    for status in ["pass", "fail", "warning", "not-tested"]:
        lines.append(f"| {STATUS_ICON.get(status, status)} | {sc.get(status, 0)} |")
    lines.append("")

    for fw in report.frameworks:
        fw_controls = [c for c in report.controls if c.framework == fw]
        lines.append(f"## {fw} controls")
        lines.append("")
        lines.append("| ID | Control | Status | Severity | Findings |")
        lines.append("|---|---|---|---|---|")
        for c in fw_controls:
            icon = STATUS_ICON.get(c.status, c.status)
            findings_str = "; ".join(c.findings[:3]) if c.findings else "—"
            if len(findings_str) > 80:
                findings_str = findings_str[:77] + "..."
            lines.append(f"| {c.control_id} | {c.name} | {icon} | {c.severity} | {findings_str} |")
        lines.append("")

    failed = [c for c in report.controls if c.status == "fail"]
    if failed:
        lines.append("## Remediation plan")
        lines.append("")
        lines.append("Priority order (critical first):")
        lines.append("")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        failed.sort(key=lambda c: severity_order.get(c.severity, 5))
        for i, c in enumerate(failed, 1):
            lines.append(f"{i}. **{c.control_id} — {c.name}** ({c.severity})")
            if c.remediation:
                lines.append(f"   {c.remediation}")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Security compliance checker")
    parser.add_argument("url", nargs="?", help="URL to check (runs live checks)")
    parser.add_argument("--from-reports", nargs="+",
                        help="Build report from existing scan JSON files")
    parser.add_argument("--out", default="compliance",
                        help="Output base name (writes .md and .json)")
    parser.add_argument("--framework", action="append", dest="frameworks",
                        help="Limit to specific frameworks (repeatable: OWASP, CIS, NIST-CSF)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    if args.from_reports:
        report = from_reports(args.from_reports, frameworks=args.frameworks)
    elif args.url:
        report = run_live_checks(args.url, frameworks=args.frameworks)
    else:
        log.error("Provide a URL or --from-reports with JSON files.")
        sys.exit(1)

    md_path = Path(f"{args.out}.md")
    md_path.write_text(to_markdown(report))

    json_path = Path(f"{args.out}.json")
    json_data = {
        "target": report.target,
        "generated_at": report.generated_at,
        "frameworks": report.frameworks,
        "summary": report.summary,
        "controls": [asdict(c) for c in report.controls],
    }
    json_path.write_text(json.dumps(json_data, indent=2))

    pct = report.summary.get("compliance_percentage", 0)
    g = report.summary.get("grade", "N/A")
    sc = report.summary.get("status_counts", {})
    print(f"Compliance report written to {md_path} and {json_path}")
    print(f"  Score: {pct}% (Grade: {g})")
    print(f"  Pass: {sc.get('pass', 0)} | Fail: {sc.get('fail', 0)} | "
          f"Warning: {sc.get('warning', 0)} | Not tested: {sc.get('not-tested', 0)}")


if __name__ == "__main__":
    main()
