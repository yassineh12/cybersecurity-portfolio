"""Passive vulnerability scanner.

Lessons 2–6 in one module: map the attack surface, fingerprint software,
match CVEs, run safe checks, and write a report.

Usage:
    python scanner.py http://testphp.vulnweb.com --max-pages 15
    python scanner.py http://localhost:3000 --max-pages 10   # Juice Shop

Only scan targets you own or that explicitly invite testing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "01-headers-auditor"))
from crawler import Crawler, Page  # noqa: E402

__version__ = "1.1.0"

log = logging.getLogger(__name__)


# ──────────────────────────────────────────── data models ───

@dataclass
class FormInfo:
    url: str
    action: str
    method: str
    inputs: list[dict]


@dataclass
class SoftwareFingerprint:
    name: str
    version: str
    source: str
    cpe: str = ""


@dataclass
class CVEMatch:
    cve_id: str
    summary: str
    cvss: float
    software: str


@dataclass
class VulnFinding:
    id: str
    severity: str
    title: str
    detail: str
    url: str
    fix: str = ""


@dataclass
class ScanResult:
    target: str
    pages_crawled: int
    forms: list[FormInfo] = field(default_factory=list)
    query_params: dict = field(default_factory=dict)
    js_files: list[str] = field(default_factory=list)
    fingerprints: list[SoftwareFingerprint] = field(default_factory=list)
    cves: list[CVEMatch] = field(default_factory=list)
    findings: list[VulnFinding] = field(default_factory=list)
    elapsed_seconds: float = 0.0


# ──────────── lesson 2: attack-surface mapping ─────────────

def map_forms(url: str, soup: BeautifulSoup) -> list[FormInfo]:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action and not action.startswith(("http://", "https://", "//")):
            action = urljoin(url, action)
        method = (form.get("method") or "GET").upper()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "tag": inp.name,
            })
        forms.append(FormInfo(url=url, action=action, method=method, inputs=inputs))
    return forms


def map_query_params(pages: list[Page]) -> dict[str, list[str]]:
    params: dict[str, list[str]] = defaultdict(list)
    for page in pages:
        qs = parse_qs(urlparse(page.url).query)
        for key in qs:
            if page.url not in params[key]:
                params[key].append(page.url)
    return dict(params)


def map_js_files(pages: list[Page]) -> list[str]:
    seen = set()
    js_files = []
    for page in pages:
        soup = BeautifulSoup(page.html, "html.parser")
        for script in soup.find_all("script", src=True):
            src = urljoin(page.url, script["src"])
            if src not in seen:
                seen.add(src)
                js_files.append(src)
    return js_files


# ──────────── lesson 3: fingerprinting ─────────────────────

HEADER_PATTERNS = [
    ("server", re.compile(r"Apache/([\d.]+)", re.I), "Apache HTTP Server",
     "cpe:2.3:a:apache:http_server:{}:*:*:*:*:*:*:*"),
    ("server", re.compile(r"nginx/([\d.]+)", re.I), "nginx",
     "cpe:2.3:a:f5:nginx:{}:*:*:*:*:*:*:*"),
    ("x-powered-by", re.compile(r"PHP/([\d.]+)", re.I), "PHP",
     "cpe:2.3:a:php:php:{}:*:*:*:*:*:*:*"),
    ("x-powered-by", re.compile(r"Express", re.I), "Express.js", ""),
    ("x-powered-by", re.compile(r"ASP\.NET", re.I), "ASP.NET", ""),
    ("server", re.compile(r"Microsoft-IIS/([\d.]+)", re.I), "Microsoft IIS",
     "cpe:2.3:a:microsoft:iis:{}:*:*:*:*:*:*:*"),
]

HTML_PATTERNS = [
    (re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d.]*)', re.I),
     "WordPress", "cpe:2.3:a:wordpress:wordpress:{}:*:*:*:*:*:*:*"),
    (re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla[!\s]*([\d.]*)', re.I),
     "Joomla", "cpe:2.3:a:joomla:joomla:{}:*:*:*:*:*:*:*"),
    (re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal\s*([\d.]*)', re.I),
     "Drupal", "cpe:2.3:a:drupal:drupal:{}:*:*:*:*:*:*:*"),
]

JS_PATTERNS = [
    (re.compile(r"jQuery\s+v?([\d.]+)", re.I), "jQuery",
     "cpe:2.3:a:jquery:jquery:{}:*:*:*:*:*:*:*"),
    (re.compile(r"Bootstrap\s+v?([\d.]+)", re.I), "Bootstrap", ""),
    (re.compile(r"Angular(?:JS)?[/\s]+v?([\d.]+)", re.I), "AngularJS", ""),
    (re.compile(r"React\s+v?([\d.]+)", re.I), "React", ""),
    (re.compile(r"Vue\.js\s+v?([\d.]+)", re.I), "Vue.js", ""),
]


def fingerprint_headers(headers: dict[str, str]) -> list[SoftwareFingerprint]:
    results = []
    for header_name, pattern, sw_name, cpe_tpl in HEADER_PATTERNS:
        value = headers.get(header_name, "")
        m = pattern.search(value)
        if m:
            ver = m.group(1) if m.lastindex else ""
            cpe = cpe_tpl.format(ver) if ver and cpe_tpl else ""
            results.append(SoftwareFingerprint(sw_name, ver, f"header:{header_name}", cpe))
    return results


def fingerprint_html(html: str) -> list[SoftwareFingerprint]:
    results = []
    for pattern, sw_name, cpe_tpl in HTML_PATTERNS:
        m = pattern.search(html)
        if m:
            ver = m.group(1) if m.lastindex else ""
            cpe = cpe_tpl.format(ver) if ver and cpe_tpl else ""
            results.append(SoftwareFingerprint(sw_name, ver, "html:meta", cpe))
    return results


def fingerprint_js(js_url: str, session: requests.Session) -> list[SoftwareFingerprint]:
    try:
        resp = session.get(js_url, timeout=8)
        content = resp.text[:10000]
    except requests.RequestException:
        return []
    results = []
    for pattern, sw_name, cpe_tpl in JS_PATTERNS:
        m = pattern.search(content)
        if m:
            ver = m.group(1) if m.lastindex else ""
            cpe = cpe_tpl.format(ver) if ver and cpe_tpl else ""
            results.append(SoftwareFingerprint(sw_name, ver, f"js:{js_url}", cpe))
    return results


# ──────────── lesson 4: CVE matching ───────────────────────

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_nvd(cpe: str, session: requests.Session) -> list[CVEMatch]:
    if not cpe:
        return []
    try:
        resp = session.get(NVD_API, params={"cpeName": cpe, "resultsPerPage": 5}, timeout=15)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []
    matches = []
    for item in data.get("vulnerabilities", [])[:5]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
        metrics = cve.get("metrics", {})
        cvss = 0.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
                break
        matches.append(CVEMatch(cve_id, summary[:200], cvss, cpe))
    return matches


# ──────────── lesson 5: safe active checks ─────────────────

XSS_MARKER = "xsscanary7v9k2"


def check_reflected_xss(url: str, params: dict[str, list[str]],
                         session: requests.Session) -> list[VulnFinding]:
    findings = []
    for param_name, urls in params.items():
        test_url = urls[0]
        parsed = urlparse(test_url)
        test_qs = f"{param_name}={XSS_MARKER}"
        probe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_qs}"
        try:
            resp = session.get(probe_url, timeout=8)
            if XSS_MARKER in resp.text:
                findings.append(VulnFinding(
                    id="reflected-xss",
                    severity="high",
                    title=f"Reflected input in parameter '{param_name}'",
                    detail=f"Marker '{XSS_MARKER}' appeared in response body at {probe_url}",
                    url=probe_url,
                    fix="Sanitize or encode user input before reflecting it in HTML."
                ))
        except requests.RequestException:
            pass
    return findings


def check_open_redirect(pages: list[Page], session: requests.Session) -> list[VulnFinding]:
    findings = []
    redirect_params = ("url", "redirect", "next", "return", "redir", "goto", "dest",
                       "destination", "continue", "return_to", "redirect_uri")
    for page in pages:
        qs = parse_qs(urlparse(page.url).query)
        for param in redirect_params:
            if param in qs:
                parsed = urlparse(page.url)
                probe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}=https://evil.example.com"
                try:
                    resp = session.get(probe_url, timeout=8, allow_redirects=False)
                    location = resp.headers.get("location", "")
                    if "evil.example.com" in location:
                        findings.append(VulnFinding(
                            id="open-redirect",
                            severity="medium",
                            title=f"Open redirect via '{param}' parameter",
                            detail=f"Redirected to {location}",
                            url=probe_url,
                            fix="Validate redirect targets against an allowlist of trusted domains."
                        ))
                except requests.RequestException:
                    pass
    return findings


def check_directory_listing(pages: list[Page], session: requests.Session) -> list[VulnFinding]:
    findings = []
    dirs_checked = set()
    common_dirs = ("/admin/", "/backup/", "/uploads/", "/config/", "/test/",
                   "/tmp/", "/logs/", "/.git/", "/api/")
    base = urlparse(pages[0].url if pages else "") if pages else None
    if not base:
        return findings

    for d in common_dirs:
        url = f"{base.scheme}://{base.netloc}{d}"
        if url in dirs_checked:
            continue
        dirs_checked.add(url)
        try:
            resp = session.get(url, timeout=8)
            if resp.status_code == 200 and "index of" in resp.text.lower():
                findings.append(VulnFinding(
                    id="dir-listing",
                    severity="low",
                    title=f"Directory listing enabled at {d}",
                    detail=f"Server shows file listing at {url}",
                    url=url,
                    fix="Disable directory listing in web server config (Options -Indexes)."
                ))
        except requests.RequestException:
            pass
    return findings


def check_sensitive_files(base_url: str, session: requests.Session) -> list[VulnFinding]:
    findings = []
    parsed = urlparse(base_url)
    sensitive = [
        ("/.env", "Environment file"),
        ("/.git/HEAD", "Git repository"),
        ("/wp-config.php.bak", "WordPress config backup"),
        ("/phpinfo.php", "PHP info page"),
        ("/.DS_Store", "macOS metadata"),
        ("/server-status", "Apache status page"),
        ("/robots.txt", None),
    ]
    for path, desc in sensitive:
        if desc is None:
            continue
        url = f"{parsed.scheme}://{parsed.netloc}{path}"
        try:
            resp = session.get(url, timeout=8)
            if resp.status_code == 200 and len(resp.text) > 10:
                findings.append(VulnFinding(
                    id="sensitive-file",
                    severity="medium" if ".env" in path or ".git" in path else "low",
                    title=f"Sensitive file accessible: {path}",
                    detail=f"{desc} found at {url} ({len(resp.text)} bytes)",
                    url=url,
                    fix="Remove or restrict access to sensitive files."
                ))
        except requests.RequestException:
            pass
    return findings


# ──────────── additional checks ───────────────────────────

def check_cors_misconfig(pages: list[Page]) -> list[VulnFinding]:
    findings = []
    seen = set()
    for page in pages:
        acao = page.headers.get("access-control-allow-origin", "")
        acac = page.headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and page.url not in seen:
            seen.add(page.url)
            sev = "high" if acac == "true" else "medium"
            findings.append(VulnFinding(
                id="cors-misconfig",
                severity=sev,
                title="CORS allows any origin" + (" with credentials" if acac == "true" else ""),
                detail=f"Access-Control-Allow-Origin: {acao}",
                url=page.url,
                fix="Restrict CORS to trusted origins; never combine '*' with credentials.",
            ))
    return findings


def check_http_methods(base_url: str, session: requests.Session) -> list[VulnFinding]:
    findings = []
    try:
        resp = session.options(base_url, timeout=8)
        allow = resp.headers.get("allow", "")
        if not allow:
            return findings
        methods = {m.strip().upper() for m in allow.split(",")}
        risky = methods & {"PUT", "DELETE", "TRACE", "CONNECT"}
        if risky:
            findings.append(VulnFinding(
                id="risky-methods",
                severity="medium",
                title=f"Risky HTTP methods enabled: {', '.join(sorted(risky))}",
                detail=f"Allow: {allow}",
                url=base_url,
                fix="Disable PUT, DELETE, TRACE, CONNECT unless required by the application.",
            ))
    except requests.RequestException:
        pass
    return findings


def check_cookie_security(pages: list[Page]) -> list[VulnFinding]:
    findings = []
    seen_cookies: set[str] = set()
    for page in pages:
        https = urlparse(page.url).scheme == "https"
        for line in page.set_cookies:
            name = line.split("=", 1)[0].strip()
            if name in seen_cookies:
                continue
            seen_cookies.add(name)
            attrs = {a.strip().split("=", 1)[0].lower() for a in line.split(";")[1:]}
            issues = []
            if https and "secure" not in attrs:
                issues.append("Secure")
            if "httponly" not in attrs:
                issues.append("HttpOnly")
            if "samesite" not in attrs:
                issues.append("SameSite")
            if issues:
                findings.append(VulnFinding(
                    id="insecure-cookie",
                    severity="medium",
                    title=f"Cookie '{name}' missing {', '.join(issues)}",
                    detail=f"Set-Cookie: {line[:80]}",
                    url=page.url,
                    fix=f"Add {', '.join(issues)} to the cookie.",
                ))
    return findings


# ──────────── lesson 6: reporting ──────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def to_markdown(result: ScanResult) -> str:
    lines = [
        f"# Vulnerability Scan Report: {result.target}",
        "",
        f"**Pages crawled:** {result.pages_crawled}",
        f"**Forms found:** {len(result.forms)}",
        f"**Query parameters:** {len(result.query_params)}",
        f"**JS files:** {len(result.js_files)}",
        "",
    ]

    if result.fingerprints:
        lines += ["## Software Detected", "",
                   "| Software | Version | Source |", "|---|---|---|"]
        for fp in result.fingerprints:
            lines.append(f"| {fp.name} | {fp.version or 'unknown'} | {fp.source} |")
        lines.append("")

    if result.cves:
        lines += ["## Known Vulnerabilities (CVEs)", "",
                   "| CVE | CVSS | Software | Summary |", "|---|---|---|---|"]
        for cve in sorted(result.cves, key=lambda c: -c.cvss):
            lines.append(f"| {cve.cve_id} | {cve.cvss} | {cve.software} | {cve.summary[:80]} |")
        lines.append("")

    if result.findings:
        lines += ["## Findings", "",
                   "| Severity | Finding | URL |", "|---|---|---|"]
        for f in sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9)):
            lines.append(f"| {f.severity.upper()} | {f.title} | {f.url[:60]} |")
        lines += ["", "### Details", ""]
        for f in sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9)):
            lines.append(f"#### [{f.severity.upper()}] {f.title}")
            lines.append(f"- URL: {f.url}")
            if f.detail:
                lines.append(f"- Evidence: `{f.detail}`")
            if f.fix:
                lines.append(f"- Fix: {f.fix}")
            lines.append("")
    else:
        lines.append("No findings. The scan found no issues in scope.\n")

    if result.forms:
        lines += ["## Attack Surface: Forms", ""]
        for form in result.forms[:10]:
            input_names = [i["name"] for i in form.inputs if i["name"]]
            lines.append(f"- **{form.method}** `{form.action or '(same page)'}` "
                         f"— inputs: {', '.join(input_names) or 'none'}")
        if len(result.forms) > 10:
            lines.append(f"- ...and {len(result.forms) - 10} more forms")
        lines.append("")

    return "\n".join(lines)


# ──────────── main ─────────────────────────────────────────

def scan(target: str, max_pages: int, delay: float) -> ScanResult:
    t0 = time.monotonic()
    result = ScanResult(target=target, pages_crawled=0)
    session = requests.Session()
    session.headers["User-Agent"] = "SecurityPortfolioCrawler/1.0"

    log.info("[1/6] Crawling %s ...", target)
    crawler = Crawler(target, max_pages=max_pages, delay=delay, respect_robots=True)
    pages = []
    all_fingerprints = []

    for page in crawler.crawl():
        log.info("  [%d] %s", page.status, page.url)
        pages.append(page)

        result.forms += map_forms(page.url, BeautifulSoup(page.html, "html.parser"))
        all_fingerprints += fingerprint_headers(page.headers)
        all_fingerprints += fingerprint_html(page.html)

    result.pages_crawled = len(pages)
    result.query_params = map_query_params(pages)
    result.js_files = map_js_files(pages)

    log.info("[2/6] Fingerprinting (%d JS files) ...", len(result.js_files))
    for js_url in result.js_files[:20]:
        all_fingerprints += fingerprint_js(js_url, session)

    seen = set()
    for fp in all_fingerprints:
        key = (fp.name, fp.version)
        if key not in seen:
            seen.add(key)
            result.fingerprints.append(fp)

    cpe_count = len([f for f in result.fingerprints if f.cpe])
    log.info("[3/6] CVE lookup (%d CPEs) ...", cpe_count)
    for fp in result.fingerprints:
        if fp.cpe:
            log.info("  querying NVD for %s %s ...", fp.name, fp.version)
            result.cves += query_nvd(fp.cpe, session)

    log.info("[4/6] Safe active checks ...")
    result.findings += check_reflected_xss(target, result.query_params, session)
    result.findings += check_open_redirect(pages, session)
    result.findings += check_directory_listing(pages, session)
    result.findings += check_sensitive_files(target, session)

    log.info("[5/6] Passive checks (CORS, methods, cookies) ...")
    result.findings += check_cors_misconfig(pages)
    result.findings += check_http_methods(target, session)
    result.findings += check_cookie_security(pages)

    elapsed = time.monotonic() - t0
    result.elapsed_seconds = round(elapsed, 2)
    log.info("[6/6] Done in %.1fs. %d findings, %d fingerprints, %d CVEs.",
             elapsed, len(result.findings), len(result.fingerprints), len(result.cves))

    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--max-pages", type=int, default=15)
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--out", default="report", help="output file prefix")
    ap.add_argument("--verbose", "-v", action="store_true", help="debug-level output")
    ap.add_argument("--quiet", "-q", action="store_true", help="errors only")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")

    log.info("Scanning %s ...", args.url)
    try:
        result = scan(args.url, args.max_pages, args.delay)
    except Exception:
        log.exception("Scan failed")
        sys.exit(1)

    md = to_markdown(result)
    with open(f"{args.out}.md", "w") as fh:
        fh.write(md)

    with open(f"{args.out}.json", "w") as fh:
        json.dump(asdict(result), fh, indent=2, default=str)

    log.info("Report: %s.md / %s.json (%.1fs)", args.out, args.out, result.elapsed_seconds)


if __name__ == "__main__":
    main()
