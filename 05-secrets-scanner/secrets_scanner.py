"""Secrets scanner for public JavaScript bundles.

Crawls a website, finds all JS files, downloads them, and searches for
accidentally exposed secrets: API keys, tokens, passwords, internal URLs,
and cloud credentials that developers left in client-side code.

This is shockingly common. Frontend builds often inline environment
variables, and developers forget that everything shipped to the browser
is public.

Usage:
    python scanner.py https://example.com --max-pages 10
    python scanner.py https://example.com --out secrets-report
    python scanner.py https://example.com --allowlist ignore.txt

Only scan sites you own or are authorised to test.
"""

from __future__ import annotations

__version__ = "1.1.0"

import argparse
import json
import logging
import math
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "01-headers-auditor"))
from crawler import Crawler  # noqa: E402

log = logging.getLogger(__name__)


@dataclass
class SecretFinding:
    rule_id: str
    rule_name: str
    severity: str
    matched_text: str
    context: str
    source_url: str
    line_number: int = 0


@dataclass
class ScanResult:
    target: str
    js_files_scanned: int = 0
    inline_scripts_scanned: int = 0
    findings: list[SecretFinding] = field(default_factory=list)
    elapsed_seconds: float = 0.0


SECRET_RULES = [
    {
        "id": "aws-access-key",
        "name": "AWS Access Key ID",
        "severity": "critical",
        "pattern": re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
    },
    {
        "id": "aws-secret-key",
        "name": "AWS Secret Access Key",
        "severity": "critical",
        "pattern": re.compile(r"""(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""", re.I),
    },
    {
        "id": "google-api-key",
        "name": "Google API Key",
        "severity": "high",
        "pattern": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    },
    {
        "id": "google-oauth-secret",
        "name": "Google OAuth Client Secret",
        "severity": "critical",
        "pattern": re.compile(r"GOCSPX-[A-Za-z0-9_-]{28}"),
    },
    {
        "id": "stripe-secret",
        "name": "Stripe Secret Key",
        "severity": "critical",
        "pattern": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    },
    {
        "id": "stripe-publishable",
        "name": "Stripe Publishable Key (not secret, but indicates Stripe usage)",
        "severity": "info",
        "pattern": re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
    },
    {
        "id": "github-token",
        "name": "GitHub Personal Access Token",
        "severity": "critical",
        "pattern": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    },
    {
        "id": "github-oauth",
        "name": "GitHub OAuth Access Token",
        "severity": "critical",
        "pattern": re.compile(r"gho_[0-9a-zA-Z]{36}"),
    },
    {
        "id": "slack-token",
        "name": "Slack Bot/User Token",
        "severity": "critical",
        "pattern": re.compile(r"xox[bpors]-[0-9a-zA-Z-]{10,}"),
    },
    {
        "id": "slack-webhook",
        "name": "Slack Webhook URL",
        "severity": "high",
        "pattern": re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+"),
    },
    {
        "id": "jwt-token",
        "name": "JSON Web Token",
        "severity": "medium",
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    },
    {
        "id": "private-key",
        "name": "Private Key",
        "severity": "critical",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    },
    {
        "id": "password-assignment",
        "name": "Hardcoded Password",
        "severity": "high",
        "pattern": re.compile(r"""(?:password|passwd|pwd|secret)\s*[=:]\s*['"][^'"]{8,}['"]""", re.I),
    },
    {
        "id": "internal-url",
        "name": "Internal/Private URL",
        "severity": "medium",
        "pattern": re.compile(r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[:/][\w/.?&=-]*"),
    },
    {
        "id": "firebase-url",
        "name": "Firebase Database URL",
        "severity": "medium",
        "pattern": re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
    },
    {
        "id": "sendgrid-key",
        "name": "SendGrid API Key",
        "severity": "critical",
        "pattern": re.compile(r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"),
    },
    {
        "id": "twilio-key",
        "name": "Twilio API Key",
        "severity": "critical",
        "pattern": re.compile(r"SK[0-9a-fA-F]{32}"),
    },
    {
        "id": "mailgun-key",
        "name": "Mailgun API Key",
        "severity": "critical",
        "pattern": re.compile(r"key-[0-9a-zA-Z]{32}"),
    },
    {
        "id": "heroku-api-key",
        "name": "Heroku API Key",
        "severity": "critical",
        "pattern": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    },
    {
        "id": "azure-storage-key",
        "name": "Azure Storage Account Key",
        "severity": "critical",
        "pattern": re.compile(r"(?:AccountKey|azure[_-]?storage[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9+/]{86}==)['\"]?", re.I),
    },
    {
        "id": "generic-api-key",
        "name": "Generic API Key Assignment",
        "severity": "medium",
        "pattern": re.compile(r"""(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"][A-Za-z0-9_\-]{20,}['"]""", re.I),
    },
]


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def detect_high_entropy(content: str, source_url: str,
                        min_length: int = 20,
                        threshold: float = 4.5) -> list[SecretFinding]:
    findings = []
    token_re = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{20,})['"]""")
    for match in token_re.finditer(content):
        token = match.group(1)
        if len(token) < min_length:
            continue
        ent = shannon_entropy(token)
        if ent >= threshold:
            findings.append(SecretFinding(
                rule_id="high-entropy-string",
                rule_name="High-Entropy String",
                severity="medium",
                matched_text=token[:200] + ("..." if len(token) > 200 else ""),
                context=get_context(content, match.start()),
                source_url=source_url,
                line_number=get_line_number(content, match.start()),
            ))
    return findings


def load_allowlist(path: str) -> set[str]:
    patterns = set()
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.add(line)
    except FileNotFoundError:
        log.warning("Allowlist file not found: %s", path)
    return patterns


def apply_allowlist(findings: list[SecretFinding], allowlist: set[str]) -> list[SecretFinding]:
    if not allowlist:
        return findings
    filtered = []
    for f in findings:
        skip = False
        for pattern in allowlist:
            if pattern in f.matched_text or pattern == f.rule_id:
                skip = True
                break
        if not skip:
            filtered.append(f)
    return filtered


def get_context(content: str, match_start: int, radius: int = 60) -> str:
    start = max(0, match_start - radius)
    end = min(len(content), match_start + radius)
    ctx = content[start:end].replace("\n", " ").strip()
    if start > 0:
        ctx = "..." + ctx
    if end < len(content):
        ctx = ctx + "..."
    return ctx


def get_line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def scan_content(content: str, source_url: str,
                 allowlist: set[str] | None = None,
                 entropy: bool = False) -> list[SecretFinding]:
    findings = []
    for rule in SECRET_RULES:
        for match in rule["pattern"].finditer(content):
            matched = match.group(0)
            if len(matched) > 200:
                matched = matched[:200] + "..."
            findings.append(SecretFinding(
                rule_id=rule["id"],
                rule_name=rule["name"],
                severity=rule["severity"],
                matched_text=matched,
                context=get_context(content, match.start()),
                source_url=source_url,
                line_number=get_line_number(content, match.start()),
            ))
    if entropy:
        findings += detect_high_entropy(content, source_url)
    if allowlist:
        findings = apply_allowlist(findings, allowlist)
    return findings


def scan_site(target: str, max_pages: int, delay: float,
              allowlist: set[str] | None = None,
              entropy: bool = False) -> ScanResult:
    t0 = time.monotonic()
    result = ScanResult(target=target)
    session = requests.Session()
    session.headers["User-Agent"] = "SecurityPortfolioCrawler/1.0"

    log.info("Crawling %s for JS files ...", target)
    crawler = Crawler(target, max_pages=max_pages, delay=delay, respect_robots=True)
    js_urls = set()

    for page in crawler.crawl():
        log.info("  [%s] %s", page.status, page.url)
        soup = BeautifulSoup(page.html, "html.parser")

        for script in soup.find_all("script", src=True):
            js_urls.add(urljoin(page.url, script["src"]))

        for script in soup.find_all("script", src=False):
            if script.string and len(script.string.strip()) > 20:
                result.inline_scripts_scanned += 1
                result.findings += scan_content(
                    script.string, page.url,
                    allowlist=allowlist, entropy=entropy,
                )

    log.info("Scanning %d external JS files ...", len(js_urls))
    for i, js_url in enumerate(sorted(js_urls), 1):
        try:
            resp = session.get(js_url, timeout=10)
            if resp.status_code == 200:
                result.findings += scan_content(
                    resp.text, js_url,
                    allowlist=allowlist, entropy=entropy,
                )
                result.js_files_scanned += 1
        except requests.RequestException:
            pass
        if i % 10 == 0:
            log.debug("  scanned %d/%d", i, len(js_urls))

    result.elapsed_seconds = round(time.monotonic() - t0, 2)
    log.info("Done. %d potential secrets found (%.1fs).",
             len(result.findings), result.elapsed_seconds)
    return result


def to_markdown(result: ScanResult) -> str:
    lines = [
        f"# Secrets Scan Report: {result.target}",
        "",
        f"**JS files scanned:** {result.js_files_scanned}",
        f"**Inline scripts scanned:** {result.inline_scripts_scanned}",
        f"**Potential secrets found:** {len(result.findings)}",
        f"**Elapsed:** {result.elapsed_seconds}s",
        "",
    ]

    if result.findings:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(result.findings,
                                  key=lambda f: severity_order.get(f.severity, 9))

        lines += ["## Findings", "",
                   "| Severity | Type | Source | Line |",
                   "|---|---|---|---|"]
        for f in sorted_findings:
            lines.append(f"| {f.severity.upper()} | {f.rule_name} | "
                         f"{urlparse(f.source_url).path[-40:]} | {f.line_number} |")

        lines += ["", "### Details", ""]
        for f in sorted_findings:
            lines.append(f"#### [{f.severity.upper()}] {f.rule_name}")
            lines.append(f"- Source: `{f.source_url}`")
            lines.append(f"- Line: {f.line_number}")
            lines.append(f"- Match: `{f.matched_text[:80]}`")
            lines.append(f"- Context: `{f.context}`")
            lines.append("")
    else:
        lines.append("No secrets found. The scan completed without findings.\n")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", help="target URL to scan")
    ap.add_argument("--max-pages", type=int, default=10)
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--out", default="secrets-report",
                    help="output file prefix")
    ap.add_argument("--allowlist", metavar="FILE",
                    help="file of patterns/rule-ids to ignore")
    ap.add_argument("--entropy", action="store_true",
                    help="also flag high-entropy strings (Shannon > 4.5)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="debug-level output")
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="errors only")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")

    allowed = load_allowlist(args.allowlist) if args.allowlist else None

    result = scan_site(args.url, args.max_pages, args.delay,
                       allowlist=allowed, entropy=args.entropy)
    md = to_markdown(result)

    with open(f"{args.out}.md", "w") as fh:
        fh.write(md)
    with open(f"{args.out}.json", "w") as fh:
        json.dump(asdict(result), fh, indent=2, default=str)

    log.info("%d findings. Report: %s.md / %s.json",
             len(result.findings), args.out, args.out)


if __name__ == "__main__":
    main()
