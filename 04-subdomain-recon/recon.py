"""Subdomain and certificate-transparency recon.

Discovers subdomains of a target domain by querying public certificate
transparency logs via crt.sh.  Every HTTPS certificate issued by a
trusted CA is logged publicly — this tool reads those logs to map the
attack surface an organisation exposes without sending a single packet
to the target.

Usage:
    python recon.py example.com
    python recon.py example.com --resolve --out report
    python recon.py example.com --resolve --filter live

Only run against domains you own or are authorised to test.
"""

from __future__ import annotations

__version__ = "1.1.0"

import argparse
import json
import logging
import socket
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime

import requests

log = logging.getLogger(__name__)

CT_LOG_URL = "https://crt.sh/?q=%.{domain}&output=json"
USER_AGENT = "SecurityPortfolioCrawler/1.0 (+educational; authorised targets only)"

TAKEOVER_CNAME_PROVIDERS = [
    "herokuapp.com",
    "herokudns.com",
    "s3.amazonaws.com",
    "s3-website",
    "cloudfront.net",
    "azurewebsites.net",
    "cloudapp.azure.com",
    "trafficmanager.net",
    "blob.core.windows.net",
    "github.io",
    "gitbook.io",
    "ghost.io",
    "pantheon.io",
    "shopify.com",
    "myshopify.com",
    "surge.sh",
    "bitbucket.io",
    "netlify.app",
    "fly.dev",
    "unbouncepages.com",
    "zendesk.com",
    "readme.io",
    "statuspage.io",
    "wordpress.com",
    "cargocollective.com",
    "feedpress.me",
    "freshdesk.com",
    "helpjuice.com",
    "helpscoutdocs.com",
    "tictail.com",
    "campaignmonitor.com",
    "createsend.com",
    "cargo.site",
    "launchrock.com",
]


@dataclass
class SubdomainInfo:
    name: str
    first_seen: str = ""
    last_seen: str = ""
    issuer: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    is_wildcard: bool = False
    still_resolves: bool = False
    takeover_risk: bool = False


@dataclass
class ReconResult:
    target: str
    total_certs: int = 0
    unique_subdomains: int = 0
    subdomains: list[SubdomainInfo] = field(default_factory=list)
    issuers: dict[str, int] = field(default_factory=dict)
    wildcard_count: int = 0
    elapsed_seconds: float = 0.0
    takeover_candidates: int = 0


def query_crt_sh(domain: str) -> list[dict]:
    url = CT_LOG_URL.format(domain=domain)
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
        if resp.status_code != 200:
            log.warning("crt.sh returned status %d", resp.status_code)
            return []
        return resp.json()
    except (requests.RequestException, ValueError) as exc:
        log.error("crt.sh query failed: %s", exc)
        return []


def parse_ct_entries(entries: list[dict], domain: str) -> dict[str, SubdomainInfo]:
    subs: dict[str, SubdomainInfo] = {}
    for entry in entries:
        names = entry.get("name_value", "").lower().split("\n")
        issuer = entry.get("issuer_name", "")
        not_before = entry.get("not_before", "")
        not_after = entry.get("not_after", "")

        for name in names:
            name = name.strip()
            if not name or not name.endswith(domain):
                continue
            is_wc = name.startswith("*.")
            clean = name.lstrip("*.")

            if clean not in subs:
                subs[clean] = SubdomainInfo(
                    name=clean,
                    first_seen=not_before,
                    last_seen=not_after,
                    issuer=issuer,
                    is_wildcard=is_wc,
                )
            else:
                if not_before and not_before < subs[clean].first_seen:
                    subs[clean].first_seen = not_before
                if not_after and not_after > subs[clean].last_seen:
                    subs[clean].last_seen = not_after
    return subs


def resolve_subdomain(name: str) -> list[str]:
    try:
        results = socket.getaddrinfo(name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return list({r[4][0] for r in results})
    except socket.gaierror:
        return []


def resolve_cnames(name: str) -> list[str]:
    try:
        answer = socket.getfqdn(name)
        if answer and answer != name:
            return [answer]
    except Exception:
        pass
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "CNAME", name],
            capture_output=True, text=True, timeout=5,
        )
        cnames = [line.strip().rstrip(".") for line in result.stdout.strip().splitlines() if line.strip()]
        return cnames
    except Exception:
        return []


def check_takeover_risk(info: SubdomainInfo) -> bool:
    if info.still_resolves:
        return False
    for cname in info.cnames:
        cname_lower = cname.lower()
        for provider in TAKEOVER_CNAME_PROVIDERS:
            if cname_lower.endswith(provider):
                log.debug("Takeover candidate: %s -> %s (provider: %s)", info.name, cname, provider)
                return True
    return False


def filter_subdomains(subdomains: list[SubdomainInfo], mode: str) -> list[SubdomainInfo]:
    if mode == "live":
        return [s for s in subdomains if s.still_resolves]
    elif mode == "dead":
        return [s for s in subdomains if not s.still_resolves and not s.is_wildcard]
    elif mode == "wildcard":
        return [s for s in subdomains if s.is_wildcard]
    elif mode == "takeover":
        return [s for s in subdomains if s.takeover_risk]
    return subdomains


def recon(domain: str, do_resolve: bool = False) -> ReconResult:
    t0 = time.monotonic()

    log.info("Querying crt.sh for *.%s ...", domain)
    entries = query_crt_sh(domain)
    result = ReconResult(target=domain, total_certs=len(entries))

    if not entries:
        log.warning("No CT log entries found for %s", domain)
        result.elapsed_seconds = round(time.monotonic() - t0, 2)
        return result

    log.info("%d certificate entries found", len(entries))

    log.info("Parsing subdomains ...")
    subs = parse_ct_entries(entries, domain)
    result.unique_subdomains = len(subs)
    result.wildcard_count = sum(1 for s in subs.values() if s.is_wildcard)

    issuer_counts = Counter(s.issuer for s in subs.values())
    result.issuers = dict(issuer_counts.most_common(10))

    if do_resolve:
        log.info("Resolving %d subdomains ...", len(subs))
        for i, (name, info) in enumerate(subs.items(), 1):
            ips = resolve_subdomain(name)
            info.ip_addresses = ips
            info.still_resolves = len(ips) > 0

            info.cnames = resolve_cnames(name)

            info.takeover_risk = check_takeover_risk(info)

            if i % 20 == 0:
                log.debug("Resolved %d/%d", i, len(subs))
    else:
        log.info("Skipping DNS resolution (use --resolve to enable)")

    result.subdomains = sorted(subs.values(), key=lambda s: s.name)
    result.takeover_candidates = sum(1 for s in result.subdomains if s.takeover_risk)
    result.elapsed_seconds = round(time.monotonic() - t0, 2)

    log.info("Recon complete: %d subdomains, %d takeover candidates (%.1fs)",
             result.unique_subdomains, result.takeover_candidates, result.elapsed_seconds)
    return result


def to_markdown(result: ReconResult) -> str:
    lines = [
        f"# Subdomain Recon Report: {result.target}",
        "",
        f"**Certificates in CT logs:** {result.total_certs}",
        f"**Unique subdomains:** {result.unique_subdomains}",
        f"**Wildcard certificates:** {result.wildcard_count}",
        f"**Takeover candidates:** {result.takeover_candidates}",
        f"**Elapsed:** {result.elapsed_seconds}s",
        "",
    ]

    if result.issuers:
        lines += ["## Certificate Issuers", "",
                   "| Issuer | Count |", "|---|---|"]
        for issuer, count in result.issuers.items():
            lines.append(f"| {issuer[:60]} | {count} |")
        lines.append("")

    if result.subdomains:
        lines += ["## Subdomains", "",
                   "| Subdomain | First Seen | Resolves | IPs | CNAME | Takeover |",
                   "|---|---|---|---|---|---|"]
        for sub in result.subdomains:
            ips = ", ".join(sub.ip_addresses[:3]) if sub.ip_addresses else "-"
            cnames = ", ".join(sub.cnames[:2]) if sub.cnames else "-"
            resolves = "yes" if sub.still_resolves else ("-" if not sub.ip_addresses and not sub.still_resolves else "no")
            takeover = "RISK" if sub.takeover_risk else "-"
            lines.append(f"| {sub.name} | {sub.first_seen[:10]} | {resolves} | {ips} | {cnames} | {takeover} |")
        lines.append("")

    if result.takeover_candidates > 0:
        takeover_subs = [s for s in result.subdomains if s.takeover_risk]
        lines += ["## Subdomain Takeover Candidates", ""]
        for s in takeover_subs:
            lines.append(f"- **{s.name}** → CNAME: {', '.join(s.cnames)} (does not resolve)")
        lines.append("")

    lines += [
        "## What this tells an attacker",
        "",
        "Certificate transparency logs are public. Every subdomain that ever had "
        "an HTTPS certificate is discoverable. Subdomains that still resolve are "
        "live attack surface. Subdomains that no longer resolve may point to "
        "abandoned infrastructure — a subdomain takeover risk.",
        "",
    ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domain", help="target domain (e.g., example.com)")
    ap.add_argument("--resolve", action="store_true",
                    help="DNS-resolve each subdomain (slower, more useful)")
    ap.add_argument("--filter", choices=["live", "dead", "wildcard", "takeover"],
                    help="show only subdomains matching this filter (requires --resolve for live/dead/takeover)")
    ap.add_argument("--out", default="recon-report",
                    help="output file prefix")
    ap.add_argument("--verbose", "-v", action="store_true", help="debug-level output")
    ap.add_argument("--quiet", "-q", action="store_true", help="errors only")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")

    result = recon(args.domain, do_resolve=args.resolve)

    if args.filter:
        result.subdomains = filter_subdomains(result.subdomains, args.filter)

    md = to_markdown(result)
    with open(f"{args.out}.md", "w") as fh:
        fh.write(md)
    with open(f"{args.out}.json", "w") as fh:
        json.dump(asdict(result), fh, indent=2, default=str)

    log.info("%d subdomains found. Report: %s.md / %s.json", result.unique_subdomains, args.out, args.out)


if __name__ == "__main__":
    main()
