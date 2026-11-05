"""Subdomain and certificate-transparency recon.

Discovers subdomains of a target domain by querying public certificate
transparency logs via crt.sh.  Every HTTPS certificate issued by a
trusted CA is logged publicly — this tool reads those logs to map the
attack surface an organisation exposes without sending a single packet
to the target.

Usage:
    python recon.py example.com
    python recon.py example.com --resolve --out report

Only run against domains you own or are authorised to test.
"""

from __future__ import annotations

import argparse
import json
import socket
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime

import requests


CT_LOG_URL = "https://crt.sh/?q=%.{domain}&output=json"
USER_AGENT = "SecurityPortfolioCrawler/1.0 (+educational; authorised targets only)"


@dataclass
class SubdomainInfo:
    name: str
    first_seen: str = ""
    last_seen: str = ""
    issuer: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    is_wildcard: bool = False
    still_resolves: bool = False


@dataclass
class ReconResult:
    target: str
    total_certs: int = 0
    unique_subdomains: int = 0
    subdomains: list[SubdomainInfo] = field(default_factory=list)
    issuers: dict[str, int] = field(default_factory=dict)
    wildcard_count: int = 0


def query_crt_sh(domain: str) -> list[dict]:
    url = CT_LOG_URL.format(domain=domain)
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
        if resp.status_code != 200:
            return []
        return resp.json()
    except (requests.RequestException, ValueError):
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


def recon(domain: str, do_resolve: bool = False) -> ReconResult:
    print(f"[1/3] Querying crt.sh for *.{domain} ...")
    entries = query_crt_sh(domain)
    result = ReconResult(target=domain, total_certs=len(entries))

    if not entries:
        print("  No CT log entries found.")
        return result

    print(f"  {len(entries)} certificate entries found.")

    print("[2/3] Parsing subdomains ...")
    subs = parse_ct_entries(entries, domain)
    result.unique_subdomains = len(subs)
    result.wildcard_count = sum(1 for s in subs.values() if s.is_wildcard)

    issuer_counts = Counter(s.issuer for s in subs.values())
    result.issuers = dict(issuer_counts.most_common(10))

    if do_resolve:
        print(f"[3/3] Resolving {len(subs)} subdomains ...")
        for i, (name, info) in enumerate(subs.items(), 1):
            ips = resolve_subdomain(name)
            info.ip_addresses = ips
            info.still_resolves = len(ips) > 0
            if i % 20 == 0:
                print(f"  resolved {i}/{len(subs)}")
    else:
        print("[3/3] Skipping DNS resolution (use --resolve to enable)")

    result.subdomains = sorted(subs.values(), key=lambda s: s.name)
    return result


def to_markdown(result: ReconResult) -> str:
    lines = [
        f"# Subdomain Recon Report: {result.target}",
        "",
        f"**Certificates in CT logs:** {result.total_certs}",
        f"**Unique subdomains:** {result.unique_subdomains}",
        f"**Wildcard certificates:** {result.wildcard_count}",
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
                   "| Subdomain | First Seen | Resolves | IPs |",
                   "|---|---|---|---|"]
        for sub in result.subdomains:
            ips = ", ".join(sub.ip_addresses[:3]) if sub.ip_addresses else "-"
            resolves = "yes" if sub.still_resolves else ("-" if not sub.ip_addresses and not sub.still_resolves else "no")
            lines.append(f"| {sub.name} | {sub.first_seen[:10]} | {resolves} | {ips} |")
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
    ap.add_argument("--out", default="recon-report",
                    help="output file prefix")
    args = ap.parse_args()

    result = recon(args.domain, do_resolve=args.resolve)

    md = to_markdown(result)
    with open(f"{args.out}.md", "w") as fh:
        fh.write(md)
    with open(f"{args.out}.json", "w") as fh:
        json.dump(asdict(result), fh, indent=2, default=str)

    print(f"\n{result.unique_subdomains} subdomains found.")
    print(f"Report: {args.out}.md / {args.out}.json")


if __name__ == "__main__":
    main()
