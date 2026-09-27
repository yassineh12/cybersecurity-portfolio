"""Security headers & TLS auditor.

Usage:
    python auditor.py http://testphp.vulnweb.com --max-pages 20
    python auditor.py https://your-own-site.example --out report

Only scan sites you own or are explicitly allowed to test.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import asdict
from urllib.parse import urlparse

from checks import SEVERITY_POINTS, Finding, check_cookies, check_headers, check_html, check_tls
from crawler import Crawler


def score(findings: list[Finding]) -> tuple[int, str]:
    # Each *kind* of problem costs points once, however many pages repeat it:
    # a missing header on 30 pages is still one misconfiguration.
    unique = {(f.id, f.title): f.severity for f in findings}
    points = max(0, 100 - sum(SEVERITY_POINTS[s] for s in unique.values()))
    for threshold, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if points >= threshold:
            return points, grade
    return points, "F"


def group(findings: list[Finding]) -> list[dict]:
    grouped: dict[tuple, dict] = {}
    urls = defaultdict(set)
    for f in findings:
        key = (f.id, f.title)
        grouped.setdefault(key, asdict(f))
        urls[key].add(f.url)
    order = {"high": 0, "medium": 1, "low": 2}
    out = []
    for key, item in grouped.items():
        item.pop("url")
        item["affected_urls"] = sorted(urls[key])
        out.append(item)
    return sorted(out, key=lambda i: (order[i["severity"]], i["id"]))


def to_markdown(target, points, grade, tls_info, pages, issues) -> str:
    lines = [f"# Security audit: {target}", "",
             f"**Grade: {grade}** ({points}/100), {len(pages)} pages crawled", ""]
    if tls_info:
        if "error" in tls_info:
            lines += [f"TLS: could not connect ({tls_info['error']})", ""]
        elif "version" in tls_info:
            lines += [f"TLS: {tls_info['version']}, certificate expires "
                      f"{tls_info.get('cert_expires')} ({tls_info.get('days_left')} days)", ""]
    lines += ["| Severity | Issue | Pages | Fix |", "|---|---|---|---|"]
    for i in issues:
        lines.append(f"| {i['severity'].upper()} | {i['title']} | {len(i['affected_urls'])} | {i['fix']} |")
    lines += ["", "## Details", ""]
    for i in issues:
        lines.append(f"### [{i['severity'].upper()}] {i['title']}")
        if i["detail"]:
            lines.append(f"- Evidence: `{i['detail']}`")
        for u in i["affected_urls"][:5]:
            lines.append(f"- {u}")
        if len(i["affected_urls"]) > 5:
            lines.append(f"- ...and {len(i['affected_urls']) - 5} more")
        lines.append("")
    return "\n".join(lines)


def audit(target: str, max_pages: int, delay: float, respect_robots: bool = True) -> dict:
    findings: list[Finding] = []
    pages = []
    crawler = Crawler(target, max_pages=max_pages, delay=delay, respect_robots=respect_robots)
    for page in crawler.crawl():
        print(f"  [{page.status}] {page.url}")
        pages.append(page.url)
        findings += check_headers(page.url, page.headers)
        findings += check_cookies(page.url, page.set_cookies)
        findings += check_html(page.url, page.html)

    tls_info = {}
    host = urlparse(target).hostname
    if pages and any(p.startswith("https://") for p in pages):
        tls_info, tls_findings = check_tls(host)
        findings += tls_findings

    points, grade = score(findings)
    return {"target": target, "grade": grade, "score": points, "pages": pages,
            "tls": tls_info, "issues": group(findings)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--max-pages", type=int, default=20)
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between requests")
    ap.add_argument("--out", default="report", help="output file prefix (writes .md and .json)")
    ap.add_argument("--ignore-robots", action="store_true",
                    help="only for your own sites")
    args = ap.parse_args()

    print(f"Auditing {args.url} ...")
    result = audit(args.url, args.max_pages, args.delay, respect_robots=not args.ignore_robots)
    md = to_markdown(result["target"], result["score"], result["grade"], result["tls"],
                     result["pages"], result["issues"])
    with open(f"{args.out}.md", "w") as fh:
        fh.write(md)
    with open(f"{args.out}.json", "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"\nGrade {result['grade']} ({result['score']}/100), "
          f"{len(result['issues'])} issue types. Report: {args.out}.md / {args.out}.json")


if __name__ == "__main__":
    main()
