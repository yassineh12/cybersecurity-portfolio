"""Lesson 1: gather labelled URLs, the raw material of any classifier.

  label 1 (phishing): the free OpenPhish feed, a list of currently live phishing URLs
  label 0 (legit):    the Tranco list, a research-grade ranking of popular domains

We only download *lists of URLs* here. We never open the phishing pages.

Watch out for a trap: Tranco gives bare domains ("google.com"), while phishing
URLs have long paths. Compare them naively and the model learns "long path =
phishing", which is a shortcut, not a real signal. To avoid it, we crawl a few
internal links from each legit homepage, so both classes contain deep URLs.

Usage:
    python collect_urls.py --legit 300 --out data/urls.csv
"""

from __future__ import annotations

import argparse
import csv
import io
import random
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "01-headers-auditor"))
from crawler import USER_AGENT, Crawler  # noqa: E402  (reusing project 1's crawler)

OPENPHISH_FEED = "https://openphish.com/feed.txt"
TRANCO_TOP_1M = "https://tranco-list.eu/top-1m.csv.zip"


def fetch_phishing() -> list[str]:
    resp = requests.get(OPENPHISH_FEED, headers={"User-Agent": USER_AGENT}, timeout=30)
    resp.raise_for_status()
    return [line.strip() for line in resp.text.splitlines() if line.strip()]


def fetch_top_domains(n: int) -> list[str]:
    resp = requests.get(TRANCO_TOP_1M, headers={"User-Agent": USER_AGENT}, timeout=60)
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        rows = zf.read(zf.namelist()[0]).decode().splitlines()
    return [row.split(",")[1] for row in rows[:n]]           # "rank,domain"


def deep_links(domain: str, per_site: int) -> list[str]:
    """Homepage plus a few internal links, gathered with the polite crawler."""
    crawler = Crawler(f"https://{domain}/", max_pages=1, delay=0, timeout=8)
    links = [f"https://{domain}/"]
    for page in crawler.crawl():                            # just the homepage
        internal = [u for u in Crawler.extract_links(page.url, page.html)
                    if urlparse(u).hostname and urlparse(u).hostname.endswith(domain)]
        links += random.sample(internal, min(per_site, len(internal)))
    return links


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--legit", type=int, default=300, help="how many top domains to sample")
    ap.add_argument("--per-site", type=int, default=3, help="internal links per legit domain")
    ap.add_argument("--out", default="data/urls.csv")
    args = ap.parse_args()
    random.seed(42)

    phishing = fetch_phishing()
    print(f"phishing URLs: {len(phishing)}")

    legit = []
    for i, domain in enumerate(fetch_top_domains(args.legit), 1):
        try:
            legit += deep_links(domain, args.per_site)
        except Exception as exc:                            # one broken site shouldn't stop the run
            print(f"  skip {domain}: {exc.__class__.__name__}")
        if i % 25 == 0:
            print(f"  legit domains done: {i}/{args.legit}, URLs so far: {len(legit)}")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "label"])
        writer.writerows([(u, 1) for u in phishing] + [(u, 0) for u in legit])
    print(f"wrote {len(phishing)} phishing + {len(legit)} legit rows to {args.out}")


if __name__ == "__main__":
    main()
