"""A small, polite, same-site web crawler.

"Polite" means it:
  * obeys robots.txt,
  * waits between requests (so it never hammers a server),
  * stays on the host it was given (it never wanders off to other sites),
  * stops after a fixed number of pages.

Project 3 (the vulnerability scanner) reuses this module.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from urllib import robotparser
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

USER_AGENT = "SecurityPortfolioCrawler/1.0 (+educational; authorised targets only)"


@dataclass
class Page:
    url: str
    status: int
    headers: dict[str, str]          # lower-cased header names
    set_cookies: list[str]           # every raw Set-Cookie line (there can be several)
    html: str
    redirect_chain: list[str] = field(default_factory=list)


def _same_host(a: str, b: str) -> bool:
    return urlparse(a).hostname == urlparse(b).hostname


def _raw_set_cookies(resp: requests.Response) -> list[str]:
    # requests merges duplicate headers into one string, which breaks cookies
    # (their dates contain commas). The underlying urllib3 object keeps them apart.
    raw = getattr(resp.raw, "headers", None)
    if raw is not None and hasattr(raw, "getlist"):
        return list(raw.getlist("Set-Cookie"))
    value = resp.headers.get("Set-Cookie")
    return [value] if value else []


class Crawler:
    def __init__(self, start_url: str, max_pages: int = 30, delay: float = 1.0,
                 timeout: float = 10.0, respect_robots: bool = True):
        self.start_url = start_url
        self.max_pages = max_pages
        self.delay = delay
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.robots = self._load_robots() if respect_robots else None

    def _load_robots(self) -> robotparser.RobotFileParser | None:
        parts = urlparse(self.start_url)
        rp = robotparser.RobotFileParser()
        try:
            resp = self.session.get(f"{parts.scheme}://{parts.netloc}/robots.txt", timeout=self.timeout)
        except requests.RequestException:
            return None
        if resp.status_code >= 400:
            return None                      # no robots.txt means everything is allowed
        rp.parse(resp.text.splitlines())
        return rp

    def allowed(self, url: str) -> bool:
        return self.robots is None or self.robots.can_fetch(USER_AGENT, url)

    @staticmethod
    def extract_links(base_url: str, html: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all("a", href=True):
            absolute, _fragment = urldefrag(urljoin(base_url, tag["href"]))
            if urlparse(absolute).scheme in ("http", "https"):
                links.append(absolute)
        return links

    def crawl(self):
        """Breadth-first crawl. Yields one Page at a time."""
        queue = deque([self.start_url])
        seen = {self.start_url}
        fetched = 0

        while queue and fetched < self.max_pages:
            url = queue.popleft()
            if not self.allowed(url):
                continue
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            except requests.RequestException as exc:
                print(f"  ! {url}: {exc.__class__.__name__}")
                continue
            fetched += 1

            is_html = "text/html" in resp.headers.get("Content-Type", "")
            page = Page(
                url=resp.url,
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                set_cookies=_raw_set_cookies(resp),
                html=resp.text if is_html else "",
                redirect_chain=[r.url for r in resp.history],
            )
            yield page

            if is_html:
                for link in self.extract_links(page.url, page.html):
                    if link not in seen and _same_host(link, self.start_url):
                        seen.add(link)
                        queue.append(link)

            time.sleep(self.delay)
