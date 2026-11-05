"""Lesson 2: features extracted from the page itself.

URL features (lesson 1) are cheap: they never touch the network.  Page
features are richer but require fetching the page, so we do it inside a
timeout-guarded, redirect-limited session — a disposable sandbox of sorts.

We look at things a phishing page typically gets wrong: mismatched domains
in links, suspicious form actions, brand logos loaded from somewhere the
domain doesn't own, freshly registered certificates, and heavy use of
data-URIs to avoid hosting detectable assets.
"""

from __future__ import annotations

import re
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


_SESSION = requests.Session()
_SESSION.headers["User-Agent"] = (
    "SecurityPortfolioCrawler/1.0 (+educational; authorised targets only)"
)
_SESSION.max_redirects = 5


def _safe_get(url: str, timeout: float = 8.0) -> requests.Response | None:
    try:
        return _SESSION.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None


def _cert_age_days(hostname: str, port: int = 443) -> int | None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
        not_before = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc
        )
        return (datetime.now(timezone.utc) - not_before).days
    except Exception:
        return None


def extract(url: str) -> dict[str, float]:
    """Fetch *url* and return content-based features.

    Returns an empty dict on network failure so callers can fall back to
    URL-only features without crashing.
    """
    resp = _safe_get(url)
    if resp is None:
        return {}

    html = resp.text
    soup = BeautifulSoup(html, "html.parser")
    page_host = urlparse(resp.url).hostname or ""

    # --- link analysis ---
    anchors = soup.find_all("a", href=True)
    external = sum(
        1 for a in anchors
        if urlparse(a["href"]).hostname
        and not urlparse(a["href"]).hostname.endswith(page_host)
    )
    empty_links = sum(
        1 for a in anchors if a["href"] in ("#", "", "javascript:void(0)")
    )

    # --- form analysis ---
    forms = soup.find_all("form")
    form_external = 0
    form_has_password = 0
    for form in forms:
        action = form.get("action", "")
        action_host = urlparse(action).hostname
        if action_host and not action_host.endswith(page_host):
            form_external += 1
        if form.find("input", {"type": "password"}):
            form_has_password += 1

    # --- resource analysis ---
    scripts = soup.find_all("script", src=True)
    ext_scripts = sum(
        1 for s in scripts
        if urlparse(s["src"]).hostname
        and not urlparse(s["src"]).hostname.endswith(page_host)
    )
    imgs = soup.find_all("img", src=True)
    data_uri_imgs = sum(1 for i in imgs if i["src"].startswith("data:"))

    # --- text signals ---
    text = soup.get_text(" ", strip=True).lower()
    urgency_words = sum(
        1 for w in ("urgent", "immediately", "suspend", "verify", "unauthorized",
                     "expire", "locked", "alert", "unusual", "confirm")
        if w in text
    )

    # --- iframe abuse ---
    iframes = soup.find_all("iframe")
    hidden_iframes = sum(
        1 for f in iframes
        if f.get("style") and ("display:none" in f["style"].replace(" ", "")
                                or "visibility:hidden" in f["style"].replace(" ", ""))
        or f.get("width") == "0" or f.get("height") == "0"
    )

    # --- redirect chain ---
    redirect_count = len(resp.history)
    final_host_differs = int(
        bool(resp.history) and urlparse(resp.history[0].url).hostname != page_host
    )

    # --- certificate freshness ---
    cert_age = _cert_age_days(page_host) if urlparse(url).scheme == "https" else None

    # --- right-click / copy disabled ---
    disables_right_click = int(bool(re.search(
        r"oncontextmenu\s*=\s*['\"]?\s*return\s+false", html, re.I
    )))

    total_links = max(len(anchors), 1)

    return {
        "num_links": len(anchors),
        "pct_external_links": round(external / total_links, 3),
        "num_empty_links": empty_links,
        "num_forms": len(forms),
        "form_posts_external": form_external,
        "form_has_password": form_has_password,
        "num_external_scripts": ext_scripts,
        "num_data_uri_images": data_uri_imgs,
        "urgency_word_count": urgency_words,
        "hidden_iframes": hidden_iframes,
        "redirect_count": redirect_count,
        "final_host_differs": final_host_differs,
        "disables_right_click": disables_right_click,
        "cert_age_days": cert_age if cert_age is not None else -1,
    }


if __name__ == "__main__":
    for demo in ("https://www.wikipedia.org", "https://example.com"):
        print(demo)
        feats = extract(demo)
        if feats:
            for k, v in feats.items():
                print(f"    {k:28} {v}")
        else:
            print("    (could not fetch)")
        print()
