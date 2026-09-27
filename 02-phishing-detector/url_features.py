"""Lesson 1: turn a URL into numbers a model can learn from.

A machine-learning model cannot read "http://paypa1-login.xyz/verify".
It can read [34, 1, 2, 0, 1, ...]. Each number is a *feature*: one
measurable clue. Choosing good clues is called feature engineering, and it
is where most of the skill in this project lives.

Everything here looks only at the URL *text*. We never visit the page, so
this step is completely safe to run on live phishing URLs.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qs, urlparse

# Words attackers use to create urgency or impersonate a login page.
SUSPICIOUS_WORDS = ("login", "signin", "verify", "account", "update", "secure",
                    "bank", "confirm", "password", "wallet", "support", "unlock")

# TLDs that are cheap or free and show up disproportionately in abuse reports.
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "icu", "cyou",
                   "buzz", "rest", "zip", "mov", "click", "live", "shop"}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "rb.gy"}


def shannon_entropy(text: str) -> float:
    """How 'random' a string looks, in bits per character.

    'google' is about 1.9, while a machine-generated 'x7kq9zp2vw' is about 3.3.
    Attackers often register random-looking domains in bulk.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract(url: str) -> dict[str, float]:
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    labels = host.split(".")
    tld = labels[-1] if len(labels) > 1 else ""
    lowered = url.lower()

    return {
        # --- size and shape ---
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "path_depth": path.count("/"),
        "num_query_params": len(parse_qs(parsed.query)),
        # --- odd characters ---
        "num_dots": url.count("."),
        "num_hyphens_host": host.count("-"),
        "num_digits": sum(ch.isdigit() for ch in url),
        "num_special": len(re.findall(r"[@~%=&!_]", url)),
        "has_at_symbol": int("@" in url),                # http://paypal.com@evil.xyz really goes to evil.xyz
        "has_double_slash_in_path": int("//" in path),
        # --- the host itself ---
        "host_is_ip": int(_is_ip(host)),
        "num_subdomains": max(0, len(labels) - 2),
        "host_entropy": round(shannon_entropy(host.replace(".", "")), 3),
        "is_punycode": int("xn--" in host),              # lookalike letters, e.g. Cyrillic 'а' in 'pаypal'
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "is_shortener": int(host in SHORTENERS),
        "has_port": int(parsed.port is not None),
        # --- the words used ---
        "uses_https": int(parsed.scheme == "https"),
        "num_suspicious_words": sum(word in lowered for word in SUSPICIOUS_WORDS),
    }


if __name__ == "__main__":
    for demo in ("https://www.wikipedia.org/wiki/Phishing",
                 "http://secure-login.paypa1-verify.xyz/account/update?id=88213",
                 "http://192.168.4.20/bank/login.php"):
        print(demo)
        for name, value in extract(demo).items():
            print(f"    {name:26} {value}")
        print()
