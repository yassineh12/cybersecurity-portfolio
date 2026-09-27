import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auditor import score  # noqa: E402
from checks import check_cookies, check_headers, check_html  # noqa: E402
from crawler import Crawler  # noqa: E402

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "server": "nginx",
}


def ids(findings):
    return {f.id for f in findings}


def test_well_configured_site_has_no_header_findings():
    assert check_headers("https://example.com/", GOOD_HEADERS) == []


def test_bare_https_site_flags_the_basics():
    found = ids(check_headers("https://example.com/", {}))
    assert {"hsts-missing", "csp-missing", "clickjacking", "nosniff-missing", "referrer-missing"} <= found


def test_http_page_flagged_but_hsts_not_expected():
    found = ids(check_headers("http://example.com/", {}))
    assert "no-https" in found and "hsts-missing" not in found


def test_short_hsts_and_unsafe_csp():
    h = dict(GOOD_HEADERS, **{"strict-transport-security": "max-age=600",
                              "content-security-policy": "script-src 'self' 'unsafe-inline'"})
    found = ids(check_headers("https://example.com/", h))
    assert {"hsts-short", "csp-unsafe", "clickjacking"} <= found


def test_version_leak():
    h = dict(GOOD_HEADERS, **{"x-powered-by": "PHP/5.6.40"})
    assert "version-leak" in ids(check_headers("https://example.com/", h))


def test_cookie_flags():
    bad = check_cookies("https://example.com/", ["session=abc; Path=/"])
    assert ids(bad) == {"cookie-secure", "cookie-httponly", "cookie-samesite"}
    good = check_cookies("https://example.com/", ["session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"])
    assert good == []


def test_mixed_content_and_insecure_form():
    html = """<script src="http://cdn.example.com/x.js"></script>
              <form action="http://example.com/login"><input type="password"></form>"""
    assert ids(check_html("https://example.com/", html)) == {"mixed-content", "insecure-form"}


def test_password_form_on_http_page():
    html = '<form action="/login"><input type="password"></form>'
    assert "insecure-form" in ids(check_html("http://example.com/", html))


def test_score_counts_each_issue_type_once():
    many = check_headers("https://a.com/1", {}) + check_headers("https://a.com/2", {})
    once = check_headers("https://a.com/1", {})
    assert score(many) == score(once)
    assert score([]) == (100, "A")


def test_link_extraction_resolves_relative_and_drops_fragments():
    html = '<a href="/about#team">x</a><a href="mailto:a@b.c">y</a><a href="https://other.com/">z</a>'
    assert Crawler.extract_links("https://example.com/page", html) == [
        "https://example.com/about", "https://other.com/"]
