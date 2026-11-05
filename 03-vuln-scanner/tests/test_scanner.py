from scanner import (
    check_cookie_security,
    check_cors_misconfig,
    fingerprint_headers,
    fingerprint_html,
    map_forms,
    map_query_params,
    map_js_files,
    to_markdown,
    CVEMatch,
    ScanResult,
    SoftwareFingerprint,
    VulnFinding,
    SEVERITY_ORDER,
)
from bs4 import BeautifulSoup

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "01-headers-auditor"))
from crawler import Page  # noqa: E402


def test_fingerprint_apache_from_header():
    headers = {"server": "Apache/2.4.51 (Ubuntu)"}
    fps = fingerprint_headers(headers)
    assert len(fps) >= 1
    assert fps[0].name == "Apache HTTP Server"
    assert fps[0].version == "2.4.51"
    assert "cpe" in fps[0].cpe


def test_fingerprint_php_from_header():
    headers = {"x-powered-by": "PHP/8.1.2"}
    fps = fingerprint_headers(headers)
    assert any(fp.name == "PHP" for fp in fps)


def test_fingerprint_wordpress_from_html():
    html = '<meta name="generator" content="WordPress 6.4.2">'
    fps = fingerprint_html(html)
    assert len(fps) == 1
    assert fps[0].name == "WordPress"
    assert fps[0].version == "6.4.2"


def test_map_forms_extracts_inputs():
    html = """
    <form action="/login" method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
        <input type="submit" value="Login">
    </form>
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = map_forms("http://example.com/login", soup)
    assert len(forms) == 1
    assert forms[0].method == "POST"
    input_names = [i["name"] for i in forms[0].inputs]
    assert "username" in input_names
    assert "password" in input_names


def test_no_headers_no_crash():
    assert fingerprint_headers({}) == []
    assert fingerprint_html("") == []


def test_severity_order():
    assert SEVERITY_ORDER["high"] < SEVERITY_ORDER["low"]


def _make_page(url, headers=None, html="", set_cookies=None, status=200):
    return Page(url=url, status=status, headers=headers or {},
                html=html, set_cookies=set_cookies or [])


def test_query_param_mapping():
    pages = [
        _make_page("http://example.com/search?q=hello"),
        _make_page("http://example.com/search?q=world"),
        _make_page("http://example.com/page?id=1"),
    ]
    params = map_query_params(pages)
    assert "q" in params
    assert len(params["q"]) == 2
    assert "id" in params


def test_js_file_discovery():
    pages = [
        _make_page("http://example.com/", html='<script src="/js/app.js"></script><script src="/js/vendor.js"></script>'),
        _make_page("http://example.com/about", html='<script src="/js/app.js"></script>'),
    ]
    js_files = map_js_files(pages)
    assert len(js_files) == 2
    assert "http://example.com/js/app.js" in js_files


def test_cors_misconfig_detected():
    pages = [
        _make_page("http://example.com/api",
                    headers={"access-control-allow-origin": "*",
                             "access-control-allow-credentials": "true"}),
    ]
    findings = check_cors_misconfig(pages)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].id == "cors-misconfig"


def test_cors_wildcard_without_credentials():
    pages = [
        _make_page("http://example.com/api",
                    headers={"access-control-allow-origin": "*"}),
    ]
    findings = check_cors_misconfig(pages)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_cookie_security_check():
    pages = [
        _make_page("https://example.com/",
                    set_cookies=["session=abc123; Path=/"]),
    ]
    findings = check_cookie_security(pages)
    assert len(findings) == 1
    assert "Secure" in findings[0].title
    assert "HttpOnly" in findings[0].title


def test_markdown_output_structure():
    result = ScanResult(
        target="http://example.com",
        pages_crawled=5,
        fingerprints=[SoftwareFingerprint("nginx", "1.19", "header:server", "")],
        cves=[CVEMatch("CVE-2021-12345", "Test vuln", 7.5, "nginx")],
        findings=[VulnFinding("test-finding", "high", "Test", "detail", "http://example.com", "Fix it")],
    )
    md = to_markdown(result)
    assert "# Vulnerability Scan Report" in md
    assert "nginx" in md
    assert "CVE-2021-12345" in md
    assert "Test" in md


def test_empty_scan_result_no_crash():
    result = ScanResult(target="http://example.com", pages_crawled=0)
    md = to_markdown(result)
    assert "No findings" in md
