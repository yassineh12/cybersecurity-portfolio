from scanner import (
    fingerprint_headers,
    fingerprint_html,
    map_forms,
    VulnFinding,
    SEVERITY_ORDER,
)
from bs4 import BeautifulSoup


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
