import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from url_features import extract, shannon_entropy  # noqa: E402


def test_entropy_orders_random_above_readable():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("x7kq9zp2vw") > shannon_entropy("google")


def test_phishy_url_lights_up_the_right_features():
    f = extract("http://secure-login.paypa1-verify.xyz/account/update?id=88213")
    assert f["suspicious_tld"] == 1
    assert f["uses_https"] == 0
    assert f["num_suspicious_words"] >= 4          # secure, login, verify, account, update
    assert f["num_subdomains"] == 1
    assert f["num_hyphens_host"] == 2


def test_ip_host_and_at_trick():
    assert extract("http://192.168.4.20/login")["host_is_ip"] == 1
    assert extract("http://paypal.com@evil.example/")["has_at_symbol"] == 1


def test_punycode_and_shortener():
    assert extract("https://xn--pypal-4ve.com/")["is_punycode"] == 1
    assert extract("https://bit.ly/abc")["is_shortener"] == 1


def test_clean_url_is_quiet():
    f = extract("https://www.wikipedia.org/wiki/Phishing")
    assert f["host_is_ip"] == f["suspicious_tld"] == f["has_at_symbol"] == 0
    assert f["uses_https"] == 1


def test_scheme_is_optional():
    assert extract("example.com/path")["host_length"] == len("example.com")
