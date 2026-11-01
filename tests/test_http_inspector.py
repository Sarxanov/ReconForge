
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from reconforge.http_inspector import (
    HttpInspectionError,
    _SameHostRedirectHandler,
    inspect_http_url,
)


def _response(status=200, headers=None, url="https://example.test/"):
    response = MagicMock()
    response.getcode.return_value = status
    response.geturl.return_value = url
    response.headers.items.return_value = list((headers or {}).items())
    response.__enter__.return_value = response
    return response


def test_success_and_missing_headers():
    response = _response(headers={"Content-Security-Policy": "default-src 'self'"})
    with patch("reconforge.http_inspector.build_opener") as build:
        build.return_value.open.return_value = response
        result = inspect_http_url("https://example.test/")
    assert result.status_code == 200
    assert "Content-Security-Policy" in result.present_security_headers
    assert "X-Frame-Options" in result.missing_security_headers


def test_http_error_preserves_status_and_headers():
    from urllib.error import HTTPError

    error = HTTPError("https://example.test/", 404, "Not Found", {"X-Test": "yes"}, None)
    with patch("reconforge.http_inspector.build_opener") as build:
        build.return_value.open.side_effect = error
        result = inspect_http_url("https://example.test/")
    assert result.status_code == 404
    assert result.error.startswith("HTTP error 404")


def test_connection_error_is_reported():
    with patch("reconforge.http_inspector.build_opener") as build:
        build.return_value.open.side_effect = URLError("offline")
        result = inspect_http_url("https://example.test/")
    assert "offline" in result.error


@pytest.mark.parametrize("url", ["example.test", "ftp://example.test", ""])
def test_invalid_url(url):
    with pytest.raises(HttpInspectionError):
        inspect_http_url(url)


def test_invalid_timeout():
    with pytest.raises(HttpInspectionError):
        inspect_http_url("https://example.test/", timeout=0)


def test_cross_host_redirect_is_rejected():
    with pytest.raises(HttpInspectionError):
        _SameHostRedirectHandler("example.test").redirect_request(
            MagicMock(),
            MagicMock(),
            302,
            "Found",
            {},
            "https://other.example/",
        )
