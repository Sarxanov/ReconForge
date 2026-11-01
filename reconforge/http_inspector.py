
"""Conservative HTTP security-header inspection for explicitly supplied URLs."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)


SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


class HttpInspectionError(ValueError):
    """Raised for invalid inspection input."""


@dataclass
class HttpInspectionResult:
    """Observed HTTP response and security-header findings."""

    url: str
    final_url: str = ""
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    present_security_headers: list[str] = field(default_factory=list)
    missing_security_headers: list[str] = field(default_factory=list)
    error: str = ""
    redirected: bool = False


class _SameHostRedirectHandler(HTTPRedirectHandler):
    """Allow redirects only when the destination keeps the original host."""

    def __init__(self, original_host: str) -> None:
        super().__init__()
        self.original_host = original_host.lower()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urlparse(newurl)
        if (destination.hostname or "").lower() != self.original_host:
            raise HttpInspectionError(
                "Redirect blocked because it points to a different host"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HttpInspectionError("URL must be an absolute http:// or https:// URL")
    return url


def inspect_http_url(
    url: str,
    timeout: float = 10.0,
    user_agent: str = "ReconForge/1.0 (authorized security assessment)",
) -> HttpInspectionResult:
    """Inspect one explicitly supplied HTTP(S) URL without making extra requests."""

    _validate_url(url)
    if timeout <= 0:
        raise HttpInspectionError("Timeout must be greater than zero")
    parsed = urlparse(url)
    request = Request(url, headers={"User-Agent": user_agent}, method="GET")
    opener = build_opener(_SameHostRedirectHandler(parsed.hostname or ""))
    result = HttpInspectionResult(url=url)
    try:
        with opener.open(request, timeout=timeout) as response:
            result.status_code = response.getcode()
            result.final_url = response.geturl()
            result.redirected = result.final_url != url
            result.headers = {key: value for key, value in response.headers.items()}
    except HTTPError as exc:
        result.status_code = exc.code
        result.final_url = exc.geturl() or url
        result.headers = {key: value for key, value in exc.headers.items()}
        result.error = f"HTTP error {exc.code}: {exc.reason}"
    except (HttpInspectionError, URLError, TimeoutError, OSError) as exc:
        result.error = str(exc)
        return result

    lower_headers = {key.lower(): value for key, value in result.headers.items()}
    result.present_security_headers = [
        header for header in SECURITY_HEADERS if header.lower() in lower_headers
    ]
    result.missing_security_headers = [
        header for header in SECURITY_HEADERS if header not in result.present_security_headers
    ]
    return result


inspect_url = inspect_http_url
