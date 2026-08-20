"""
HTTP request/response parsing and normalization.

This module converts raw mitmproxy flow objects into a normalized,
JSON-serializable representation used throughout the rest of the
application (UI, storage, exporters, detectors).

This module is passive: it only reads and structures data that already
passed through the proxy. It does not modify, retry, or replay requests.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, parse_qsl


# Headers that are considered sensitive and redacted by default anywhere
# they are displayed or exported. See storage/redaction.py for the actual
# redaction implementation; this constant is the single source of truth
# for "which header names count as sensitive" so detectors/UI/exporters
# never disagree with each other.
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}


@dataclass
class ParsedRequest:
    """Normalized representation of a single HTTP request/response pair."""

    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)

    method: str = ""
    url: str = ""
    scheme: str = ""
    host: str = ""
    port: int | None = None
    path: str = ""
    query_params: list[tuple[str, str]] = field(default_factory=list)
    http_version: str = ""

    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)

    status_code: int | None = None
    response_size: int | None = None
    response_time_ms: float | None = None
    content_type: str | None = None

    redirect_chain: list[str] = field(default_factory=list)

    # Populated by connection_analysis, not by the parser itself.
    connection_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "method": self.method,
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "query_params": self.query_params,
            "http_version": self.http_version,
            "request_headers": self.request_headers,
            "response_headers": self.response_headers,
            "status_code": self.status_code,
            "response_size": self.response_size,
            "response_time_ms": self.response_time_ms,
            "content_type": self.content_type,
            "redirect_chain": self.redirect_chain,
            "connection_id": self.connection_id,
        }


def parse_url(url: str) -> dict[str, Any]:
    """Split a URL into scheme/host/port/path/query components.

    Pure function, no I/O. Used both by the live parser and by unit tests.
    """
    parts = urlsplit(url)
    if parts.port:
        port = parts.port
    elif parts.scheme == "https":
        port = 443
    elif parts.scheme == "http":
        port = 80
    else:
        port = None

    return {
        "scheme": parts.scheme,
        "host": parts.hostname or "",
        "port": port,
        "path": parts.path or "/",
        "query_params": parse_qsl(parts.query, keep_blank_values=True),
    }


def parse_flow(flow: Any) -> ParsedRequest:
    """Convert a mitmproxy HTTPFlow into a ParsedRequest.

    `flow` is typed as Any to avoid a hard import dependency on mitmproxy
    in modules/tests that don't need it; at runtime it is a
    mitmproxy.http.HTTPFlow supplied by capture/proxy_addon.py.
    """
    request = flow.request
    response = flow.response

    url_parts = parse_url(request.url)
    parsed = ParsedRequest(
        method=request.method,
        url=request.url,
        scheme=url_parts["scheme"],
        host=url_parts["host"],
        port=url_parts["port"],
        path=url_parts["path"],
        query_params=url_parts["query_params"],
        http_version=request.http_version,
        request_headers=dict(request.headers),
    )

    if response is not None:
        parsed.response_headers = dict(response.headers)
        parsed.status_code = response.status_code
        parsed.response_size = len(response.raw_content or b"")
        parsed.content_type = response.headers.get("content-type")

        if flow.request.timestamp_start and response.timestamp_end:
            elapsed = response.timestamp_end - flow.request.timestamp_start
            parsed.response_time_ms = round(elapsed * 1000, 2)

    # mitmproxy exposes redirect history through flow metadata when the
    # user has redirect-following enabled at the client; if the client
    # follows redirects itself, each hop appears as its own flow and the
    # connection_analysis module links them via the Location header
    # instead. We surface whatever is directly available here.
    if hasattr(flow, "metadata") and "redirect_chain" in flow.metadata:
        parsed.redirect_chain = list(flow.metadata["redirect_chain"])

    return parsed
