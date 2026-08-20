"""
mitmproxy addon: the actual traffic capture layer.

This runs as a local HTTP/HTTPS proxy (default 127.0.0.1:8080) that
the user explicitly configures their browser or application to use.
It only sees traffic that was deliberately routed through it.

HTTPS visibility model (see also tls/tls_parser.py docstring):
  - If the client does NOT trust this proxy's CA: mitmproxy passes TLS
    through untouched (passthrough mode). We see TCP/TLS-handshake
    metadata only -- SNI, ALPN, cipher, negotiated version -- exactly
    what any passive network observer would see. No decrypted content
    is ever available to this addon in that mode.
  - If the client DOES trust this proxy's CA (the user generated it
    via `mitmproxy --set confdir=...` on first run and installed it
    themselves in their OS/browser trust store): mitmproxy terminates
    TLS and we can see decrypted headers/bodies, same as any other
    local debugging proxy (Charles, Fiddler, Burp).
This addon does not choose which mode is active -- that is entirely a
function of what the user's own device trusts, decided outside this
codebase.
"""
from __future__ import annotations

import queue
from typing import Any

from mitmproxy import http

from connection_analysis.analyzer import ConnectionAnalyzer
from cookies.cookie_analyzer import CookieTracker
from parsers.http_parser import parse_flow
from tls.tls_parser import parse_tls_info


class TrafficCaptureAddon:
    """mitmproxy addon class. mitmproxy discovers and calls `response()`
    automatically once this is registered via `addons = [...]` in the
    mitmproxy options (see main.py).
    """

    def __init__(self, event_queue: "queue.Queue[dict[str, Any]]") -> None:
        # UI runs on the main thread; mitmproxy runs its own event loop
        # in a background thread (see main.py). We hand events across
        # via a thread-safe queue rather than touching Qt objects from
        # mitmproxy's thread directly.
        self._event_queue = event_queue
        self._cookie_tracker = CookieTracker()
        self._connection_analyzer = ConnectionAnalyzer()

    def response(self, flow: http.HTTPFlow) -> None:
        """Called by mitmproxy once a response has been received.

        This is a read-only observer hook: mitmproxy calls this AFTER
        the response has already been sent to/from the origin. Nothing
        in this method can alter, delay, retry, or replay the request
        or response -- it only inspects flow objects that already exist.
        """
        parsed = parse_flow(flow)
        tls_info = parse_tls_info(flow)

        connection_id = str(getattr(flow.client_conn, "id", flow.id))
        parsed.connection_id = connection_id
        self._connection_analyzer.observe(parsed, connection_id, tls_info.http_protocol)

        newly_set_cookies = self._cookie_tracker.observe(parsed)

        self._event_queue.put({
            "type": "flow",
            "request": parsed,
            "tls_info": tls_info,
            "newly_set_cookies": newly_set_cookies,
        })

    def error(self, flow: http.HTTPFlow) -> None:
        """Called on connection errors (e.g. client disconnect, TLS
        handshake failure). Surfaced to the UI as an informational
        event only -- no retry logic lives here.
        """
        self._event_queue.put({
            "type": "error",
            "flow_id": flow.id,
            "message": str(flow.error) if flow.error else "unknown error",
        })
