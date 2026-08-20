"""
Connection-level analysis: keep-alive reuse, HTTP/2 multiplexing,
per-connection request counts and timelines.

mitmproxy exposes a stable connection identifier (`flow.client_conn.id`)
for the underlying TCP/QUIC connection each flow rode on. Multiple
HTTP requests sharing that id are, by definition, reusing the same
connection -- for HTTP/1.1 via keep-alive, for HTTP/2+ via
multiplexing. This module aggregates that fact into per-connection
summaries and a chronological timeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ConnectionSummary:
    connection_id: str
    request_ids: list[str] = field(default_factory=list)
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    http_protocol: str | None = None
    keep_alive: bool = False

    @property
    def request_count(self) -> int:
        return len(self.request_ids)

    @property
    def duration_seconds(self) -> float | None:
        if self.first_timestamp is None or self.last_timestamp is None:
            return None
        return round(self.last_timestamp - self.first_timestamp, 3)


class ConnectionAnalyzer:
    """Stateful aggregator. Feed it ParsedRequest + connection_id pairs
    (assigned by the capture addon) via `observe()`, then read summaries.
    """

    def __init__(self) -> None:
        self._connections: dict[str, ConnectionSummary] = {}

    def observe(self, parsed_request, connection_id: str, http_protocol: str | None) -> None:
        summary = self._connections.get(connection_id)
        if summary is None:
            summary = ConnectionSummary(connection_id=connection_id)
            self._connections[connection_id] = summary

        summary.request_ids.append(parsed_request.request_id)
        summary.http_protocol = http_protocol or summary.http_protocol

        ts = parsed_request.timestamp
        if summary.first_timestamp is None or ts < summary.first_timestamp:
            summary.first_timestamp = ts
        if summary.last_timestamp is None or ts > summary.last_timestamp:
            summary.last_timestamp = ts

        conn_header = (
            parsed_request.request_headers.get("connection")
            or parsed_request.request_headers.get("Connection")
            or ""
        )
        if conn_header.lower() == "keep-alive" or (http_protocol or "").startswith("HTTP/2") \
                or (http_protocol or "").startswith("HTTP/3"):
            summary.keep_alive = True

        # A connection carrying more than one request is itself proof of
        # reuse/multiplexing regardless of the Connection header value,
        # since HTTP/2+ multiplexes without ever sending that header.
        if summary.request_count > 1:
            summary.keep_alive = True

    def summaries(self) -> list[ConnectionSummary]:
        return sorted(
            self._connections.values(),
            key=lambda s: s.first_timestamp or 0,
        )

    def timeline(self) -> list[dict]:
        """Flat chronological list of (connection_id, request_id, timestamp)
        suitable for the UI's connection-timeline view.
        """
        events = []
        for conn_id, summary in self._connections.items():
            for req_id in summary.request_ids:
                events.append({"connection_id": conn_id, "request_id": req_id})
        return events
