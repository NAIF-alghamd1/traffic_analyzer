"""Request Explorer detail tab: everything in spec section 1."""
from __future__ import annotations

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QScrollArea


class RequestDetailsWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)

        self._summary_label = QLabel("Select a request to view details.")
        self._summary_label.setWordWrap(True)
        layout.addWidget(self._summary_label)

        self._headers_view = QTextEdit()
        self._headers_view.setReadOnly(True)
        self._headers_view.setFontFamily("monospace")
        layout.addWidget(self._headers_view)

    def show_request(self, parsed) -> None:
        summary_lines = [
            f"<b>{parsed.method}</b> {parsed.url}",
            f"Request ID: {parsed.request_id}",
            f"Timestamp: {parsed.timestamp}",
            f"Scheme: {parsed.scheme}  |  Host: {parsed.host}  |  Port: {parsed.port}",
            f"Path: {parsed.path}",
            f"Query params: {parsed.query_params or '(none)'}",
            f"HTTP version: {parsed.http_version}",
            f"Status: {parsed.status_code}  |  Size: {parsed.response_size} bytes  "
            f"|  Time: {parsed.response_time_ms} ms",
            f"Content-Type: {parsed.content_type}",
            f"Redirect chain: {' -> '.join(parsed.redirect_chain) if parsed.redirect_chain else '(none)'}",
            f"Connection ID: {parsed.connection_id}",
        ]
        self._summary_label.setText("<br>".join(summary_lines))

        headers_text = "== Request Headers ==\n"
        for k, v in parsed.request_headers.items():
            headers_text += f"{k}: {v}\n"
        headers_text += "\n== Response Headers ==\n"
        for k, v in parsed.response_headers.items():
            headers_text += f"{k}: {v}\n"
        self._headers_view.setPlainText(headers_text)
