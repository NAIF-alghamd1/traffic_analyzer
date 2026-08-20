"""TLS/Encryption analysis tab: spec section 3."""
from __future__ import annotations

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


class TLSViewWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        self._label = QLabel("Select a request to view TLS info.")
        self._label.setWordWrap(True)
        layout.addWidget(self._label)

    def show_tls_info(self, tls_info) -> None:
        if tls_info is None:
            self._label.setText("No TLS info available for this request (plain HTTP, "
                                 "or request not yet processed).")
            return

        lines = [
            f"TLS version: {tls_info.tls_version or '(not available)'}",
            f"Cipher suite: {tls_info.cipher_suite or '(not available)'}",
            f"ALPN protocol: {tls_info.alpn_protocol or '(not available)'}",
            f"SNI: {tls_info.sni or '(not available)'}",
            f"HTTP protocol: {tls_info.http_protocol or '(not available)'}",
            "",
        ]

        if tls_info.interception_active:
            lines += [
                "<b>Certificate details</b> (HTTPS interception active — "
                "your device trusts this proxy's local CA):",
                f"Subject: {tls_info.cert_subject or '(not available)'}",
                f"Issuer: {tls_info.cert_issuer or '(not available)'}",
                f"Valid from: {tls_info.cert_not_before or '(not available)'}",
                f"Valid until: {tls_info.cert_not_after or '(not available)'}",
            ]
        else:
            lines += [
                "<i>Certificate subject/issuer/validity are not shown: HTTPS "
                "interception is not active for this connection. Only TLS "
                "handshake metadata above is visible. To see certificate "
                "details and decrypted content, install this tool's CA "
                "certificate in your own device's trust store (see Help → "
                "About / Safety Boundary) — this tool never inspects encrypted "
                "content without that explicit step.</i>",
            ]

        self._label.setText("<br>".join(lines))
