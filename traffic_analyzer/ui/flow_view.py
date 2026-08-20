"""Request flow visualization tab: spec section 7 —
Browser/App -> DNS -> TCP/QUIC -> TLS -> CDN/WAF -> Origin
"""
from __future__ import annotations

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


class FlowViewWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        self._label = QLabel("Select a request to view its flow.")
        self._label.setWordWrap(True)
        self._label.setStyleSheet("font-family: monospace; font-size: 13px;")
        layout.addWidget(self._label)

    def show_flow(self, parsed, waf_findings: list, antibot_findings: list) -> None:
        stages = ["Browser/App", "DNS", "TCP/QUIC", "TLS"]

        cdn_stage = "CDN/WAF"
        if waf_findings:
            cdn_stage = f"CDN/WAF  [{waf_findings[0].service}, {waf_findings[0].confidence}%]"
        elif antibot_findings:
            cdn_stage = f"CDN/WAF  [{antibot_findings[0].detection_type} suspected]"

        stages.append(cdn_stage)
        stages.append(f"Origin  ({parsed.host})")

        diagram_lines = []
        for i, stage in enumerate(stages):
            diagram_lines.append(stage)
            if i < len(stages) - 1:
                diagram_lines.append("    ↓")

        redirect_note = ""
        if parsed.redirect_chain:
            redirect_note = (
                "<br><br><b>Redirect chain:</b><br>" + "<br>→ ".join(parsed.redirect_chain)
            )

        self._label.setText("<br>".join(diagram_lines) + redirect_note)
