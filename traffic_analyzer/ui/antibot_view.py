"""Anti-bot/CAPTCHA detection tab: spec section 5. Detection-only —
no solve/bypass/automate affordance exists in this widget or anywhere
downstream of it.
"""
from __future__ import annotations

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


class AntiBotViewWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        self._label = QLabel("No anti-bot/CAPTCHA indicators detected for this request.")
        self._label.setWordWrap(True)
        layout.addWidget(self._label)

    def show_findings(self, findings: list) -> None:
        if not findings:
            self._label.setText("No anti-bot/CAPTCHA indicators detected for this request.")
            return

        blocks = []
        for finding in findings:
            evidence_html = "".join(f"<li>{e}</li>" for e in finding.evidence)
            blocks.append(
                f"<b>Detection type:</b> {finding.detection_type}<br>"
                f"<b>Domain:</b> {finding.domain}  <b>Path:</b> {finding.path}<br>"
                f"<b>Confidence:</b> {finding.confidence}%<br>"
                f"<b>Evidence:</b><ul>{evidence_html}</ul>"
            )
        self._label.setText("<hr>".join(blocks))
