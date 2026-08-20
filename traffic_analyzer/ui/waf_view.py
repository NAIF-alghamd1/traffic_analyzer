"""WAF/CDN detection tab: spec section 4. Detection-only display —
there is intentionally no action button here that does anything other
than show what was found.
"""
from __future__ import annotations

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


class WAFViewWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        self._label = QLabel("No WAF/CDN indicators detected for this request.")
        self._label.setWordWrap(True)
        layout.addWidget(self._label)

    def show_findings(self, findings: list) -> None:
        if not findings:
            self._label.setText("No WAF/CDN indicators detected for this request.")
            return

        blocks = []
        for finding in findings:
            evidence_html = "".join(f"<li>{e}</li>" for e in finding.evidence)
            blocks.append(
                f"<b>WAF/CDN:</b> {finding.service}<br>"
                f"<b>Confidence:</b> {finding.confidence}%<br>"
                f"<b>Evidence:</b><ul>{evidence_html}</ul>"
            )
        self._label.setText("<hr>".join(blocks))
