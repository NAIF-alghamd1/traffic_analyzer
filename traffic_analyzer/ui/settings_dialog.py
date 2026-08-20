"""Redaction & privacy settings dialog: spec section 10 —
configurable sensitive-data redaction, with safe defaults.
"""
from __future__ import annotations

from PyQt6.QtWidgets import QDialog, QVBoxLayout, QCheckBox, QDialogButtonBox, QLabel

from storage.redaction import RedactionConfig


class SettingsDialog(QDialog):
    def __init__(self, current_config: RedactionConfig, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Redaction & Privacy Settings")

        layout = QVBoxLayout(self)

        warning = QLabel(
            "Defaults are the safe/private state. Only change these if you "
            "understand the tradeoff and are working in an authorized "
            "environment you control."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)

        self._redact_headers_box = QCheckBox("Redact sensitive headers "
                                              "(Authorization, Cookie, etc.)")
        self._redact_headers_box.setChecked(current_config.redact_headers)
        layout.addWidget(self._redact_headers_box)

        self._redact_cookies_box = QCheckBox("Redact cookie values")
        self._redact_cookies_box.setChecked(current_config.redact_cookie_values)
        layout.addWidget(self._redact_cookies_box)

        self._store_session_tokens_box = QCheckBox(
            "Store session-token-like cookie values (off by default — "
            "session tokens are withheld from storage unless enabled here)"
        )
        self._store_session_tokens_box.setChecked(current_config.store_session_tokens)
        layout.addWidget(self._store_session_tokens_box)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def result_config(self) -> RedactionConfig:
        return RedactionConfig(
            redact_headers=self._redact_headers_box.isChecked(),
            redact_cookie_values=self._redact_cookies_box.isChecked(),
            store_session_tokens=self._store_session_tokens_box.isChecked(),
        )
