"""Cookie analysis tab: spec section 2, including the created-by /
sent-by relationship view.
"""
from __future__ import annotations

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView


class CookieViewWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)

        self._table = QTableWidget(0, 10)
        self._table.setHorizontalHeaderLabels([
            "Name", "Value", "Domain", "Path", "Secure", "HttpOnly",
            "SameSite", "Max-Age", "Created By", "Sent By (count)",
        ])
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self._table)

    def show_cookies_for_request(self, request_id: str, all_cookies) -> None:
        # Show every known cookie whose lifecycle touches this request
        # (created here, or sent here), so the relationship is visible
        # from either direction.
        relevant = [
            c for c in all_cookies
            if c.created_by_request_id == request_id or request_id in c.sent_by_request_ids
        ]
        self._render(relevant or all_cookies)

    def _render(self, cookies) -> None:
        self._table.setRowCount(0)
        for cookie in cookies:
            row = self._table.rowCount()
            self._table.insertRow(row)
            values = [
                cookie.name,
                cookie.value,
                cookie.domain,
                cookie.path,
                "Yes" if cookie.secure else "No",
                "Yes" if cookie.http_only else "No",
                cookie.same_site or "-",
                str(cookie.max_age) if cookie.max_age is not None else "-",
                cookie.created_by_request_id or "-",
                str(len(cookie.sent_by_request_ids)),
            ]
            for col, value in enumerate(values):
                self._table.setItem(row, col, QTableWidgetItem(value))
