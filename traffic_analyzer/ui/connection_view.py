"""Keep-alive/connection analysis tab: spec section 6."""
from __future__ import annotations

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView


class ConnectionViewWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)

        self._current_label = QLabel("Select a request to view its connection.")
        self._current_label.setWordWrap(True)
        layout.addWidget(self._current_label)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Connection ID", "Requests", "Protocol", "Keep-Alive", "Duration (s)"]
        )
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self._table)

    def show_connection(self, connection_id: str | None, all_summaries) -> None:
        current = next((s for s in all_summaries if s.connection_id == connection_id), None)
        if current is not None:
            self._current_label.setText(
                f"This request is on connection <b>{current.connection_id}</b>, which carried "
                f"<b>{current.request_count}</b> request(s) over "
                f"<b>{current.duration_seconds}</b>s using "
                f"<b>{current.http_protocol or 'unknown protocol'}</b>."
            )

        self._table.setRowCount(0)
        for summary in all_summaries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            values = [
                summary.connection_id,
                str(summary.request_count),
                summary.http_protocol or "-",
                "Yes" if summary.keep_alive else "No",
                str(summary.duration_seconds) if summary.duration_seconds is not None else "-",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if summary.connection_id == connection_id:
                    from PyQt6.QtGui import QColor
                    item.setBackground(QColor("#e3f2fd"))
                self._table.setItem(row, col, item)
