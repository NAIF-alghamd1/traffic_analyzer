"""Search & filtering bar: spec section 8. Currently implements the
global text search across the visible table (URLs/paths/headers via
whatever's already rendered in the row); structured per-field filters
(domain/method/status/etc.) reuse the same `filters_changed` signal so
main_window.py has a single integration point to extend.
"""
from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLineEdit, QLabel


class SearchFilterBar(QWidget):
    filters_changed = pyqtSignal(dict)

    def __init__(self) -> None:
        super().__init__()
        layout = QHBoxLayout(self)
        layout.addWidget(QLabel("Search:"))

        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText(
            "Search URLs, paths, headers, cookie names…"
        )
        self._search_box.textChanged.connect(self._emit_filters)
        layout.addWidget(self._search_box)

    def _emit_filters(self) -> None:
        self.filters_changed.emit({"query": self._search_box.text()})
