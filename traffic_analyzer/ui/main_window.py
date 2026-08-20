"""
Main application window.

Layout: a filterable/searchable request table on top, a tabbed detail
panel below showing whichever request is selected across all the
analysis dimensions (headers, cookies, TLS, WAF/CDN, anti-bot,
connection). A background QTimer drains the capture event queue so
mitmproxy's thread never touches Qt widgets directly.
"""
from __future__ import annotations

import queue
from typing import Any

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
    QTableWidgetItem, QTabWidget, QLabel, QLineEdit, QPushButton,
    QHeaderView, QStatusBar, QMenuBar, QFileDialog, QMessageBox,
)

from antibot_detection.detector import detect as detect_antibot
from connection_analysis.analyzer import ConnectionAnalyzer
from cookies.cookie_analyzer import CookieTracker
from exporters.exporter import export_json, export_csv, export_har, export_html_report
from storage.redaction import RedactionConfig
from storage.storage import Storage
from waf_detection.detector import detect as detect_waf

from ui.request_details import RequestDetailsWidget
from ui.cookie_view import CookieViewWidget
from ui.tls_view import TLSViewWidget
from ui.waf_view import WAFViewWidget
from ui.antibot_view import AntiBotViewWidget
from ui.connection_view import ConnectionViewWidget
from ui.flow_view import FlowViewWidget
from ui.search_filter import SearchFilterBar
from ui.settings_dialog import SettingsDialog


class MainWindow(QMainWindow):
    def __init__(self, event_queue: "queue.Queue[dict[str, Any]]", proxy_port: int):
        super().__init__()
        self.setWindowTitle(f"HTTP/HTTPS Traffic Analyzer  —  proxy on 127.0.0.1:{proxy_port}")
        self.resize(1400, 900)

        self._event_queue = event_queue
        self._proxy_port = proxy_port
        self._redaction_config = RedactionConfig()
        self._storage = Storage(redaction_config=self._redaction_config)

        # These duplicate-but-independent trackers exist because
        # Storage holds the *redacted* view (safe for export/display by
        # default), while these hold the live view used to compute
        # relationships as events arrive. Detection results are
        # attached to the redacted request objects for display.
        self._connection_analyzer = ConnectionAnalyzer()
        self._cookie_tracker = CookieTracker()

        self._waf_findings: dict[str, list] = {}
        self._antibot_findings: dict[str, list] = {}
        self._tls_info_by_request: dict[str, Any] = {}

        self._build_menu()
        self._build_ui()
        self._build_status_bar()

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._drain_event_queue)
        self._poll_timer.start(150)

    # -- UI construction -------------------------------------------------

    def _build_menu(self) -> None:
        menu_bar: QMenuBar = self.menuBar()

        file_menu = menu_bar.addMenu("&File")
        export_json_action = file_menu.addAction("Export as JSON…")
        export_json_action.triggered.connect(lambda: self._export("json"))
        export_csv_action = file_menu.addAction("Export as CSV…")
        export_csv_action.triggered.connect(lambda: self._export("csv"))
        export_har_action = file_menu.addAction("Export as HAR…")
        export_har_action.triggered.connect(lambda: self._export("har"))
        export_html_action = file_menu.addAction("Export as HTML report…")
        export_html_action.triggered.connect(lambda: self._export("html"))
        file_menu.addSeparator()
        quit_action = file_menu.addAction("Quit")
        quit_action.triggered.connect(self.close)

        settings_menu = menu_bar.addMenu("&Settings")
        redaction_action = settings_menu.addAction("Redaction & Privacy…")
        redaction_action.triggered.connect(self._open_settings)

        help_menu = menu_bar.addMenu("&Help")
        about_action = help_menu.addAction("About / Safety Boundary")
        about_action.triggered.connect(self._show_about)

    def _build_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)

        self._search_filter_bar = SearchFilterBar()
        self._search_filter_bar.filters_changed.connect(self._apply_filters)
        layout.addWidget(self._search_filter_bar)

        self._table = QTableWidget(0, 8)
        self._table.setHorizontalHeaderLabels(
            ["Method", "Host", "Path", "Status", "Type", "Size", "Time (ms)", "WAF/Anti-Bot"]
        )
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._table, stretch=2)

        self._tabs = QTabWidget()
        self._details_tab = RequestDetailsWidget()
        self._cookie_tab = CookieViewWidget()
        self._tls_tab = TLSViewWidget()
        self._waf_tab = WAFViewWidget()
        self._antibot_tab = AntiBotViewWidget()
        self._connection_tab = ConnectionViewWidget()
        self._flow_tab = FlowViewWidget()

        self._tabs.addTab(self._details_tab, "Request Details")
        self._tabs.addTab(self._cookie_tab, "Cookies")
        self._tabs.addTab(self._tls_tab, "TLS / Encryption")
        self._tabs.addTab(self._waf_tab, "WAF / CDN")
        self._tabs.addTab(self._antibot_tab, "Anti-Bot / CAPTCHA")
        self._tabs.addTab(self._connection_tab, "Connections")
        self._tabs.addTab(self._flow_tab, "Request Flow")
        layout.addWidget(self._tabs, stretch=3)

        self.setCentralWidget(central)

    def _build_status_bar(self) -> None:
        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)
        self._status_bar.showMessage(
            "Defensive analysis mode. HTTPS body content requires the user's own "
            "CA installation — see Help → About / Safety Boundary."
        )

    # -- Event queue draining ---------------------------------------------

    def _drain_event_queue(self) -> None:
        drained = 0
        while drained < 200:  # bound per tick so the UI stays responsive
            try:
                event = self._event_queue.get_nowait()
            except queue.Empty:
                break
            self._handle_event(event)
            drained += 1

    def _handle_event(self, event: dict[str, Any]) -> None:
        if event["type"] == "flow":
            self._handle_flow_event(event)
        elif event["type"] == "error":
            self._status_bar.showMessage(f"Connection error: {event['message']}", 5000)

    def _handle_flow_event(self, event: dict[str, Any]) -> None:
        parsed = event["request"]
        tls_info = event["tls_info"]

        self._storage.add_request(parsed)
        self._tls_info_by_request[parsed.request_id] = tls_info

        for cookie in event["newly_set_cookies"]:
            self._storage.add_cookie(cookie)

        cookie_names = [c.name for c in self._cookie_tracker.observe(parsed)] or \
            _cookie_names_from_header(parsed)
        self._connection_analyzer.observe(parsed, parsed.connection_id or parsed.request_id,
                                           tls_info.http_protocol)

        waf_results = detect_waf(parsed.response_headers, cookie_names, parsed.status_code)
        if waf_results:
            self._waf_findings[parsed.request_id] = waf_results

        antibot_results = detect_antibot(
            request_id=parsed.request_id,
            domain=parsed.host,
            path=parsed.path,
            response_headers=parsed.response_headers,
            cookie_names=cookie_names,
            body_text=None,  # body capture wired in at proxy_addon level when enabled
            status_code=parsed.status_code,
        )
        if antibot_results:
            self._antibot_findings[parsed.request_id] = antibot_results

        self._append_row(parsed, waf_results, antibot_results)

    def _append_row(self, parsed, waf_results, antibot_results) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)

        badge = ""
        if waf_results:
            badge += waf_results[0].service
        if antibot_results:
            badge += (" + " if badge else "") + antibot_results[0].detection_type

        values = [
            parsed.method,
            parsed.host,
            parsed.path,
            str(parsed.status_code or ""),
            parsed.content_type or "",
            str(parsed.response_size or ""),
            str(parsed.response_time_ms or ""),
            badge,
        ]
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setData(Qt.ItemDataRole.UserRole, parsed.request_id)
            self._table.setItem(row, col, item)

    # -- Selection / detail views -------------------------------------

    def _on_selection_changed(self) -> None:
        selected = self._table.selectedItems()
        if not selected:
            return
        request_id = selected[0].data(Qt.ItemDataRole.UserRole)
        parsed = self._storage.get_request(request_id)
        if parsed is None:
            return

        self._details_tab.show_request(parsed)
        self._cookie_tab.show_cookies_for_request(request_id, self._storage.all_cookies())
        self._tls_tab.show_tls_info(self._tls_info_by_request.get(request_id))
        self._waf_tab.show_findings(self._waf_findings.get(request_id, []))
        self._antibot_tab.show_findings(self._antibot_findings.get(request_id, []))
        self._connection_tab.show_connection(
            parsed.connection_id, self._connection_analyzer.summaries()
        )
        self._flow_tab.show_flow(parsed, self._waf_findings.get(request_id, []),
                                  self._antibot_findings.get(request_id, []))

    # -- Filtering ------------------------------------------------------

    def _apply_filters(self, filters: dict[str, str]) -> None:
        query = (filters.get("query") or "").lower()
        for row in range(self._table.rowCount()):
            visible = True
            if query:
                row_text = " ".join(
                    self._table.item(row, col).text().lower()
                    for col in range(self._table.columnCount())
                    if self._table.item(row, col) is not None
                )
                visible = query in row_text
            self._table.setRowHidden(row, not visible)

    # -- Export -----------------------------------------------------------

    def _export(self, fmt: str) -> None:
        requests = self._storage.all_requests()
        if not requests:
            QMessageBox.information(self, "Nothing to export", "No requests captured yet.")
            return

        extensions = {"json": "JSON (*.json)", "csv": "CSV (*.csv)",
                      "har": "HAR (*.har)", "html": "HTML (*.html)"}
        path, _ = QFileDialog.getSaveFileName(self, "Export", "", extensions[fmt])
        if not path:
            return

        if fmt == "json":
            content = export_json(requests)
        elif fmt == "csv":
            content = export_csv(requests)
        elif fmt == "har":
            content = export_har(requests)
        else:
            content = export_html_report(requests, self._waf_findings, self._antibot_findings)

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self._status_bar.showMessage(f"Exported {len(requests)} requests to {path}", 5000)

    # -- Settings / about -------------------------------------------------

    def _open_settings(self) -> None:
        dialog = SettingsDialog(self._redaction_config, parent=self)
        if dialog.exec():
            self._redaction_config = dialog.result_config()
            self._storage.redaction_config = self._redaction_config

    def _show_about(self) -> None:
        QMessageBox.information(
            self,
            "About / Safety Boundary",
            "This is a defensive traffic-analysis tool for authorized testing "
            "environments only.\n\n"
            "It detects WAF/CDN and anti-bot/CAPTCHA systems passively, based on "
            "response headers and cookies, and reports a confidence score with "
            "supporting evidence. It does not implement bypass, evasion, "
            "solving, or automation for any system it detects.\n\n"
            "HTTPS content (headers/bodies) is only visible if you explicitly "
            "installed this tool's local CA certificate in your own device's "
            "trust store. Without that step, only TLS handshake metadata "
            "(SNI, ALPN, cipher suite) is shown.",
        )


def _cookie_names_from_header(parsed) -> list[str]:
    cookie_header = parsed.request_headers.get("cookie") or parsed.request_headers.get("Cookie")
    if not cookie_header:
        return []
    names = []
    for part in cookie_header.split(";"):
        if "=" in part:
            names.append(part.split("=", 1)[0].strip())
    return names
