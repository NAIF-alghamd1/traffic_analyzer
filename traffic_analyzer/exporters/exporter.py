"""
Export captured data to JSON, CSV, HAR, and standalone HTML report.

All exporters consume already-redacted ParsedRequest/Cookie objects
from Storage (redaction happened at write-time -- see storage.py) so
there is no separate "remember to redact before export" step to
forget; whatever is in storage is what's safe to write to disk.
"""
from __future__ import annotations

import csv
import html
import json
from io import StringIO
from typing import Any

from parsers.http_parser import ParsedRequest


def export_json(requests: list[ParsedRequest]) -> str:
    return json.dumps([r.to_dict() for r in requests], indent=2)


def export_csv(requests: list[ParsedRequest]) -> str:
    buffer = StringIO()
    fieldnames = [
        "request_id", "timestamp", "method", "url", "host", "path",
        "status_code", "response_size", "response_time_ms", "content_type",
        "http_version",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in requests:
        writer.writerow(r.to_dict())
    return buffer.getvalue()


def export_har(requests: list[ParsedRequest]) -> str:
    """Minimal but valid HAR 1.2. Fields we don't track (e.g. per-header
    request/response sizes broken down by section) are set to -1, which
    is the HAR spec's documented value for "not available."
    """
    entries = []
    for r in requests:
        entries.append({
            "startedDateTime": _iso8601(r.timestamp),
            "time": r.response_time_ms or 0,
            "request": {
                "method": r.method,
                "url": r.url,
                "httpVersion": r.http_version or "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in r.request_headers.items()],
                "queryString": [{"name": k, "value": v} for k, v in r.query_params],
                "cookies": [],
                "headersSize": -1,
                "bodySize": -1,
            },
            "response": {
                "status": r.status_code or 0,
                "statusText": "",
                "httpVersion": r.http_version or "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in r.response_headers.items()],
                "cookies": [],
                "content": {
                    "size": r.response_size or 0,
                    "mimeType": r.content_type or "",
                },
                "redirectURL": r.redirect_chain[-1] if r.redirect_chain else "",
                "headersSize": -1,
                "bodySize": r.response_size or -1,
            },
            "cache": {},
            "timings": {
                "send": 0,
                "wait": r.response_time_ms or 0,
                "receive": 0,
            },
        })

    har: dict[str, Any] = {
        "log": {
            "version": "1.2",
            "creator": {"name": "HTTP/HTTPS Traffic Analyzer", "version": "1.0"},
            "entries": entries,
        }
    }
    return json.dumps(har, indent=2)


def export_html_report(
    requests: list[ParsedRequest],
    waf_findings: dict[str, list] | None = None,
    antibot_findings: dict[str, list] | None = None,
) -> str:
    """Self-contained static HTML summary report. No external assets, no
    script execution of anything from captured traffic -- all captured
    values are HTML-escaped before insertion.
    """
    waf_findings = waf_findings or {}
    antibot_findings = antibot_findings or {}

    rows = []
    for r in requests:
        waf_list = waf_findings.get(r.request_id, [])
        antibot_list = antibot_findings.get(r.request_id, [])
        waf_str = ", ".join(f"{f.service} ({f.confidence}%)" for f in waf_list) or "-"
        antibot_str = ", ".join(
            f"{f.detection_type} ({f.confidence}%)" for f in antibot_list
        ) or "-"

        rows.append(
            "<tr>"
            f"<td>{html.escape(str(r.method))}</td>"
            f"<td>{html.escape(str(r.url))}</td>"
            f"<td>{html.escape(str(r.status_code))}</td>"
            f"<td>{html.escape(str(r.response_time_ms))} ms</td>"
            f"<td>{html.escape(waf_str)}</td>"
            f"<td>{html.escape(antibot_str)}</td>"
            "</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Traffic Analysis Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
  th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; }}
  th {{ background: #f4f4f4; }}
  tr:nth-child(even) {{ background: #fafafa; }}
  .notice {{ background: #fff8e1; border: 1px solid #ffe082; padding: 10px 14px;
             border-radius: 4px; margin-bottom: 1.5rem; font-size: 0.9rem; }}
</style>
</head>
<body>
<h1>HTTP/HTTPS Traffic Analysis Report</h1>
<div class="notice">
  Sensitive header and cookie values shown here were redacted at capture
  time per the tool's default privacy settings. This report reflects a
  defensive, passive analysis only -- no bypass or exploitation actions
  were performed to generate it.
</div>
<table>
  <thead>
    <tr>
      <th>Method</th><th>URL</th><th>Status</th><th>Time</th>
      <th>WAF/CDN</th><th>Anti-Bot/CAPTCHA</th>
    </tr>
  </thead>
  <tbody>
    {"".join(rows)}
  </tbody>
</table>
</body>
</html>"""


def _iso8601(unix_timestamp: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc).isoformat()
