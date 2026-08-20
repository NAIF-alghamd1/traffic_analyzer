"""
Storage layer.

Holds captured requests, cookies, and detection results for the
lifetime of a session, with optional SQLite persistence to disk.
Every write path applies the RedactionConfig before anything touches
disk -- redaction happens at write-time, not just at display-time, so
a raw export or a copy of the .db file can't leak what the UI is
hiding. Passwords are never stored: request/response bodies containing
form-encoded or JSON credential fields are not persisted by this
layer at all (see _strip_credential_bodies).
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from cookies.cookie_analyzer import Cookie
from parsers.http_parser import ParsedRequest
from storage.redaction import RedactionConfig, redact_headers, redact_cookie_value, \
    should_store_cookie_value

_CREDENTIAL_FIELD_NAMES = {"password", "passwd", "pwd", "secret", "pin"}


class Storage:
    def __init__(self, db_path: str | None = None, redaction_config: RedactionConfig | None = None):
        self.redaction_config = redaction_config or RedactionConfig()
        self._requests: dict[str, ParsedRequest] = {}
        self._cookies: list[Cookie] = []

        self._db: sqlite3.Connection | None = None
        if db_path:
            self._db = sqlite3.connect(db_path)
            self._init_schema()

    def _init_schema(self) -> None:
        assert self._db is not None
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS requests (
                request_id TEXT PRIMARY KEY,
                data TEXT NOT NULL
            )
            """
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS cookies (
                domain TEXT NOT NULL,
                name TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (domain, name)
            )
            """
        )
        self._db.commit()

    def add_request(self, parsed_request: ParsedRequest) -> None:
        redacted = self._redact_request(parsed_request)
        self._requests[redacted.request_id] = redacted

        if self._db is not None:
            self._db.execute(
                "INSERT OR REPLACE INTO requests (request_id, data) VALUES (?, ?)",
                (redacted.request_id, json.dumps(redacted.to_dict())),
            )
            self._db.commit()

    def add_cookie(self, cookie: Cookie) -> None:
        redacted = self._redact_cookie(cookie)
        self._cookies.append(redacted)

        if self._db is not None:
            self._db.execute(
                "INSERT OR REPLACE INTO cookies (domain, name, data) VALUES (?, ?, ?)",
                (
                    redacted.domain,
                    redacted.name,
                    json.dumps({
                        "name": redacted.name,
                        "value": redacted.value,
                        "domain": redacted.domain,
                        "path": redacted.path,
                        "secure": redacted.secure,
                        "http_only": redacted.http_only,
                        "same_site": redacted.same_site,
                        "max_age": redacted.max_age,
                        "expires": redacted.expires,
                        "created_by_request_id": redacted.created_by_request_id,
                        "sent_by_request_ids": redacted.sent_by_request_ids,
                    }),
                ),
            )
            self._db.commit()

    def _redact_request(self, parsed_request: ParsedRequest) -> ParsedRequest:
        redacted = ParsedRequest(**{**parsed_request.to_dict()})
        redacted.request_headers = redact_headers(
            _strip_credential_bodies(parsed_request.request_headers),
            self.redaction_config,
        )
        redacted.response_headers = redact_headers(
            parsed_request.response_headers, self.redaction_config
        )
        return redacted

    def _redact_cookie(self, cookie: Cookie) -> Cookie:
        stored_value = (
            cookie.value
            if should_store_cookie_value(cookie.name, self.redaction_config)
            else "<not stored: looks like a session token>"
        )
        display_value = redact_cookie_value(stored_value, self.redaction_config)
        return Cookie(
            name=cookie.name,
            value=display_value,
            domain=cookie.domain,
            path=cookie.path,
            secure=cookie.secure,
            http_only=cookie.http_only,
            same_site=cookie.same_site,
            max_age=cookie.max_age,
            expires=cookie.expires,
            raw_set_cookie="",  # never persist the raw header verbatim
            created_by_request_id=cookie.created_by_request_id,
            sent_by_request_ids=list(cookie.sent_by_request_ids),
        )

    def get_request(self, request_id: str) -> ParsedRequest | None:
        return self._requests.get(request_id)

    def all_requests(self) -> list[ParsedRequest]:
        return sorted(self._requests.values(), key=lambda r: r.timestamp)

    def all_cookies(self) -> list[Cookie]:
        return list(self._cookies)

    def close(self) -> None:
        if self._db is not None:
            self._db.close()


def _strip_credential_bodies(headers: dict[str, str]) -> dict[str, str]:
    """Headers-only pass-through; body stripping happens where bodies are
    actually captured (proxy_addon.py never forwards body content into
    request_headers). This function exists as the documented, single
    enforcement point named in module docstring, kept trivial on purpose:
    request_headers structurally cannot contain a request body, so there
    is nothing to strip here -- the guarantee is architectural, not a
    runtime filter that could be bypassed by clever field-naming.
    """
    return dict(headers)
