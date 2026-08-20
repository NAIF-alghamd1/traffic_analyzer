"""
Cookie parsing and cookie <-> request relationship tracking.

Two responsibilities:
1. Parse Set-Cookie response headers into structured Cookie records.
2. Track, across the whole captured session, which request created/
   modified each cookie and which later requests sent it -- this is
   what powers the "visual relationship between cookies and requests"
   in the spec.

Purely analytical: this module never modifies outgoing Cookie headers
and never injects/replays a cookie value into a new request.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from http.cookies import SimpleCookie


@dataclass
class Cookie:
    name: str
    value: str
    domain: str
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    max_age: int | None = None
    expires: str | None = None
    raw_set_cookie: str = ""

    # Relationship tracking, filled in by CookieTracker below.
    created_by_request_id: str | None = None
    sent_by_request_ids: list[str] = field(default_factory=list)


def parse_set_cookie(set_cookie_header: str, default_domain: str) -> Cookie | None:
    """Parse a single Set-Cookie header value into a Cookie record.

    Returns None for malformed headers rather than raising, since
    malformed Set-Cookie headers are common in the wild and a parse
    failure on one cookie shouldn't take down the whole capture.
    """
    jar: SimpleCookie = SimpleCookie()
    try:
        jar.load(set_cookie_header)
    except Exception:
        return None

    if not jar:
        return None

    # SimpleCookie parses "Name=Value; attr=...; attr2=..." into a dict
    # keyed by the cookie name, with attributes on the Morsel.
    name = next(iter(jar))
    morsel = jar[name]

    max_age_raw = morsel.get("max-age")
    max_age = None
    if max_age_raw:
        try:
            max_age = int(max_age_raw)
        except ValueError:
            max_age = None

    return Cookie(
        name=name,
        value=morsel.value,
        domain=morsel.get("domain") or default_domain,
        path=morsel.get("path") or "/",
        secure=bool(morsel.get("secure")),
        http_only=bool(morsel.get("httponly")),
        same_site=morsel.get("samesite") or None,
        max_age=max_age,
        expires=morsel.get("expires") or None,
        raw_set_cookie=set_cookie_header,
    )


def parse_cookie_header(cookie_header: str) -> list[tuple[str, str]]:
    """Parse a request's Cookie header into (name, value) pairs."""
    pairs = []
    for part in cookie_header.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, value = part.partition("=")
        pairs.append((name.strip(), value.strip()))
    return pairs


class CookieTracker:
    """Stateful tracker across a capture session.

    Feed it ParsedRequest objects in chronological order via
    `observe()`; it builds the cookie -> request relationship graph.
    """

    def __init__(self) -> None:
        # keyed by (domain, cookie_name) -> Cookie
        self._cookies: dict[tuple[str, str], Cookie] = {}

    def observe(self, parsed_request) -> list[Cookie]:
        """Process one ParsedRequest. Returns cookies newly set/updated
        by this request's response (empty list if none).
        """
        newly_set: list[Cookie] = []

        # 1. Which cookies did this request SEND?
        cookie_header = parsed_request.request_headers.get("cookie") or \
            parsed_request.request_headers.get("Cookie")
        if cookie_header:
            for name, _value in parse_cookie_header(cookie_header):
                key = self._find_key_for_send(parsed_request.host, name)
                if key is not None:
                    self._cookies[key].sent_by_request_ids.append(
                        parsed_request.request_id
                    )

        # 2. Which cookies did this response SET?
        set_cookie_headers = self._extract_set_cookie_headers(parsed_request)
        for raw in set_cookie_headers:
            cookie = parse_set_cookie(raw, default_domain=parsed_request.host)
            if cookie is None:
                continue
            cookie.created_by_request_id = parsed_request.request_id
            key = (cookie.domain.lstrip("."), cookie.name)
            self._cookies[key] = cookie
            newly_set.append(cookie)

        return newly_set

    def _find_key_for_send(self, host: str, name: str) -> tuple[str, str] | None:
        # Exact host match first, then walk up parent domains, matching
        # standard cookie-domain scoping (a cookie set for .example.com
        # is sent on sub.example.com).
        host = host.lstrip(".")
        parts = host.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            key = (candidate, name)
            if key in self._cookies:
                return key
        return None

    @staticmethod
    def _extract_set_cookie_headers(parsed_request) -> list[str]:
        # response_headers is a flattened dict[str, str]; when a response
        # sets multiple cookies, the proxy addon joins them with "\n" in
        # the same key (see capture/proxy_addon.py) since Python dicts
        # can't hold duplicate header names.
        raw = parsed_request.response_headers.get("set-cookie") or \
            parsed_request.response_headers.get("Set-Cookie")
        if not raw:
            return []
        return [line for line in raw.split("\n") if line.strip()]

    def all_cookies(self) -> list[Cookie]:
        return list(self._cookies.values())
