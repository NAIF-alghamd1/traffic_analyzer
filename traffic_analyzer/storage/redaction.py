"""
Redaction system.

Central place that decides what gets shown vs. masked. Every UI view,
exporter, and storage write path routes sensitive values through here
so there is exactly one place that implements "redact by default,"
rather than each module re-implementing (and potentially forgetting)
the same rule.

Design intent (see spec section 10 - Security & Privacy):
- Authorization headers redacted by default.
- Cookie values redacted by default.
- Passwords are never stored, full stop (see storage/storage.py).
- Session tokens are not stored unless the user explicitly opts in.
- Redaction rules are user-configurable, but default to "safe."
"""
from __future__ import annotations

from dataclasses import dataclass

from parsers.http_parser import SENSITIVE_HEADER_NAMES

MASK = "••••••••"


@dataclass
class RedactionConfig:
    """User-configurable redaction settings. Defaults are the safe state."""

    redact_headers: bool = True
    redact_cookie_values: bool = True
    store_session_tokens: bool = False  # explicit opt-in only
    extra_sensitive_header_names: frozenset[str] = frozenset()

    def sensitive_header_names(self) -> frozenset[str]:
        return frozenset(SENSITIVE_HEADER_NAMES) | self.extra_sensitive_header_names


def redact_headers(headers: dict[str, str], config: RedactionConfig) -> dict[str, str]:
    """Return a copy of `headers` with sensitive values masked per config."""
    if not config.redact_headers:
        return dict(headers)

    sensitive = config.sensitive_header_names()
    result = {}
    for name, value in headers.items():
        if name.lower() in sensitive:
            result[name] = MASK
        else:
            result[name] = value
    return result


def redact_cookie_value(value: str, config: RedactionConfig) -> str:
    if not config.redact_cookie_values:
        return value
    return MASK


def is_session_token_like(cookie_name: str) -> bool:
    """Heuristic only, used to decide whether to withhold storage by
    default -- never used to extract, replay, or act on the token.
    """
    lowered = cookie_name.lower()
    markers = ("session", "sess", "token", "auth", "jwt", "sid")
    return any(marker in lowered for marker in markers)


def should_store_cookie_value(cookie_name: str, config: RedactionConfig) -> bool:
    """Per spec: avoid storing session tokens unless explicitly enabled."""
    if config.store_session_tokens:
        return True
    return not is_session_token_like(cookie_name)
