"""
Passive anti-bot / CAPTCHA / JS-challenge detection.

Identifies whether a response LOOKS LIKE a challenge page, based on
markers in headers, cookies, and (when available) response body
snippets. This module has no knowledge of how to solve, automate, or
defeat any challenge it detects -- it only flags that one is present,
with evidence, for a human reviewing the capture. There is
intentionally no "solve" or "submit_challenge_response" function
anywhere in this codebase.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AntiBotDetection:
    detection_type: str  # e.g. "CAPTCHA", "JS Challenge", "Browser Verification"
    request_id: str
    domain: str
    path: str
    evidence: list[str] = field(default_factory=list)
    confidence: int = 0  # 0-100


_HEADER_MARKERS = {
    "cf-mitigated": ("JS Challenge", 40, "cf-mitigated header present"),
    "x-datadome": ("Anti-Bot (DataDome)", 40, "x-datadome header present"),
}

_COOKIE_MARKERS = {
    "cf_chl_": ("JS Challenge", 35, "Cloudflare challenge cookie"),
    "__cf_bm": ("Anti-Bot (Cloudflare Bot Management)", 30, "__cf_bm cookie present"),
    "datadome": ("Anti-Bot (DataDome)", 35, "DataDome cookie present"),
    "perimeterx": ("Anti-Bot (PerimeterX)", 35, "PerimeterX cookie present"),
    "_px": ("Anti-Bot (PerimeterX)", 30, "PerimeterX cookie present"),
}

# Body markers are matched as case-insensitive substrings against
# whatever text content is already available in the captured response
# (per spec: "Global search across ... Response bodies when available").
# This module never fetches, renders, or executes anything to obtain
# body content it wasn't already given.
_BODY_MARKERS = {
    "g-recaptcha": ("CAPTCHA (reCAPTCHA)", 45, 'body contains "g-recaptcha"'),
    "h-captcha": ("CAPTCHA (hCaptcha)", 45, 'body contains "h-captcha"'),
    "cf-turnstile": ("CAPTCHA (Cloudflare Turnstile)", 45, 'body contains "cf-turnstile"'),
    "checking your browser": ("Browser Verification", 40, "browser-check interstitial text"),
    "verify you are human": ("Browser Verification", 40, "human-verification interstitial text"),
    "attention required! | cloudflare": ("Challenge Page", 50, "Cloudflare attention-required page"),
    "just a moment": ("JS Challenge", 35, 'interstitial title "Just a moment..."'),
}


def detect(
    request_id: str,
    domain: str,
    path: str,
    response_headers: dict[str, str],
    cookie_names: list[str],
    body_text: str | None = None,
    status_code: int | None = None,
) -> list[AntiBotDetection]:
    """Inspect one response's already-captured data for challenge markers.

    Every argument is data already obtained during passive capture.
    This function does not perform any network I/O, does not execute
    JavaScript, and does not attempt to determine (let alone produce)
    a valid challenge response.
    """
    lowered_headers = {k.lower(): v for k, v in response_headers.items()}
    lowered_cookies = [c.lower() for c in cookie_names]
    lowered_body = (body_text or "").lower()

    found: dict[str, AntiBotDetection] = {}

    def record(kind: str, weight: int, evidence_line: str) -> None:
        if kind not in found:
            found[kind] = AntiBotDetection(
                detection_type=kind,
                request_id=request_id,
                domain=domain,
                path=path,
                evidence=[],
                confidence=0,
            )
        det = found[kind]
        det.confidence = min(det.confidence + weight, 99)
        det.evidence.append(evidence_line)

    for header_name, (kind, weight, evidence) in _HEADER_MARKERS.items():
        if header_name in lowered_headers:
            record(kind, weight, evidence)

    for marker, (kind, weight, evidence) in _COOKIE_MARKERS.items():
        if any(marker in c for c in lowered_cookies):
            record(kind, weight, evidence)

    for marker, (kind, weight, evidence) in _BODY_MARKERS.items():
        if marker in lowered_body:
            record(kind, weight, evidence)

    # A bare 403/429 nudges an *existing* detection's confidence but,
    # same as WAF detection, never fires a detection on its own --
    # too many ordinary error pages use those codes.
    if status_code in (403, 429) and found:
        for det in found.values():
            det.confidence = min(det.confidence + 5, 99)
            det.evidence.append(f"status code {status_code} alongside above markers")

    return sorted(found.values(), key=lambda d: d.confidence, reverse=True)
