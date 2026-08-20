"""
Passive WAF / CDN detection.

Signature-based pattern matching against response headers, cookies,
and status codes -- the same category of technique used by
well-established, publicly documented recon tools like wafw00f and
whatweb. This module ONLY identifies which service is likely present;
it does not implement, suggest, or contain any bypass/evasion logic
for any of the services it detects. See DetectionResult -- there is no
"bypass" or "evade" method or field on this class, by design.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DetectionResult:
    service: str
    confidence: int  # 0-100
    evidence: list[str] = field(default_factory=list)


@dataclass
class _Signature:
    service: str
    header_markers: dict[str, str | None]  # header name -> substring to match, or None for "header present"
    cookie_name_markers: list[str]
    weight_per_match: int


# Signature weights are intentionally conservative and additive rather
# than binary, so confidence reflects how much independent evidence was
# found rather than a single header triggering a false 100%.
_SIGNATURES: list[_Signature] = [
    _Signature(
        service="Cloudflare",
        header_markers={"server": "cloudflare", "cf-ray": None, "cf-cache-status": None},
        cookie_name_markers=["__cflb", "__cfduid", "cf_clearance"],
        weight_per_match=30,
    ),
    _Signature(
        service="AWS CloudFront / AWS WAF",
        header_markers={"x-amz-cf-id": None, "x-amz-cf-pop": None, "via": "cloudfront"},
        cookie_name_markers=["aws-waf-token"],
        weight_per_match=30,
    ),
    _Signature(
        service="Akamai",
        header_markers={"server": "akamaighost", "x-akamai-transformed": None},
        cookie_name_markers=["akamai_", "ak_bmsc"],
        weight_per_match=30,
    ),
    _Signature(
        service="Fastly",
        header_markers={"server": "fastly", "x-served-by": "fastly", "fastly-debug-digest": None},
        cookie_name_markers=[],
        weight_per_match=35,
    ),
    _Signature(
        service="Imperva",
        header_markers={"x-iinfo": None, "x-cdn": "imperva"},
        cookie_name_markers=["incap_ses", "visid_incap"],
        weight_per_match=35,
    ),
    _Signature(
        service="Azure Front Door",
        header_markers={"x-azure-ref": None, "x-fd-healthprobe": None},
        cookie_name_markers=[],
        weight_per_match=40,
    ),
    _Signature(
        service="Sucuri",
        header_markers={"server": "sucuri/cloudproxy", "x-sucuri-id": None, "x-sucuri-cache": None},
        cookie_name_markers=["sucuri-"],
        weight_per_match=35,
    ),
]


def detect(response_headers: dict[str, str], cookie_names: list[str],
           status_code: int | None = None) -> list[DetectionResult]:
    """Return likely WAF/CDN services for one response, most confident first.

    Pure function: takes already-captured headers/cookies, returns
    structured results. Never issues additional requests, never varies
    its own behavior based on what it detects.
    """
    lowered_headers = {k.lower(): v for k, v in response_headers.items()}
    lowered_cookies = [c.lower() for c in cookie_names]

    results: list[DetectionResult] = []

    for sig in _SIGNATURES:
        score = 0
        evidence: list[str] = []

        for header_name, expected_substring in sig.header_markers.items():
            actual = lowered_headers.get(header_name)
            if actual is None:
                continue
            if expected_substring is None or expected_substring in actual.lower():
                score += sig.weight_per_match
                evidence.append(f"header `{header_name}: {actual}`")

        for cookie_marker in sig.cookie_name_markers:
            for cookie_name in lowered_cookies:
                if cookie_marker in cookie_name:
                    score += sig.weight_per_match
                    evidence.append(f"cookie name matches `{cookie_marker}*`")
                    break

        # Challenge-page status codes (403/503 alongside other markers)
        # nudge confidence up slightly but never fire alone -- a bare
        # 403/503 is far too common to be evidence by itself.
        if status_code in (403, 503) and score > 0:
            score += 5
            evidence.append(f"status code {status_code} alongside above markers")

        if score > 0:
            results.append(DetectionResult(
                service=sig.service,
                confidence=min(score, 99),  # never claim absolute certainty
                evidence=evidence,
            ))

    results.sort(key=lambda r: r.confidence, reverse=True)
    return results
