"""
TLS / encryption metadata extraction.

Reads TLS handshake metadata that mitmproxy already collected (cipher
suite, negotiated version, SNI, ALPN, peer certificate fields). This
module never touches encrypted payload bytes -- only handshake-level
metadata, which is visible to any passive network observer regardless
of whether the traffic is proxied.

Certificate *contents* (subject/issuer/validity) are only populated
when mitmproxy performed TLS termination, which itself only happens
because the user pointed their own client at this proxy and installed
its locally-generated CA in their own trust store. If that hasn't
happened, mitmproxy passes TLS through untouched and these fields stay
None -- there is no code path here that can populate them otherwise.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TLSInfo:
    tls_version: str | None = None
    cipher_suite: str | None = None
    alpn_protocol: str | None = None
    sni: str | None = None

    # Only populated if this connection was actually intercepted
    # (user-installed CA). None otherwise -- see module docstring.
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_before: str | None = None
    cert_not_after: str | None = None

    http_protocol: str | None = None  # "HTTP/1.1", "HTTP/2", "HTTP/3"
    interception_active: bool = False


def parse_tls_info(flow) -> TLSInfo:
    """Extract TLS metadata from a mitmproxy flow's client connection.

    `flow` is a mitmproxy.http.HTTPFlow. Accessed defensively with
    getattr throughout because not every field is present on every
    connection (e.g. plain HTTP has no TLS info at all).
    """
    info = TLSInfo()

    client_conn = getattr(flow, "client_conn", None)
    if client_conn is None:
        return info

    tls_version = getattr(client_conn, "tls_version", None)
    if tls_version:
        info.tls_version = tls_version

    cipher = getattr(client_conn, "cipher_name", None)
    if cipher:
        info.cipher_suite = cipher

    alpn = getattr(client_conn, "alpn_proto_negotiated", None)
    if alpn:
        info.alpn_protocol = alpn.decode() if isinstance(alpn, bytes) else alpn
        info.http_protocol = _http_version_from_alpn(info.alpn_protocol)

    sni = getattr(client_conn, "sni", None)
    if sni:
        info.sni = sni

    cert = getattr(client_conn, "certificate_list", None) or []
    if cert:
        leaf = cert[0]
        # mitmproxy's Certificate object exposes cn/subject/issuer/notbefore/
        # notafter directly, populated only if TLS was actually terminated
        # (see docstring). We defensively getattr since API surface has
        # shifted across mitmproxy versions.
        info.cert_subject = getattr(leaf, "cn", None) or str(
            getattr(leaf, "subject", "") or ""
        ) or None
        info.cert_issuer = str(getattr(leaf, "issuer", "") or "") or None
        not_before = getattr(leaf, "notbefore", None)
        not_after = getattr(leaf, "notafter", None)
        info.cert_not_before = str(not_before) if not_before else None
        info.cert_not_after = str(not_after) if not_after else None
        info.interception_active = True

    if not info.http_protocol:
        # Fall back to the HTTP-layer version string mitmproxy already
        # parsed off the request line for non-TLS or non-ALPN cases.
        request_http_version = getattr(
            getattr(flow, "request", None), "http_version", None
        )
        if request_http_version:
            info.http_protocol = request_http_version

    return info


def _http_version_from_alpn(alpn_protocol: str) -> str | None:
    mapping = {
        "h2": "HTTP/2",
        "http/1.1": "HTTP/1.1",
        "http/1.0": "HTTP/1.0",
        "h3": "HTTP/3",
    }
    return mapping.get(alpn_protocol.lower())
