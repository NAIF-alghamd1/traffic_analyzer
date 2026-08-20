import unittest
from types import SimpleNamespace

from tls.tls_parser import parse_tls_info, _http_version_from_alpn


def _make_flow(client_conn=None, request_http_version=None):
    return SimpleNamespace(
        client_conn=client_conn,
        request=SimpleNamespace(http_version=request_http_version),
    )


class TestHttpVersionFromAlpn(unittest.TestCase):
    def test_h2(self):
        self.assertEqual(_http_version_from_alpn("h2"), "HTTP/2")

    def test_http11(self):
        self.assertEqual(_http_version_from_alpn("http/1.1"), "HTTP/1.1")

    def test_unknown_returns_none(self):
        self.assertIsNone(_http_version_from_alpn("spdy/3"))

    def test_case_insensitive(self):
        self.assertEqual(_http_version_from_alpn("H2"), "HTTP/2")


class TestParseTlsInfo(unittest.TestCase):
    def test_no_client_conn_returns_empty_info(self):
        flow = _make_flow(client_conn=None)
        info = parse_tls_info(flow)
        self.assertIsNone(info.tls_version)
        self.assertFalse(info.interception_active)

    def test_plain_http_falls_back_to_request_http_version(self):
        flow = _make_flow(client_conn=None, request_http_version="HTTP/1.1")
        info = parse_tls_info(flow)
        self.assertEqual(info.http_protocol, "HTTP/1.1")

    def test_handshake_metadata_without_certificate_no_interception(self):
        client_conn = SimpleNamespace(
            tls_version="TLSv1.3",
            cipher_name="TLS_AES_128_GCM_SHA256",
            alpn_proto_negotiated=b"h2",
            sni="example.com",
            certificate_list=[],
        )
        flow = _make_flow(client_conn=client_conn)
        info = parse_tls_info(flow)

        self.assertEqual(info.tls_version, "TLSv1.3")
        self.assertEqual(info.cipher_suite, "TLS_AES_128_GCM_SHA256")
        self.assertEqual(info.alpn_protocol, "h2")
        self.assertEqual(info.http_protocol, "HTTP/2")
        self.assertEqual(info.sni, "example.com")
        # Critical safety property: no cert data without interception.
        self.assertFalse(info.interception_active)
        self.assertIsNone(info.cert_subject)
        self.assertIsNone(info.cert_issuer)

    def test_certificate_present_sets_interception_active_and_fields(self):
        cert = SimpleNamespace(
            cn="example.com", subject="CN=example.com", issuer="CN=Test CA",
            notbefore="2024-01-01", notafter="2025-01-01",
        )
        client_conn = SimpleNamespace(
            tls_version="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384",
            alpn_proto_negotiated=None, sni="example.com",
            certificate_list=[cert],
        )
        flow = _make_flow(client_conn=client_conn)
        info = parse_tls_info(flow)

        self.assertTrue(info.interception_active)
        self.assertEqual(info.cert_subject, "example.com")
        self.assertEqual(info.cert_issuer, "CN=Test CA")
        self.assertEqual(info.cert_not_before, "2024-01-01")
        self.assertEqual(info.cert_not_after, "2025-01-01")


if __name__ == "__main__":
    unittest.main()
