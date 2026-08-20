import unittest

from parsers.http_parser import parse_url, ParsedRequest


class TestParseUrl(unittest.TestCase):
    def test_https_default_port(self):
        result = parse_url("https://example.com/path?a=1&b=2")
        self.assertEqual(result["scheme"], "https")
        self.assertEqual(result["host"], "example.com")
        self.assertEqual(result["port"], 443)
        self.assertEqual(result["path"], "/path")
        self.assertEqual(result["query_params"], [("a", "1"), ("b", "2")])

    def test_http_default_port(self):
        result = parse_url("http://example.com/")
        self.assertEqual(result["port"], 80)

    def test_explicit_port(self):
        result = parse_url("https://example.com:8443/x")
        self.assertEqual(result["port"], 8443)

    def test_no_path_defaults_to_slash(self):
        result = parse_url("https://example.com")
        self.assertEqual(result["path"], "/")

    def test_empty_query_string(self):
        result = parse_url("https://example.com/x?")
        self.assertEqual(result["query_params"], [])

    def test_blank_valued_query_param_kept(self):
        result = parse_url("https://example.com/x?flag=")
        self.assertEqual(result["query_params"], [("flag", "")])


class TestParsedRequestSerialization(unittest.TestCase):
    def test_to_dict_round_trips_core_fields(self):
        req = ParsedRequest(
            method="GET",
            url="https://example.com/",
            scheme="https",
            host="example.com",
            port=443,
            path="/",
            status_code=200,
        )
        d = req.to_dict()
        self.assertEqual(d["method"], "GET")
        self.assertEqual(d["status_code"], 200)
        self.assertIn("request_id", d)
        self.assertIn("timestamp", d)

    def test_request_id_auto_generated_and_unique(self):
        a = ParsedRequest()
        b = ParsedRequest()
        self.assertNotEqual(a.request_id, b.request_id)


if __name__ == "__main__":
    unittest.main()
