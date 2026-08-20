import unittest

from cookies.cookie_analyzer import parse_set_cookie, parse_cookie_header, CookieTracker
from parsers.http_parser import ParsedRequest


class TestParseSetCookie(unittest.TestCase):
    def test_basic_cookie(self):
        cookie = parse_set_cookie("session=abc123; Path=/; HttpOnly", default_domain="example.com")
        self.assertEqual(cookie.name, "session")
        self.assertEqual(cookie.value, "abc123")
        self.assertEqual(cookie.path, "/")
        self.assertTrue(cookie.http_only)
        self.assertEqual(cookie.domain, "example.com")  # fell back to default

    def test_full_attributes(self):
        header = (
            "id=xyz; Domain=.example.com; Path=/app; Secure; HttpOnly; "
            "SameSite=Strict; Max-Age=3600"
        )
        cookie = parse_set_cookie(header, default_domain="example.com")
        self.assertEqual(cookie.domain, ".example.com")
        self.assertEqual(cookie.path, "/app")
        self.assertTrue(cookie.secure)
        self.assertTrue(cookie.http_only)
        self.assertEqual(cookie.same_site, "Strict")
        self.assertEqual(cookie.max_age, 3600)

    def test_malformed_header_returns_none(self):
        cookie = parse_set_cookie("", default_domain="example.com")
        self.assertIsNone(cookie)

    def test_invalid_max_age_ignored_gracefully(self):
        cookie = parse_set_cookie("id=1; Max-Age=notanumber", default_domain="example.com")
        self.assertIsNotNone(cookie)
        self.assertIsNone(cookie.max_age)


class TestParseCookieHeader(unittest.TestCase):
    def test_multiple_cookies(self):
        pairs = parse_cookie_header("a=1; b=2; c=3")
        self.assertEqual(pairs, [("a", "1"), ("b", "2"), ("c", "3")])

    def test_empty_header(self):
        self.assertEqual(parse_cookie_header(""), [])

    def test_malformed_segment_skipped(self):
        pairs = parse_cookie_header("a=1; garbage; b=2")
        self.assertEqual(pairs, [("a", "1"), ("b", "2")])


class TestCookieTracker(unittest.TestCase):
    def test_tracks_created_by(self):
        tracker = CookieTracker()
        req = ParsedRequest(
            request_id="req-1", host="example.com",
            response_headers={"set-cookie": "session=abc; Path=/"},
        )
        newly_set = tracker.observe(req)
        self.assertEqual(len(newly_set), 1)
        self.assertEqual(newly_set[0].created_by_request_id, "req-1")

    def test_tracks_sent_by_on_subsequent_request(self):
        tracker = CookieTracker()
        set_req = ParsedRequest(
            request_id="req-1", host="example.com",
            response_headers={"set-cookie": "session=abc; Path=/"},
        )
        tracker.observe(set_req)

        send_req = ParsedRequest(
            request_id="req-2", host="example.com",
            request_headers={"cookie": "session=abc"},
        )
        tracker.observe(send_req)

        cookies = tracker.all_cookies()
        self.assertEqual(len(cookies), 1)
        self.assertIn("req-2", cookies[0].sent_by_request_ids)

    def test_subdomain_matches_parent_domain_cookie(self):
        tracker = CookieTracker()
        set_req = ParsedRequest(
            request_id="req-1", host="example.com",
            response_headers={"set-cookie": "id=1; Domain=.example.com; Path=/"},
        )
        tracker.observe(set_req)

        send_req = ParsedRequest(
            request_id="req-2", host="api.example.com",
            request_headers={"cookie": "id=1"},
        )
        tracker.observe(send_req)

        cookies = tracker.all_cookies()
        self.assertIn("req-2", cookies[0].sent_by_request_ids)

    def test_multiple_set_cookie_headers_joined_by_newline(self):
        tracker = CookieTracker()
        req = ParsedRequest(
            request_id="req-1", host="example.com",
            response_headers={"set-cookie": "a=1; Path=/\nb=2; Path=/"},
        )
        newly_set = tracker.observe(req)
        names = {c.name for c in newly_set}
        self.assertEqual(names, {"a", "b"})


if __name__ == "__main__":
    unittest.main()
