import unittest

from storage.redaction import (
    RedactionConfig, redact_headers, redact_cookie_value,
    is_session_token_like, should_store_cookie_value, MASK,
)


class TestRedactionConfig(unittest.TestCase):
    def test_defaults_are_safe(self):
        config = RedactionConfig()
        self.assertTrue(config.redact_headers)
        self.assertTrue(config.redact_cookie_values)
        self.assertFalse(config.store_session_tokens)

    def test_sensitive_header_names_always_includes_defaults(self):
        config = RedactionConfig()
        names = config.sensitive_header_names()
        self.assertIn("authorization", names)
        self.assertIn("cookie", names)
        self.assertIn("set-cookie", names)

    def test_extra_sensitive_header_names_added(self):
        config = RedactionConfig(
            extra_sensitive_header_names=frozenset(["x-custom-secret"])
        )
        names = config.sensitive_header_names()
        self.assertIn("x-custom-secret", names)


class TestRedactHeaders(unittest.TestCase):
    def test_redact_enabled_masks_sensitive(self):
        config = RedactionConfig(redact_headers=True)
        headers = {
            "content-type": "text/html",
            "authorization": "Bearer token123",
            "x-api-key": "secret",
        }
        result = redact_headers(headers, config)
        self.assertEqual(result["content-type"], "text/html")
        self.assertEqual(result["authorization"], MASK)
        self.assertEqual(result["x-api-key"], MASK)

    def test_redact_disabled_passes_through(self):
        config = RedactionConfig(redact_headers=False)
        headers = {"authorization": "Bearer token123"}
        result = redact_headers(headers, config)
        self.assertEqual(result["authorization"], "Bearer token123")

    def test_case_insensitive_header_matching(self):
        config = RedactionConfig(redact_headers=True)
        headers = {
            "Authorization": "Bearer token123",
            "COOKIE": "session=abc",
        }
        result = redact_headers(headers, config)
        self.assertEqual(result["Authorization"], MASK)
        self.assertEqual(result["COOKIE"], MASK)


class TestRedactCookieValue(unittest.TestCase):
    def test_redact_enabled(self):
        config = RedactionConfig(redact_cookie_values=True)
        result = redact_cookie_value("session_id_abc123", config)
        self.assertEqual(result, MASK)

    def test_redact_disabled(self):
        config = RedactionConfig(redact_cookie_values=False)
        result = redact_cookie_value("session_id_abc123", config)
        self.assertEqual(result, "session_id_abc123")


class TestIsSessionTokenLike(unittest.TestCase):
    def test_session_variations(self):
        self.assertTrue(is_session_token_like("sessionid"))
        self.assertTrue(is_session_token_like("SESSIONID"))
        self.assertTrue(is_session_token_like("sess_id"))

    def test_auth_variations(self):
        self.assertTrue(is_session_token_like("auth_token"))
        self.assertTrue(is_session_token_like("authorization"))

    def test_jwt(self):
        self.assertTrue(is_session_token_like("jwt"))

    def test_sid(self):
        self.assertTrue(is_session_token_like("sid"))

    def test_regular_cookie(self):
        self.assertFalse(is_session_token_like("user_preference"))
        self.assertFalse(is_session_token_like("theme"))


class TestShouldStoreCookieValue(unittest.TestCase):
    def test_with_explicit_opt_in_always_stores(self):
        config = RedactionConfig(store_session_tokens=True)
        self.assertTrue(should_store_cookie_value("sessionid", config))
        self.assertTrue(should_store_cookie_value("theme", config))

    def test_without_opt_in_withholds_token_like(self):
        config = RedactionConfig(store_session_tokens=False)
        self.assertFalse(should_store_cookie_value("sessionid", config))
        self.assertFalse(should_store_cookie_value("auth_token", config))

    def test_without_opt_in_stores_regular_cookies(self):
        config = RedactionConfig(store_session_tokens=False)
        self.assertTrue(should_store_cookie_value("theme", config))
        self.assertTrue(should_store_cookie_value("user_preference", config))


if __name__ == "__main__":
    unittest.main()
