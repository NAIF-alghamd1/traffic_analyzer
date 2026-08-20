import unittest

from antibot_detection.detector import detect


class TestAntiBotDetection(unittest.TestCase):
    def test_no_evidence_no_detection(self):
        results = detect("req-1", "example.com", "/", {}, [], body_text=None, status_code=200)
        self.assertEqual(results, [])

    def test_recaptcha_body_marker(self):
        results = detect(
            "req-1", "example.com", "/login", {}, [],
            body_text="<div class='g-recaptcha' data-sitekey='...'></div>",
            status_code=200,
        )
        self.assertEqual(len(results), 1)
        self.assertIn("reCAPTCHA", results[0].detection_type)

    def test_datadome_header(self):
        results = detect(
            "req-1", "example.com", "/", {"x-datadome": "1"}, [],
            body_text=None, status_code=200,
        )
        self.assertTrue(any("DataDome" in r.detection_type for r in results))

    def test_cloudflare_challenge_cookie(self):
        results = detect(
            "req-1", "example.com", "/", {}, ["cf_chl_2_abc"],
            body_text=None, status_code=200,
        )
        self.assertTrue(any(r.detection_type == "JS Challenge" for r in results))

    def test_bare_403_alone_detects_nothing(self):
        results = detect("req-1", "example.com", "/", {}, [], body_text=None, status_code=403)
        self.assertEqual(results, [])

    def test_status_code_boosts_existing_detection_only(self):
        without_403 = detect(
            "req-1", "example.com", "/", {}, [],
            body_text="verify you are human", status_code=200,
        )
        with_403 = detect(
            "req-1", "example.com", "/", {}, [],
            body_text="verify you are human", status_code=403,
        )
        self.assertGreater(with_403[0].confidence, without_403[0].confidence)

    def test_no_solve_or_bypass_method_exists(self):
        # Structural guarantee: the module has no callable that solves
        # or bypasses anything it detects.
        import antibot_detection.detector as module
        module_names = dir(module)
        for forbidden in ("solve", "bypass", "submit_challenge_response", "auto_solve"):
            self.assertNotIn(forbidden, module_names)

    def test_confidence_capped_at_99(self):
        results = detect(
            "req-1", "example.com", "/",
            {"cf-mitigated": "1"},
            ["cf_chl_1", "__cf_bm"],
            body_text="just a moment attention required! | cloudflare",
            status_code=403,
        )
        for r in results:
            self.assertLessEqual(r.confidence, 99)


if __name__ == "__main__":
    unittest.main()
