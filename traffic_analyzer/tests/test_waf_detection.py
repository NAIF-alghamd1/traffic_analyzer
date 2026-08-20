import unittest

from waf_detection.detector import detect


class TestWAFDetection(unittest.TestCase):
    def test_no_evidence_no_detection(self):
        results = detect({"content-type": "text/html"}, [], status_code=200)
        self.assertEqual(results, [])

    def test_cloudflare_header_only(self):
        results = detect({"server": "cloudflare"}, [], status_code=200)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].service, "Cloudflare")
        self.assertGreater(results[0].confidence, 0)

    def test_cloudflare_multiple_signals_higher_confidence(self):
        headers = {"server": "cloudflare", "cf-ray": "abc123"}
        results = detect(headers, ["__cfduid_session"], status_code=200)
        self.assertEqual(results[0].service, "Cloudflare")
        self.assertGreaterEqual(len(results[0].evidence), 2)

    def test_confidence_never_reaches_100(self):
        headers = {"server": "cloudflare", "cf-ray": "x", "cf-cache-status": "HIT"}
        results = detect(headers, ["__cfduid", "cf_clearance"], status_code=403)
        self.assertLessEqual(results[0].confidence, 99)

    def test_bare_403_alone_detects_nothing(self):
        # Status code alone, with zero header/cookie evidence, must not
        # produce a detection -- too many ordinary pages 403.
        results = detect({}, [], status_code=403)
        self.assertEqual(results, [])

    def test_results_sorted_by_confidence_descending(self):
        headers = {
            "server": "cloudflare",
            "x-amz-cf-id": "abc",
        }
        results = detect(headers, [], status_code=200)
        confidences = [r.confidence for r in results]
        self.assertEqual(confidences, sorted(confidences, reverse=True))

    def test_case_insensitive_header_matching(self):
        results = detect({"Server": "CLOUDFLARE"}, [], status_code=200)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].service, "Cloudflare")

    def test_fastly_detection(self):
        results = detect({"server": "fastly", "x-served-by": "fastly-cache"}, [])
        self.assertTrue(any(r.service == "Fastly" for r in results))

    def test_no_bypass_fields_exist_on_result(self):
        # Structural guarantee: DetectionResult has no bypass-related
        # attribute, so downstream code has nothing to call even by
        # accident.
        results = detect({"server": "cloudflare"}, [])
        result_fields = vars(results[0]).keys()
        for forbidden in ("bypass", "evade", "solve"):
            self.assertNotIn(forbidden, result_fields)


if __name__ == "__main__":
    unittest.main()
