import unittest
from urllib.parse import urlparse
from headerhawk import check_security_headers


class TestHeaderHawk(unittest.TestCase):

    def test_valid_https_url(self):
        url = "https://example.com"
        parsed = urlparse(url)

        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "example.com")

    def test_valid_http_url(self):
        url = "http://example.com"
        parsed = urlparse(url)

        self.assertEqual(parsed.scheme, "http")
        self.assertEqual(parsed.hostname, "example.com")

    def test_missing_security_headers(self):
        headers = {}

        findings = check_security_headers(headers)

        self.assertEqual(len(findings), 5)

        for finding in findings:
            self.assertEqual(finding["status"], "MISSING")

    
    def test_all_security_headers_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }

        findings = check_security_headers(headers)

        self.assertEqual(len(findings), 5)

        for finding in findings:
            self.assertEqual(finding["status"], "FOUND")
            self.assertIsNone(finding["risk"])
            self.assertIsNone(finding["recommendation"])

if __name__ == "__main__":
    unittest.main()