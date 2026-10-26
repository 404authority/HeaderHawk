
import unittest
from unittest.mock import patch, Mock
from io import StringIO
from contextlib import redirect_stdout

from headerhawk import (
    check_security_headers,
    main,
    analyse_website,
    is_valid_url,
    is_public_ip,
    hostname_resolves_to_public_ip
)


class TestHeaderHawk(unittest.TestCase):

    @patch("headerhawk.socket.getaddrinfo")
    def test_valid_https_url(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("8.8.8.8", 443))
        ]

        self.assertTrue(is_valid_url("https://example.com"))

    @patch("headerhawk.socket.getaddrinfo")
    def test_valid_http_url(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("8.8.8.8", 80))
        ]

        self.assertTrue(is_valid_url("http://example.com"))

    def test_invalid_urls_are_rejected(self):
        invalid_urls = [
            "ftp://example.com",
            "https://",
            "https://user:password@example.com",
            "https://example.com:99999",
            "https://example.com:invalid"
        ]

        for url in invalid_urls:
            with self.subTest(url=url):
                self.assertFalse(is_valid_url(url))

    def test_missing_security_headers(self):
        findings = check_security_headers({})

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

    def test_some_security_headers_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff"
        }

        findings = check_security_headers(headers)

        self.assertEqual(len(findings), 5)

        found = [
            item for item in findings
            if item["status"] == "FOUND"
        ]
        missing = [
            item for item in findings
            if item["status"] == "MISSING"
        ]

        self.assertEqual(len(found), 2)
        self.assertEqual(len(missing), 3)

    @patch("headerhawk.requests.get")
    def test_website_response_is_processed(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.url = "https://example.com"
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }
        mock_get.return_value = mock_response

        with patch(
            "builtins.input",
            return_value="https://example.com"
        ):
            with patch("builtins.open", create=True) as mock_open:
                with patch("headerhawk.json.dump") as mock_dump:
                    main()

        mock_get.assert_called_once_with(
            "https://example.com",
            timeout=10,
            allow_redirects=False,
            headers={"User-Agent": "HeaderHawk/0.1.0"}
        )

        mock_dump.assert_called_once()
        mock_open.assert_called_once_with(
            "headerhawk_report.json",
            "w",
            encoding="utf-8"
        )

    @patch("headerhawk.requests.get")
    @patch("builtins.input", return_value="https://example.com")
    def test_redirect_response_is_not_followed(
        self, mock_input, mock_get
    ):
        mock_response = Mock()
        mock_response.status_code = 302
        mock_response.headers = {
            "Location": "https://other-example.com"
        }
        mock_response.url = "https://example.com"
        mock_get.return_value = mock_response

        output = StringIO()

        with patch("builtins.open", unittest.mock.mock_open()):
            with patch("headerhawk.json.dump"):
                with redirect_stdout(output):
                    main()

        mock_get.assert_called_once_with(
            "https://example.com",
            timeout=10,
            allow_redirects=False,
            headers={"User-Agent": "HeaderHawk/0.1.0"}
        )

        self.assertIn(
            "NOTICE: The website returned a redirect response.",
            output.getvalue()
        )
        self.assertIn(
            "HeaderHawk did not follow the redirect.",
            output.getvalue()
        )

    @patch("headerhawk.requests.get")
    def test_network_failure_is_handled(self, mock_get):
        import requests

        mock_get.side_effect = requests.ConnectionError(
            "Connection failed"
        )

        with patch("builtins.print") as mock_print:
            analyse_website("https://example.com")

        mock_print.assert_any_call(
            "\nRequest failed: Connection failed"
        )

    def test_private_ip_is_not_public(self):
        self.assertFalse(is_public_ip("127.0.0.1"))
        self.assertFalse(is_public_ip("192.168.1.1"))
        self.assertFalse(is_public_ip("10.0.0.1"))
        self.assertFalse(is_public_ip("169.254.1.1"))
        self.assertFalse(is_public_ip("224.0.0.1"))
        self.assertFalse(is_public_ip("0.0.0.0"))

    @patch("headerhawk.socket.getaddrinfo")
    def test_hostname_with_public_ip_is_allowed(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("8.8.8.8", 443))
        ]

        self.assertTrue(
            hostname_resolves_to_public_ip("example.com", 443)
        )

    @patch("headerhawk.socket.getaddrinfo")
    def test_hostname_with_private_ip_is_rejected(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("192.168.1.1", 443))
        ]

        self.assertFalse(
            hostname_resolves_to_public_ip("example.com", 443)
        )


if __name__ == "__main__":
    unittest.main()
