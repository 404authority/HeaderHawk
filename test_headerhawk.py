
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from headerhawk import (
    VERSION,
    analyse_website,
    build_report,
    check_security_headers,
    hostname_resolves_to_public_ip,
    is_public_ip,
    is_valid_url,
    main,
    normalise_url,
)


class TestURLValidation(unittest.TestCase):
    def test_normalise_url_adds_https(self):
        self.assertEqual(
            normalise_url(" example.com "),
            "https://example.com",
        )

    def test_normalise_url_preserves_scheme(self):
        self.assertEqual(
            normalise_url("http://example.com"),
            "http://example.com",
        )

    def test_rejects_invalid_urls(self):
        invalid_urls = [
            "",
            "ftp://example.com",
            "https://",
            "https://user:password@example.com",
            "https://example.com:99999",
            "https://example.com:invalid",
            "https://example.com/path with spaces",
            "javascript:alert(1)",
        ]

        for url in invalid_urls:
            with self.subTest(url=url):
                self.assertFalse(is_valid_url(url))

    def test_rejects_non_public_literal_ips(self):
        addresses = [
            "127.0.0.1",
            "192.168.1.10",
            "10.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
        ]

        for address in addresses:
            with self.subTest(address=address):
                self.assertFalse(
                    is_valid_url(f"https://{address}")
                )

    @patch("headerhawk.socket.getaddrinfo")
    def test_accepts_hostname_with_public_ip(self, mock_dns):
        mock_dns.return_value = [
            (2, 1, 6, "", ("8.8.8.8", 443))
        ]

        self.assertTrue(is_valid_url("https://example.com"))
        mock_dns.assert_called_once()

    @patch("headerhawk.socket.getaddrinfo")
    def test_rejects_hostname_with_private_ip(self, mock_dns):
        mock_dns.return_value = [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", ("192.168.1.2", 443)),
        ]

        self.assertFalse(is_valid_url("https://example.com"))

    @patch(
        "headerhawk.socket.getaddrinfo",
        side_effect=OSError("DNS unavailable"),
    )
    def test_rejects_hostname_when_dns_fails(self, _mock_dns):
        self.assertFalse(is_valid_url("https://example.com"))

    def test_public_ip_classifier(self):
        self.assertTrue(is_public_ip("8.8.8.8"))

        for address in (
            "127.0.0.1",
            "192.168.1.1",
            "not-an-ip",
        ):
            with self.subTest(address=address):
                self.assertFalse(is_public_ip(address))

    @patch("headerhawk.socket.getaddrinfo")
    def test_rejects_empty_dns_results(self, mock_dns):
        mock_dns.return_value = []

        self.assertFalse(
            hostname_resolves_to_public_ip("example.com", 443)
        )


class TestHeaderFindings(unittest.TestCase):
    def test_all_missing_headers(self):
        findings = check_security_headers({})

        self.assertEqual(len(findings), 5)
        self.assertTrue(
            all(item["status"] == "MISSING" for item in findings)
        )
        self.assertTrue(
            all(item["recommendation"] for item in findings)
        )

    def test_all_headers_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }

        findings = check_security_headers(headers)

        self.assertEqual(len(findings), 5)
        self.assertTrue(
            all(item["status"] == "FOUND" for item in findings)
        )
        self.assertTrue(
            all(item["observed_value"] for item in findings)
        )
        self.assertTrue(
            all(item["risk"] is None for item in findings)
        )

    def test_partial_headers_are_counted(self):
        findings = check_security_headers({
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        })

        found = sum(
            item["status"] == "FOUND" for item in findings
        )
        missing = sum(
            item["status"] == "MISSING" for item in findings
        )

        self.assertEqual(found, 2)
        self.assertEqual(missing, 3)


class TestReportingAndRequests(unittest.TestCase):
    def make_response(self, status=200, headers=None):
        response = Mock()
        response.status_code = status
        response.headers = headers or {}
        response.url = "https://example.com"
        return response

    def test_report_has_version_counts_and_limitations(self):
        response = self.make_response(
            headers={"X-Frame-Options": "DENY"}
        )
        findings = check_security_headers(response.headers)

        report = build_report(
            "https://example.com",
            response,
            findings,
        )

        self.assertEqual(report["version"], VERSION)
        self.assertEqual(report["headers_checked"], 5)
        self.assertEqual(report["headers_found"], 1)
        self.assertEqual(report["headers_missing"], 4)
        self.assertFalse(report["redirect_followed"])
        self.assertTrue(report["limitations"])

    @patch("headerhawk.requests.get")
    def test_does_not_follow_redirect_and_saves_json(self, mock_get):
        mock_get.return_value = self.make_response(
            status=302,
            headers={"Location": "https://elsewhere.example"},
        )

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"

            report = analyse_website(
                "https://example.com",
                output_path=output,
            )

            saved = json.loads(
                output.read_text(encoding="utf-8")
            )

        mock_get.assert_called_once_with(
            "https://example.com",
            timeout=10,
            allow_redirects=False,
            headers={"User-Agent": f"HeaderHawk/{VERSION}"},
        )

        self.assertEqual(report["http_status"], 302)
        self.assertEqual(saved["version"], VERSION)
        self.assertEqual(saved["headers_checked"], 5)

    @patch(
        "headerhawk.requests.get",
        side_effect=requests.ConnectionError("offline"),
    )
    def test_network_error_is_propagated(self, _mock_get):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"

            with self.assertRaises(requests.ConnectionError):
                analyse_website(
                    "https://example.com",
                    output_path=output,
                )

    @patch("headerhawk.is_valid_url", return_value=False)
    def test_cli_rejects_invalid_target(self, _mock_validation):
        self.assertEqual(main(["http://127.0.0.1"]), 2)

    @patch("headerhawk.is_valid_url", return_value=True)
    @patch("headerhawk.analyse_website")
    def test_cli_passes_options(self, mock_analyse, _mock_validation):
        mock_analyse.return_value = {}

        result = main([
            "https://example.com",
            "--output",
            "out.json",
            "--timeout",
            "4",
        ])

        self.assertEqual(result, 0)
        mock_analyse.assert_called_once_with(
            "https://example.com",
            output_path="out.json",
            timeout=4.0,
        )

    def test_cli_rejects_non_positive_timeout(self):
        with self.assertRaises(SystemExit):
            main([
                "https://example.com",
                "--timeout",
                "0",
            ])


if __name__ == "__main__":
    unittest.main()
