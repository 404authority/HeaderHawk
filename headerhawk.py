
#!/usr/bin/env python3
"""HeaderHawk: an educational HTTP security-header analyser."""

import argparse
import ipaddress
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

TOOL_NAME = "HeaderHawk"
VERSION = "0.2.0"
DEFAULT_TIMEOUT = 10
DEFAULT_REPORT = "headerhawk_report.json"
USER_AGENT = f"{TOOL_NAME}/{VERSION}"

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "risk": (
            "Browsers may not be instructed to require HTTPS "
            "on future visits."
        ),
        "recommendation": (
            "Configure HSTS after HTTPS is correctly deployed "
            "for the intended host scope."
        ),
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "risk": (
            "The application may lack an important browser-enforced "
            "restriction on content sources."
        ),
        "recommendation": (
            "Define and test a CSP suited to the application's "
            "scripts, styles, and other resources."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "risk": (
            "Some browsers may perform content-type sniffing "
            "when it could be avoided."
        ),
        "recommendation": (
            "Set X-Content-Type-Options: nosniff where appropriate."
        ),
    },
    "X-Frame-Options": {
        "severity": "LOW",
        "risk": (
            "The response may lack a legacy browser control "
            "against unwanted framing."
        ),
        "recommendation": (
            "Review CSP frame-ancestors and consider "
            "X-Frame-Options for browser compatibility."
        ),
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "risk": (
            "The browser may disclose more referrer information "
            "than the application intends."
        ),
        "recommendation": (
            "Choose a Referrer-Policy that limits referrer "
            "information to what the application needs."
        ),
    },
}


def normalise_url(url):
    """Trim a URL and assume HTTPS when no scheme is provided."""
    url = (url or "").strip()

    if url and "://" not in url:
        url = "https://" + url

    return url


def is_public_ip(value):
    """Return True only for globally routable, non-multicast IP addresses."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    return (
        address.is_global
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_private
        and not address.is_reserved
    )


def hostname_resolves_to_public_ip(hostname, port):
    """Reject hostnames that resolve to non-public IP addresses."""
    try:
        results = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, OSError, ValueError):
        return False

    if not results:
        return False

    for result in results:
        try:
            address = result[4][0]
        except (IndexError, TypeError):
            return False

        if not is_public_ip(address):
            return False

    return True


def is_valid_url(url):
    """Validate an HTTP(S) URL and its resolved IP addresses.

    This is a cautious safeguard, not a complete SSRF defence.
    DNS can change between validation and the HTTP connection.
    """
    url = normalise_url(url)

    if not url or any(character.isspace() for character in url):
        return False

    try:
        parsed = urlparse(url)
        port = parsed.port
    except (ValueError, TypeError):
        return False

    if parsed.scheme.lower() not in ("http", "https"):
        return False

    if not parsed.hostname:
        return False

    if parsed.username is not None or parsed.password is not None:
        return False

    hostname = parsed.hostname.rstrip(".")

    if not hostname or "%" in hostname:
        return False

    effective_port = port or (
        443 if parsed.scheme.lower() == "https" else 80
    )

    if not 1 <= effective_port <= 65535:
        return False

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return hostname_resolves_to_public_ip(
            hostname,
            effective_port,
        )

    return is_public_ip(hostname)


def check_security_headers(response_headers):
    """Create a structured finding for each checked header."""
    findings = []

    for header, details in SECURITY_HEADERS.items():
        present = header in response_headers

        findings.append({
            "header": header,
            "status": "FOUND" if present else "MISSING",
            "severity": details["severity"],
            "observed_value": (
                response_headers.get(header) if present else None
            ),
            "risk": None if present else details["risk"],
            "recommendation": (
                None if present else details["recommendation"]
            ),
        })

    return findings


def build_report(url, response, findings):
    """Build a JSON-serialisable scan report."""
    missing = [
        finding
        for finding in findings
        if finding["status"] == "MISSING"
    ]

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "requested_url": url,
        "response_url": response.url,
        "http_status": response.status_code,
        "redirect_followed": False,
        "headers_checked": len(findings),
        "headers_found": len(findings) - len(missing),
        "headers_missing": len(missing),
        "findings": findings,
        "limitations": [
            (
                "A missing header is a configuration observation, "
                "not proof of an exploitable vulnerability."
            ),
            (
                "HeaderHawk checks response headers; it does not "
                "prove application security or exploitability."
            ),
            (
                "DNS validation cannot completely prevent DNS "
                "rebinding or time-of-check/time-of-use issues."
            ),
        ],
    }


def print_report(report):
    """Print the scan findings in a readable format."""
    print("\nHEADERHAWK SECURITY REPORT")
    print(f"Version: {report['version']}")
    print(f"Target: {report['requested_url']}")
    print(f"HTTP Status: {report['http_status']}")
    print("=" * 54)

    if 300 <= report["http_status"] < 400:
        print("NOTICE: The server returned a redirect response.")
        print("HeaderHawk did not follow the redirect.")

    for finding in report["findings"]:
        print(f"\n[{finding['status']}] {finding['header']}")

        if finding["status"] == "FOUND":
            print(f"  Observed value: {finding['observed_value']}")
        else:
            print(f"  Severity: {finding['severity']}")
            print(f"  Observation: {finding['risk']}")
            print(
                f"  Recommendation: {finding['recommendation']}"
            )

    print("\nSUMMARY")
    print(f"Headers checked: {report['headers_checked']}")
    print(f"Headers found: {report['headers_found']}")
    print(f"Headers missing: {report['headers_missing']}")


def analyse_website(
    url,
    output_path=DEFAULT_REPORT,
    timeout=DEFAULT_TIMEOUT,
):
    """Request one URL without following redirects and save a report."""
    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    )

    findings = check_security_headers(response.headers)
    report = build_report(url, response, findings)

    print_report(report)

    report_path = Path(output_path)

    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump(
            report,
            report_file,
            indent=2,
            ensure_ascii=False,
        )
        report_file.write("\n")

    print(f"\nJSON report saved to: {report_path}")

    return report


def main(argv=None):
    """Parse command-line arguments and run HeaderHawk."""
    parser = argparse.ArgumentParser(
        description=(
            "Check common HTTP security headers on an authorised website."
        )
    )

    parser.add_argument(
        "url",
        nargs="?",
        help="Target URL. HTTPS is assumed when the scheme is omitted.",
    )

    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_REPORT,
        help=f"JSON report path (default: {DEFAULT_REPORT}).",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )

    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    raw_url = (
        args.url
        if args.url is not None
        else input("Enter an authorised website URL: ")
    )

    url = normalise_url(raw_url)

    if not is_valid_url(url):
        print(
            "Invalid or non-public target. Enter a valid HTTP(S) URL "
            "whose hostname resolves only to globally routable IPs.",
            file=sys.stderr,
        )
        return 2

    try:
        analyse_website(
            url,
            output_path=args.output,
            timeout=args.timeout,
        )
    except requests.RequestException as error:
        print(f"\nRequest failed: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"\nCould not save the report: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
