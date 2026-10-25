
import json
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone

# HeaderHawk - HTTP Security Header Analyser
# Built by 404authority

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "risk": "The browser may not be instructed to enforce HTTPS on future visits.",
        "fix": "Configure HSTS on HTTPS responses after verifying HTTPS works correctly."
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "risk": "The application may lack an important browser-enforced content restriction.",
        "fix": "Define a CSP appropriate to the application's scripts and resources."
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "risk": "Browsers may interpret some responses as a different content type.",
        "fix": "Set X-Content-Type-Options: nosniff where appropriate."
    },
    "X-Frame-Options": {
        "severity": "LOW",
        "risk": "The site may lack a legacy browser control against unwanted framing.",
        "fix": "Use a suitable framing policy, such as CSP frame-ancestors."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "risk": "URLs may disclose more referrer information than intended.",
        "fix": "Choose a suitable Referrer-Policy for the application."
    }
}


def check_security_headers(response_headers):
    findings = []

    for header, details in SECURITY_HEADERS.items():
        present = header in response_headers

        finding = {
            "header": header,
            "status": "FOUND" if present else "MISSING",
            "severity": details["severity"],
            "risk": None if present else details["risk"],
            "recommendation": None if present else details["fix"]
        }

        findings.append(finding)

    return findings


def analyse_website(url):
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        findings = check_security_headers(response.headers)

        report = {
            "tool": "HeaderHawk",
            "version": "0.1.0",
            "scan_time_utc": datetime.now(timezone.utc).isoformat(),
            "requested_url": url,
            "final_url": response.url,
            "http_status": response.status_code,
            "headers_checked": len(findings),
            "headers_found": sum(
                item["status"] == "FOUND" for item in findings
            ),
            "headers_missing": sum(
                item["status"] == "MISSING" for item in findings
            ),
            "findings": findings
        }

        print("\nHEADERHAWK SECURITY REPORT")
        print(f"Target: {url}")
        print(f"HTTP Status: {response.status_code}")
        print("=" * 50)

        for item in findings:
            print(f"\n[{item['status']}] {item['header']}")

            if item["status"] == "MISSING":
                print(f"  Severity: {item['severity']}")
                print(f"  Risk: {item['risk']}")
                print(f"  Fix: {item['recommendation']}")

        print("\nSUMMARY")
        print(f"Headers checked: {report['headers_checked']}")
        print(f"Headers found: {report['headers_found']}")
        print(f"Headers missing: {report['headers_missing']}")

        filename = "headerhawk_report.json"

        with open(filename, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print(f"\nJSON report saved to: {filename}")

    except requests.RequestException as error:
        print(f"\nRequest failed: {error}")

    except OSError as error:
        print(f"\nCould not save the report: {error}")


def main():
    url = input("Enter an authorised website URL: ").strip()

    if "://" not in url:
        url = "https://" + url

    parsed_url = urlparse(url)

    try:
        valid_port = parsed_url.port
    except ValueError:
        print("Invalid URL. Check the website address and port.")
        return

    if (
        parsed_url.scheme not in ("http", "https")
        or not parsed_url.hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
    ):
        print("Invalid URL. Enter a valid HTTP or HTTPS website address.")
        return

    if valid_port is not None and not (1 <= valid_port <= 65535):
        print("Invalid URL. The port must be between 1 and 65535.")
        return

    analyse_website(url)


if __name__ == "__main__":
    main()
