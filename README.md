# HeaderHawk 🦅

**HeaderHawk** is a Python-based HTTP security header analyser built by **404authority**. It checks public websites for five commonly used HTTP security headers and generates a JSON report of its findings.

## Features

- Checks five HTTP security headers:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
- Reports headers as `FOUND` or `MISSING`.
- Provides severity ratings, potential risks, and remediation recommendations for missing headers.
- Validates HTTP and HTTPS URLs.
- Checks resolved IP addresses and rejects hostnames that resolve to non-public addresses.
- Uses a 10-second request timeout.
- Does not automatically follow HTTP redirects.
- Identifies itself using the `HeaderHawk/0.1.0` User-Agent.
- Exports findings to a JSON report.
- Includes automated unit tests.

## Requirements

- Python 3.10 or newer
- `requests`

## Installation

Clone the repository:

```bash
git clone https://github.com/404authority/HeaderHawk.git
cd HeaderHawk
```

Install the dependency:

```bash
pip install -r requirements.txt
```

## Usage

Run the analyser:

```bash
python headerhawk.py
```

When prompted, enter an HTTP or HTTPS URL for a public website you own or have permission to assess.

Example:

```text
Enter an authorised website URL: https://example.com
```

HeaderHawk prints a report in the terminal and saves the results to:

```text
headerhawk_report.json
```

The JSON report includes the requested URL, response status, scan timestamp, header counts, and individual findings.

## Running the Tests

Run the automated test suite:

```bash
python -m unittest -v
```

The tests cover URL validation, security header checks, public-IP validation, network failures, and redirect handling.

## Security Limitations

HeaderHawk is an educational security assessment tool, not a complete SSRF prevention solution.

- DNS resolution is checked before the HTTP request, but the HTTP client may resolve the hostname again when connecting. This leaves a potential DNS-rebinding risk.
- Redirects are disabled, but this alone does not guarantee that all requests are restricted to safe network destinations.
- The tool checks whether headers are present; it does not fully evaluate whether their values provide an effective security policy.
- Only assess websites you own or have explicit permission to test.

Do not treat the current IP checks as a substitute for network isolation or connection-level destination enforcement in production systems.

## Project Purpose

HeaderHawk demonstrates foundational Python development, HTTP request handling, URL validation, security-header analysis, JSON reporting, error handling, and automated testing.

**Author:** 404authority  
**Version:** 0.1.0  
**Language:** Python
