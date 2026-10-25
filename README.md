# HeaderHawk

**An HTTP Security Header Analyser by 404authority**

HeaderHawk is a Python-based security tool that checks a website's HTTP response for five commonly used security headers. It reports which headers are present or missing, explains potential risks associated with missing headers, and recommends remediation steps.

## Features

- Analyses five HTTP security headers.
- Identifies headers as `FOUND` or `MISSING`.
- Provides risk descriptions and remediation recommendations.
- Displays a summary of the scan results.
- Exports results to a JSON report.
- Includes automated tests using Python's built-in `unittest` framework.

## Security Headers Checked

| Header | Purpose |
|---|---|
| `Strict-Transport-Security` | Helps browsers enforce HTTPS connections. |
| `Content-Security-Policy` | Restricts the sources from which a page may load resources. |
| `X-Content-Type-Options` | Helps prevent MIME-type sniffing. |
| `X-Frame-Options` | Provides a browser control against unwanted framing. |
| `Referrer-Policy` | Controls referrer information sent with requests. |

## Requirements

- Python 3.10 or later
- `requests` Python package

## Installation

Clone the repository or download the project files.

Install the dependency:

```bash
py -m pip install requests
```

## Usage

Run the tool from the project directory:

```bash
py headerhawk.py
```

Enter an HTTP or HTTPS website address when prompted. Only scan websites you own or have explicit permission to assess.

The results are displayed in the terminal and saved to `headerhawk_report.json`.

## Running Tests

Run the automated tests with:

```bash
py -m unittest -v
```

The tests cover URL parsing and security-header detection using simulated response headers.

## Limitations

- Header presence alone does not prove that a security control is configured correctly.
- Missing headers are review findings, not proof that a website is vulnerable.
- The tool checks a limited set of HTTP security headers and does not perform a comprehensive penetration test.
- The current implementation follows redirects and does not implement comprehensive protections against requests to internal or otherwise restricted network destinations. Use only authorised targets.

## Disclaimer

HeaderHawk is an educational security assessment project. Use it responsibly and only against systems you own or are explicitly authorised to test.

## Author

**404authority** — Cybersecurity and web application security portfolio.

Project version: `0.1.0`