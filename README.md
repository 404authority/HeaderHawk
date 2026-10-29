# HeaderHawk

**HeaderHawk v0.2.0** is a lightweight Python command-line tool that checks HTTP security headers on a website and generates a JSON report.

Built by **404authority** as a beginner-friendly cybersecurity portfolio project.

## Features

- Checks five common HTTP security headers.
- Reports missing headers and explains their security purpose.
- Provides recommendations for improving header configuration.
- Displays a terminal summary.
- Saves findings in JSON format.
- Validates URL format, schemes, ports, and target IP addresses.
- Checks DNS results before making a request.
- Does not automatically follow HTTP redirects.
- Supports a configurable request timeout.
- Includes automated unit tests.

## Security Headers Checked

| Header | Purpose |
| --- | --- |
| `Strict-Transport-Security` | Encourages browsers to use HTTPS for future connections. |
| `Content-Security-Policy` | Helps restrict the sources from which a page can load content. |
| `X-Content-Type-Options` | Helps prevent MIME-type sniffing. |
| `X-Frame-Options` | Helps control whether a page can be embedded in frames. |
| `Referrer-Policy` | Controls how much referrer information browsers send. |

A missing header is an observation, not automatic proof that a website is vulnerable. The appropriate configuration depends on the application and its requirements.

## Requirements

- Python 3.10 or later
- `requests`

## Installation

Clone the repository:

```bash
git clone https://github.com/404authority/HeaderHawk.git
cd HeaderHawk
```

Install the dependency:

```bash
python -m pip install -r requirements.txt
```

For a safer, isolated installation, use a Python virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage

Analyse a website:

```bash
python headerhawk.py example.com
```

HeaderHawk normalises a hostname to HTTPS when a scheme is not supplied.

Choose the JSON report filename:

```bash
python headerhawk.py example.com --output report.json
```

Set the request timeout in seconds:

```bash
python headerhawk.py example.com --timeout 15
```

Display command-line help:

```bash
python headerhawk.py --help
```

The default JSON report filename is `headerhawk_report.json`, which is excluded from version control.

## Running the Tests

Run the automated unit tests:

```bash
python -m unittest -v
```

The tests cover URL validation, IP address checks, security-header findings, report structure, redirect handling, network errors, and command-line arguments.

## Security Considerations and Limitations

- **Authorisation:** Only test websites you own or have explicit permission to assess.
- **Redirects:** HeaderHawk does not automatically follow HTTP redirects. A redirect response may therefore describe the redirecting server rather than the final destination.
- **DNS checks:** DNS resolution is checked before the HTTP request, but DNS answers can change between validation and connection. This means the checks are not a complete defence against DNS rebinding or server-side request forgery (SSRF).
- **Public IP checks:** IP validation reduces the risk of accidentally targeting private or non-public addresses, but it does not replace network-level security controls.
- **Header interpretation:** The tool checks whether selected headers are present. It does not fully validate each policy's correctness or assess the entire website's security.
- **Network behaviour:** Results can be affected by connectivity, server configuration, proxies, and the target's response.

HeaderHawk is an educational assessment aid, not a substitute for a comprehensive security review.

## Project Structure

```text
HeaderHawk/
├── headerhawk.py
├── test_headerhawk.py
├── requirements.txt
├── README.md
├── .gitignore
└── headerhawk-demo.png
```

The screenshot may be absent in a local checkout if it has not been added to the repository.

## Version

Current version: `0.2.0`

## Author

**404authority**

GitHub: https://github.com/404authority
