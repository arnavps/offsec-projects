# Cookie Sentinel

**Cookie Sentinel** is a professional, modular cookie security attribute analyzer and compliance auditor. It evaluates HTTP cookies captured from active web requests, raw header outputs, or Netscape cookie files, identifying misconfigurations such as missing security flags (`HttpOnly`, `Secure`, `SameSite`), incorrect prefix usages (`__Secure-` and `__Host-`), overly broad domain scopes, and long-lived sessions.

This tool is designed for penetration testers, security researchers, red teamers, and defensive security engineers who require automated cookie auditing capabilities for authorization and compliance assessments.

---

## Features

- **Active URL Auditing**: Fetches headers from live HTTP endpoints, follows redirects, and captures cookies from all intermediate redirection hops to detect cleartext exposure.
- **RFC Attribute Validation**: Checks for missing or misconfigured `HttpOnly`, `Secure`, and `SameSite` flags.
- **Security Prefix Checks**: Validates compliance with `__Secure-` and `__Host-` cookie prefixes according to RFC standards.
- **Domain Scope Analysis**: Detects wildcard scopes (e.g. `.example.com` or parent domains) that expose cookies to subdomain takeover attacks.
- **Lifetime Expirations**: Flags persistent session identifiers with excessive lifetimes (lifespans > 1 year).
- **Passive Parsing Support**: Audits raw headers copied from tools like Burp Suite, raw headers files, or standard Netscape-formatted cookie databases.
- **Safe Session Masking**: Automatically redacts sensitive session values in standard console logs and generated reports to prevent credential leaks.
- **Premium Terminal UI**: Renders findings using structured, color-coded tables and panels for legacy and modern shells.
- **Multi-Format Export**: Generates developer-ready JSON and Markdown reports.

---

## Use Cases

- **Penetration Testing**: Rapidly audit cookies set during authentication or session establishment to evaluate susceptibility to session hijacking or Cross-Site Scripting (XSS).
- **Compliance Auditing**: Assess compliance against security frameworks (e.g., OWASP ASVS, PCI-DSS, and ISO 27001) which mandate secure cookie flags.
- **DevSecOps Integration**: Incorporate JSON output audits into CI/CD build scripts to block staging releases that set insecure cookies.
- **Security Research**: Analyze browser cookies or cookie dumps to evaluate application architecture and session lifetimes.

---

## Tech Stack

- **Language**: Python 3.13
- **Active Fetching**: `requests` / `urllib3`
- **Console Output**: `rich` (with UTF-8 fallback reconfigurations for legacy Windows CMD/PowerShell)
- **Testing**: `pytest`
- **Protocols**: HTTP/1.1, SSL/TLS

---

## Project Architecture

Cookie Sentinel is designed around a modular pipeline that isolates fetching, parsing, and rules evaluation.

```
                  [ CLI / Raw Input ]
                           │
                           ▼
                  [ Core Coordinator ]
                   /               \
                  /                 \
        [ Fetcher ]                 [ Parser ]
      (Active URL Scans)       (Headers & Netscape)
                  \                 /
                   \               /
                    ▼             ▼
                 [ Security Analyzer ]
               (Owasp Rules evaluation)
                           │
                           ▼
                 [ Output Reporters ]
             (Console / JSON / Markdown)
```

- **`cli.py`**: Handles argument configuration, initializes the terminal console interface, and directs control flows.
- **`core.py`**: Coordinates the data pipeline. Converts active responses or passive files into parsed lists, and pipes them to the analyzer.
- **`fetcher.py`**: Handles active HTTP transport. Includes advanced redirect logging to detect if cookies are set before redirection to TLS.
- **`parser.py`**: Custom parser that isolates semi-colon boundaries and performs case-normalization on attributes to prevent parsing bypasses.
- **`analyzer.py`**: Rule-evaluation engine. Compares cookie profiles against a checklist of risk indicators and generates structured findings.
- **`reporter.py`**: Serializes findings and applies security masking to cookie values before printing or saving.

---

## Installation

1. Navigate to the project root directory:
   ```bash
   cd projects/cookie-analyzer
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

```bash
python -m src.cli [TARGET] [OPTIONS]
```

### Command Line Arguments

#### Targets (Specify one)
* `-u, --url <url>`: Actively fetch and scan a target URL.
* `-r, --raw <header>`: Parse and scan a single raw `Set-Cookie` header string.
* `-f, --file <file>`: Parse and scan a file containing `Set-Cookie` headers (one per line, or standard HTTP headers block).
* `-n, --netscape <file>`: Parse and scan a Netscape format cookie file.

#### Active Scan Options (Only with -u)
* `-m, --method <GET|POST>`: HTTP method to use (default: GET).
* `-H, --header <Key: Value>`: Custom request header (can be repeated).
* `-d, --data <payload>`: POST request data payload (e.g. `param=val`).
* `--no-verify`: Disable SSL certificate validation (for self-signed test environments).
* `--timeout <seconds>`: Connection timeout in seconds (default: 10.0).
* `--no-redirect`: Do not follow HTTP redirects.
* `--user-agent <string>`: Override default User-Agent.

#### Reporting Options
* `-oJ, --output-json <path>`: Save detailed findings as JSON.
* `-oM, --output-markdown <path>`: Save detailed findings as a Markdown report.
* `-v, --verbose`: Enable debug logging.

---

## Example Workflow

### Scenario: Auditing a Target Authentication End-point

1. **Active Scan Target**:
   Fetch response headers and trace all redirections.
   ```bash
   python -m src.cli -u "https://example.com/login" -oM login_report.md
   ```
2. **Analysis Process**:
   * The tool connects to the login page.
   * If the server redirects (e.g. from `http://example.com` to `https://example.com`), it records all cookies set at each step.
   * The parser normalizes the attributes and sends the session variables to the ruleset engine.
   * Visual table outputs highlight missing protections.
3. **Passive Check (Headers Copy-Pasted from Burp Suite)**:
   Paste response headers into `headers.txt` and run:
   ```bash
   python -m src.cli -f headers.txt
   ```

---

## Example Output

### Terminal Output
```text
[*] Analyzing raw Set-Cookie header input...

Cookie Sentinel Audit Summary
========================================
Total Cookies Scanned: 1
Total Security Issues: 2
Critical: 0 | High: 1 | Medium: 1 | Low: 0 | Info: 0

                           Scanned Cookies Overview                            
┌────────────┬─────────────┬──────────┬────────┬──────────┬────────────┬──────┐
│ Cookie     │ Value       │          │        │          │            │      │
│ Name       │ (Masked)    │ HttpOnly │ Secure │ SameSite │ Domain     │ Path │
├────────────┼─────────────┼──────────┼────────┼──────────┼────────────┼──────┤
│ session    │ ******      │    No    │  Yes   │   Lax    │ .example.… │ /    │
└────────────┴─────────────┴──────────┴────────┴──────────┴────────────┴──────┘

Detailed Security Findings
========================================

Cookie: session
┌─────────────────────── High - Rule: MISSING_HTTPONLY ───────────────────────┐
│ Description: Cookie appears to be a session identifier but lacks the        │
│ 'HttpOnly' flag.                                                            │
│                                                                             │
│ Remediation: Configure the 'Set-Cookie' header to include the 'HttpOnly'    │
│ attribute. This prevents client-side scripts (e.g. XSS) from reading the    │
│ session cookie.                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
┌────────────────── Medium - Rule: OVERLY_BROAD_DOMAIN_DOT ───────────────────┐
│ Description: Cookie domain '.example.com' starts with a leading dot, making │
│ it accessible to all subdomains.                                            │
│                                                                             │
│ Remediation: Omit the 'Domain' attribute completely to lock the cookie to   │
│ the host that set it, or specify the exact hostname without a leading dot.  │
└─────────────────────────────────────────────────────────────────────────────┘
[+] JSON report saved to report.json
[+] Markdown report saved to report.md
```

---

## Detection / OPSEC Notes

- **Low Passive Footprint**: Analyzing raw headers (`-r`), file headers (`-f`), and Netscape cookie exports (`-n`) operates strictly local. There is no active network footprint.
- **Active Scanning Traffic**: Using `-u` performs standard HTTP requests. Although cookie scanning does not send malicious exploit payloads, multiple requests (from following redirects) will be logged in target web server access logs.
- **WAF Visibility**: Active scans use a standard browser User-Agent by default. If a Web Application Firewall (WAF) triggers on rate limits, custom headers (`-H`) and customizable User-Agents (`--user-agent`) can be used to blend in with legitimate web traffic.

---

## Limitations

- **No JavaScript Execution Engine**: Does not execute JavaScript. If cookies are set dynamically on the client side via scripts, they will not be detected in active response header scans.
- **Unauthenticated Scope**: Unless custom session headers (`-H`) or request cookies are passed manually, active scans only capture public and anonymous session headers.
- **DPAPI Encryption**: Cannot parse native local browser cookie databases (like Chrome v80+) directly due to operating-system level DPAPI decryption barriers. Use Netscape format exports instead.

---

## Future Improvements

- **Playwright Headless Browser Support**: Integrate headless browser control to execute JS and dump state cookies directly from the DOM.
- **Interactive Login Sessions**: Allow manual cookie injection/authentication flows to scan authenticated cookies interactively.
- **Continuous Integration Rules**: Create configuration schemas defining custom severity mapping thresholds to automate build-fails on custom conditions.

---

## Learning Objectives

By studying and reviewing this project, developers and security engineers will learn:
1. **Browser Security Controls**: The mechanics of `HttpOnly`, `Secure`, and `SameSite` values.
2. **Cookie Prefix Specifications**: How the `__Secure-` and `__Host-` prefixes provide structural host-locking and secure transmission guarantees.
3. **HTTP Header Parsing Edge Cases**: How to build robust text parsers that handle malformed server headers while preserving critical properties like date separators.
4. **Platform Shell Encoding**: How to handle UTF-8 print layouts safely on legacy and modern Windows consoles without triggering encoding failures.

---

## Disclaimer

> [!WARNING]
> This tool is intended only for educational purposes, security research, and authorized defensive assessments. Scanning target systems without explicit authorization is illegal. The author accepts no liability for misuse, damages, or legal consequences resulting from the use of this software.
