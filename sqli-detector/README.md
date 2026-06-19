# SQLi-Detector

A lightweight, modular error-based SQL Injection detection tool designed for offensive security engineers and penetration testers during the reconnaissance phase.

## Features
- **Surgical Parameter Isolation**: Mutates parameters individually (e.g., `?id=1'&role=admin`) to prevent application-level crashes from masking underlying database errors.
- **Precompiled Signature Matching**: Fast, regex-based detection engine mapping unhandled exceptions to specific backends (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).
- **Safe Execution Controls**: Configurable request delays to respect WAFs, fragile infrastructure, and rate limits during authorized testing.
- **Structured Reporting**: Terminal-friendly UI built with `rich` for immediate, readable findings and summary tables.

## Use Cases
- **Reconnaissance**: Quickly verifying if a set of URL parameters reflects database errors before launching heavier exploitation frameworks like `sqlmap`.
- **CI/CD Security Gating**: Running a fast, targeted scan against internal staging environments to catch basic SQLi regressions before production deployment.
- **Bug Bounty Hunting**: Automating initial error-based discovery across large scopes with custom delays to avoid tripping intrusion detection systems.

## Tech Stack
- **Language**: Python 3.10+
- **Libraries**:
  - `httpx`: High-performance HTTP client for robust request handling and proxy support.
  - `rich`: For beautiful, color-coded terminal output and summary tables.
  - `urllib.parse` (Standard Library): Safe and robust URL deconstruction and reconstruction.
- **Protocols**: HTTP/HTTPS

## Project Architecture
The project is strictly modularized to separate data from execution logic:
- **Mutator (`src/core/mutator.py`)**: Parses the target URL, iterates through query parameters, and safely appends payloads to one parameter at a time while leaving others intact.
- **Engine (`src/core/engine.py`)**: Handles the network layer, managing HTTP connections, timeouts, proxies, and intentional delays.
- **Analyzer (`src/core/analyzer.py`)**: The detection core. Compiles regex patterns from `signatures.json` on startup and scans HTTP response bodies for unhandled database exceptions.
- **Logger (`src/utils/logger.py`)**: Formats real-time alerts and end-of-scan summaries.

## Installation
```bash
git clone https://github.com/yourusername/sqli-detector.git
cd sqli-detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage
Run the tool against a target URL containing query parameters:
```bash
python src/main.py -u "http://target.com/api/users?id=1&role=admin" --delay 0.5 --timeout 10
```

**Flags:**
- `-u, --url` : Target URL (Required).
- `--delay` : Delay between requests in seconds (Default: 0.0).
- `--proxy` : Route traffic through an intercepting proxy (e.g., `http://127.0.0.1:8080`).
- `--timeout` : HTTP request timeout in seconds (Default: 10).

## Example Workflow
1. **Target Identification**: A pentester identifies an endpoint `http://target.local/view?item=42`.
2. **Execution**: The tester runs `sqli-detector` against the URL, passing traffic through Burp Suite (`--proxy`) for manual verification and logging.
3. **Mutation**: The tool injects standard syntax-breaking payloads (`'`, `"`, `\`) into the `item` parameter.
4. **Detection**: The tool receives a `500 Internal Server Error` containing the string `SQL syntax near ''`.
5. **Reporting**: The tool instantly flags the vulnerability and the backend database type (MySQL).
6. **Exploitation (Manual)**: The tester moves to specialized tools or manual exploitation techniques to confirm data extraction.

## Example Output
```text
[*] Initializing scan for: http://127.0.0.1:5000/user?id=1&role=user
[*] Loaded 11 payloads.
[*] Found 2 parameters to test.
[*] Starting injection process...

[!] VULNERABILITY FOUND
 > Parameter: id
 > Payload: '
 > DB Type: SQLite

Scan Complete: Vulnerabilities Detected!
┏━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Parameter ┃ DBMS    ┃ Payload ┃
┡━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ id        │ SQLite  │ '       │
└───────────┴─────────┴─────────┘
```

## Detection / OPSEC Notes
- **Noisy Operations**: This tool is inherently noisy. It intentionally injects syntax-breaking characters which will generate application logs, stack traces, and 500 errors on the target system.
- **WAF Visibility**: Modern Web Application Firewalls (WAFs) will easily detect basic payloads like `'` and `@@version`. The tool currently focuses on baseline detection and does not implement WAF evasion techniques (e.g., tampering or payload obfuscation).
- **Rate Limiting**: Use the `--delay` flag to space out requests and avoid triggering basic rate-limiting or DDoS mitigation mechanisms.

## Limitations
- **No Exploitation**: The tool stops at detection. It does not dump databases, extract tables, or execute OS commands.
- **Error-Based Only**: It relies entirely on the application reflecting unhandled exceptions. It cannot detect Blind SQLi (time-based or boolean-based inference).
- **GET Parameters Only**: Currently only parses and mutates query string parameters. POST body and header injection are not yet supported.

## Future Improvements
- **POST/JSON Support**: Extend the mutator to parse and inject into form data and `application/json` payloads.
- **Asynchronous Execution**: Refactor the request engine to use `httpx.AsyncClient` alongside a semaphore to speed up scanning of large parameter sets.
- **Header Injection**: Add the ability to automatically inject payloads into `User-Agent`, `Referer`, and `X-Forwarded-For` headers.

## Learning Objectives
By studying and modifying this project, researchers can learn:
- How to programmatically isolate and mutate HTTP parameters without breaking application state logic.
- How to parse raw HTTP responses for specific database error signatures.
- The distinction between the reconnaissance/detection phase and the exploitation phase in offensive security.
- How to build a modular, extensible command-line tool in Python using modern libraries like `httpx` and `rich`.

## Disclaimer
This tool is designed for educational purposes and authorized penetration testing only. Do not use this software against systems you do not own or do not have explicit, written permission to test. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
