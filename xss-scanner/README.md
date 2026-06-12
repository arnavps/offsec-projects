# Vanguard XSS Scanner

## Overview
- **What it does:** Automates the discovery of Reflected Cross-Site Scripting (XSS) vulnerabilities by crawling target URLs, parsing HTML forms, injecting predefined payloads, and analyzing HTTP responses.
- **Key capability:** The crawler uses structural parsing (`BeautifulSoup`) to extract actionable form data (`action`, `method`, hidden/visible `inputs`) and programmatically fires HTTP requests to test how the server handles malicious input.
- **Scope:** A lightweight, single-page vulnerability scanner focused strictly on Reflected XSS. It does not perform deep web crawling or spidering.

---

## Problem Statement
- **Problem addressed:** Manual discovery of XSS via input field fuzzing is tedious and prone to human error. Attackers and pentesters need automated ways to verify if data sinks properly sanitize input before reflection.
- **Why it matters:** Automating payload injection allows security engineers to scale their testing efforts and identify vulnerabilities faster in the software development lifecycle (SDLC) or during engagements.

---

## Objective
- **Why built:** To understand the mechanical workflow of offensive web tooling—specifically, how a scanner interacts with the DOM to extract attack vectors and automates HTTP requests.
- **Skills targeted:** Web scraping, DOM parsing, HTTP request manipulation, vulnerability validation, and Python scripting.

---

## System Architecture
```text
[Target URL] → Crawler → [Extracted Forms/Inputs] → Scanner Engine → [HTTP Request + Payload] → Target Server → Checker (Analyzes Response) → [Vulnerability Output]
```

---

## Core Features
- **Form Extraction:**
  - *What it does:* Identifies all `<form>` tags on a given page.
  - *Internal logic:* Utilizes `bs4.BeautifulSoup` to parse the DOM tree, resolving relative `action` URLs into absolute paths and indexing all child `<input>` tags, noting their `name` and `type`.
- **Payload Injection & Submission:**
  - *What it does:* Replaces user-facing fields with malicious XSS strings.
  - *Internal logic:* Filters inputs by type (e.g., `text`, `search`). It injects payloads into these fields while maintaining the default values of hidden fields to ensure the server processes the request normally. Uses `requests.Session` to maintain state.
- **Reflection Validation:**
  - *What it does:* Checks if the payload successfully bypassed sanitization.
  - *Internal logic:* Conducts a raw string matching check against the HTTP response body returned by the server. If the exact payload exists in the DOM response, it confirms a Reflected XSS vulnerability.

---

## Execution Flow (Step-by-Step)
1. User executes `main.py` with a target URL (`-u`).
2. `main.py` loads signatures from `data/payloads.txt`.
3. `Crawler.extract_forms(url)` fetches the HTML and returns a list of form DOM elements.
4. `Crawler.parse_form_details(form)` breaks down each form into its `action`, `method`, and input parameters.
5. `Scanner.scan_page()` loops through forms and payloads.
6. `Scanner.submit_form()` constructs the HTTP GET/POST request with the injected payload and fires it.
7. The scanner checks the response text. If the payload is reflected, it prints a vulnerability alert and the specific form endpoint.

---

## Key Component Deep Dive
- **Component:** `Scanner.submit_form()`
- **Logic & Internal Working:** This function is responsible for the actual exploitation phase. It dynamically reads the form's `method` (GET or POST) and routes the request accordingly via the `requests` library. For GET requests, the data is passed into the URL query parameters (`params=data`), while POST requests place the payload in the request body (`data=data`). 
- **Edge Cases:** It respects the `type` of the input field. It avoids injecting into `<input type="hidden">`, which often contains CSRF tokens or state-tracking hashes that, if modified, would cause the server to drop the request entirely.

---

## Tech Stack (With Justification)
- **Python 3:** Chosen for rapid scripting capabilities and readability.
- **BeautifulSoup4:** 
  - *Why:* Used to accurately parse poorly formatted HTML.
  - *Trade-off:* Slower than regex, but significantly more robust for extracting nested DOM elements.
- **Requests:** 
  - *Why:* Simplifies HTTP connection management, timeouts, and sessions compared to Python's native `urllib`.

---

## What I Built vs What I Used
### Built:
- Custom crawler logic for mapping form parameters.
- Custom injection engine logic for routing GET/POST exploits.
- A local deliberately vulnerable HTTP server (`test_server.py`) for safe testing.

### Used:
- `requests` (HTTP library).
- `beautifulsoup4` (DOM parser library).

---

## Proof of Functionality

### Example Attack / Input
```bash
python test_server.py &
python src/main.py -u http://127.0.0.1:8080
```

### System Response
```text
=========================================
      VANGUARD XSS SCANNER (v1.0)        
=========================================
[*] Loaded 4 payloads.
[*] Initiating scan on http://127.0.0.1:8080...
[*] Crawling http://127.0.0.1:8080 for forms...
[+] Found 1 forms on http://127.0.0.1:8080.

[!!!] XSS VULNERABILITY FOUND [!!!]
[*] URL: http://127.0.0.1:8080
[*] Form Action: http://127.0.0.1:8080/
[*] Payload: <script>alert('VANGUARD')</script>
```

### Observations
- The crawler successfully parsed the vulnerable search form.
- The scanner bypassed the default value, injected the `<script>` payload, and verified its unescaped reflection in the HTTP response.

---

## Security Relevance
- **TTP Mapping:** Maps to **Active Scanning (T1595)** and **Exploit Public-Facing Application (T1190)**.
- **Concepts Demonstrated:** Demonstrates how attackers map the attack surface of a web application and fuzz data sinks. It also highlights the necessity of output encoding and input validation for defenders.

---

## Comparison with Existing Solutions
- **Similar Tools:** XSStrike, Dalfox, OWASP ZAP.
- **How this differs:** Vanguard is highly experimental and niche. It is a strictly educational tool designed for simplicity and code readability. Unlike XSStrike (which uses complex contextual analysis), Vanguard relies on basic reflection testing.

---

## Limitations
- **Not Implemented:** Does not handle CSRF tokens, DOM-based XSS (which requires headless browsers like Selenium/Playwright), or asynchronous AJAX forms.
- **Where it fails:** Will fail on Single Page Applications (SPAs) built with React/Angular where forms are handled purely via JavaScript instead of traditional HTML `<form>` tags.

---

## Future Improvements
- **Headless Browser Integration:** Switch from `requests` to `Playwright` to execute JavaScript, allowing the detection of DOM-based XSS.
- **Deep Crawling:** Add an automated spider to recursively find all pages and parameters on a domain before scanning.
- **Context-Aware Injection:** Analyze *where* the input reflects (e.g., inside a `<script>` tag vs HTML body) to inject contextually accurate payloads (like XSStrike).

---

## Key Learnings
- Gained a deep understanding of how offensive tools map application logic automatically.
- Learned the nuances of programmatically dealing with HTTP state, form methods, and parameter fuzzing.

---

## Conclusion
This project represents a critical step in understanding offensive web security by demystifying how automated scanners function under the hood. It bridges the gap between manual payload injection and tool development.

---

