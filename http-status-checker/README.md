# http-status-checker

`http-status-checker` is a high-performance, asynchronous HTTP endpoint prober and passive reconnaissance tool written in Python. It is designed to take a large list of domains, subdomains, or raw URLs, concurrently probe them to verify active web services, trace full redirect chains, extract technology banners, audit cookie security policies, and identify potential subdomain takeovers.

Built specifically for penetration testers, security researchers, and bug bounty hunters, this tool bridges the gap between raw subdomain discovery and targeted web application testing, allowing auditors to rapidly assess large external attack surfaces.

---

## Features

- **High-Concurrency Probing:** Powered by `asyncio` and `aiohttp` to run hundreds of requests concurrently without the socket-exhaustion overhead of traditional multi-threading.
- **Protocol Expansion & Deduplication:** Cleans host inputs, dedupes duplicates, and automatically resolves bare domains against both HTTP (`http://`) and HTTPS (`https://`) to discover hidden services.
- **Redirect Chain Reconstruction:** Follows and records every HTTP redirect hop (e.g., `301 -> 302 -> 200`), exposing open redirect vulnerabilities and internal routing names.
- **Passive Technology Fingerprinting:** Identifies web server headers (`Server`), application runtimes (`X-Powered-By`), frameworks, and technology-specific session cookies (e.g., Laravel, PHP, WordPress).
- **Cookie Security Auditing:** Flags session cookies missing critical security flags (e.g., `HttpOnly`, `Secure`).
- **Passive Subdomain Takeover Analysis:** Scans HTTP error response bodies against a signature database (`data/takeover_signatures.json`) to detect orphaned cloud configurations (AWS S3, GitHub Pages, Heroku, Shopify, etc.).
- **Global Rate Limiting:** Enforces strict requests-per-second (RPS) locks to bypass WAF rate limiting and prevent self-denial of service.
- **Cross-Platform Console Compatibility:** Overrides Windows event loops and reconfigures stdout encoding to prevent Unicode rendering crashes on standard command shells.

---

## Use Cases

1. **External Attack Surface Management (EASM):**
   After running passive subdomain enumeration (using tools like `subfinder` or `amass`), input the domain list to identify which hosts are actually hosting active HTTP/S services, saving downstream vulnerability scanners time and bandwidth.
2. **Open Redirect & Routing Audits:**
   Analyze redirection chains to verify if domains redirect users to external login portals or leak corporate domain tokens via HTTP referrers.
3. **Subdomain Takeover Hunting:**
   Identify domains pointing to third-party services (like Amazon S3 or GitHub) that return "NoSuchBucket" or "site not found" errors, indicating that the DNS record is orphaned and vulnerable to takeover.
4. **Technology Stacking & Profiling:**
   Generate clean technology stacks and security header lists across large IP spaces to locate outdated web servers (e.g., legacy Apache/IIS instances) exposed to public exploits.

---

## Tech Stack

- **Language:** Python 3.10+
- **Asynchronous Networking:** `asyncio` & `aiohttp` (HTTP/1.1 client session engine)
- **Fast Name Resolution:** `aiodns` (asynchronous DNS caching wrapper)
- **CLI Rendering & Formatting:** `rich` (for tables, spinners, and progress logs)
- **Data Exchange Formats:** JSON and CSV (for parsing outputs into other tools)

---

## Project Architecture

```
                       Input File (domains.txt)
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                            CLI Module                            │
│           (Parses configurations: timeout, concurrency,          │
│            custom headers, rate limits, outputs)                 │
└─────────────────────────────────┬────────────────────────────────┘
                                  │ Config & Targets
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                           Core Engine                            │
│    (Orchestrates Async Queue, Concurrency, Rate Limiting,       │
│     and Session Lifecycle Management)                            │
└─────────────────────────────────┬────────────────────────────────┘
                                  │ Target URL Stream
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                             Prober                               │
│       (Initiates HTTP requests, handles redirects, catches       │
│        network/SSL/DNS exceptions, measures response times)      │
└───────────┬──────────────────────────────────────────┬───────────┘
            │ Response Data                            │ Error Info
            ▼                                          ▼
┌──────────────────────────────┐          ┌────────────────────────┐
│      Analyzer Module         │          │  Error Classifier      │
│  (Takeover signatures, tech  │          │  (DNS, SSL, Timeout,   │
│   fingerprinting, headers)   │          │   Refused, etc.)       │
└───────────┬──────────────────┘          └────────────┬───────────┘
            │ Result Object                            │ Result Object
            └─────────────────────┬────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                          Result Handler                          │
│         (Formats Console Output and writes JSON/CSV output)      │
└───────────┬──────────────────────────────────────────┬───────────┘
            │                                          │
            ▼ (CLI / rich logs)                        ▼ (Reports)
      Interactive CLI                            output.json/csv
```

### Module Breakdown
- **`src/main.py`:** Orchestrator. Resolves bare domains, reads file/stdin inputs, creates worker tasks, and writes out final logs and file reports.
- **`src/core/prober.py`:** Connection handler. Performs actual socket requests, tracks redirections, reads initial body buffers, and translates OS network exceptions into classified errors.
- **`src/core/engine.py`:** Queue manager. Handles task workers and enforces global request pacing using an asynchronous lock.
- **`src/modules/fingerprint.py`:** Technology extractor. Examines cookies, banners, and security header parameters.
- **`src/modules/takeover.py`:** Content analyzer. Loads signatures and checks response body strings for takeover signals.
- **`src/utils/file_io.py`:** I/O handler. Parses target text files and exports structured results to JSON or CSV.

---

## Installation

Ensure you have Python 3.10+ installed.

1. Navigate to the project directory:
   ```bash
   cd http-status-checker
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

You can feed targets into `http-status-checker` either using the `-i` parameter or by piping from stdin:

```bash
# Basic usage with input file
python -m src.main -i targets.txt

# Pipe targets from subdomain discovery tools
cat subdomains.txt | python -m src.main -o results.json

# Export outputs in CSV format
python -m src.main -i targets.txt -o results.csv -f csv

# Rate-limit requests-per-second (RPS) to prevent WAF bans
python -m src.main -i targets.txt -c 20 -r 10 -o results.json
```

### CLI Arguments

```
options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to a file containing domains/URLs. If omitted, reads from stdin.
  -o OUTPUT, --output OUTPUT
                        Path to output file for results.
  -f {json,csv}, --format {json,csv}
                        Format for output file: 'json' or 'csv' (default: json).
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Maximum concurrent HTTP connections (default: 50).
  -r RATE_LIMIT, --rate-limit RATE_LIMIT
                        Maximum requests per second (RPS) limit (default: 0, which means unlimited).
  -t TIMEOUT, --timeout TIMEOUT
                        Connection timeout in seconds per request (default: 10).
  --no-redirects        Do not follow redirects. Reports original status codes.
  --max-redirects MAX_REDIRECTS
                        Maximum number of redirects to follow (default: 5).
  --verify-ssl          Enable SSL certificate verification (disabled by default for offensive recon).
  -u USER_AGENT, --user-agent USER_AGENT
                        Custom User-Agent header to override the default browser agent.
  -H HEADER [HEADER ...], --header HEADER [HEADER ...]
                        Custom HTTP headers to include in requests. Format: 'Name: Value'. Can specify multiple times.
  --prefer-http         Prefer HTTP over HTTPS. If a bare domain is passed, probe http:// first instead of https://.
  --only-ssl            Force HTTPS probing only. Do not fallback to or probe HTTP.
  --only-http           Force HTTP probing only. Do not fallback to or probe HTTPS.
```

---

## Example Workflow

Let's assume a bug bounty target list contains `example.com` and `nonexistent-dns-test-domain-xyz.co`.

1. **Prepare targets list:**
   Create a `targets.txt` file containing your domains.
2. **Execute scan with CSV output:**
   ```bash
   python -m src.main -i targets.txt -o results.csv -f csv
   ```
3. **Analysis of terminal feedback:**
   - Real-time logging outputs each host's status, resolved endpoint, server technology, and errors.
   - Redirect targets are mapped via visual arrows (`➜`).
   - Final console prints a summary statistics table grouping responses, average connection times, and flagged vulnerabilities.

---

## Example Output

### Console Real-time Logs
```
[*] Loaded 2 unique target host(s), expanded into 3 HTTP/S endpoint(s)
[*] Starting async engine (Concurrency: 50, Timeout: 10s)
[ERR: DNS Resolution Failure] https://nonexistent-dns-test-domain-xyz.co        (15.43ms)
[200] http://example.com                                                        (32.58ms) [Server: cloudflare]
[200] https://example.com                                                       (43.43ms) [Server: cloudflare]

[+] CSV results saved to results.csv
```

### Summary Table
```
================================================================================
🚀 PROBING COMPLETE SUMMARY
================================================================================
[*] Total Endpoints Scanned  : 3
[*] Successful HTTP Responses: 2
[*] Connection Failures     : 1
[*] Average Response Time   : 30.48 ms
[*] Elapsed Execution Time  : 0.22 s
[*] Subdomain Takeovers      : 0 detected

                         Top Probed Endpoints Details                          
┌────────────────────────────────────────────┬───────┬───────┬───────┬────────┐
│                                            │       │       │       │ Techn… │
│                                            │ Reso… │       │  Resp │ /      │
│ Target URL                                 │ URL   │ Stat… │  Time │ Server │
├────────────────────────────────────────────┼───────┼───────┼───────┼────────┤
│ https://nonexistent-dns-test-domain-xyz.co │ -     │ ERR:  │ 15.43 │ -      │
│                                            │       │  DNS  │    ms │        │
├────────────────────────────────────────────┼───────┼───────┼───────┼────────┤
│ http://example.com                         │ -     │  200  │ 29.53 │ cloud… │
│                                            │       │       │    ms │        │
├────────────────────────────────────────────┼───────┼───────┼───────┼────────┤
│ https://example.com                        │ -     │  200  │ 39.66 │ cloud… │
│                                            │       │       │    ms │        │
└────────────────────────────────────────────┴───────┴───────┴───────┴────────┘
```

---

## Detection / OPSEC Notes

- **Stealth and Noise:** Sending concurrent HTTP probes to a single domain will stand out in application firewall access logs (e.g., ModSecurity, Cloudflare WAF). Always apply the `--rate-limit` flag to pace request flows and use realistic User-Agent strings.
- **SSL Certificate Triggers:** The tool disables SSL verification by default (`--verify-ssl` is disabled). While this is necessary for testing targets with expired, internal, or self-signed certificates, some Intrusion Detection Systems (IDS) track SSL handshake anomalies or empty TLS SNIs.
- **Port Profiling:** This tool makes standard requests to ports 80 and 443. If target services are running on non-standard ports (such as 8080, 8443), they will be missed unless explicitly passed as part of the input target URL (e.g. `http://example.com:8080`).

---

## Limitations

- **CNAME Inspection:** `http-status-checker` evaluates takeovers based on HTML body string fingerprints rather than active CNAME queries. For definitive takeover validation, check raw DNS records.
- **Byte cap limits:** Only downloads the first 10KB of HTTP responses to prevent memory exhaustion when scanning large files.
- **No Screenshotting:** This tool does not capture website screenshots. Use visual screenshotting tools (e.g., `Gowitness` or `EyeWitness`) on the output JSON/CSV file.

---

## Future Improvements

- **Async CNAME Resolving:** Incorporate asynchronous DNS querying to verify orphaned hosting zones (CNAMEs) alongside body fingerprint checks.
- **HTTP/2 Support:** Extend client engine connections to support HTTP/2 probing for modern targets.
- **SOCKS5/HTTP Proxy Support:** Integrate proxy rotation to mask scanning source IPs.

---

## Learning Objectives

By reading or expanding this project, developers can learn:
1. **Asynchronous Network I/O:** Orchestrating non-blocking network requests, managing timeouts, and implementing connection pools.
2. **Pacing and Flow Control:** Structuring asynchronous rate limit locks to control request distribution.
3. **HTTP Protocol Specifics:** Parsing redirection headers, analyzing cookies, and identifying tech-stacks based on response parameters.
4. **Robust Exception Catching:** Processing operating-system level socket errors (such as DNS errors and SSL failures) in an async environment.

---

## Disclaimer

This tool is designed for authorized educational research, security testing, and auditing purposes only. Performing active scans on third-party systems without prior written consent is illegal and violating. The author assumes no liability for misuse of this tool.
