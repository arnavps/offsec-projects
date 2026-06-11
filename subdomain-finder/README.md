# SubdomainFinder

SubdomainFinder is an asynchronous, high-performance subdomain enumeration tool designed for offensive security engagements. It maps external attack surfaces by combining passive open-source intelligence (OSINT) gathering with concurrent active DNS resolution, providing an accurate and deduplicated list of target assets.

## Features
- **Passive Enumeration:** Gathers subdomains without touching target infrastructure by querying Certificate Transparency logs and Threat Intelligence APIs.
- **Active DNS Brute-Forcing:** Discovers undocumented, internal-facing, or forgotten subdomains via high-speed asynchronous DNS resolution.
- **Wildcard Detection:** Automatically tests for wildcard DNS configurations and filters out false positives to ensure clean data.
- **Asynchronous Execution:** Uses non-blocking I/O to perform hundreds of concurrent network requests, drastically reducing scan times.
- **Deduplication:** Aggregates results from multiple sources and provides a clean, deduplicated output.

## Use Cases
- **Penetration Testing:** Identifying forgotten or unpatched subdomains that host vulnerable administrative panels, outdated CMS platforms, or exposed APIs.
- **Bug Bounty Hunting:** Mapping the complete scope of a target organization to find less-tested assets.
- **External Attack Surface Management (EASM):** Auditing organizational exposure to ensure all external-facing assets are known and tracked.

## Tech Stack
- **Language:** Python 3.10+
- **Libraries:** 
  - `aiohttp`: For fast, concurrent HTTP requests to passive API sources.
  - `aiodns` (built on `c-ares`): For non-blocking, asynchronous UDP DNS queries.
- **Protocols:** DNS (UDP/53), HTTP/HTTPS (TCP/80/443)

## Project Architecture
SubdomainFinder is built with a modular architecture to separate data gathering techniques from core logic:

1. **Initialization:** The tool parses command-line arguments and loads the provided wordlist into memory.
2. **Wildcard Detection (Core Engine):** Before active enumeration begins, the tool generates cryptographically random subdomains (e.g., `a1b2c3d4.target.com`) and attempts to resolve them. If they resolve, the target utilizes wildcard DNS. The returned IPs are stored in a filter list.
3. **Passive Engine:** Independent modules concurrently query APIs (crt.sh, HackerTarget, AlienVault OTX), parse the JSON/text responses, and extract matching subdomains.
4. **Active Engine:** The DNS resolver reads the wordlist, appends the target domain, and dispatches concurrent DNS A-record queries throttled by an `asyncio.Semaphore`.
5. **Aggregation & Filtering:** Any actively resolved subdomains pointing to a known wildcard IP are discarded. Remaining results from both engines are merged and deduplicated.
6. **Data Output:** The final clean dataset is written to stdout or a specified file.

## Installation

Ensure you have Python 3.10 or higher installed.

```bash
# Clone the repository
git clone https://github.com/yourusername/SubdomainFinder.git
cd SubdomainFinder

# Set up a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

SubdomainFinder uses standard command-line flags for configuration.

### Arguments
- `-d`, `--domain` : Target domain (Required)
- `-w`, `--wordlist` : Path to wordlist for active enumeration
- `-o`, `--output` : Output file to save discovered subdomains
- `--passive-only` : Skip active DNS resolution and only query APIs
- `-t`, `--threads` : Number of concurrent connections/tasks (Default: 100)

### Examples

**Standard Enumeration (Passive + Active):**
```bash
python -m src.main -d example.com -w data/default_wordlist.txt -o results.txt
```

**Passive Reconnaissance Only (Stealth Mode):**
```bash
python -m src.main -d example.com --passive-only
```

**High-Speed Active Brute-Forcing:**
```bash
python -m src.main -d example.com -w data/large_wordlist.txt -t 500 -o results.txt
```

## Example Workflow
1. A penetration tester receives `example.com` as an in-scope target.
2. To avoid triggering early alerts, the tester first runs SubdomainFinder in `--passive-only` mode to map publicly known infrastructure.
3. After mapping the public footprint, the tester runs the tool with a large 100k-word SecLists dictionary (`-w subdomains-top1million-110000.txt`) to uncover hidden staging environments (e.g., `staging-api.example.com`).
4. SubdomainFinder automatically detects that `*.example.com` resolves to a generic load balancer, filters out the wildcard noise, and outputs only the legitimately configured subdomains.
5. The tester pipes the output into `httpx` to probe for active web servers.

## Example Output
```text
[*] Starting SubdomainFinder against example.com
[*] Checking for wildcard DNS on example.com...
[!] Wildcard DNS detected! IPs: 104.18.2.1, 104.18.3.1
[*] Starting passive enumeration...
[SUCCESS] HackerTarget found 12 subdomains
[SUCCESS] crt.sh found 45 subdomains
[SUCCESS] AlienVault found 8 subdomains
[*] Starting active enumeration against 5000 words...
[SUCCESS] Active enumeration found 3 unique subdomains
[SUCCESS] Total unique subdomains discovered: 54
[SUCCESS] Saved 54 subdomains to results.txt
```

## Detection / OPSEC Notes
- **Passive Enumeration:** Highly stealthy. Queries are made to third-party APIs, meaning your IP address never interacts directly with the target's infrastructure.
- **Active Enumeration:** Extremely noisy. High concurrency levels (`-t 500+`) will generate massive spikes in UDP port 53 traffic directed at the target's authoritative nameservers. This can easily trigger intrusion detection systems (IDS) or SOC alerts for DNS brute-forcing.
- **Rate Limiting:** Public APIs (like HackerTarget) have strict rate limits for free tiers. Excessive passive scanning across multiple targets in a short timeframe may result in temporary IP bans from those intelligence providers.

## Limitations
- This tool does **not** perform HTTP probing or port scanning. It only identifies if a DNS record exists. Use tools like `nmap` or `httpx` on the output for further service discovery.
- It does **not** bypass advanced wildcard configurations (e.g., CDNs that dynamically rotate wildcard IP responses based on load).
- It relies on the host machine's default DNS resolvers.

## Future Improvements
- **Custom Resolver Support:** Implement the ability to load a list of public DNS resolvers (`resolvers.txt`) to distribute active queries and avoid local ISP throttling.
- **Permutation/Alteration Engine:** Automatically generate and resolve variations of discovered subdomains (e.g., finding `dev.api.target.com`, trying `dev1.api.target.com` or `test.api.target.com`).
- **Subdomain Takeover Checks:** Cross-reference discovered CNAME records against known vulnerable cloud provider signatures (e.g., unclaimed AWS S3 buckets or GitHub Pages).

## Learning Objectives
By studying and building upon this project, you will learn:
- The fundamental mechanics of the Domain Name System (DNS) and how records are resolved.
- How to manage high-throughput network I/O in Python using `asyncio` and non-blocking sockets.
- The concept of Wildcard DNS and how to defensively program against false positives in security tooling.
- How to consume and parse REST APIs for Threat Intelligence gathering.

## Disclaimer
This project is intended for educational purposes and authorized security research only. Do not use this tool against infrastructure you do not own or have explicit permission to test. The authors are not responsible for any misuse or damage caused by this software.
