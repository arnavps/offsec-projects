import argparse
import sys
from typing import List, Dict, Any, Tuple

class CustomActionHeader(argparse.Action):
    """Custom action to parse headers in the format 'Key: Value' into a dict."""
    def __call__(self, parser, namespace, values, option_string=None):
        headers = getattr(namespace, self.dest) or {}
        for item in values:
            if ":" not in item:
                parser.error(f"Invalid header format: '{item}'. Must be in 'Key: Value' format.")
            k, v = item.split(":", 1)
            headers[k.strip()] = v.strip()
        setattr(namespace, self.dest, headers)

def parse_arguments() -> argparse.Namespace:
    """Parses command line arguments for http-status-checker."""
    parser = argparse.ArgumentParser(
        description="http-status-checker - Asynchronous HTTP Endpoint Prober & Recon Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  python -m src.main -i subdomains.txt -o results.json\n"
               "  cat subdomains.txt | python -m src.main -o results.csv -f csv\n"
               "  python -m src.main -i targets.txt -c 100 -r 20 -H \"X-Bug-Bounty: hackerone\""
    )

    # Input/Output Configs
    parser.add_argument(
        "-i", "--input",
        type=str,
        help="Path to a file containing domains/URLs. If omitted, reads from stdin."
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Path to output file for results."
    )
    parser.add_argument(
        "-f", "--format",
        choices=["json", "csv"],
        default="json",
        help="Format for output file: 'json' or 'csv' (default: json)."
    )

    # Concurrency & Performance Configs
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=50,
        help="Maximum concurrent HTTP connections (default: 50)."
    )
    parser.add_argument(
        "-r", "--rate-limit",
        type=float,
        default=0.0,
        help="Maximum requests per second (RPS) limit (default: 0, which means unlimited)."
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="Connection timeout in seconds per request (default: 10)."
    )

    # HTTP Customization Configs
    parser.add_argument(
        "--no-redirects",
        action="store_true",
        help="Do not follow redirects. Reports original status codes."
    )
    parser.add_argument(
        "--max-redirects",
        type=int,
        default=5,
        help="Maximum number of redirects to follow (default: 5)."
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Enable SSL certificate verification (disabled by default for offensive recon)."
    )
    parser.add_argument(
        "-u", "--user-agent",
        type=str,
        help="Custom User-Agent header to override the default browser agent."
    )
    parser.add_argument(
        "-H", "--header",
        action=CustomActionHeader,
        nargs="+",
        default={},
        help="Custom HTTP headers to include in requests. Format: 'Name: Value'. Can specify multiple times."
    )

    # Scanning Logic Configs
    parser.add_argument(
        "--prefer-http",
        action="store_true",
        help="Prefer HTTP over HTTPS. If a bare domain is passed, probe http:// first instead of https://."
    )
    parser.add_argument(
        "--only-ssl",
        action="store_true",
        help="Force HTTPS probing only. Do not fallback to or probe HTTP."
    )
    parser.add_argument(
        "--only-http",
        action="store_true",
        help="Force HTTP probing only. Do not fallback to or probe HTTPS."
    )

    return parser.parse_args()
