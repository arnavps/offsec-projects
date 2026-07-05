"""
Cookie Sentinel CLI Entrypoint.
Handles command line argument parsing, verification options, and coordinates output reports.
"""

import argparse
import sys
import logging
from typing import Dict, Any

from rich.console import Console

# Use relative imports when running as a module, or support standalone running
try:
    from .core import (
        run_url_analysis,
        run_raw_header_analysis,
        run_netscape_file_analysis,
        run_headers_file_analysis
    )
    from .reporter import Reporter
except ImportError:
    # Fallback to local imports for direct execution
    from core import (
        run_url_analysis,
        run_raw_header_analysis,
        run_netscape_file_analysis,
        run_headers_file_analysis
    )
    from reporter import Reporter

def parse_header_arg(header_list: list) -> Dict[str, str]:
    """Parses a list of 'Key: Value' header strings into a dictionary."""
    headers = {}
    if not header_list:
        return headers
    for h in header_list:
        if ":" not in h:
            continue
        key, val = h.split(":", 1)
        headers[key.strip()] = val.strip()
    return headers

def parse_data_arg(data_str: str) -> Dict[str, str]:
    """Parses a query-string format data argument 'key1=val1&key2=val2' into a dict."""
    data = {}
    if not data_str:
        return data
    pairs = data_str.split("&")
    for pair in pairs:
        if "=" not in pair:
            data[pair.strip()] = ""
        else:
            key, val = pair.split("=", 1)
            data[key.strip()] = val.strip()
    return data

def main():
    # Force UTF-8 stdout encoding on Windows to prevent UnicodeEncodeError in legacy terminals
    if sys.platform.startswith("win"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description="Cookie Sentinel: Enterprise Cookie Attribute Security Auditing Tool.",
        epilog="Authorized security testing only. Focus on detection and reporting."
    )
    
    # Input targets
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Target URL to fetch and scan (active mode)")
    target_group.add_argument("-r", "--raw", help="Raw Set-Cookie header value to parse and scan")
    target_group.add_argument("-f", "--file", help="File containing Set-Cookie headers (one per line, or standard HTTP headers block)")
    target_group.add_argument("-n", "--netscape", help="Path to Netscape format cookie file")

    # HTTP configurations (active mode)
    http_group = parser.add_argument_group("Active Scan Configuration")
    http_group.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method to use (default: GET)")
    http_group.add_argument("-H", "--header", action="append", help="Custom request header in 'Name: Value' format (can be repeated)")
    http_group.add_argument("-d", "--data", help="POST data payload in 'param1=val1&param2=val2' format")
    http_group.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification (risky)")
    http_group.add_argument("--timeout", type=float, default=10.0, help="HTTP request timeout in seconds (default: 10.0)")
    http_group.add_argument("--no-redirect", action="store_true", help="Do not follow redirects")
    http_group.add_argument("--user-agent", help="Custom User-Agent header")

    # Output options
    output_group = parser.add_argument_group("Reporting Options")
    output_group.add_argument("-oJ", "--output-json", help="Save detailed findings as JSON to path")
    output_group.add_argument("-oM", "--output-markdown", help="Save human-readable Markdown report to path")
    
    # Logging
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    console = Console()
    reporter = Reporter(console)

    cookies = []
    findings = {}

    try:
        if args.url:
            console.print(f"[bold blue][*] Actively scanning target: {args.url}[/bold blue]")
            headers = parse_header_arg(args.header)
            data = parse_data_arg(args.data)
            
            cookies, findings = run_url_analysis(
                url=args.url,
                method=args.method,
                headers=headers,
                data=data,
                verify=not args.no_verify,
                timeout=args.timeout,
                allow_redirects=not args.no_redirect,
                user_agent=args.user_agent
            )
            
        elif args.raw:
            console.print("[bold blue][*] Analyzing raw Set-Cookie header input...[/bold blue]")
            cookies, findings = run_raw_header_analysis(args.raw)
            
        elif args.netscape:
            console.print(f"[bold blue][*] Loading Netscape cookie file: {args.netscape}[/bold blue]")
            cookies, findings = run_netscape_file_analysis(args.netscape)
            
        elif args.file:
            console.print(f"[bold blue][*] Parsing raw headers file: {args.file}[/bold blue]")
            cookies, findings = run_headers_file_analysis(args.file)

        # Print outputs to console
        if not cookies:
            console.print("[bold yellow][!] No cookies detected in the specified input.[/bold yellow]")
            sys.exit(0)
            
        reporter.print_cli_summary(cookies, findings)
        reporter.print_cli_cookie_table(cookies)
        reporter.print_cli_findings(findings)

        # Save files if requested
        if args.output_json:
            reporter.generate_json_report(cookies, findings, args.output_json)
        if args.output_markdown:
            reporter.generate_markdown_report(cookies, findings, args.output_markdown)

    except Exception as e:
        console.print(f"[bold red][Error] {e}[/bold red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
