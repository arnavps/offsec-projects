import argparse
import sys
import os
from src.core.mutator import Mutator
from src.core.engine import RequestEngine
from src.core.analyzer import Analyzer
from src.utils.logger import Logger

def load_payloads(path: str) -> list[str]:
    """Load injection payloads from file."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            # Strip newlines and ignore empty lines
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading payloads: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Error-Based SQL Injection Tester")
    parser.add_argument("-u", "--url", required=True, help="Target URL (must include query parameters, e.g., http://target.com/page?id=1)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--proxy", type=str, help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    
    args = parser.parse_args()
    
    logger = Logger()
    logger.info(f"Initializing scan for: {args.url}")

    # 1. Setup Data Paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    payloads_path = os.path.join(base_dir, 'data', 'payloads.txt')
    signatures_path = os.path.join(base_dir, 'data', 'signatures.json')

    # 2. Initialize Core Modules
    try:
        payloads = load_payloads(payloads_path)
        analyzer = Analyzer(signatures_path)
        mutator = Mutator(args.url)
        engine = RequestEngine(timeout=args.timeout, delay=args.delay, proxy=args.proxy)
    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        sys.exit(1)

    if not mutator.parameters:
        logger.warning("No URL parameters found to inject. Ensure URL has query string (e.g., ?id=1)")
        sys.exit(0)

    logger.info(f"Loaded {len(payloads)} payloads.")
    logger.info(f"Found {len(mutator.parameters)} parameters to test.")
    
    # Disable warnings for unverified HTTPS requests if testing internally
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # 3. Execution Loop
    logger.info("Starting injection process...")
    
    for payload in payloads:
        # Get URLs with the payload injected into each parameter one by one
        mutated_targets = mutator.get_mutated_urls(payload)
        
        for param_name, mutated_url in mutated_targets:
            # Send Request
            response = engine.send_get(mutated_url)
            
            if response is None:
                continue # Request failed (timeout/connection error)

            # Analyze Response
            result = analyzer.analyze_response(response.text)
            
            if result:
                dbms, pattern_matched = result
                logger.log_finding(parameter=param_name, payload=payload, dbms=dbms, url=mutated_url)
                # Note: We don't break here because we might want to see if other payloads trigger different errors,
                # but a more advanced tool might offer an --early-stop flag.

    # 4. Cleanup and Reporting
    engine.close()
    logger.print_summary()

if __name__ == "__main__":
    main()
