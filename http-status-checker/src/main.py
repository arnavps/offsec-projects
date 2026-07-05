import asyncio
import sys
import time
from typing import List

from src.cli.parser import parse_arguments
from src.cli.formatter import ConsoleFormatter
from src.utils.logger import logger
from src.utils.file_io import read_target_file, save_json, save_csv
from src.core.prober import Prober
from src.core.engine import Engine
from src.modules.fingerprint import Fingerprinter
from src.modules.takeover import TakeoverDetector

def expand_targets(raw_targets: List[str], only_ssl: bool, only_http: bool) -> List[str]:
    """Expands list of bare domains into URL endpoints based on protocol selections."""
    expanded = []
    
    # Simple deduplication maintaining insertion order
    seen = set()
    deduped_targets = []
    for t in raw_targets:
        if t not in seen:
            seen.add(t)
            deduped_targets.append(t)

    for target in deduped_targets:
        target_lower = target.lower()
        if target_lower.startswith("http://") or target_lower.startswith("https://"):
            expanded.append(target)
        else:
            # Bare domain/subdomain, expand based on CLI configurations
            if only_ssl:
                expanded.append(f"https://{target}")
            elif only_http:
                expanded.append(f"http://{target}")
            else:
                # Default behavior: probe both protocols to discover all listening web servers
                expanded.append(f"https://{target}")
                expanded.append(f"http://{target}")
                
    return expanded

async def main():
    args = parse_arguments()
    formatter = ConsoleFormatter()
    
    # Read targets from file or stdin
    raw_targets = []
    if args.input:
        raw_targets = read_target_file(args.input)
    elif not sys.stdin.isatty():
        # Pipe input (e.g. cat domains.txt | python -m src.main)
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                raw_targets.append(line)
    else:
        # No input file and no piped data, print help and exit
        formatter.console.print("[red][-] Error: No target input specified. Provide an input file (-i) or pipe domains via stdin.[/]\n")
        sys.argv.append("-h")
        parse_arguments()
        sys.exit(1)

    if not raw_targets:
        logger.warning("[!] Target list is empty. Exiting...")
        sys.exit(0)

    # Expand domains into URLs
    targets = expand_targets(raw_targets, args.only_ssl, args.only_http)
    
    logger.info(f"[*] Loaded {len(raw_targets)} unique target host(s), expanded into {len(targets)} HTTP/S endpoint(s)")
    logger.info(f"[*] Starting async engine (Concurrency: {args.concurrency}, Timeout: {args.timeout}s)")
    if args.rate_limit > 0:
        logger.info(f"[*] Rate Limit: {args.rate_limit} requests/sec")

    # Instantiate modules
    takeover_detector = TakeoverDetector()
    
    # Setup CLI progress bar
    progress = formatter.get_progress_bar()
    task_id = progress.add_task("[cyan]Probing target endpoints...", total=len(targets))
    
    # Instantiate the individual prober
    prober = Prober(
        timeout=args.timeout,
        allow_redirects=not args.no_redirects,
        max_redirects=args.max_redirects,
        verify_ssl=args.verify_ssl,
        custom_headers=args.header
    )

    # Real-time callback to process, fingerprint, analyze takeovers, and log results
    async def process_and_log(result):
        # 1. Tech fingerprinting and security header audit
        analysis = Fingerprinter.analyze(result["headers"])
        result.update(analysis)
        
        # 2. Subdomain takeover check
        takeover = takeover_detector.check(result["body_preview"], result["status_code"])
        result["takeover"] = takeover
        
        # 3. Clean body_preview before output save to save space
        # We don't need the entire body preview string in the final output unless requested,
        # but preserving a tiny snippet is fine. Let's limit it to 200 chars or remove it.
        result["body_preview"] = result["body_preview"][:200].replace("\n", " ") if result["body_preview"] else ""
        
        # 4. Display result in terminal
        formatter.print_result(result)
        
        # 5. Update progress bar
        progress.advance(task_id)

    # Initialize and run concurrent async engine
    engine = Engine(
        targets=targets,
        prober=prober,
        concurrency=args.concurrency,
        rate_limit=args.rate_limit,
        progress_callback=process_and_log
    )

    start_time = time.perf_counter()
    
    # Run the progress bar and engine concurrently
    with progress:
        results = await engine.run()
        
    duration = time.perf_counter() - start_time

    # Output reports if specified
    if args.output:
        if args.format == "csv":
            save_csv(args.output, results)
        else:
            save_json(args.output, results)

    # Print final summary statistics table
    formatter.print_summary(results, duration)

if __name__ == "__main__":
    try:
        # Check OS to configure appropriate async event loop policy on Windows
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            # Force stdout and stderr to use UTF-8 on Windows to prevent UnicodeEncodeError
            try:
                sys.stdout.reconfigure(encoding='utf-8')
                sys.stderr.reconfigure(encoding='utf-8')
            except AttributeError:
                # Python versions without reconfigure support (older than 3.7)
                pass
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("\n[!] Execution interrupted by user. Exiting...")
        sys.exit(1)
