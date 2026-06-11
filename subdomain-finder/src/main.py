import argparse
import asyncio
import sys
from src.utils.logger import logger
from src.utils.file_io import read_wordlist, save_output
from src.core.engine import Engine

async def main():
    parser = argparse.ArgumentParser(description="SubdomainFinder - Offensive Security Subdomain Enumerator")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Wordlist for active enumeration")
    parser.add_argument("-o", "--output", help="Output file to save subdomains")
    parser.add_argument("--passive-only", action="store_true", help="Only run passive API enumeration")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of concurrent DNS resolutions (default 100)")
    
    args = parser.parse_args()
    
    logger.info(f"Starting SubdomainFinder against {args.domain}")
    
    words = []
    if args.wordlist and not args.passive_only:
        words = read_wordlist(args.wordlist)
        
    engine = Engine(target=args.domain, wordlist=words, concurrency=args.threads)
    
    subdomains = await engine.run(passive_only=args.passive_only)
    
    logger.info(f"[SUCCESS] Total unique subdomains discovered: {len(subdomains)}")
    
    if args.output:
        save_output(args.output, subdomains)
    else:
        # If no output file, just print them nicely
        logger.info("Results:")
        for sub in sorted(subdomains):
            print(sub)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("\nExecution interrupted by user. Exiting...")
        sys.exit(1)
