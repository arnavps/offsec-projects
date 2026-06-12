import os
import sys
import argparse
from core.crawler import Crawler
from core.scanner import Scanner

def load_payloads(filepath: str) -> list:
    if not os.path.exists(filepath):
        print(f"[-] Error: Payloads file not found at {filepath}")
        sys.exit(1)
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.readlines()

def main():
    print("=========================================")
    print("      VANGUARD XSS SCANNER (v1.0)        ")
    print("=========================================\n")

    parser = argparse.ArgumentParser(description="A lightweight Reflected XSS Scanner.")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan (e.g., http://testphp.vulnweb.com/)")
    args = parser.parse_args()

    target_url = args.url

    # Resolve absolute path to payloads.txt
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    payloads_path = os.path.join(base_dir, "data", "payloads.txt")
    
    payloads = load_payloads(payloads_path)
    print(f"[*] Loaded {len([p for p in payloads if p.strip()])} payloads.")

    crawler = Crawler()
    scanner = Scanner(crawler)

    print(f"[*] Initiating scan on {target_url}...\n")
    
    is_vuln = scanner.scan_page(target_url, payloads)
    
    if not is_vuln:
        print("\n[-] Scan complete. No XSS vulnerabilities found with the provided payloads.")

if __name__ == "__main__":
    main()
