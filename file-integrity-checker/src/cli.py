import argparse
from pathlib import Path
from src.core.hasher import SUPPORTED_ALGORITHMS

def setup_parser() -> argparse.ArgumentParser:
    """
    Sets up the command-line argument parser for the tool.
    """
    parser = argparse.ArgumentParser(
        description="File Hash Generator & Integrity Checker (FIM Utility)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a baseline for a web root using SHA-512
  python main.py generate --target /var/www/html --baseline /var/sec/www_baseline.json --algorithm sha512
  
  # Verify the web root against the baseline
  python main.py verify --target /var/www/html --baseline /var/sec/www_baseline.json
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Generate Subcommand
    parser_gen = subparsers.add_parser("generate", help="Generate a new file integrity baseline")
    parser_gen.add_argument("-t", "--target", type=Path, required=True, help="Target directory to hash")
    parser_gen.add_argument("-b", "--baseline", type=Path, required=True, help="Path to save the baseline JSON file")
    parser_gen.add_argument("-a", "--algorithm", choices=SUPPORTED_ALGORITHMS, default="sha256", help="Hashing algorithm to use")
    
    # Verify Subcommand
    parser_ver = subparsers.add_parser("verify", help="Verify target directory against an existing baseline")
    parser_ver.add_argument("-t", "--target", type=Path, required=True, help="Target directory to verify")
    parser_ver.add_argument("-b", "--baseline", type=Path, required=True, help="Path to load the baseline JSON file from")
    
    # Global flags
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug output")
    
    return parser
