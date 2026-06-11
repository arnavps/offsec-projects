import os
from .logger import logger

def read_wordlist(filepath: str) -> list[str]:
    """Reads a wordlist and returns deduplicated list of words."""
    if not os.path.exists(filepath):
        logger.error(f"Wordlist not found: {filepath}")
        return []
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            words = {line.strip() for line in f if line.strip() and not line.startswith('#')}
            logger.info(f"Loaded {len(words)} unique words from {filepath}")
            return list(words)
    except Exception as e:
        logger.error(f"Error reading wordlist: {e}")
        return []

def save_output(filepath: str, subdomains: set[str]):
    """Saves discovered subdomains to a file."""
    if not subdomains:
        logger.warning("No subdomains to save.")
        return

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for sub in sorted(subdomains):
                f.write(f"{sub}\n")
        logger.info(f"[SUCCESS] Saved {len(subdomains)} subdomains to {filepath}")
    except Exception as e:
        logger.error(f"Failed to save output to {filepath}: {e}")
