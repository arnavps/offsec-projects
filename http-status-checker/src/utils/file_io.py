import csv
import json
import os
from typing import List, Dict, Any
from src.utils.logger import logger

def read_target_file(file_path: str) -> List[str]:
    """Reads a list of domains or URLs from a file, sanitizing inputs."""
    if not os.path.exists(file_path):
        logger.error(f"[-] Input file not found: {file_path}")
        return []
    
    targets = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                targets.append(line)
    except Exception as e:
        logger.error(f"[-] Error reading file {file_path}: {e}")
        
    return targets

def save_json(file_path: str, data: List[Dict[str, Any]]) -> bool:
    """Saves list of dictionaries to a JSON file."""
    try:
        # Create directories if they do not exist
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logger.info(f"[SUCCESS] JSON results saved to {file_path}")
        return True
    except Exception as e:
        logger.error(f"[-] Failed to save JSON output: {e}")
        return False

def save_csv(file_path: str, data: List[Dict[str, Any]]) -> bool:
    """Saves list of dictionaries to a CSV file."""
    if not data:
        logger.warning("[!] No data to save to CSV.")
        return False
    
    try:
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        # Identify headers from keys of the first dict
        # Flatten dictionary values if they are nested, but let's make sure our data format is flat.
        headers = list(data[0].keys())
        
        with open(file_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for row in data:
                # Format list/dict values as string to fit CSV
                row_str = {}
                for k, v in row.items():
                    if isinstance(v, (list, dict)):
                        row_str[k] = json.dumps(v)
                    else:
                        row_str[k] = v
                writer.writerow(row_str)
        logger.info(f"[SUCCESS] CSV results saved to {file_path}")
        return True
    except Exception as e:
        logger.error(f"[-] Failed to save CSV output: {e}")
        return False
