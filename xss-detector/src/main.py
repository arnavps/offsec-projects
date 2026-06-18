import json
import sys
import os
from core.normalizer import InputNormalizer
from core.detector import XSSDetector

def load_rules(filepath: str):
    if not os.path.exists(filepath):
        print(f"[-] Error: Rules file not found at {filepath}")
        sys.exit(1)
    with open(filepath, 'r') as f:
        return json.load(f)["rules"]

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py \"<payload>\"")
        sys.exit(1)

    payload = sys.argv[1]
    
    # Resolve absolute path to rules.json based on current file location
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rules_path = os.path.join(base_dir, "data", "rules.json")
    rules = load_rules(rules_path)
    
    normalizer = InputNormalizer()
    detector = XSSDetector(rules)

    print(f"[*] Analyzing Payload: {payload}")
    
    # 1. Normalize
    variations = normalizer.normalize(payload)
    print(f"[*] Fully Decoded String: {variations['combined_fully_decoded']}")
    
    # 2. Analyze
    result = detector.analyze(variations, threshold=80)
    
    # 3. Output
    if result["is_malicious"]:
        print(f"[!] MALICIOUS PAYLOAD DETECTED (Score: {result['score']})")
        print(f"[!] Rules Triggered: {', '.join(result['triggered_rules'])}")
    else:
        print("[+] Payload appears benign.")

if __name__ == "__main__":
    main()
