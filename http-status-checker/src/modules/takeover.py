import json
import os
from typing import List, Dict, Any, Optional

class TakeoverDetector:
    """Scans response bodies against signatures of orphan cloud hosting to detect subdomain takeovers."""

    def __init__(self, signatures_path: Optional[str] = None):
        if not signatures_path:
            # Locate signatures relative to codebase root
            current_dir = os.path.dirname(os.path.abspath(__file__))
            signatures_path = os.path.normpath(
                os.path.join(current_dir, "../../data/takeover_signatures.json")
            )
            
        self.signatures = self._load_signatures(signatures_path)

    def _load_signatures(self, path: str) -> List[Dict[str, Any]]:
        """Loads signature JSON from disk with static fallbacks on failure."""
        if not os.path.exists(path):
            # Fallback signatures in case data file is missing
            return [
                {
                    "service": "GitHub Pages",
                    "fingerprints": ["There isn't a GitHub Pages site here.", "github.io"],
                    "status": "404"
                },
                {
                    "service": "Heroku",
                    "fingerprints": ["no-such-app.html", "No such app", "herokucdn.com"],
                    "status": "404"
                },
                {
                    "service": "AWS S3",
                    "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
                    "status": "404"
                }
            ]
            
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def check(self, body_preview: str, status_code: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Scans response contents for service-specific error strings."""
        if not body_preview:
            return None
            
        for sig in self.signatures:
            # OPTIONAL: check status code to narrow down matching,
            # but sometimes WAFs or custom errors modify status codes, so body string matching is principal.
            for fingerprint in sig.get("fingerprints", []):
                if fingerprint in body_preview:
                    return {
                        "detected": True,
                        "service": sig["service"],
                        "matched_fingerprint": fingerprint
                    }
                    
        return None
