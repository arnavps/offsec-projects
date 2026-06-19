import re
import json
from typing import Dict, List, Optional, Tuple

class Analyzer:
    """
    Scans HTTP response bodies against a database of known SQL error signatures.
    
    Security Context:
    The analyzer uses precompiled regular expressions for speed. It is crucial 
    that the signatures are highly specific to avoid false positives. It treats
    the response strictly as a string, avoiding any DOM parsing to prevent
    Client-Side vulnerabilities within the tool itself.
    """

    def __init__(self, signatures_path: str):
        self.signatures = self._load_signatures(signatures_path)
        self.compiled_patterns = self._compile_patterns()

    def _load_signatures(self, path: str) -> Dict[str, List[str]]:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise RuntimeError(f"Failed to load signatures from {path}: {e}")

    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        compiled = {}
        for dbms, patterns in self.signatures.items():
            compiled[dbms] = []
            for pattern in patterns:
                # Compile with IGNORECASE as error messages might vary in case
                compiled[dbms].append(re.compile(pattern, re.IGNORECASE))
        return compiled

    def analyze_response(self, response_text: str) -> Optional[Tuple[str, str]]:
        """
        Scans the response text for any matching SQL error signature.
        
        Returns:
            Tuple of (DBMS_Name, Matched_Pattern_String) if found.
            None if no error is detected.
        """
        # Fast exit if response is empty
        if not response_text:
            return None

        # Iterate through databases and their patterns
        for dbms, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(response_text):
                    # We return the raw pattern string (pattern.pattern) for reporting
                    return (dbms, pattern.pattern)
                    
        return None
