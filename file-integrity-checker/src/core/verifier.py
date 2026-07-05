from typing import Dict, List, Tuple
from src.core.baseline import BaselineManager

class VerificationResult:
    def __init__(self):
        self.ok: List[str] = []
        self.modified: List[str] = []
        self.missing: List[str] = []
        self.untracked: List[str] = []
        
    def is_clean(self) -> bool:
        return len(self.modified) == 0 and len(self.missing) == 0 and len(self.untracked) == 0

def compare_baselines(trusted: BaselineManager, current: BaselineManager) -> VerificationResult:
    """
    Compares two baselines to identify file changes.
    
    Security relevance:
    This is the core detection logic. 
    - modified: The file exists but its hash changed (e.g., binary patching, config altering).
    - missing: The file was in the trusted state but is now gone (e.g., log wiping).
    - untracked: The file is in the current state but wasn't in the trusted state (e.g., dropped webshell).
    """
    if trusted.algorithm != current.algorithm:
        raise ValueError(f"Algorithm mismatch: Trusted used '{trusted.algorithm}', Current used '{current.algorithm}'")
        
    result = VerificationResult()
    trusted_hashes = trusted.state
    current_hashes = current.state
    
    # Check for OK, MODIFIED, and MISSING
    for file_path, trusted_hash in trusted_hashes.items():
        if file_path not in current_hashes:
            result.missing.append(file_path)
        elif trusted_hash == current_hashes[file_path]:
            result.ok.append(file_path)
        else:
            result.modified.append(file_path)
            
    # Check for UNTRACKED
    for file_path in current_hashes.keys():
        if file_path not in trusted_hashes:
            result.untracked.append(file_path)
            
    return result
