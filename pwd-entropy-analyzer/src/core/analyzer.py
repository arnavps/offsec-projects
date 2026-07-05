import math
import string

class EntropyAnalyzer:
    """
    Core engine to calculate the Shannon entropy of a given password.
    
    Security Relevance:
    Password length and character complexity dictate resistance to offline brute-force attacks.
    By strictly calculating entropy E = L * log2(R), we strip away heuristic assumptions 
    and evaluate the theoretical maximum difficulty of guessing the password.
    """

    def __init__(self):
        # Define standard character pools and their sizes
        self.pools = {
            'lowercase': (set(string.ascii_lowercase), 26),
            'uppercase': (set(string.ascii_uppercase), 26),
            'digits': (set(string.digits), 10),
            'special': (set(string.punctuation + ' '), 33) # 32 punctuation chars + space
        }

    def _determine_pool_size(self, password: str) -> int:
        """
        Determines the total possible character space (R) used in the password.
        """
        if not password:
            return 0
            
        pool_size = 0
        used_pools = set()

        for char in password:
            for pool_name, (char_set, size) in self.pools.items():
                if char in char_set and pool_name not in used_pools:
                    pool_size += size
                    used_pools.add(pool_name)
                    break
                    
        # Fallback for characters outside standard ASCII
        # Assume an extended Unicode pool size if we encounter unmapped chars
        for char in password:
            mapped = any(char in char_set for char_set, _ in self.pools.values())
            if not mapped:
                pool_size += 256 # Assume at least a 1-byte extended character space
                break

        return pool_size

    def calculate_entropy(self, password: str) -> float:
        """
        Calculates the entropy in bits. E = L * log2(R)
        """
        if not password:
            return 0.0
            
        L = len(password)
        R = self._determine_pool_size(password)
        
        if R == 0:
            return 0.0
            
        return L * math.log2(R)
