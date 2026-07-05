class StrengthClassifier:
    """
    Maps calculated entropy (in bits) to qualitative security categories.
    
    Security Relevance:
    Raw numbers are difficult for non-technical users to contextualize. 
    By applying standard cryptographic thresholds (e.g., NIST recommendations), 
    we provide actionable risk assessment metrics. 
    """

    # Thresholds mapped based on common cryptographic guidance for offline attacks
    THRESHOLDS = [
        (28, "Very Weak"),     # Easily guessable / crackable almost instantly
        (35, "Weak"),          # Can be cracked relatively quickly by dedicated hardware
        (59, "Reasonable"),    # Resists casual cracking, but vulnerable to extensive offline attacks
        (127, "Strong"),       # Highly resistant to offline cracking attempts
        (float('inf'), "Very Strong") # Computationally infeasible with current technology
    ]

    @classmethod
    def classify(cls, entropy_bits: float) -> str:
        """
        Returns a human-readable classification based on bit strength.
        """
        for threshold, category in cls.THRESHOLDS:
            if entropy_bits <= threshold:
                return category
        return "Unknown"
