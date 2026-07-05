import sys
import os

# Ensure the src directory is in the path for direct execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.analyzer import EntropyAnalyzer
from src.core.classifier import StrengthClassifier
from src.cli.parser import parse_args, get_password
from src.cli.formatter import ReportFormatter

def main():
    """
    Entry point for the Password Entropy Analyzer.
    Coordinates input, processing, and output rendering.
    """
    args = parse_args()
    password = get_password(args)
    
    if not password:
        print("No password provided. Exiting.")
        sys.exit(1)
        
    analyzer = EntropyAnalyzer()
    
    # Calculate metrics
    length = len(password)
    pool_size = analyzer._determine_pool_size(password)
    entropy = analyzer.calculate_entropy(password)
    
    # Classify strength
    classification = StrengthClassifier.classify(entropy)
    
    # Render Output
    formatter = ReportFormatter()
    formatter.print_report(length, pool_size, entropy, classification)

if __name__ == "__main__":
    main()
