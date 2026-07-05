import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.core.classifier import StrengthClassifier

class TestStrengthClassifier(unittest.TestCase):

    def test_classification_thresholds(self):
        # Thresholds: <=28 (Very Weak), <=35 (Weak), <=59 (Reasonable), <=127 (Strong), >127 (Very Strong)
        self.assertEqual(StrengthClassifier.classify(10), "Very Weak")
        self.assertEqual(StrengthClassifier.classify(28), "Very Weak")
        
        self.assertEqual(StrengthClassifier.classify(29), "Weak")
        self.assertEqual(StrengthClassifier.classify(35), "Weak")
        
        self.assertEqual(StrengthClassifier.classify(36), "Reasonable")
        self.assertEqual(StrengthClassifier.classify(59), "Reasonable")
        
        self.assertEqual(StrengthClassifier.classify(60), "Strong")
        self.assertEqual(StrengthClassifier.classify(127), "Strong")
        
        self.assertEqual(StrengthClassifier.classify(128), "Very Strong")
        self.assertEqual(StrengthClassifier.classify(500), "Very Strong")

if __name__ == '__main__':
    unittest.main()
