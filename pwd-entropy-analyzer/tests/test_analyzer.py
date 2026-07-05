import unittest
import math
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.core.analyzer import EntropyAnalyzer

class TestEntropyAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = EntropyAnalyzer()

    def test_pool_size_lowercase(self):
        # 'a' is lowercase only (pool size 26)
        self.assertEqual(self.analyzer._determine_pool_size("a"), 26)
        self.assertEqual(self.analyzer._determine_pool_size("hello"), 26)

    def test_pool_size_mixed(self):
        # 'aA' has lower (26) + upper (26) = 52
        self.assertEqual(self.analyzer._determine_pool_size("aA"), 52)
        # 'aA1' has lower (26) + upper (26) + digits (10) = 62
        self.assertEqual(self.analyzer._determine_pool_size("aA1"), 62)
        # 'aA1!' has lower (26) + upper (26) + digits (10) + special (33) = 95
        self.assertEqual(self.analyzer._determine_pool_size("aA1!"), 95)

    def test_entropy_calculation(self):
        # E = L * log2(R)
        # L=1, R=26 -> 1 * log2(26) ~ 4.7
        self.assertAlmostEqual(self.analyzer.calculate_entropy("a"), math.log2(26))
        # L=5, R=26
        self.assertAlmostEqual(self.analyzer.calculate_entropy("hello"), 5 * math.log2(26))

    def test_empty_string(self):
        self.assertEqual(self.analyzer.calculate_entropy(""), 0.0)

if __name__ == '__main__':
    unittest.main()
