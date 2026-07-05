import unittest
from src.modules.takeover import TakeoverDetector

class TestTakeoverDetector(unittest.TestCase):
    """Tests the subdomain takeover module against simulated service signatures."""

    def setUp(self):
        # Instantiate with default configuration (loads data/takeover_signatures.json)
        # It should fall back to internal defaults if files are not found, making it resilient.
        self.detector = TakeoverDetector()

    def test_github_pages_detection(self):
        """Checks detection of orphan GitHub Pages instances."""
        body = "<html><body>There isn't a GitHub Pages site here. Check your DNS configuration.</body></html>"
        result = self.detector.check(body, 404)
        
        self.assertIsNotNone(result)
        self.assertTrue(result["detected"])
        self.assertEqual(result["service"], "GitHub Pages")
        self.assertEqual(result["matched_fingerprint"], "There isn't a GitHub Pages site here.")

    def test_aws_s3_detection(self):
        """Checks detection of orphan Amazon S3 buckets."""
        body = '<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>'
        result = self.detector.check(body, 404)
        
        self.assertIsNotNone(result)
        self.assertTrue(result["detected"])
        self.assertEqual(result["service"], "AWS S3")
        self.assertIn(result["matched_fingerprint"], ["The specified bucket does not exist", "NoSuchBucket"])

    def test_no_detection_on_clean_site(self):
        """Verifies clean sites do not trigger false positive takeover alerts."""
        body = "<html><body>Welcome to our corporate homepage. All systems operational.</body></html>"
        result = self.detector.check(body, 200)
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()
