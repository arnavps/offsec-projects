import unittest
import tempfile
import os
from pathlib import Path
from src.core.hasher import compute_file_hash, HashComputationError

class TestHasher(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_file = Path(self.test_dir.name) / "test.txt"
        with open(self.test_file, "w") as f:
            f.write("test_content")
            
    def tearDown(self):
        self.test_dir.cleanup()
        
    def test_sha256(self):
        h = compute_file_hash(self.test_file, "sha256")
        self.assertEqual(h, "594a1b494545be568120d28c43b3319e41d7b8e51a8112ebbece7b3275591a9a")
        
    def test_md5(self):
        h = compute_file_hash(self.test_file, "md5")
        self.assertEqual(h, "27565f9a57c128674736aa644012ce67")
        
    def test_invalid_algorithm(self):
        with self.assertRaises(ValueError):
            compute_file_hash(self.test_file, "invalid_algo")
            
    def test_file_not_found(self):
        with self.assertRaises(HashComputationError):
            compute_file_hash(Path("nonexistent_file.txt"), "sha256")

if __name__ == "__main__":
    unittest.main()
