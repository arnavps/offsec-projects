import unittest
import tempfile
import os
from pathlib import Path
from src.core.baseline import BaselineManager
from src.core.verifier import compare_baselines

class TestVerifier(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)
        
        # Create some test files
        self.file1 = self.base_path / "file1.txt"
        self.file2 = self.base_path / "file2.txt"
        
        with open(self.file1, "w") as f: f.write("content1")
        with open(self.file2, "w") as f: f.write("content2")
        
    def tearDown(self):
        self.test_dir.cleanup()
        
    def test_clean_baseline(self):
        trusted = BaselineManager(self.base_path)
        trusted.generate_baseline()
        
        current = BaselineManager(self.base_path)
        current.generate_baseline()
        
        result = compare_baselines(trusted, current)
        self.assertTrue(result.is_clean())
        self.assertEqual(len(result.ok), 2)
        
    def test_modified_file(self):
        trusted = BaselineManager(self.base_path)
        trusted.generate_baseline()
        
        with open(self.file1, "w") as f: f.write("modified_content")
        
        current = BaselineManager(self.base_path)
        current.generate_baseline()
        
        result = compare_baselines(trusted, current)
        self.assertFalse(result.is_clean())
        self.assertIn("file1.txt", result.modified)
        
    def test_missing_and_untracked(self):
        trusted = BaselineManager(self.base_path)
        trusted.generate_baseline()
        
        os.remove(self.file2)
        new_file = self.base_path / "file3.txt"
        with open(new_file, "w") as f: f.write("new_content")
        
        current = BaselineManager(self.base_path)
        current.generate_baseline()
        
        result = compare_baselines(trusted, current)
        self.assertFalse(result.is_clean())
        self.assertIn("file2.txt", result.missing)
        self.assertIn("file3.txt", result.untracked)

if __name__ == "__main__":
    unittest.main()
