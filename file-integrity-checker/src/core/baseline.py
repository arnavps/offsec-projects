import json
import os
from pathlib import Path
from typing import Dict
import time

from src.core.hasher import compute_file_hash, HashComputationError

class BaselineManager:
    """
    Handles the creation, loading, and saving of known-good baseline states.
    
    Security relevance:
    A baseline acts as the source of truth for the file system state. 
    In an enterprise scenario, this JSON would be signed or stored on a read-only 
    media to prevent attackers from altering the baseline itself.
    """
    
    def __init__(self, target_dir: Path, algorithm: str = "sha256"):
        self.target_dir = Path(target_dir).resolve()
        self.algorithm = algorithm
        self.state: Dict[str, str] = {}
        
    def generate_baseline(self) -> Dict[str, str]:
        """
        Recursively scans the target directory and hashes every file.
        """
        if not self.target_dir.is_dir():
            raise NotADirectoryError(f"Target is not a directory: {self.target_dir}")
            
        for root, _, files in os.walk(self.target_dir):
            for file_name in files:
                full_path = Path(root) / file_name
                # Compute relative path for portability across different mount points
                rel_path = full_path.relative_to(self.target_dir).as_posix()
                
                try:
                    file_hash = compute_file_hash(full_path, self.algorithm)
                    self.state[rel_path] = file_hash
                except HashComputationError as e:
                    # In a real tool, we might want to log this but continue
                    pass
                    
        return self.state

    def save_to_file(self, output_file: Path) -> None:
        """Serializes the state to a JSON file with metadata."""
        data = {
            "metadata": {
                "timestamp": int(time.time()),
                "target_dir": str(self.target_dir),
                "algorithm": self.algorithm,
                "file_count": len(self.state)
            },
            "hashes": self.state
        }
        
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(data, f, indent=4)
            
    def load_from_file(self, input_file: Path) -> None:
        """Loads a previously saved baseline from a JSON file."""
        if not input_file.exists():
            raise FileNotFoundError(f"Baseline file not found: {input_file}")
            
        with open(input_file, "r") as f:
            try:
                data = json.load(f)
                self.state = data.get("hashes", {})
                self.algorithm = data.get("metadata", {}).get("algorithm", "sha256")
                
                # We do NOT overwrite self.target_dir from metadata here, 
                # because we might want to verify the baseline against the same files
                # copied to a different directory. We rely on relative paths.
            except json.JSONDecodeError:
                raise ValueError(f"Invalid JSON format in baseline file: {input_file}")
