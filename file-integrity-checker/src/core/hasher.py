import hashlib
from pathlib import Path

SUPPORTED_ALGORITHMS = ["sha256", "sha512", "md5"]
DEFAULT_CHUNK_SIZE = 4096 * 1024  # 4 MB

class HashComputationError(Exception):
    """Raised when hashing fails (e.g., permission denied, file not found)."""
    pass

def compute_file_hash(file_path: Path, algorithm: str = "sha256", chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Computes the cryptographic hash of a file efficiently using chunked reading.
    
    Security relevance:
    1. Chunked reading prevents Denial of Service (DoS) by memory exhaustion 
       when hashing massive files (e.g., 50GB database dumps or ISOs).
    2. Dynamic algorithm selection allows users to trade off speed vs security 
       (e.g., MD5 for speed/legacy vs SHA-512 for collision resistance).
    """
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Supported: {', '.join(SUPPORTED_ALGORITHMS)}")

    try:
        # Instantiate the correct hash object dynamically
        hasher = hashlib.new(algorithm)
    except ValueError as e:
        raise HashComputationError(f"Hash initialization failed: {e}")

    try:
        # Open in binary mode ('rb') to handle arbitrary bytes without decoding errors
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
                
        return hasher.hexdigest()
        
    except PermissionError:
        raise HashComputationError(f"Permission denied reading file: {file_path}")
    except FileNotFoundError:
        raise HashComputationError(f"File not found: {file_path}")
    except OSError as e:
        raise HashComputationError(f"OS Error while reading {file_path}: {e}")
