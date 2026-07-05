# File Hash Generator & Integrity Checker

A modular, zero-dependency File Integrity Monitoring utility built in Python. This tool generates cryptographic hashes for directories, establishes known-good baselines, and detects unauthorized file modifications, additions, and deletions.

## Features
- **Cryptographic Hashing:** Supports SHA-256 (default), SHA-512, and MD5 hashing algorithms.
- **Chunked File Processing:** Safely reads and hashes massive files in 4MB chunks to prevent RAM exhaustion.
- **State Serialization:** Generates and exports the known-good state of a directory tree to a portable JSON baseline file.
- **Delta Verification:** Compares the current filesystem state against a trusted baseline to explicitly identify modified, missing, and untracked files.
- **Structured Logging:** Standardized, clear console output designed for integration into security operations workflows.

## Use Cases
- **Incident Response:** Verifying if critical system binaries or configuration files have been altered after a suspected breach.
- **System Analysis Labs:** Capturing a filesystem baseline before executing unknown software, and then identifying exactly which files were dropped or modified.
- **Application Auditing:** Monitoring a web root for unauthorized script drops or patched source code.

## Tech Stack
- **Language:** Python 3
- **Libraries:** Python Standard Library (`hashlib`, `json`, `argparse`, `pathlib`, `logging`)
- **Protocols/Algorithms:** Cryptographic hashing (SHA-2/MD5)

## Project Architecture
The project follows a modular, decoupled architecture separating the cryptographic logic from the CLI implementation:

- **Input Validation:** Securely parses and validates paths and chosen algorithms.
- **Hash Engine (`hasher.py`):** Instantiates the chosen hash object and processes files in binary mode (`rb`) using 4MB chunks to maintain a constant `O(1)` memory footprint.
- **Baseline Manager (`baseline.py`):** Recursively traverses the target directory, delegates hashing, and serializes the resulting map of relative POSIX paths to hashes into a JSON file.
- **Verification Engine (`verifier.py`):** Calculates the exact delta between a trusted JSON baseline and a live filesystem state.

## Installation
Since the project relies entirely on the Python Standard Library, no external dependencies are required.

```bash
git clone https://github.com/yourusername/file-integrity-checker.git
cd file-integrity-checker
python3 --version
```

## Usage
The tool relies on two primary subcommands: `generate` and `verify`.

```bash
# Generate a baseline
python main.py generate -t <target_directory> -b <output_baseline.json> [-a {sha256,sha512,md5}] [-v]

# Verify a directory against a baseline
python main.py verify -t <target_directory> -b <input_baseline.json> [-v]
```

## Example Workflow
A typical security engineer or researcher would use this tool as follows:

1. **Establish Trust:** Immediately after deploying a fresh server or application, generate a known-good baseline.
2. **Operations & Time Pass:** The server operates normally. An unauthorized user potentially gains access.
3. **Verification:** During a routine audit or incident response, verify the current state against the trusted baseline. The tool will output standard logging identifying any changed, missing, or new files.

## Example Output
```bash
[INFO] Loading trusted baseline from: /root/sec/web_baseline.json
[INFO] Baseline loaded. Contains 154 tracked files using sha512.
[INFO] Scanning current state of /var/www/html...
[INFO] Comparing states...
[WARNING] INTEGRITY COMPROMISED: Changes detected!
[WARNING] MODIFIED (1):
[WARNING]   [~] index.php
[WARNING] MISSING (1):
[WARNING]   [-] config.bak
[WARNING] UNTRACKED (1):
[WARNING]   [+] unknown_script.py
```

## Detection / OPSEC Notes
- **Disk I/O Intensity:** Generating a baseline on a massive directory will trigger significant disk read operations (I/O). This is extremely noisy and can spike disk usage metrics in monitoring solutions.
- **Timestamps:** The tool only opens files for reading in binary mode, which updates the access time on Linux systems unless the partition is mounted with noatime. It does not alter modification or creation times.

## Limitations
- **Point-in-time constraints:** This is a point-in-time scanning tool. It cannot detect ephemeral scripts that create, execute, and delete a file entirely between manual verification scans.
- **Metadata Blindness:** The tool verifies file contents. It does not track changes to file permissions, ownership, or extended attributes.
- **Single-Threaded:** It is currently bottlenecked by sequential disk I/O when hashing large numbers of small files.

## Future Improvements
- **Real-Time Integration:** Integrate with inotify (Linux) or ETW (Windows) to capture real-time file creation/modification events rather than relying on point-in-time polling.
- **Multiprocessing:** Implement concurrent hashing using Python's multiprocessing pool or asyncio for environments with high-speed NVMe storage.
- **Exclusion Filters:** Add support for regex exclusion lists (e.g., ignoring /var/log/*) to reduce false positives in volatile directories.

## Learning Objectives
By studying and building this project, one learns:
1. The difference between collision resistance and cryptographic speed (SHA-256 vs MD5).
2. How to handle large files in Python without causing memory errors via binary chunked reading.
3. The underlying logic behind commercial File Integrity Monitoring agents.
4. How to categorize file system deltas securely and avoid bypasses related to simple file renaming or timestomping.

## Disclaimer
This project is intended for educational purposes, authorized security auditing, and incident response. The developer is not responsible for any misuse or damage caused by this software. Always ensure you have explicit permission before scanning or auditing systems you do not own.
