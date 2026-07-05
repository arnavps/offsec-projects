# Technical Deep Dive: The Integrity Verification Engine

The core technical achievement of this project is the **Integrity Verification Engine**, composed of `hasher.py`, `baseline.py`, and `verifier.py`. While generating a hash is trivial, securely capturing the state of a filesystem and computing the delta against a future state is where the complexity lies.

## 1. Internal Logic & Data Flow

```text
[ File System ] --> (Chunked Reader) --> [ Hash Function (SHA256) ] --> (Hash String)
                                                                            |
                                                                            v
[ Target Directory Tree ] --------------------------------------------> [ Baseline State ]
                                                                       (Dict: path -> hash)
```

1. **State Generation (`generate_baseline`):** The tool recursively traverses the target directory using `os.walk`. For each file, it converts the absolute path to a relative POSIX path. This relative path mapping is critical; it allows a baseline generated on `/mnt/server_a/` to be verified on `C:\\backups\\server_a\\` without failing due to path mismatches.
2. **Chunked Hashing:** `compute_file_hash` reads files in 4MB chunks (`f.read(4096 * 1024)`). This ensures the tool's memory footprint remains constant (~4-10MB) regardless of whether it is hashing a 1KB config file or a 50GB database dump.
3. **Serialization:** The state is serialized to a JSON file alongside metadata (timestamp, algorithm, target directory).
4. **Verification (`compare_baselines`):** The tool loads the trusted JSON into memory (Time A), generates a new baseline for the directory in memory (Time B), and computes the delta using set/dictionary operations.

## 2. The Detection Logic

The delta calculation is the heart of the engine. It categorizes files into four states:
- **OK:** `file in trusted AND trusted[file] == current[file]`
- **MODIFIED:** `file in trusted AND file in current AND trusted[file] != current[file]`
- **MISSING:** `file in trusted AND file NOT in current`
- **UNTRACKED:** `file in current AND file NOT in trusted`

This strict categorization prevents attackers from bypassing detection by simply renaming a file (it will show up as one MISSING and one UNTRACKED) or modifying a file and attempting to spoof its timestamps (because we rely purely on cryptographic hashing, not `mtime`/`ctime`).

## 3. Cryptographic Algorithms

- **SHA-256 (Default):** The current industry standard. It is collision-resistant and fast enough for general use on modern CPUs (often hardware-accelerated).
- **SHA-512:** Recommended for 64-bit systems where it can actually outperform SHA-256 in software, while providing an immense margin of security against collisions.
- **MD5:** Included purely for educational comparison or extreme legacy environments. MD5 is broken (susceptible to collision attacks) and should never be used where an attacker might have the ability to supply a malicious file that hashes to the same value as a legitimate one.

## 4. Edge Cases Handled

- **Permission Denied:** If the tool encounters a locked file (e.g., `NTUSER.DAT` on Windows) or lacks read permissions, `hasher.py` catches `PermissionError` and skips the file rather than crashing the entire baseline generation.
- **Cross-Platform Paths:** Windows uses `\` and Linux uses `/`. The tool forces all relative paths to POSIX (`/`) internally before saving to JSON, ensuring cross-platform verification compatibility.

## 5. Limitations

- **Memory vs. Disk Bound:** The tool is disk I/O bound. Hashing 1TB of small files is bottlenecked by the OS filesystem traversal and disk read speed, not the CPU.
- **No Parallelism:** Currently single-threaded. While hashing itself cannot be easily parallelized per-file, reading multiple files simultaneously via `multiprocessing` or `asyncio` could speed up scans on NVMe SSDs.
