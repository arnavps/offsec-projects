# Security Analysis & Critical Evaluation

As an offensive security engineer, building a defensive tool requires a critical evaluation of how an attacker might bypass it. This analysis outlines the security flaws, weak assumptions, and operational risks of the File Integrity Checker.

## 1. Security Flaws & Bypass Opportunities

### 1.1 Baseline Tampering (The Achilles Heel)
The most glaring vulnerability in this architecture is the trust placed in the baseline JSON file. 
- **The Attack:** If an attacker gains root/SYSTEM access, they can replace a binary (e.g., `/bin/ls`), recalculate its SHA-256 hash, and silently update the `baseline.json` file. The next time the verifier runs, it will report `OK`.
- **The Mitigation:** In a production environment, baselines must be stored on a remote, append-only syslog server, or the JSON file itself must be cryptographically signed (e.g., using GPG or an asymmetric key where the private key is not stored on the monitored host).

### 1.2 Time-of-Check to Time-of-Use (TOCTOU)
- **The Attack:** This tool runs on a schedule (e.g., via cron job). An attacker can drop a malicious payload, execute it, and delete it between the scheduled scans. Because the tool relies on point-in-time polling rather than real-time event tracing (like Windows ETW or Linux eBPF/inotify), ephemeral malware will bypass detection entirely.
- **The Mitigation:** Integrate real-time kernel-level filesystem monitoring.

### 1.3 Hash Collisions (If using MD5)
- **The Attack:** If the tool is configured to use MD5 (`--algorithm md5`), an attacker can use a chosen-prefix collision attack to create a malicious binary that shares the exact same MD5 hash as the legitimate binary. The tool will see the hashes match and report `OK`.
- **The Mitigation:** Default to SHA-256/SHA-512 (as currently implemented).

## 2. Weak Assumptions

- **Assumption: "Read access implies file stability."** 
  The tool assumes that while it is reading a 4MB chunk of a file, the file is not being modified by another process. If a file is modified mid-read, the resulting hash will be a corrupted mix of the old and new states.
- **Assumption: "File contents are the only thing that matters."**
  The tool only hashes file *contents*. It ignores file *metadata* (permissions, ownership, ACLs, ADS). An attacker could `chmod 777 /etc/shadow` without changing its contents, and this tool would not detect the permission alteration.

## 3. Scalability Limitations

- **Large Directories:** Hashing `C:\Windows\System32` (tens of thousands of files) takes significant time. This tool lacks incremental scanning. Every time `verify` is run, it must re-hash *everything*, which is CPU and I/O intensive.
- **No Exclusion Lists:** Currently, the tool hashes everything in the target directory. It cannot exclude volatile directories (e.g., `/var/log/` or `/tmp/`), meaning verifications on root directories will always produce massive amounts of "MODIFIED" noise.

## 4. Brutally Honest Conclusion

This utility is a **functionally accurate, intermediate-level implementation of core FIM concepts**, but it is **not a production-ready endpoint security agent**. It is highly effective for localized tasks (e.g., verifying a web root after deployment, or checking a specific binary directory), but lacks the real-time capabilities, metadata tracking, and baseline protection required to stop an advanced persistent threat (APT).
