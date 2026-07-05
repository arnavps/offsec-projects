# Password Entropy Analyzer

An offline authentication testing tool designed to calculate the theoretical cryptographic strength of passwords using Shannon entropy. By analyzing the structural complexity of a password, this tool estimates the mathematical search space an attacker must traverse during an offline brute-force attack.

## Features
- **Entropy Calculation Engine**: Uses Shannon entropy ($E = L \times \log_2(R)$) to determine raw bit strength.
- **Dynamic Pool Detection**: Automatically evaluates character sets used (lowercase, uppercase, digits, special characters, and extended ASCII).
- **Strength Classification**: Maps mathematical entropy bits to human-readable cryptographic strength tiers based on standard security thresholds.
- **OPSEC-Friendly Input**: Utilizes secure prompts to prevent sensitive passwords from being logged in shell history (e.g., `.bash_history`).
- **Rich Terminal Output**: Renders clean, color-coded, and actionable assessment tables for security analysts.

## Use Cases
- **Penetration Testing**: Demonstrating to clients how mathematically weak their "compliant" passwords (e.g., `Company2024!`) are against offline cracking.
- **Security Auditing**: Auditing internal password policies to shift from rigid regex rules to entropy-based complexity models.
- **Lab Simulations**: Generating baseline entropy data before running Hashcat or John the Ripper to estimate brute-force feasibility.

## Tech Stack
- **Language**: Python 3.10+
- **Libraries**: 
  - `math` & `string` (Standard libraries for calculations and pool mapping)
  - `argparse` & `getpass` (For secure CLI handling)
  - `rich` (For terminal UX and formatting)

## Project Architecture
The project follows a decoupled, modular architecture typical of modern offensive security tooling:
- **Input Sanitization**: Evaluates command-line flags or prompts the user via `getpass`.
- **Core Engine (`src/core/analyzer.py`)**: Iterates through the input string, identifies unique character pools, and computes the total pool size ($R$). It then multiplies the length ($L$) by the base-2 logarithm of the pool size.
- **Classification Logic (`src/core/classifier.py`)**: Checks the raw entropy against threshold boundaries (e.g., <28 bits is Very Weak, >127 bits is Very Strong).
- **Presentation (`src/cli/formatter.py`)**: Formats the resulting data points into a readable table.

## Installation
```bash
git clone https://github.com/yourusername/pwd-entropy-analyzer.git
cd pwd-entropy-analyzer
pip install -r requirements.txt
```

## Usage
The tool can be run interactively or via automated command-line arguments.

**Interactive Mode (Recommended for OPSEC):**
```bash
python src/main.py
```
*(You will be prompted to securely enter the password without terminal echo).*

**Argument Mode (For scripting/automation):**
```bash
python src/main.py -p "SuperSecretPassword123!"
```

## Example Workflow
1. A penetration tester recovers an NTLM hash and cracks it. The plaintext is `Winter2024!`.
2. To explain the weakness of this password in a client report, the tester runs it through the Entropy Analyzer.
3. The tool confirms the entropy is ~65 bits. 
4. The tester notes that while 65 bits is technically "Strong" against naive brute force, the use of seasonal dictionary words drastically reduces the real-world complexity against rulesets.

## Example Output
```text
$ python src/main.py -p "Winter2024!"
╭─────────────────────────────── Results ────────────────────────────────╮
│  Password Analysis Report                                              │
│ ┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓                               │
│ ┃ Metric                  ┃      Value ┃                               │
│ ┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩                               │
│ │ Length (L)              │         11 │                               │
│ │ Pool Size (R)           │         95 │                               │
│ │ Entropy (bits)          │      72.26 │                               │
│ │ Strength Classification │ Strong     │                               │
│ └─────────────────────────┴────────────┘                               │
╰────────────────────────────────────────────────────────────────────────╯
```

## Detection / OPSEC Notes
- **Local Execution**: The tool operates entirely offline. No data is transmitted, making it safe for analyzing sensitive client credentials in isolated environments.
- **Logging Risks**: Supplying the password directly via the `-p` flag leaves a trace in the host's `.bash_history` or `.zsh_history`. When operating on jump boxes or shared infrastructure, always use the interactive prompt.
- **Noisy Operations**: The tool performs mathematical calculations only and generates zero network traffic. It is invisible to IDS/WAF solutions.

## Limitations
- **Dictionary Ignorance**: The tool calculates theoretical maximum brute-force entropy. A password like `correcthorsebatterystaple` will yield high entropy, but is highly vulnerable to dictionary attacks.
- **Pattern Recognition**: It does not penalize predictable keyboard walking (e.g., `qwertyuiop`) or sequential numbers. 
- **Hash Cracking**: This is an analyzer, not a cracking utility. It will not break hashes.

## Future Improvements
- **Hashcat Time-to-Crack Estimator**: Translating entropy bits into estimated cracking time across common hash formats (e.g., NTLM, MD5, bcrypt) using modern GPU baselines (e.g., RTX 4090).
- **zxcvbn Integration**: Incorporating a local wordlist checker to penalize passwords containing common dictionary words or leaked credentials.

## Learning Objectives
By studying this project, you will learn:
- The fundamental mathematics of password security (Shannon entropy).
- Why traditional compliance rules (length + complexity) are often inferior to raw entropy measurement.
- How to architect clean, modular Python tools for security operations.
- Best practices for OPSEC-aware input handling in CLI utilities.

## Disclaimer
This tool is designed strictly for educational purposes, security research, and authorized penetration testing. Do not use this tool to analyze credentials you do not own or have explicit permission to test. The developers assume no liability and are not responsible for any misuse or damage caused by this project.
