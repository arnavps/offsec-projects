# Aegis XSS Detection Engine

## Overview
Aegis is a lightweight, dependency-free Python engine designed to detect Cross-Site Scripting (XSS) payloads. It operates by simulating the core functionality of a Web Application Firewall (WAF) using a **Hybrid Detection Architecture**. The engine ingests raw strings, strips away multiple layers of encoding (URL and HTML entities) up to a safe depth, and evaluates the normalized string against both a heuristic regex-based signature database AND a structural Abstract Syntax Tree (AST) parser.

## Problem Statement
Many entry-level security practitioners and developers rely on basic string matching (e.g., blocking `<script>`) to prevent XSS. In the real world, attackers trivially bypass these filters using techniques like double URL encoding or HTML entity obfuscation. This project bridges that learning gap by demonstrating how defense systems actually process obfuscated strings and why input normalization paired with structural parsing is the bedrock of payload detection.

## Objective
This project was built to gain a deep, functional understanding of how WAFs and security filters de-obfuscate payloads. It targets skills in string manipulation, encoding mechanisms, heuristic anomaly scoring, and structural DOM-based parsing.

## System Architecture
Input String → Normalizer Pipeline → Hybrid Engine (Regex + AST) → Heuristic Scorer → Output Log

1. **Input String**: Raw payload from the user.
2. **Normalizer Pipeline**: Recursively decodes URL and HTML entities.
3. **Hybrid Engine**: 
   - **Regex Scanner**: Loads JSON-based rules.
   - **AST Parser**: Walks the DOM structure to identify malicious nodes/attributes natively.
4. **Heuristic Scorer**: Aggregates risk scores from triggered rules and structural anomalies.
5. **Output Log**: Flags payload as malicious or benign based on a threshold.

## Core Features
- **Hybrid Regex + AST Detection**: Combines fast signature matching with robust structural parsing using Python's native `html.parser`, allowing it to detect obfuscated event handlers that bypass regex.
- **Deep Recursive Normalization**: Recursively unquotes URL encodings and unescapes HTML entities up to a defined depth (default 3) to prevent evasion via multiple encoding layers, while capping depth to prevent Infinite Loop DoS.
- **Externalized Signature Database**: Rules are stored in a standalone JSON file, separating business logic from detection signatures.
- **Heuristic Scoring**: Rather than a binary block/allow based on a single regex match, rules carry weights. A payload is only flagged if the cumulative score breaches a defined threshold.

## Execution Flow (Step-by-Step)
1. **Start**: The `main.py` entrypoint receives the payload via CLI.
2. **Rule Loading**: Parses `data/rules.json` to load regex signatures and risk scores.
3. **Normalization**: `InputNormalizer.normalize()` applies URL and HTML decoding, returning a dictionary of variations including a `combined_fully_decoded` string.
4. **Regex Analysis**: Scans compiled regex rules against the fully decoded string.
5. **AST Analysis**: `ASTAnalyzer.analyze()` parses the decoded string as HTML, walking through DOM nodes looking for `script` tags or `javascript:` protocols in attributes.
6. **Scoring**: Matches append to the total risk score.
7. **Final Output**: If `total_score >= threshold`, the system alerts and lists the triggered rules.

## Key Component Deep Dive
The most critical component is the **Hybrid Detection Approach**.
- **The Evasion Battle**: Attackers bypass naive regex by adding excess whitespace or mutating characters (e.g. `<img src=x    onerror  =  alert(1)>`). A brittle regex fails here.
- **The AST Solution**: By utilizing `html.parser`, the engine natively understands that `onerror` is an attribute attached to `img`, regardless of how much whitespace the attacker injects. The engine doesn't just read strings; it understands structural intent.

## Tech Stack (With Justification)
- **Language: Python 3.10+**
  - *Why*: The standard library (`urllib.parse`, `html`, `re`, `html.parser`) is perfectly suited for string manipulation and decoding without requiring third-party dependencies (like BeautifulSoup).
  - *Trade-offs*: Slower at high concurrency compared to compiled languages like Go or Rust, but execution speed is secondary to architectural clarity for this scope.

## What I Built vs What I Used

### Built:
- `InputNormalizer`: Custom recursive decoding pipeline.
- `ASTAnalyzer`: Custom structural DOM walker for malicious nodes.
- `XSSDetector`: Custom hybrid application and heuristic scoring engine.
- `rules.json`: Custom dataset of regex signatures for XSS vectors.

### Used:
- `urllib.parse` & `html`: Python standard libraries for unquoting and unescaping.
- `re`: Python standard library for regex execution.
- `html.parser`: Python standard library for AST generation.

## Proof of Functionality

### Example Attack / Input
A structurally obfuscated payload that evades basic regex due to heavy whitespace, paired with HTML entity encoding:
```powershell
python src/main.py "&#x3C;img src=x    onerror   =   alert(1)&#x3E;"
```

### System Response
```text
[*] Analyzing Payload: &#x3C;img src=x    onerror   =   alert(1)&#x3E;
[*] Fully Decoded String: <img src=x    onerror   =   alert(1)>
[!] MALICIOUS PAYLOAD DETECTED (Score: 80)
[!] Rules Triggered: AST: Structural Event Handler (onerror)
```

### Observations
The Regex engine completely missed it due to the heavy whitespace obfuscation. However, the `ASTAnalyzer` natively parsed the structure, identified `onerror` as a real attribute, and flagged it structurally!

## Security Relevance
This project directly relates to Blue Team defense engineering and Red Team evasion. By understanding how a normalizer processes a payload and how AST parsers analyze DOM structures, an offensive security engineer learns exactly how to craft payloads that fall outside the bounds of structural parsing or exploit misconfigured decoding sequences.

## Limitations
- **Headless Execution Missing**: While it uses an AST parser, it still doesn't execute JavaScript. It cannot detect payloads obfuscated via complex JavaScript execution tricks (e.g., `eval(atob(...))`).
- **Context Ignorance**: It analyzes strings in a vacuum. A payload like `<script>` is flagged as malicious even if it is safely destined for a JSON value field where it cannot execute.

## Conclusion
This project represents the shift from learning *how* to break things to learning *why* things break. It is a foundational step in understanding defensive architecture (AST parsing + Normalization), which is a mandatory prerequisite for advanced offensive security and evasion research.

## Final Evaluation (MANDATORY)
- **Is this project beginner / intermediate / advanced?** Intermediate to Advanced. Integrating an AST parser alongside heuristic scoring pushes this out of beginner territory. It mimics real-world WAF logic.
- **Is it portfolio-worthy for cybersecurity roles?** Absolutely. 
- **Why?** Most junior candidates showcase tools that *execute* vulnerabilities (e.g., Python exploit scripts). Showcasing a tool that *detects* vulnerabilities using AST parsing proves you understand the underlying mechanics of web application firewalls, structural parsing, and input validation systems.
