# Deep Dive: SQLi Mutation and Detection Logic

As a security engineer, understanding *why* the tool is built a certain way is more important than just seeing it run. This deep dive dissects the most critical component of the `sqli-detector`: the interplay between the `Mutator` and the `Analyzer`.

## 1. The Mutator: Surgical Precision in Payload Delivery

The `Mutator` class (`src/core/mutator.py`) is responsible for parameter isolation. 

### Why is parameter isolation critical?
Imagine a URL: `http://target.com/api/users?id=1&role=admin&format=json`

If an automated scanner replaces *all* parameters with a payload like `'` simultaneously (e.g., `?id='&role='&format='`), the application is highly likely to crash before it even reaches the database query layer. The `format` handler might throw a `JSONDecodeError`, or the `role` validator might throw a `TypeMismatch`. These application-level errors mask the underlying database errors we are trying to detect.

### The Algorithm:
```python
# Simplified pseudo-code of Mutator.get_mutated_urls()
for index, (name, value) in enumerate(parameters):
    # 1. Copy the original state
    test_params = parameters.copy() 
    
    # 2. Mutate exactly ONE parameter by appending the payload
    test_params[index] = (name, value + payload)
    
    # 3. Rebuild the URL
    yield rebuild_url(test_params)
```

**Key Decision: Appending vs. Replacing**
Notice we do `value + payload` (e.g., `id=1'`) instead of `payload` (e.g., `id='`). 
- **Reasoning**: Many modern frameworks use Object-Relational Mappers (ORMs) or strict typing. If `id` expects an integer, sending `'` might trigger an application `ValueError` ("invalid literal for int()"). However, if the application loosely validates but concatenates the string later in a raw query (e.g., `SELECT * FROM users WHERE id = ` + user_input), sending `1'` might bypass initial length/type checks but break the SQL syntax, successfully triggering the database error.

## 2. The Analyzer: Signature-Based Detection

The `Analyzer` (`src/core/analyzer.py`) is the brain. It doesn't look for successful exploitation; it looks for unhandled exceptions that leak the backend database type.

### The Problem with Status Codes
We cannot rely on HTTP 500 status codes. 
1. **False Positives**: Any server misconfiguration or unhandled application logic flaw can return a 500.
2. **False Negatives**: Many web applications are configured to catch all exceptions globally and return a generic 200 OK with an error message rendered inside the HTML (e.g., "An error occurred").

### The Solution: Precompiled Regex Signatures
The tool relies on `signatures.json`.

```json
"MySQL": [
    "SQL syntax.*MySQL",
    "Warning.*mysql_.*"
]
```

**How it works:**
1. **Startup**: On initialization, `Analyzer._compile_patterns()` reads the JSON and converts string patterns into compiled regex objects using `re.compile(pattern, re.IGNORECASE)`. Compiling upfront is crucial for performance; compiling the regex *per request* would bottleneck the scanner.
2. **Execution**: During the scan, `Analyzer.analyze_response()` takes the raw HTTP response text (`response.text`).
3. **Detection Logic**: It iterates through the precompiled patterns. The `.*` in patterns like `SQL syntax.*MySQL` allows for variability in how the application formats the output between the key phrases.

### Limitations & Edge Cases

1. **Custom Error Handling**: If the target application has a global exception handler that catches `SQLException` and returns a generic "Database Error" string *without* leaking the specific DBMS signature, this tool will fail to detect it (False Negative).
2. **Blind SQLi**: If the application catches the error and silently drops it (returning the normal page, or a blank page), error-based detection is useless. Time-based or boolean-based inference is required, which is outside the scope of this tool.
3. **WAF Interference**: A Web Application Firewall (WAF) might detect the payload `'` and intercept the request, returning a 403 Forbidden. The tool will not see the database error. Advanced tools handle this by analyzing the HTTP response codes to detect WAF presence.

## 3. The Network Layer (`engine.py`)

The network engine uses `httpx`.
- `verify=False`: Standard in offensive tools because internal corporate networks or lab environments often use self-signed certificates. We want the tool to test the application, not fail on certificate validation.
- `follow_redirects=True`: Sometimes an error occurs on a page that redirects (e.g., after a POST request). Following redirects ensures we capture the final error state.
