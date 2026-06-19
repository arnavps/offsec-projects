# Testing & Validation Strategy

To validate the `sqli-detector` without attacking a real production system, we must simulate a vulnerable environment. This document outlines how to test the tool, the expected outputs, and how to conduct a security analysis of the tool itself.

## 1. Local Vulnerable Target Simulation

The safest way to test is to write a tiny, deliberately vulnerable Python script using Flask and SQLite.

### Setup (Target Simulation)
Create a file `target_app.py` (Do not include this in the final release, it's strictly for testing):

```python
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user():
    user_id = request.args.get('id', '')
    # VULNERABILITY: Raw string concatenation
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    
    try:
        conn = sqlite3.connect(':memory:') # In-memory DB for safety
        cursor = conn.cursor()
        # Creating dummy table
        cursor.execute("CREATE TABLE users (id TEXT, name TEXT)")
        cursor.execute("INSERT INTO users VALUES ('1', 'admin')")
        
        cursor.execute(query) # Execution of vulnerable query
        result = cursor.fetchall()
        return str(result)
    except Exception as e:
        # VULNERABILITY: Leaking raw DB exception to the response
        return str(e), 500

if __name__ == '__main__':
    app.run(port=5000)
```

### Execution
1. Run the target: `python target_app.py`
2. Run the detector: `python src/main.py -u "http://127.0.0.1:5000/user?id=1&role=user"`

### Expected Output
The tool should successfully inject into both `id` and `role`. It should identify `id` as vulnerable because modifying `id` triggers the SQLite exception in the vulnerable query.

```text
[*] Initializing scan for: http://127.0.0.1:5000/user?id=1&role=user
[*] Loaded 11 payloads.
[*] Found 2 parameters to test.
[*] Starting injection process...

[!] VULNERABILITY FOUND
 > Parameter: id
 > Payload: '
 > DB Type: SQLite

[!] VULNERABILITY FOUND
 > Parameter: id
 > Payload: "
 > DB Type: SQLite

Scan Complete: Vulnerabilities Detected!
┏━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Parameter ┃ DBMS    ┃ Payload ┃
┡━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ id        │ SQLite  │ '       │
│ id        │ SQLite  │ "       │
└───────────┴─────────┴─────────┘
```

## 2. Security Analysis of the Tool

As offensive security engineers, we must audit our own tools.

### Flaws & Limitations
1. **No Output Encoding Awareness**: The analyzer assumes the error message is reflected in plain text or standard HTML. If the application reflects the error inside a JSON blob and escapes quotes (e.g., `"error": "SQLite error near \\\"" `), the regex might fail if it relies on exact spacing.
2. **Synchronous Execution Bottleneck**: The tool uses synchronous HTTP requests (`httpx.Client` instead of `httpx.AsyncClient`). If testing a URL with 5 parameters against 20 payloads, it makes 100 sequential requests. Against a slow server, this takes considerable time.
3. **State Mutation Risk**: If the target URL points to a state-changing operation (e.g., `http://target.com/delete_user?id=1`), the tool will execute that operation repeatedly with different payloads. It does not distinguish between idempotent (GET) and non-idempotent operations.

### Weak Assumptions
1. **Assumption:** All query parameters are strings. 
   **Reality:** Some frameworks parse array parameters like `?id[]=1&id[]=2`. The `mutator.py` uses standard URL parsing, which might flatten or mishandle complex nested parameters.

### Operational Risks
1. **Accidental DoS**: Without strict rate limiting (the user *must* supply `--delay`), running this against a fragile legacy system could crash the database connection pool due to an influx of unhandled exceptions.

## 3. Future Improvements (Roadmap)

To elevate this from an intermediate tool to an advanced, production-ready offensive security asset:

1. **Concurrency (AsyncIO)**: Refactor `engine.py` to use `asyncio` and `httpx.AsyncClient`. Introduce a semaphore to limit concurrent connections (e.g., max 10 concurrent requests) to balance speed and stealth.
2. **Header & Body Injection**: Extend `mutator.py` to handle POST requests. Parse `application/x-www-form-urlencoded` and `application/json` bodies to test REST API endpoints.
3. **Heuristic Detection (Blind SQLi)**: Add a timing module. Send a baseline request to measure response time, then send a payload like `' OR SLEEP(5)--` and measure the delay. This detects injection even when errors are suppressed.
4. **WAF Detection**: Implement logic to detect common WAF response signatures (e.g., Cloudflare 1020 pages) and alert the user that testing is being blocked.
