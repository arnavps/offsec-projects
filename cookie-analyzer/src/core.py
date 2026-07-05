"""
Cookie Sentinel core engine.
Orchestrates inputs, parsing, analysis, and execution flows.
"""

import os
from typing import Dict, List, Any, Tuple, Optional

from .fetcher import fetch_cookies_from_url
from .parser import parse_set_cookie_header, parse_netscape_cookies
from .analyzer import analyze_cookies, Finding

def run_url_analysis(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, Any]] = None,
    verify: bool = True,
    timeout: float = 10.0,
    allow_redirects: bool = True,
    user_agent: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Dict[str, List[Finding]]]:
    """Runs active cookie scanning against a target URL."""
    captured = fetch_cookies_from_url(
        url=url,
        method=method,
        headers=headers,
        data=data,
        verify=verify,
        timeout=timeout,
        allow_redirects=allow_redirects,
        user_agent=user_agent
    )
    
    parsed_cookies = []
    for raw_cookie in captured:
        cookie_data = parse_set_cookie_header(raw_cookie["raw_header"])
        if cookie_data:
            # Propagate the request metadata
            cookie_data["url"] = raw_cookie["url"]
            cookie_data["status_code"] = raw_cookie["status_code"]
            parsed_cookies.append(cookie_data)
            
    findings = analyze_cookies(parsed_cookies)
    return parsed_cookies, findings

def run_raw_header_analysis(header_val: str) -> Tuple[List[Dict[str, Any]], Dict[str, List[Finding]]]:
    """Runs analysis on a single raw Set-Cookie header string."""
    cookie_data = parse_set_cookie_header(header_val)
    parsed_cookies = [cookie_data] if cookie_data else []
    findings = analyze_cookies(parsed_cookies)
    return parsed_cookies, findings

def run_netscape_file_analysis(filepath: str) -> Tuple[List[Dict[str, Any]], Dict[str, List[Finding]]]:
    """Runs analysis on cookies loaded from a Netscape format cookie file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
        
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
        
    parsed_cookies = parse_netscape_cookies(content)
    findings = analyze_cookies(parsed_cookies)
    return parsed_cookies, findings

def run_headers_file_analysis(filepath: str) -> Tuple[List[Dict[str, Any]], Dict[str, List[Finding]]]:
    """
    Parses a file containing raw HTTP headers.
    Splits the content into separate lines and looks for Set-Cookie header lines,
    or processes the file as a list of raw Set-Cookie values (one per line).
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
        
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()
        
    parsed_cookies = []
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
            
        # Check if the line is prefixed with "Set-Cookie:" (standard HTTP response header format)
        header_val = line
        if line.lower().startswith("set-cookie:"):
            header_val = line[len("set-cookie:"):].strip()
            
        cookie_data = parse_set_cookie_header(header_val)
        if cookie_data:
            # Annotate raw header location for references
            cookie_data["raw_header"] = f"{os.path.basename(filepath)}:L{line_num}"
            parsed_cookies.append(cookie_data)
            
    findings = analyze_cookies(parsed_cookies)
    return parsed_cookies, findings
