"""
Cookie Sentinel fetcher module.
Performs active scans on web targets to collect Set-Cookie headers.
"""

import logging
from typing import List, Dict, Any, Tuple, Optional
import requests
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL verification warnings if verify=False is used
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logger = logging.getLogger("CookieSentinel.Fetcher")

class FetchError(Exception):
    """Raised when an active HTTP fetch fails."""
    pass

def fetch_cookies_from_url(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, Any]] = None,
    verify: bool = True,
    timeout: float = 10.0,
    allow_redirects: bool = True,
    user_agent: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Sends an HTTP request to the target URL and extracts Set-Cookie headers.
    If redirects occur, captures Set-Cookie headers from all intermediate hops.
    
    Returns a list of dicts:
    [
        {
            "url": str,         # URL that set this cookie
            "status_code": int, # HTTP status code
            "raw_header": str   # Raw Set-Cookie header content
        },
        ...
    ]
    """
    req_headers = {
        "User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 SecurityScanner/1.0"
    }
    if headers:
        req_headers.update(headers)

    captured_cookies: List[Dict[str, Any]] = []

    def extract_set_cookies(resp: requests.Response, resp_url: str):
        """Helper to extract multiple Set-Cookie headers from a response."""
        # urllib3's HTTPHeaderDict supports getlist to avoid comma-merging issues.
        # Fall back to checking case variations.
        raw_headers = getattr(resp.raw, "headers", None)
        set_cookie_headers = []
        
        if raw_headers and hasattr(raw_headers, "getlist"):
            # getlist is case-insensitive in newer urllib3 versions
            set_cookie_headers = raw_headers.getlist("Set-Cookie") or raw_headers.getlist("set-cookie")
        
        # Fallback if getlist failed or wasn't available
        if not set_cookie_headers:
            # Check response.headers, which joins duplicates with commas
            header_str = resp.headers.get("Set-Cookie")
            if header_str:
                # Basic comma split that avoids splitting HTTP dates
                # e.g., "Expires=Mon, 22-Jun-2026 12:00:00 GMT"
                # A heuristic regex split: split by comma only if followed by non-date patterns
                # but since urllib3 headers should have it, this fallback is a backup.
                set_cookie_headers = split_joined_cookies(header_str)

        for header_val in set_cookie_headers:
            captured_cookies.append({
                "url": resp_url,
                "status_code": resp.status_code,
                "raw_header": header_val
            })

    try:
        if method.upper() == "POST":
            response = requests.post(
                url,
                headers=req_headers,
                data=data,
                verify=verify,
                timeout=timeout,
                allow_redirects=allow_redirects
            )
        else:
            response = requests.get(
                url,
                headers=req_headers,
                verify=verify,
                timeout=timeout,
                allow_redirects=allow_redirects
            )
            
        # Process redirection hops first
        if response.history:
            for hop in response.history:
                extract_set_cookies(hop, hop.url)
                
        # Process final response
        extract_set_cookies(response, response.url)
        
    except requests.exceptions.SSLError as e:
        raise FetchError(f"SSL/TLS verification failed: {e}. Try running with --no-verify if authorized.")
    except requests.exceptions.ConnectionError as e:
        raise FetchError(f"Failed to connect to target URL: {e}")
    except requests.exceptions.Timeout as e:
        raise FetchError(f"Request timed out after {timeout} seconds: {e}")
    except Exception as e:
        raise FetchError(f"HTTP request failed: {e}")

    return captured_cookies

def split_joined_cookies(cookie_header_str: str) -> List[str]:
    """
    Splits a comma-joined Set-Cookie header string into individual cookie headers,
    preserving comma characters inside 'Expires' dates.
    
    Example input:
        "session=abc; Expires=Mon, 22-Jun-2026 12:00:00 GMT, tracking=xyz; Path=/"
    Output:
        ["session=abc; Expires=Mon, 22-Jun-2026 12:00:00 GMT", "tracking=xyz; Path=/"]
    """
    # Lookahead: split on comma only if it is NOT followed by a weekday like 'Mon', 'Tue', etc.
    # or look for a comma followed by a token containing '=' that is NOT a date.
    # A standard way: split on commas that are followed by something like ' name=' where name is key.
    # Let's use a regex that matches commas followed by name= but ignores dates.
    # A valid cookie attribute/key name doesn't contain spaces and is followed by '=' or is a standalone flag.
    # We split on commas that are followed by: \s* [a-zA-Z0-9_\-]+ (?:=|\s|;|$)
    # but we must exclude date weekdays (Mon, Tue, Wed, Thu, Fri, Sat, Sun).
    tokens = re.split(r',(?=\s*[a-zA-Z0-9_\-]+(?:=|\s|;|$))', cookie_header_str)
    
    # Reassemble tokens if they were incorrectly split (e.g. Expires=Mon)
    cleaned = []
    temp = ""
    
    weekdays = {"mon", "tue", "wed", "thu", "fri", "sat", "sun", 
                "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
                
    for token in tokens:
        stripped = token.strip()
        # If the last word of temp is a weekday, then this token was a part of the date.
        # e.g. temp ends with "Expires=Mon" and token is " 22-Jun-26..."
        if temp:
            last_word = temp.strip().split()[-1].lower().rstrip(',')
            if last_word in weekdays or any(temp.lower().endswith(f"expires={w}") for w in weekdays):
                temp += "," + token
                continue
        
        if temp:
            cleaned.append(temp.strip())
        temp = token
        
    if temp:
        cleaned.append(temp.strip())
        
    return cleaned
