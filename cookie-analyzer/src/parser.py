"""
Cookie Sentinel parser module.
Parses raw Set-Cookie headers and Netscape cookie files.
"""

import re
from typing import Dict, List, Any, Optional

class CookieParseError(Exception):
    """Raised when cookie parsing fails catastrophically."""
    pass

def parse_set_cookie_header(header_value: str) -> Dict[str, Any]:
    """
    Parses a single Set-Cookie header value into a structured dictionary.
    Ensures robust handling of malformed or non-standard headers.
    
    Example input:
        "session_id=xyz123; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Lax"
    """
    if not header_value:
        return {}

    # Split the header by semicolon
    parts = [part.strip() for part in header_value.split(";")]
    if not parts or not parts[0]:
        return {}

    # The first part is always the cookie name and value
    first_part = parts[0]
    if "=" not in first_part:
        # Malformed but browsers might still treat the whole thing as the name with empty value
        name = first_part
        value = ""
    else:
        name, value = first_part.split("=", 1)
        name = name.strip()
        value = value.strip()

    cookie_data: Dict[str, Any] = {
        "name": name,
        "value": value,
        "attributes": {
            "httponly": False,
            "secure": False,
            "samesite": None,
            "domain": None,
            "path": None,
            "expires": None,
            "max_age": None,
        },
        "raw_attributes": {},
        "raw_header": header_value
    }

    # Parse remaining attributes
    for part in parts[1:]:
        if not part:
            continue
        
        if "=" in part:
            attr_name, attr_val = part.split("=", 1)
            attr_name = attr_name.strip().lower()
            attr_val = attr_val.strip()
        else:
            attr_name = part.strip().lower()
            attr_val = True

        cookie_data["raw_attributes"][attr_name] = attr_val

        # Map to standard attributes
        if attr_name == "httponly":
            cookie_data["attributes"]["httponly"] = True
        elif attr_name == "secure":
            cookie_data["attributes"]["secure"] = True
        elif attr_name == "samesite":
            # Normalize casing
            if isinstance(attr_val, str):
                val_lower = attr_val.lower()
                if val_lower == "lax":
                    cookie_data["attributes"]["samesite"] = "Lax"
                elif val_lower == "strict":
                    cookie_data["attributes"]["samesite"] = "Strict"
                elif val_lower == "none":
                    cookie_data["attributes"]["samesite"] = "None"
                else:
                    cookie_data["attributes"]["samesite"] = attr_val  # Preserve invalid value for analyzer
            else:
                cookie_data["attributes"]["samesite"] = attr_val
        elif attr_name == "domain":
            cookie_data["attributes"]["domain"] = attr_val
        elif attr_name == "path":
            cookie_data["attributes"]["path"] = attr_val
        elif attr_name == "expires":
            cookie_data["attributes"]["expires"] = attr_val
        elif attr_name == "max-age":
            try:
                cookie_data["attributes"]["max_age"] = int(attr_val)
            except (ValueError, TypeError):
                cookie_data["attributes"]["max_age"] = attr_val  # Keep raw value for analyzer to detect misconfigurations

    return cookie_data

def parse_netscape_cookies(file_content: str) -> List[Dict[str, Any]]:
    """
    Parses cookies from a Netscape cookie file content (standard format used by curl/wget/browser extensions).
    Format columns:
    domain - boolean (include subdomains) - path - secure - expiration - name - value
    """
    cookies = []
    lines = file_content.splitlines()
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
            
        parts = line.split("\t")
        if len(parts) < 7:
            # Maybe space-separated?
            parts = line.split()
            if len(parts) < 7:
                continue
                
        try:
            domain = parts[0]
            # include_subdomains is parts[1] (TRUE/FALSE)
            path = parts[2]
            secure = parts[3].upper() == "TRUE"
            expires_raw = parts[4]
            name = parts[5]
            value = parts[6]
            
            # Convert expires Unix timestamp
            try:
                expires = int(expires_raw)
            except ValueError:
                expires = expires_raw
                
            cookie_data = {
                "name": name,
                "value": value,
                "attributes": {
                    "httponly": False, # Netscape format doesn't explicitly store HttpOnly in standard columns, 
                                      # though HTTPOnly cookies are often prefixed with #HttpOnly_ in the file
                    "secure": secure,
                    "samesite": None,
                    "domain": domain,
                    "path": path,
                    "expires": expires,
                    "max_age": None
                },
                "raw_attributes": {
                    "domain": domain,
                    "path": path,
                    "secure": secure,
                    "expires": expires
                },
                "raw_header": f"Netscape Cookie Line {line_num}"
            }
            
            # Support #HttpOnly_ prefix standard used by curl
            # If the line was originally commented with #HttpOnly_, the line processing might skip it.
            # Let's handle it by checking lines starting with #HttpOnly_ separately
            cookies.append(cookie_data)
        except Exception:
            # Skip malformed lines
            continue
            
    # Re-run for #HttpOnly_ lines since they are commented out in standard Netscape files
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if line.startswith("#HttpOnly_"):
            # strip the comment prefix
            actual_line = line[len("#HttpOnly_"):]
            parts = actual_line.split("\t")
            if len(parts) < 7:
                parts = actual_line.split()
                if len(parts) < 7:
                    continue
            try:
                domain = parts[0]
                path = parts[2]
                secure = parts[3].upper() == "TRUE"
                expires_raw = parts[4]
                name = parts[5]
                value = parts[6]
                
                cookie_data = {
                    "name": name,
                    "value": value,
                    "attributes": {
                        "httponly": True,
                        "secure": secure,
                        "samesite": None,
                        "domain": domain,
                        "path": path,
                        "expires": expires_raw,
                        "max_age": None
                    },
                    "raw_attributes": {
                        "domain": domain,
                        "path": path,
                        "secure": secure,
                        "expires": expires_raw,
                        "httponly": True
                    },
                    "raw_header": f"Netscape Cookie Line {line_num} (HttpOnly)"
                }
                cookies.append(cookie_data)
            except Exception:
                continue
                
    return cookies
