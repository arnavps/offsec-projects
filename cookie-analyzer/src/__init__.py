"""
Cookie Sentinel package initialization.
"""

from .parser import parse_set_cookie_header, parse_netscape_cookies
from .analyzer import analyze_cookie, analyze_cookies, Finding
from .fetcher import fetch_cookies_from_url
from .core import (
    run_url_analysis,
    run_raw_header_analysis,
    run_netscape_file_analysis,
    run_headers_file_analysis
)

__version__ = "1.0.0"
