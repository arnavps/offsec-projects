"""
Unit tests for Cookie Sentinel parser module.
"""

import pytest
import sys
import os

# Adjust path to find the src package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from parser import parse_set_cookie_header, parse_netscape_cookies

def test_parse_simple_cookie():
    header = "session=xyz123"
    result = parse_set_cookie_header(header)
    assert result["name"] == "session"
    assert result["value"] == "xyz123"
    assert result["attributes"]["httponly"] is False
    assert result["attributes"]["secure"] is False
    assert result["attributes"]["samesite"] is None

def test_parse_complete_cookie():
    header = "auth_token=jwt_val; Domain=.example.com; Path=/api; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
    result = parse_set_cookie_header(header)
    assert result["name"] == "auth_token"
    assert result["value"] == "jwt_val"
    assert result["attributes"]["domain"] == ".example.com"
    assert result["attributes"]["path"] == "/api"
    assert result["attributes"]["secure"] is True
    assert result["attributes"]["httponly"] is True
    assert result["attributes"]["samesite"] == "Strict"
    assert result["attributes"]["max_age"] == 3600

def test_case_insensitivity_and_spacing():
    header = "session_id = val ; domain = App.Example.Com ; samesite = lax ; httponly ; secure"
    result = parse_set_cookie_header(header)
    assert result["name"] == "session_id"
    assert result["value"] == "val"
    assert result["attributes"]["domain"] == "App.Example.Com"
    assert result["attributes"]["httponly"] is True
    assert result["attributes"]["secure"] is True
    assert result["attributes"]["samesite"] == "Lax"

def test_invalid_max_age():
    header = "temp=1; Max-Age=invalid_number"
    result = parse_set_cookie_header(header)
    assert result["attributes"]["max_age"] == "invalid_number" # Raw string passed for analyzer checks

def test_parse_netscape_format():
    netscape_content = (
        "# Netscape HTTP Cookie File\n"
        "# http://curl.haxx.se/rfc/cookie_spec.html\n"
        "# This is a generated file!  Do not edit.\n\n"
        "example.com\tFALSE\t/\tTRUE\t1893456000\tsecret_cookie\tsecret_value\n"
        "#HttpOnly_example.com\tFALSE\t/admin\tFALSE\t1893456000\tadmin_session\tadmin_value\n"
    )
    
    cookies = parse_netscape_cookies(netscape_content)
    assert len(cookies) == 2
    
    # Check standard secure cookie
    assert cookies[0]["name"] == "secret_cookie"
    assert cookies[0]["value"] == "secret_value"
    assert cookies[0]["attributes"]["secure"] is True
    assert cookies[0]["attributes"]["httponly"] is False
    assert cookies[0]["attributes"]["domain"] == "example.com"
    assert cookies[0]["attributes"]["path"] == "/"
    
    # Check commented HttpOnly cookie
    assert cookies[1]["name"] == "admin_session"
    assert cookies[1]["value"] == "admin_value"
    assert cookies[1]["attributes"]["secure"] is False
    assert cookies[1]["attributes"]["httponly"] is True
    assert cookies[1]["attributes"]["domain"] == "example.com"
    assert cookies[1]["attributes"]["path"] == "/admin"
