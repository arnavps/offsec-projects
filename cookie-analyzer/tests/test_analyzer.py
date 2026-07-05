"""
Unit tests for Cookie Sentinel analyzer module.
"""

import pytest
import sys
import os

# Adjust path to find the src package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from parser import parse_set_cookie_header
from analyzer import analyze_cookie

def test_missing_httponly_severity():
    # Session cookie missing HttpOnly should be High severity
    cookie = parse_set_cookie_header("session_id=123; Secure")
    findings = analyze_cookie(cookie)
    missing_httponly = [f for f in findings if f.rule_id == "MISSING_HTTPONLY"]
    assert len(missing_httponly) == 1
    assert missing_httponly[0].severity == "High"

    # Non-session cookie missing HttpOnly should be Low severity
    cookie = parse_set_cookie_header("theme=dark; Secure")
    findings = analyze_cookie(cookie)
    missing_httponly = [f for f in findings if f.rule_id == "MISSING_HTTPONLY"]
    assert len(missing_httponly) == 1
    assert missing_httponly[0].severity == "Low"

def test_missing_secure_severity():
    # Session cookie missing Secure should be High severity
    cookie = parse_set_cookie_header("session_id=123; HttpOnly")
    findings = analyze_cookie(cookie)
    missing_secure = [f for f in findings if f.rule_id == "MISSING_SECURE"]
    assert len(missing_secure) == 1
    assert missing_secure[0].severity == "High"

    # Non-session cookie missing Secure on HTTP should be Medium severity
    cookie = parse_set_cookie_header("theme=dark; HttpOnly")
    findings = analyze_cookie(cookie, request_url="http://example.com")
    missing_secure = [f for f in findings if f.rule_id == "MISSING_SECURE"]
    assert len(missing_secure) == 1
    assert missing_secure[0].severity == "Medium"

    # Non-session cookie missing Secure on HTTPS should be High severity
    cookie = parse_set_cookie_header("theme=dark; HttpOnly")
    findings = analyze_cookie(cookie, request_url="https://example.com")
    missing_secure = [f for f in findings if f.rule_id == "MISSING_SECURE"]
    assert len(missing_secure) == 1
    assert missing_secure[0].severity == "High"

def test_samesite_none_without_secure():
    cookie = parse_set_cookie_header("tracker=abc; SameSite=None")
    findings = analyze_cookie(cookie)
    same_site_err = [f for f in findings if f.rule_id == "SAMESITE_NONE_WITHOUT_SECURE"]
    assert len(same_site_err) == 1
    assert same_site_err[0].severity == "High"

def test_overly_broad_domain():
    cookie = parse_set_cookie_header("auth=xyz; Domain=.example.com")
    findings = analyze_cookie(cookie)
    broad_domain = [f for f in findings if f.rule_id == "OVERLY_BROAD_DOMAIN_DOT"]
    assert len(broad_domain) == 1
    assert broad_domain[0].severity == "Medium"

    cookie = parse_set_cookie_header("auth=xyz; Domain=example.com")
    # request is to subdomain
    findings = analyze_cookie(cookie, request_url="https://app.sub.example.com")
    broad_domain = [f for f in findings if f.rule_id == "OVERLY_BROAD_DOMAIN_PARENT"]
    assert len(broad_domain) == 1
    assert broad_domain[0].severity == "Medium"

def test_cookie_prefixes():
    # __Secure- prefix missing Secure
    cookie = parse_set_cookie_header("__Secure-session=abc")
    findings = analyze_cookie(cookie)
    prefix_err = [f for f in findings if f.rule_id == "PREFIX_MISSING_SECURE"]
    assert len(prefix_err) == 1
    assert prefix_err[0].severity == "High"

    # __Host- prefix missing attributes
    cookie = parse_set_cookie_header("__Host-session=abc; Domain=example.com; Path=/api")
    findings = analyze_cookie(cookie)
    prefix_err = [f for f in findings if f.rule_id == "PREFIX_MISSING_HOST"]
    assert len(prefix_err) == 1
    assert prefix_err[0].severity == "High"
    assert "Secure" in prefix_err[0].description
    assert "Domain" in prefix_err[0].description
    assert "Path" in prefix_err[0].description

def test_cookie_lifetime():
    # Overly long Max-Age (e.g. 2 years)
    cookie = parse_set_cookie_header("auth=xyz; Max-Age=63072000")
    findings = analyze_cookie(cookie)
    lifetime_err = [f for f in findings if f.rule_id == "OVERLY_LONG_MAX_AGE"]
    assert len(lifetime_err) == 1
    assert lifetime_err[0].severity == "Low"
