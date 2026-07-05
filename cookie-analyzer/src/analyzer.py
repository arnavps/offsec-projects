"""
Cookie Sentinel analyzer module.
Applies security auditing rules to parsed cookies and returns graded findings.
"""

import datetime
import email.utils
import re
from typing import Dict, List, Any, Optional

# Regex for common session identifiers
SESSION_COOKIE_REGEX = re.compile(
    r'(session|sid|token|jwt|auth|phpsessid|jsessionid|aspsessionid|cfduid|connect\.sid|remember_me|login)',
    re.IGNORECASE
)

class Finding:
    """Represents a single cookie security vulnerability or misconfiguration."""
    def __init__(
        self,
        cookie_name: str,
        rule_id: str,
        severity: str,
        description: str,
        remediation: str,
        details: Optional[str] = None
    ):
        self.cookie_name = cookie_name
        self.rule_id = rule_id
        self.severity = severity  # Critical, High, Medium, Low, Info
        self.description = description
        self.remediation = remediation
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cookie_name": self.cookie_name,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "details": self.details
        }

def analyze_cookie(cookie: Dict[str, Any], request_url: Optional[str] = None) -> List[Finding]:
    """
    Applies security rules to a single parsed cookie dictionary.
    Optionally utilizes the requested URL to evaluate scope and TLS status.
    """
    findings: List[Finding] = []
    
    name = cookie.get("name", "")
    attrs = cookie.get("attributes", {})
    
    is_session = bool(SESSION_COOKIE_REGEX.search(name))
    is_https = False
    if request_url:
        is_https = request_url.lower().startswith("https://")

    # 1. HttpOnly Flag Check
    if not attrs.get("httponly"):
        if is_session:
            findings.append(Finding(
                cookie_name=name,
                rule_id="MISSING_HTTPONLY",
                severity="High",
                description="Cookie appears to be a session identifier but lacks the 'HttpOnly' flag.",
                remediation="Configure the 'Set-Cookie' header to include the 'HttpOnly' attribute. This prevents client-side scripts (e.g. XSS) from reading the session cookie."
            ))
        else:
            findings.append(Finding(
                cookie_name=name,
                rule_id="MISSING_HTTPONLY",
                severity="Low",
                description="Cookie lacks the 'HttpOnly' flag, making it accessible to client-side scripts.",
                remediation="If this cookie does not need to be read by client-side JavaScript, add the 'HttpOnly' flag."
            ))

    # 2. Secure Flag Check
    if not attrs.get("secure"):
        if is_session or is_https:
            findings.append(Finding(
                cookie_name=name,
                rule_id="MISSING_SECURE",
                severity="High",
                description="Cookie lacks the 'Secure' flag but is either a session cookie or was served over HTTPS.",
                remediation="Add the 'Secure' attribute to the 'Set-Cookie' header. This ensures the cookie is only transmitted over encrypted connections (SSL/TLS) and prevents interception over unencrypted HTTP."
            ))
        else:
            findings.append(Finding(
                cookie_name=name,
                rule_id="MISSING_SECURE",
                severity="Medium",
                description="Cookie lacks the 'Secure' flag and could be sent over cleartext connections.",
                remediation="Ensure the 'Secure' attribute is added so the cookie is restricted to SSL/TLS channels."
            ))

    # 3. SameSite Flag Check
    samesite = attrs.get("samesite")
    if samesite is None:
        findings.append(Finding(
            cookie_name=name,
            rule_id="MISSING_SAMESITE",
            severity="Medium",
            description="Cookie does not declare a 'SameSite' attribute.",
            remediation="Explicitly set 'SameSite=Lax' (recommended default) or 'SameSite=Strict' to protect the application against Cross-Site Request Forgery (CSRF) attacks."
        ))
    elif isinstance(samesite, str):
        if samesite.lower() == "none" and not attrs.get("secure"):
            findings.append(Finding(
                cookie_name=name,
                rule_id="SAMESITE_NONE_WITHOUT_SECURE",
                severity="High",
                description="Cookie is set with 'SameSite=None' but lacks the 'Secure' flag. Modern browsers will reject this cookie.",
                remediation="Set 'Secure' to True when using 'SameSite=None'. Browsers will only allow third-party cookie transmission over TLS."
            ))
        elif samesite.lower() not in ["lax", "strict", "none"]:
            findings.append(Finding(
                cookie_name=name,
                rule_id="INVALID_SAMESITE_VALUE",
                severity="Low",
                description=f"Cookie specifies an invalid SameSite value: '{samesite}'.",
                remediation="Change the SameSite value to one of: 'Lax', 'Strict', or 'None'."
            ))

    # 4. Domain Scope Check (Overly Broad Domain)
    domain = attrs.get("domain")
    if domain:
        # Check if domain scopes too broadly, e.g. starting with . (makes it wildcard-like for subdomains)
        # or matches a parent domain of the request_url
        if domain.startswith("."):
            findings.append(Finding(
                cookie_name=name,
                rule_id="OVERLY_BROAD_DOMAIN_DOT",
                severity="Medium",
                description=f"Cookie domain '{domain}' starts with a leading dot, making it accessible to all subdomains.",
                remediation="Omit the 'Domain' attribute completely to lock the cookie to the host that set it, or specify the exact hostname without a leading dot."
            ))
        elif request_url:
            # Parse request hostname
            from urllib.parse import urlparse
            req_host = urlparse(request_url).hostname
            if req_host:
                # If cookie domain is a suffix of req_host and not equal to req_host
                # e.g., domain=example.com, req_host=app.sub.example.com
                normalized_domain = domain.lower().lstrip('.')
                normalized_host = req_host.lower()
                if normalized_host.endswith(normalized_domain) and normalized_host != normalized_domain:
                    findings.append(Finding(
                        cookie_name=name,
                        rule_id="OVERLY_BROAD_DOMAIN_PARENT",
                        severity="Medium",
                        description=f"Cookie domain '{domain}' scopes to a parent domain, exposing it to subdomains of '{normalized_host}'.",
                        remediation="Lock the cookie to the specific hostname by omitting the 'Domain' attribute or setting it to the exact host."
                    ))

    # 5. Cookie Prefix Checks (__Secure- and __Host-)
    if name.startswith("__Secure-"):
        if not attrs.get("secure"):
            findings.append(Finding(
                cookie_name=name,
                rule_id="PREFIX_MISSING_SECURE",
                severity="High",
                description="Cookie name begins with '__Secure-' prefix but lacks the 'Secure' attribute. Browsers will reject this cookie.",
                remediation="Ensure the 'Secure' attribute is set when using the '__Secure-' prefix."
            ))
            
    if name.startswith("__Host-"):
        # __Host- requires: Secure, Path=/, and NO Domain attribute
        prefix_issues = []
        if not attrs.get("secure"):
            prefix_issues.append("lacks the 'Secure' attribute")
        if attrs.get("domain"):
            prefix_issues.append(f"specifies a 'Domain' attribute ('{attrs.get('domain')}')")
        if attrs.get("path") != "/":
            prefix_issues.append(f"specifies Path='{attrs.get('path')}' instead of '/'")
            
        if prefix_issues:
            details = "Cookie name begins with '__Host-' prefix but: " + ", ".join(prefix_issues)
            findings.append(Finding(
                cookie_name=name,
                rule_id="PREFIX_MISSING_HOST",
                severity="High",
                description=details + ". Browsers will reject this cookie.",
                remediation="Configure the cookie to have 'Secure', 'Path=/', and omit the 'Domain' attribute."
            ))

    # 6. Overly Long Lifetime
    max_age = attrs.get("max_age")
    expires = attrs.get("expires")
    
    one_year_seconds = 31536000
    
    if max_age is not None:
        try:
            val = int(max_age)
            if val > one_year_seconds:
                findings.append(Finding(
                    cookie_name=name,
                    rule_id="OVERLY_LONG_MAX_AGE",
                    severity="Low",
                    description=f"Cookie has a Max-Age lifetime of {val} seconds (> 1 year).",
                    remediation="Set a shorter Max-Age limit. For session cookies or sensitive data, lifetimes should not exceed days or weeks."
                ))
        except ValueError:
            pass

    if expires:
        # Attempt to parse RFC 1123 date
        try:
            exp_dt = email.utils.parsedate_to_datetime(expires)
            now = datetime.datetime.now(datetime.timezone.utc)
            # Compare datetime diff
            if exp_dt > now:
                diff = exp_dt - now
                if diff.days > 365:
                    findings.append(Finding(
                        cookie_name=name,
                        rule_id="OVERLY_LONG_EXPIRES",
                        severity="Low",
                        description=f"Cookie expiration date '{expires}' is set more than 1 year in the future ({diff.days} days).",
                        remediation="Set a shorter expiration date. Avoid long-lived authentication sessions."
                    ))
        except Exception:
            # If parsing fails, it might be an invalid date format or session-only string (e.g. numeric timestamp)
            pass

    return findings

def analyze_cookies(cookies: List[Dict[str, Any]]) -> Dict[str, List[Finding]]:
    """
    Analyzes a list of cookies and groups findings by cookie name.
    """
    all_findings: Dict[str, List[Finding]] = {}
    for cookie in cookies:
        cookie_name = cookie.get("name", "unnamed")
        url = cookie.get("url")  # might be None for Netscape/raw imports
        findings = analyze_cookie(cookie, request_url=url)
        if findings:
            if cookie_name not in all_findings:
                all_findings[cookie_name] = []
            all_findings[cookie_name].extend(findings)
    return all_findings
