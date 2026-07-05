from typing import Dict, Any, List, Set

class Fingerprinter:
    """Analyzes HTTP headers to detect technologies and evaluate security postures."""

    SECURITY_HEADERS = {
        "strict-transport-security": "HSTS is not configured, leaving connections vulnerable to SSL stripping",
        "content-security-policy": "CSP is missing, heightening the risk of Cross-Site Scripting (XSS)",
        "x-frame-options": "X-Frame-Options is missing, making the application vulnerable to clickjacking",
        "x-content-type-options": "X-Content-Type-Options is missing, allowing MIME sniffing attacks",
        "referrer-policy": "Referrer-Policy is missing, potentially leaking sensitive data in referral URLs"
    }

    @staticmethod
    def analyze(headers: Dict[str, str]) -> Dict[str, Any]:
        """Runs security and technology fingerprinting on lower-cased response headers."""
        # Convert all header keys to lowercase for uniform lookup
        lowercased_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        
        technologies = Fingerprinter._detect_technologies(lowercased_headers)
        missing_headers, warnings = Fingerprinter._audit_security(lowercased_headers)
        
        return {
            "technologies": list(technologies),
            "missing_security_headers": missing_headers,
            "security_warnings": warnings
        }

    @staticmethod
    def _detect_technologies(headers: Dict[str, str]) -> Set[str]:
        """Infers backend stack based on common server, runtime, and cookie headers."""
        technologies = set()
        
        # 1. Inspect Server Header
        server = headers.get("server", "")
        if server and server.strip() != "Unknown":
            technologies.add(server)
            
        # 2. Inspect X-Powered-By Header
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            technologies.add(powered_by)
            
        # 3. Check for tech-specific headers
        if "x-aspnet-version" in headers or "x-aspnetmvc-version" in headers:
            technologies.add("ASP.NET")
        if "x-generator" in headers:
            technologies.add(f"Generator: {headers['x-generator']}")
        if "x-drupal-cache" in headers:
            technologies.add("Drupal")
            
        # 4. Check for framework cookie signatures
        cookies = headers.get("set-cookie", "").lower()
        if "phpsessid" in cookies:
            technologies.add("PHP")
        if "jsessionid" in cookies:
            technologies.add("Java/Java EE")
        if "aspsessionid" in cookies or "asp.net_sessionid" in cookies:
            technologies.add("ASP.NET")
        if "laravel_session" in cookies:
            technologies.add("Laravel")
        if "wp-settings" in cookies:
            technologies.add("WordPress")
            
        return technologies

    @staticmethod
    def _audit_security(headers: Dict[str, str]) -> tuple[List[str], List[str]]:
        """Identifies missing security controls and flags exposure of detailed version banners."""
        missing = []
        warnings = []
        
        # 1. Audit Missing security headers
        for header_name, description in Fingerprinter.SECURITY_HEADERS.items():
            if header_name not in headers:
                missing.append(header_name.upper())
                
        # 2. Audit Server Banner Version disclosures (helps in vuln matching)
        server = headers.get("server", "")
        if server:
            # Check if server string contains a number (indicates software version exposure)
            if any(char.isdigit() for char in server):
                warnings.append(f"Detailed version banner disclosed: {server}")
                
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            if any(char.isdigit() for char in powered_by):
                warnings.append(f"Detailed technology runtime disclosure: {powered_by}")
                
        # 3. Audit HTTP cookies without safety attributes (Secure, HttpOnly)
        cookies = headers.get("set-cookie", "")
        if cookies:
            cookie_lines = cookies.split("\n")
            for line in cookie_lines:
                if line.strip():
                    parts = [p.strip().lower() for p in line.split(";")]
                    # Flag cookie if missing crucial security attributes
                    missing_attrs = []
                    if "httponly" not in parts:
                        missing_attrs.append("HttpOnly")
                    if "secure" not in parts:
                        missing_attrs.append("Secure")
                        
                    if missing_attrs:
                        # Find cookie name
                        cookie_name = line.split("=")[0].strip()
                        warnings.append(
                            f"Cookie '{cookie_name}' is missing security flag(s): {', '.join(missing_attrs)}"
                        )

        return missing, warnings
