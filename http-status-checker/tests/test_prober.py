import unittest
from unittest.mock import MagicMock
import asyncio
import aiohttp
import ssl

from src.core.prober import Prober
from src.modules.fingerprint import Fingerprinter
from src.main import expand_targets

class TestProberUtils(unittest.TestCase):
    """Tests utility functions and synchronous logic inside the core engine and modules."""

    def test_target_expansion(self):
        """Verifies bare domains are correctly expanded into HTTP/S endpoints."""
        raw_targets = ["example.com", "http://already-url.com/path", "sub.domain.org"]
        
        # Test default: expand both protocols
        expanded = expand_targets(raw_targets, only_ssl=False, only_http=False)
        self.assertEqual(len(expanded), 5)
        self.assertIn("https://example.com", expanded)
        self.assertIn("http://example.com", expanded)
        self.assertIn("http://already-url.com/path", expanded)
        self.assertNotIn("https://already-url.com/path", expanded) # Should not double-expand
        
        # Test SSL only
        expanded_ssl = expand_targets(raw_targets, only_ssl=True, only_http=False)
        self.assertEqual(len(expanded_ssl), 3)
        self.assertIn("https://example.com", expanded_ssl)
        self.assertNotIn("http://example.com", expanded_ssl)
        
        # Test HTTP only
        expanded_http = expand_targets(raw_targets, only_ssl=False, only_http=True)
        self.assertEqual(len(expanded_http), 3)
        self.assertIn("http://example.com", expanded_http)
        self.assertNotIn("https://example.com", expanded_http)

    def test_error_classification(self):
        """Checks if network and client exceptions are accurately classified."""
        prober = Prober()
        
        # 1. Timeout
        timeout_err = asyncio.TimeoutError()
        self.assertEqual(prober._classify_error(timeout_err), "Connection Timeout")
        
        # 2. DNS failure
        mock_conn_key = MagicMock()
        mock_conn_key.ssl = False
        dns_err = aiohttp.ClientConnectorError(
            connection_key=mock_conn_key,
            os_error=OSError(8, "gaierror: Name or service not known")
        )
        self.assertEqual(prober._classify_error(dns_err), "DNS Resolution Failure")
        
        # 3. Connection Refused
        refused_err = aiohttp.ClientConnectorError(
            connection_key=mock_conn_key,
            os_error=ConnectionRefusedError(111, "Connection refused")
        )
        self.assertEqual(prober._classify_error(refused_err), "Connection Refused")
        
        # 4. SSL failure
        ssl_err = ssl.SSLError("certificate verify failed")
        self.assertEqual(prober._classify_error(ssl_err), "SSL Handshake Failure")

    def test_technology_fingerprinting(self):
        """Validates banner, powered-by, cookie, and security header audit outputs."""
        headers = {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4.3",
            "Set-Cookie": "PHPSESSID=xyz123; path=/;",
            "Content-Security-Policy": "default-src 'self'"
        }
        
        analysis = Fingerprinter.analyze(headers)
        
        # Verify tech detection
        techs = analysis["technologies"]
        self.assertIn("nginx/1.18.0", techs)
        self.assertIn("PHP/7.4.3", techs)
        self.assertIn("PHP", techs) # Inferred from cookie
        
        # Verify security header auditing
        missing = analysis["missing_security_headers"]
        self.assertIn("X-FRAME-OPTIONS", missing)
        self.assertNotIn("CONTENT-SECURITY-POLICY", missing)
        
        # Verify warnings (version disclosure and cookie flags)
        warnings = analysis["security_warnings"]
        self.assertTrue(any("version banner disclosed" in w for w in warnings))
        self.assertTrue(any("missing security flag(s)" in w for w in warnings))

if __name__ == "__main__":
    unittest.main()
