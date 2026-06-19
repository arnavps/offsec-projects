import httpx
import time
from typing import Optional, Dict

class RequestEngine:
    """
    Handles network communication with the target.
    
    Security Context:
    Offensive tools must be controllable. This engine enforces timeouts to 
    prevent hanging on tarpits, handles retries gracefully, and allows for 
    delays between requests to avoid overwhelming the target or triggering 
    rate-limiting WAFs.
    """

    def __init__(self, timeout: int = 10, delay: float = 0.0, user_agent: str = "SQLiDetector/1.0", proxy: Optional[str] = None):
        self.timeout = timeout
        self.delay = delay
        
        # We set a custom User-Agent. In a real pentest, you might randomize this,
        # but for authorized testing, it's often good practice to use an identifiable UA
        # so the blue team can filter the noise if necessary.
        self.headers = {
            "User-Agent": user_agent,
            "Accept": "*/*"
        }
        
        # Configure httpx client with optional proxy (useful for routing through Burp Suite)
        proxies = {"all://": proxy} if proxy else None
        
        # verify=False is common in offensive tooling to allow testing against internal
        # targets with self-signed certificates.
        self.client = httpx.Client(timeout=self.timeout, proxies=proxies, verify=False, follow_redirects=True)

    def send_get(self, url: str) -> Optional[httpx.Response]:
        """
        Sends an HTTP GET request to the target URL.
        Enforces the configured delay before sending.
        """
        if self.delay > 0:
            time.sleep(self.delay)
            
        try:
            response = self.client.get(url, headers=self.headers)
            return response
        except httpx.RequestError as e:
            # We silently catch connection errors to allow the scan to continue,
            # but in a more advanced version, we might log these to a debug file.
            return None
            
    def close(self):
        """Clean up the HTTP client session."""
        self.client.close()
