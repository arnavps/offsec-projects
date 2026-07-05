import asyncio
import time
import ssl
from typing import Dict, Any, List
import aiohttp
from src.utils.logger import logger

class Prober:
    """Handles HTTP probing for a single URL endpoint."""

    def __init__(
        self,
        timeout: int = 10,
        allow_redirects: bool = True,
        max_redirects: int = 5,
        verify_ssl: bool = False,
        custom_headers: Dict[str, str] = None,
        max_body_read: int = 10 * 1024  # Read first 10KB of body
    ):
        self.timeout = timeout
        self.allow_redirects = allow_redirects
        self.max_redirects = max_redirects
        self.verify_ssl = verify_ssl
        self.max_body_read = max_body_read
        
        # Setup headers (spoofing a realistic browser is standard in recon)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if custom_headers:
            self.headers.update(custom_headers)

    def _classify_error(self, exception: Exception) -> str:
        """Classifies network exceptions into offensive-recon-friendly categories."""
        exc_str = str(exception)
        
        # Timeout Error
        if isinstance(exception, asyncio.TimeoutError):
            return "Connection Timeout"
        
        # Connection/DNS errors
        if isinstance(exception, aiohttp.ClientConnectorError):
            # DNS Resolution Error
            if "gaierror" in exc_str or "Name or service not known" in exc_str or "not found" in exc_str:
                return "DNS Resolution Failure"
            # Connection Refused
            if "ConnectionRefusedError" in exc_str or "refused" in exc_str:
                return "Connection Refused"
            # SSL errors nested inside connector error
            if "ssl" in exc_str.lower() or "cert" in exc_str.lower():
                return "SSL Handshake Failure"
            return f"Connection Failed: {exc_str}"
        
        # Explicit SSL Error
        if isinstance(exception, (aiohttp.ClientSSLError, ssl.SSLError)):
            return "SSL Handshake Failure"
        
        # Server disconnected
        if isinstance(exception, aiohttp.ServerDisconnectedError):
            return "Server Prematurely Disconnected"
            
        # OS network errors
        if isinstance(exception, aiohttp.ClientOSError):
            return f"Network OS Error: {exc_str}"

        # Generic client exception
        if isinstance(exception, aiohttp.ClientError):
            return f"HTTP Client Error: {exc_str}"
            
        return f"Unexpected Error: {type(exception).__name__}"

    async def probe(self, url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Probes a single URL and returns detailed structural response metrics."""
        result = {
            "url": url,
            "resolved_url": url,
            "status_code": None,
            "response_time_ms": None,
            "redirect_chain": [],
            "headers": {},
            "server": "Unknown",
            "body_preview": "",
            "error": None
        }

        # Setup custom SSL context if validation is toggled
        # By default in offensive recon, we disable cert verification to find dev/staging sites
        ssl_ctx = None
        if not self.verify_ssl:
            ssl_ctx = False

        start_time = time.perf_counter()
        
        try:
            # Enforce timeout at the request level
            async with session.get(
                url,
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                allow_redirects=self.allow_redirects,
                max_redirects=self.max_redirects,
                ssl=ssl_ctx
            ) as response:
                end_time = time.perf_counter()
                result["response_time_ms"] = round((end_time - start_time) * 1000, 2)
                
                # Extract response properties
                result["status_code"] = response.status
                result["resolved_url"] = str(response.url)
                result["headers"] = dict(response.headers)
                result["server"] = response.headers.get("Server", "Unknown")
                
                # Capture redirect history
                if response.history:
                    chain = []
                    for resp in response.history:
                        chain.append(f"{resp.status} -> {resp.url}")
                    chain.append(f"{response.status} -> {response.url}")
                    result["redirect_chain"] = chain

                # Read body content safely (limit bytes to prevent DoS by loading large files)
                try:
                    body_bytes = await response.content.read(self.max_body_read)
                    result["body_preview"] = body_bytes.decode("utf-8", errors="ignore")
                except Exception as body_err:
                    logger.debug(f"[DEBUG] Failed to read body preview for {url}: {body_err}")

        except Exception as err:
            end_time = time.perf_counter()
            result["response_time_ms"] = round((end_time - start_time) * 1000, 2)
            result["error"] = self._classify_error(err)
            
        return result
