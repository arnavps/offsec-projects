import aiodns
import asyncio
from src.utils.logger import logger

class AsyncResolver:
    def __init__(self, concurrency: int = 100):
        self.resolver = aiodns.DNSResolver()
        self.semaphore = asyncio.Semaphore(concurrency)
        
    async def resolve(self, domain: str) -> str | None:
        """Attempt to resolve a domain. Returns an IP if successful, else None."""
        async with self.semaphore:
            try:
                # We primarily care about A records for simple enum
                result = await self.resolver.query(domain, 'A')
                if result:
                    return result[0].host
            except aiodns.error.DNSError:
                # Domain doesn't exist or doesn't have an A record
                pass
            except Exception as e:
                logger.debug(f"Unexpected error resolving {domain}: {e}")
        return None
        
    async def brute_force(self, target: str, wordlist: list[str], wildcard_ips: set[str]) -> set[str]:
        """Bruteforces subdomains against a wordlist."""
        found = set()
        logger.info(f"Starting active enumeration against {len(wordlist)} words...")
        
        async def check_word(word: str):
            subdomain = f"{word}.{target}"
            ip = await self.resolve(subdomain)
            if ip:
                if ip not in wildcard_ips:
                    found.add(subdomain)
                else:
                    logger.debug(f"Filtered wildcard subdomain: {subdomain} -> {ip}")

        tasks = [check_word(word) for word in wordlist]
        
        await asyncio.gather(*tasks)
        
        logger.info(f"[SUCCESS] Active enumeration found {len(found)} subdomains")
        return found
