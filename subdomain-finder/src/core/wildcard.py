import uuid
import asyncio
from src.active.resolver import AsyncResolver
from src.utils.logger import logger

async def detect_wildcards(domain: str, resolver: AsyncResolver, tests: int = 3) -> set[str]:
    """
    Detects if a domain uses wildcard DNS records by resolving random subdomains.
    Returns a set of IP addresses associated with wildcard responses.
    """
    logger.info(f"Checking for wildcard DNS on {domain}...")
    wildcard_ips = set()
    
    # Generate random non-existent subdomains
    random_subs = [f"{uuid.uuid4().hex[:12]}.{domain}" for _ in range(tests)]
    
    tasks = [resolver.resolve(sub) for sub in random_subs]
    results = await asyncio.gather(*tasks)
    
    for ip in results:
        if ip:
            wildcard_ips.add(ip)
            
    if wildcard_ips:
        logger.warning(f"Wildcard DNS detected! IPs: {', '.join(wildcard_ips)}")
    else:
        logger.info("No wildcard DNS detected.")
        
    return wildcard_ips
