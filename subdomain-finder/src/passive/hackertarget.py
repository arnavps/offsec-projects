import aiohttp
from src.utils.logger import logger

async def run(domain: str, session: aiohttp.ClientSession) -> set[str]:
    """Queries HackerTarget API for subdomains."""
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    logger.debug(f"Querying HackerTarget for {domain}")
    
    try:
        async with session.get(url, timeout=15) as response:
            if response.status == 200:
                text = await response.text()
                if "error" not in text.lower():
                    for line in text.split('\n'):
                        if ',' in line:
                            sub = line.split(',')[0].strip().lower()
                            if sub.endswith(domain):
                                subdomains.add(sub)
                    logger.info(f"[SUCCESS] HackerTarget found {len(subdomains)} subdomains")
            else:
                logger.warning(f"HackerTarget returned status {response.status}")
    except Exception as e:
        logger.error(f"HackerTarget exception: {e}")
        
    return subdomains
