import aiohttp
from src.utils.logger import logger

async def run(domain: str, session: aiohttp.ClientSession) -> set[str]:
    """Queries crt.sh (Certificate Transparency logs) for subdomains."""
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    logger.debug(f"Querying crt.sh for {domain}")
    
    try:
        async with session.get(url, timeout=15) as response:
            if response.status == 200:
                data = await response.json()
                for entry in data:
                    name = entry.get('name_value', '').lower()
                    for sub in name.split('\n'):
                        sub = sub.strip()
                        if not sub.startswith('*') and sub.endswith(domain):
                            subdomains.add(sub)
                logger.info(f"[SUCCESS] crt.sh found {len(subdomains)} subdomains")
            else:
                logger.warning(f"crt.sh returned status {response.status}")
    except Exception as e:
        logger.error(f"crt.sh exception: {e}")
        
    return subdomains
