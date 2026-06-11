import aiohttp
from src.utils.logger import logger

async def run(domain: str, session: aiohttp.ClientSession) -> set[str]:
    """Queries AlienVault OTX API for subdomains."""
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    logger.debug(f"Querying AlienVault OTX for {domain}")
    
    try:
        async with session.get(url, timeout=15) as response:
            if response.status == 200:
                data = await response.json()
                for entry in data.get('passive_dns', []):
                    sub = entry.get('hostname', '').lower().strip()
                    if sub and not sub.startswith('*') and sub.endswith(domain):
                        subdomains.add(sub)
                logger.info(f"[SUCCESS] AlienVault found {len(subdomains)} subdomains")
            else:
                logger.warning(f"AlienVault returned status {response.status}")
    except Exception as e:
        logger.error(f"AlienVault exception: {e}")
        
    return subdomains
