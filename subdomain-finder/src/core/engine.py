import asyncio
import aiohttp
from src.passive import MODULES
from src.active.resolver import AsyncResolver
from src.core.wildcard import detect_wildcards
from src.utils.logger import logger

class Engine:
    def __init__(self, target: str, wordlist: list[str] = None, concurrency: int = 100):
        self.target = target
        self.wordlist = wordlist or []
        self.concurrency = concurrency
        self.subdomains = set()
        
    async def run_passive(self):
        """Runs all passive API modules concurrently."""
        logger.info("Starting passive enumeration...")
        async with aiohttp.ClientSession() as session:
            tasks = []
            for name, func in MODULES.items():
                tasks.append(func(self.target, session))
                
            results = await asyncio.gather(*tasks)
            for res in results:
                self.subdomains.update(res)

    async def run_active(self):
        """Runs active wordlist bruteforcing."""
        if not self.wordlist:
            logger.warning("No wordlist provided. Skipping active enumeration.")
            return
            
        resolver = AsyncResolver(self.concurrency)
        
        # 1. Detect wildcards first
        wildcard_ips = await detect_wildcards(self.target, resolver)
        
        # 2. Brute force
        active_subs = await resolver.brute_force(self.target, self.wordlist, wildcard_ips)
        self.subdomains.update(active_subs)
        
    async def run(self, passive_only: bool = False):
        """Main orchestrator."""
        await self.run_passive()
        
        if not passive_only:
            await self.run_active()
            
        return self.subdomains
