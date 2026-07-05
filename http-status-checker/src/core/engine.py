import asyncio
from typing import List, Dict, Any, Callable, Optional
import aiohttp
from src.core.prober import Prober
from src.utils.logger import logger

class AsyncRateLimiter:
    """Controls the rate of outgoing requests globally across workers."""
    
    def __init__(self, rps: float):
        self.delay = 1.0 / rps if rps > 0 else 0.0
        self.last_request = 0.0
        self.lock = asyncio.Lock()

    async def wait(self):
        if self.delay == 0.0:
            return
        async with self.lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self.last_request
            if elapsed < self.delay:
                await asyncio.sleep(self.delay - elapsed)
            self.last_request = asyncio.get_event_loop().time()

class Engine:
    """Orchestrates concurrent HTTP probing using an async worker queue."""

    def __init__(
        self,
        targets: List[str],
        prober: Prober,
        concurrency: int = 50,
        rate_limit: float = 0.0,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.targets = targets
        self.prober = prober
        self.concurrency = concurrency
        self.rate_limit = rate_limit
        self.progress_callback = progress_callback
        self.results = []

    async def _worker(self, queue: asyncio.Queue, session: aiohttp.ClientSession, rate_limiter: AsyncRateLimiter):
        """Worker loop pulling targets from the queue."""
        while True:
            try:
                target = await queue.get()
            except asyncio.CancelledError:
                break
                
            if target is None:
                queue.task_done()
                break

            try:
                # Enforce rate-limiting before request triggers
                await rate_limiter.wait()
                
                # Probe the endpoint
                result = await self.prober.probe(target, session)
                
                # Append to class level results in thread-safe async environment
                self.results.append(result)
                
                # Trigger callback if defined (e.g. CLI progress bar updates)
                if self.progress_callback:
                    if asyncio.iscoroutinefunction(self.progress_callback):
                        await self.progress_callback(result)
                    else:
                        self.progress_callback(result)
                        
            except Exception as e:
                logger.debug(f"[DEBUG] Worker encountered error processing target {target}: {e}")
            finally:
                queue.task_done()

    async def run(self) -> List[Dict[str, Any]]:
        """Prepares the queue and starts workers to probe all targets concurrently."""
        queue = asyncio.Queue()
        
        # Populate target queue
        for target in self.targets:
            await queue.put(target)
            
        # Add termination sentinel values for each worker
        for _ in range(self.concurrency):
            await queue.put(None)

        # Build custom connector. limit=0 disables the native connection pool cap,
        # letting us manage concurrency explicitly via the engine's worker count.
        connector = aiohttp.TCPConnector(
            limit=0,
            ttl_dns_cache=300,
            use_dns_cache=True
        )

        rate_limiter = AsyncRateLimiter(self.rate_limit)

        # Setup ClientSession and launch workers
        async with aiohttp.ClientSession(connector=connector) as session:
            workers = []
            for _ in range(self.concurrency):
                task = asyncio.create_task(
                    self._worker(queue, session, rate_limiter)
                )
                workers.append(task)
                
            # Wait for all queue items to be processed
            await queue.join()
            
            # Cancel workers and clean up
            for w in workers:
                if not w.done():
                    w.cancel()
            
            # Gather worker tasks to clean exceptions
            await asyncio.gather(*workers, return_exceptions=True)
            
        return self.results
