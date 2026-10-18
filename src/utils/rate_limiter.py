"""Token bucket rate limiter for API compliance."""

import asyncio
import time
from dataclasses import dataclass


@dataclass
class RateLimitConfig:
    requests_per_second: float = 0.6  # NVD default: 6 req / 10 sec
    burst_size: int = 1


class TokenBucketRateLimiter:
    def __init__(self, config: RateLimitConfig | None = None):
        self.config = config or RateLimitConfig()
        self.tokens = self.config.burst_size
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(
                self.config.burst_size,
                self.tokens + elapsed * self.config.requests_per_second,
                )
            self.last_update = now

            if self.tokens < 1:
                wait = (1 - self.tokens) / self.config.requests_per_second
                await asyncio.sleep(wait)
                self.tokens = 0
            else:
                self.tokens -= 1