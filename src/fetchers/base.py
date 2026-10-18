"""Base async fetcher with rate limiting, retry, and circuit breaker."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Generic, TypeVar

import aiohttp

from src.utils.rate_limiter import RateLimitConfig, TokenBucketRateLimiter
from src.utils.circuit_breaker import CircuitBreaker

T = TypeVar("T")


class AsyncFetcher(ABC, Generic[T]):
    """Base class for all async data fetchers."""

    def __init__(
            self,
            session: aiohttp.ClientSession,
            rate_limit: RateLimitConfig | None = None,
            circuit_breaker: CircuitBreaker | None = None,
    ):
        self.session = session
        self.rate_limiter = TokenBucketRateLimiter(rate_limit)
        self.circuit = circuit_breaker or CircuitBreaker()

    async def _fetch(self, url: str, **kwargs) -> dict[str, Any]:
        """Fetch with rate limiting and circuit breaker."""
        await self.rate_limiter.acquire()

        async def _do_fetch():
            async with self.session.get(url, **kwargs) as resp:
                resp.raise_for_status()
                return await resp.json()

        return await self.circuit.call(_do_fetch)

    @abstractmethod
    async def fetch_all(self) -> list[T]:
        """Fetch all records from source."""

    @abstractmethod
    async def fetch_incremental(self, since: str | None = None) -> list[T]:
        """Fetch only records changed since watermark."""

    @abstractmethod
    def transform(self, raw: Any) -> dict[str, Any]:
        """Transform raw API response to unified enrichment record format."""