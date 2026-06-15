"""Rate Limiting Middleware for VulnRadar API.

Implements the Token Bucket algorithm to limit incoming client requests by IP.
"""

import time
import logging
from aiohttp import web

logger = logging.getLogger(__name__)


class TokenBucket:
    """Represents an individual rate limit bucket for a client IP."""

    def __init__(self, capacity: float, refill_rate: float) -> None:
        """Initialize the token bucket.
        
        :param capacity: Max tokens the bucket can hold.
        :param refill_rate: How many tokens are added back per second.
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_update = time.time()

    def consume(self, tokens_to_consume: float = 1.0) -> bool:
        """Deduct tokens from the bucket if available.
        
        Uses lazy refilling based on elapsed time.
        """
        now = time.time()
        elapsed = now - self.last_update
        self.last_update = now

        # Add accumulated tokens up to maximum capacity
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

        if self.tokens >= tokens_to_consume:
            self.tokens -= tokens_to_consume
            return True
        return False


class RateLimiter:
    """Manages token buckets for client IP addresses."""

    def __init__(self, requests_per_minute: int = 60) -> None:
        """Initialize the rate limiter.
        
        :param requests_per_minute: Allowed requests per minute per IP.
        """
        self.capacity = float(requests_per_minute)
        # Refill rate per second
        self.refill_rate = float(requests_per_minute) / 60.0
        self.buckets: dict[str, TokenBucket] = {}

    def is_allowed(self, ip: str) -> bool:
        """Check if the request from the given IP is allowed under the rate limit."""
        if ip not in self.buckets:
            self.buckets[ip] = TokenBucket(self.capacity, self.refill_rate)
        return self.buckets[ip].consume()


def rate_limiter_middleware(requests_per_minute: int = 60):
    """Factory creating an aiohttp rate limiting middleware."""
    limiter = RateLimiter(requests_per_minute)

    @web.middleware
    async def middleware(request: web.Request, handler):
        # Extract IP address, checking headers for reverse proxy compatibility
        client_ip = request.headers.get("X-Forwarded-For")
        if client_ip:
            # Get the original client IP in case of multiple proxy hops
            client_ip = client_ip.split(",")[0].strip()
        else:
            client_ip = request.remote or "unknown"

        if not limiter.is_allowed(client_ip):
            logger.warning(f"Rate limit exceeded for client IP: {client_ip}")
            return web.json_response(
                {
                    "error": "Too Many Requests",
                    "message": f"Rate limit of {requests_per_minute} requests per minute exceeded."
                },
                status=429
            )

        return await handler(request)

    return middleware
