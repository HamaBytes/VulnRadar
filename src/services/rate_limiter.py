import time
from aiohttp import web


class TokenBucket:
    def __init__(self, capacity: float, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_update = time.time()

    def consume(self) -> bool:
        now = time.time()
        # 1. Calculate how many tokens accumulated since last check
        elapsed = now - self.last_update
        self.last_update = now

        # 2. Add accumulated tokens (capped at max capacity)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

        # 3. Try to consume 1 token
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimiter:
    def __init__(self, capacity: float, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.buckets = {}

    def is_allowed(self, ip: str) -> bool:
        if ip not in self.buckets:
            # Create a new bucket for new IP addresses
            self.buckets[ip] = TokenBucket(self.capacity, self.refill_rate)
        return self.buckets[ip].consume()


# The aiohttp middleware factory
def rate_limit_middleware(limiter: RateLimiter):
    @web.middleware
    async def middleware(request: web.Request, handler):
        # Extract IP address
        client_ip = request.headers.get("X-Forwarded-For", request.remote)

        # Check limit
        if not limiter.is_allowed(client_ip):
            return web.json_response(
                {"error": "Too Many Requests. Limit is 60 req/min."},
                status=429
            )

        return await handler(request)

    return middleware