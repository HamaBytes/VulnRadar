"""Circuit breaker pattern for unreliable external APIs."""

import asyncio
import logging
from enum import Enum
from functools import wraps

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing fast
    HALF_OPEN = "half_open"  # Testing recovery


class CircuitBreaker:
    def __init__(
            self,
            failure_threshold: int = 5,
            recovery_timeout: float = 60.0,
            half_open_max_calls: int = 3,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self.state = CircuitState.CLOSED
        self.failures = 0
        self.last_failure_time: float | None = None
        self.half_open_calls = 0

    def _trip(self):
        self.state = CircuitState.OPEN
        self.last_failure_time = asyncio.get_event_loop().time()
        logger.warning(f"Circuit breaker OPENED")

    def _reset(self):
        self.state = CircuitState.CLOSED
        self.failures = 0
        self.half_open_calls = 0
        logger.info("Circuit breaker CLOSED")

    def _should_attempt_reset(self) -> bool:
        if self.last_failure_time is None:
            return False
        elapsed = asyncio.get_event_loop().time() - self.last_failure_time
        return elapsed >= self.recovery_timeout

    async def call(self, coro_factory, *args, **kwargs):
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
                self.half_open_calls = 0
                logger.info("Circuit breaker HALF_OPEN")
            else:
                raise CircuitBreakerOpen("Service temporarily unavailable")

        if self.state == CircuitState.HALF_OPEN:
            if self.half_open_calls >= self.half_open_max_calls:
                self._trip()
                raise CircuitBreakerOpen("Half-open limit reached")
            self.half_open_calls += 1

        try:
            result = await coro_factory(*args, **kwargs)
            self._reset()
            return result
        except Exception as e:
            self.failures += 1
            if self.failures >= self.failure_threshold:
                self._trip()
            raise


class CircuitBreakerOpen(Exception):
    pass