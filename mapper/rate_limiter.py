from __future__ import annotations

import asyncio
import time


class TokenBucketRateLimiter:
    """
    Async token bucket rate limiter.

    Capacity equals rate_limit (one full minute of requests).
    Refills at rate_limit tokens per minute (rate_limit/60 per second).
    Each acquire() call consumes one token. If the bucket is empty the
    coroutine sleeps (outside the lock) until a token is available,
    without blocking the event loop.
    """

    def __init__(self, rate_per_minute: int):
        self._rate = max(1, rate_per_minute)
        self._capacity = float(self._rate)
        self._tokens: float = float(self._rate)   # start full
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        added = elapsed * (self._rate / 60.0)
        self._tokens = min(self._capacity, self._tokens + added)
        self._last_refill = now

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Calculate how long until one token is available
                wait_for = (1.0 - self._tokens) / (self._rate / 60.0)

            # Sleep outside the lock so other coroutines can progress
            await asyncio.sleep(wait_for)
