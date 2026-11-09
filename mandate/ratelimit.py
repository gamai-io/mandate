from __future__ import annotations

import threading
import time


class RateLimiter:
    """Bounded per-IP token bucket. per_minute=0 disables limiting."""

    def __init__(self, per_minute: float = 0, burst: float = 0,
                 max_ips: int = 1024):
        self.rate = max(0.0, float(per_minute)) / 60.0
        self.burst = max(1.0, float(burst or 1))
        self.max_ips = max(1, int(max_ips))
        self._lock = threading.Lock()
        self._state: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> tuple[bool, float]:
        if self.rate <= 0:
            return True, 0.0
        now = time.monotonic()
        with self._lock:
            if len(self._state) >= self.max_ips and key not in self._state:
                oldest = min(self._state, key=lambda k: self._state[k][1])
                self._state.pop(oldest, None)
            tokens, last = self._state.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens >= 1:
                self._state[key] = (tokens - 1, now)
                return True, 0.0
            self._state[key] = (tokens, now)
            retry = (1 - tokens) / self.rate if self.rate else 1.0
            return False, max(0.1, retry)
