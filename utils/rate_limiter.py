"""
Rate Limiting Utility
Simple sliding-window rate limiter.
"""

import time
from collections import defaultdict
from telegram.ext import ContextTypes
from config import config


class RateLimiter:
    def __init__(self, max_requests: int = None, window_seconds: int = None):
        self.max_requests = max_requests or config.RATE_LIMIT
        self.window = window_seconds or config.RATE_WINDOW
        self.requests: dict[int, list] = defaultdict(list)

    def is_allowed(self, user_id: int) -> tuple[bool, int]:
        now = time.time()
        user_reqs = [t for t in self.requests[user_id] if now - t < self.window]
        self.requests[user_id] = user_reqs
        if len(user_reqs) >= self.max_requests:
            oldest = min(user_reqs)
            retry_after = int(self.window - (now - oldest)) + 1
            return False, retry_after
        user_reqs.append(now)
        return True, 0


# Singleton
rate_limiter = RateLimiter()


def check_rate_limit(user_id: int, category: str = None) -> bool:
    """Quick check — returns True if allowed."""
    allowed, _ = rate_limiter.is_allowed(user_id)
    return allowed


def is_admin(user_id: int) -> bool:
    """Check if a user ID is in the admin list."""
    return user_id in config.ADMIN_IDS
