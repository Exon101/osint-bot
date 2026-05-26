"""
Unit tests for rate limiter and logger modules.
"""

import time
import pytest
from utils.rate_limiter import RateLimiter, rate_limiter, check_rate_limit


class TestRateLimiter:
    """Test the sliding-window rate limiter."""

    def test_initial_request_allowed(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        allowed, retry = limiter.is_allowed(12345)
        assert allowed is True
        assert retry == 0

    def test_within_limit(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        limiter.is_allowed(99999)
        limiter.is_allowed(99999)
        allowed, _ = limiter.is_allowed(99999)
        assert allowed is True

    def test_over_limit(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.is_allowed(88888)
        limiter.is_allowed(88888)
        allowed, retry = limiter.is_allowed(88888)
        assert allowed is False
        assert retry > 0

    def test_different_users_independent(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        limiter.is_allowed(11111)
        allowed, _ = limiter.is_allowed(22222)
        assert allowed is True

    def test_window_expiry(self):
        """After window expires, user should be allowed again."""
        limiter = RateLimiter(max_requests=1, window_seconds=1)
        limiter.is_allowed(55555)
        # Wait for window to expire
        time.sleep(1.1)
        allowed, _ = limiter.is_allowed(55555)
        assert allowed is True

    def test_retry_after_is_positive(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        limiter.is_allowed(77777)
        _, retry = limiter.is_allowed(77777)
        assert retry > 0
        assert retry <= 60

    def test_check_rate_limit_function(self):
        """Test the quick check function."""
        # Use a fresh limiter for testing
        limiter = RateLimiter(max_requests=100, window_seconds=60)
        allowed = check_rate_limit.__wrapped__(33333, limiter=limiter)
        assert allowed is True


class TestLogger:
    """Test the logging module."""

    def test_logger_imports(self):
        from utils.logger import logger, setup_logger, log_query
        assert logger is not None

    def test_log_query(self):
        from utils.logger import log_query
        # Should not raise any exceptions
        log_query(user_id=1, command="test", query="test_query", result="success")

    def test_setup_logger_returns_logger(self):
        from utils.logger import setup_logger
        result = setup_logger(name="test_osint")
        assert result is not None
        assert hasattr(result, "info")
