"""
Per-student, per-course sliding-window rate limiter.

Tracks AI request timestamps in memory using a deque per (course, student) pair.
All access happens on the single asyncio event loop, so no locks are needed.
"""

import time
from collections import defaultdict, deque


class StudentRateLimiter:
    """In-memory sliding-window rate limiter keyed by (course_handle, student_email)."""

    def __init__(self):
        self._windows: dict[tuple[str, str], deque] = defaultdict(deque)

    def check_and_record(self, course_handle: str, student_email: str,
                         max_requests: int, window_seconds: int) -> bool:
        """Return True if the request is allowed (and record it). False if limit exceeded."""
        key = (course_handle, student_email.lower())
        now = time.monotonic()
        window = self._windows[key]

        # Evict expired entries
        cutoff = now - window_seconds
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= max_requests:
            return False

        window.append(now)
        return True

    def remaining(self, course_handle: str, student_email: str,
                  max_requests: int, window_seconds: int) -> int:
        """Return how many requests remain in the current window."""
        key = (course_handle, student_email.lower())
        now = time.monotonic()
        window = self._windows[key]
        cutoff = now - window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        return max(0, max_requests - len(window))

    def clear_course(self, course_handle: str):
        """Remove all tracking data for a course (useful when config changes)."""
        to_remove = [k for k in self._windows if k[0] == course_handle]
        for k in to_remove:
            del self._windows[k]

    def get_course_usage(self, course_handle: str, max_requests: int,
                         window_seconds: int) -> dict:
        """Return per-student usage stats for a course (for instructor diagnostics)."""
        now = time.monotonic()
        cutoff = now - window_seconds
        usage = {}
        for (ch, email), window in self._windows.items():
            if ch != course_handle:
                continue
            # Evict expired
            while window and window[0] < cutoff:
                window.popleft()
            if window:
                usage[email] = {
                    "used": len(window),
                    "remaining": max(0, max_requests - len(window)),
                }
        return usage


# Module-level singleton
student_rate_limiter = StudentRateLimiter()
