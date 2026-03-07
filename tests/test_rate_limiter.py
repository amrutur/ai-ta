"""
Tests for the StudentRateLimiter sliding-window rate limiter.
"""

import time
from unittest.mock import patch

from rate_limiter import StudentRateLimiter


class TestCheckAndRecord:
    def test_allows_requests_within_limit(self):
        limiter = StudentRateLimiter()
        for i in range(5):
            assert limiter.check_and_record("course1", "student@test.com", 5, 3600)

    def test_blocks_after_limit_exceeded(self):
        limiter = StudentRateLimiter()
        for _ in range(3):
            assert limiter.check_and_record("course1", "student@test.com", 3, 3600)
        assert not limiter.check_and_record("course1", "student@test.com", 3, 3600)

    def test_different_students_independent(self):
        limiter = StudentRateLimiter()
        for _ in range(3):
            limiter.check_and_record("course1", "alice@test.com", 3, 3600)
        # Alice is blocked
        assert not limiter.check_and_record("course1", "alice@test.com", 3, 3600)
        # Bob still has quota
        assert limiter.check_and_record("course1", "bob@test.com", 3, 3600)

    def test_different_courses_independent(self):
        limiter = StudentRateLimiter()
        for _ in range(3):
            limiter.check_and_record("course1", "student@test.com", 3, 3600)
        assert not limiter.check_and_record("course1", "student@test.com", 3, 3600)
        # Same student, different course — still has quota
        assert limiter.check_and_record("course2", "student@test.com", 3, 3600)

    def test_email_case_insensitive(self):
        limiter = StudentRateLimiter()
        limiter.check_and_record("course1", "Student@Test.COM", 2, 3600)
        limiter.check_and_record("course1", "student@test.com", 2, 3600)
        # Should be blocked — both count against the same key
        assert not limiter.check_and_record("course1", "STUDENT@TEST.COM", 2, 3600)

    def test_expired_entries_evicted(self):
        limiter = StudentRateLimiter()
        # Use a very short window
        with patch("rate_limiter.time.monotonic", return_value=1000.0):
            limiter.check_and_record("course1", "student@test.com", 2, 10)
            limiter.check_and_record("course1", "student@test.com", 2, 10)
        # Now blocked
        with patch("rate_limiter.time.monotonic", return_value=1005.0):
            assert not limiter.check_and_record("course1", "student@test.com", 2, 10)
        # After window expires, should be allowed again
        with patch("rate_limiter.time.monotonic", return_value=1011.0):
            assert limiter.check_and_record("course1", "student@test.com", 2, 10)

    def test_limit_of_one(self):
        limiter = StudentRateLimiter()
        assert limiter.check_and_record("course1", "student@test.com", 1, 3600)
        assert not limiter.check_and_record("course1", "student@test.com", 1, 3600)


class TestRemaining:
    def test_full_quota_remaining(self):
        limiter = StudentRateLimiter()
        assert limiter.remaining("course1", "student@test.com", 5, 3600) == 5

    def test_remaining_decreases(self):
        limiter = StudentRateLimiter()
        limiter.check_and_record("course1", "student@test.com", 5, 3600)
        limiter.check_and_record("course1", "student@test.com", 5, 3600)
        assert limiter.remaining("course1", "student@test.com", 5, 3600) == 3

    def test_remaining_zero_when_exhausted(self):
        limiter = StudentRateLimiter()
        for _ in range(5):
            limiter.check_and_record("course1", "student@test.com", 5, 3600)
        assert limiter.remaining("course1", "student@test.com", 5, 3600) == 0


class TestClearCourse:
    def test_clear_resets_all_students_for_course(self):
        limiter = StudentRateLimiter()
        for _ in range(3):
            limiter.check_and_record("course1", "alice@test.com", 3, 3600)
            limiter.check_and_record("course1", "bob@test.com", 3, 3600)
        # Both blocked
        assert not limiter.check_and_record("course1", "alice@test.com", 3, 3600)
        assert not limiter.check_and_record("course1", "bob@test.com", 3, 3600)

        limiter.clear_course("course1")

        # Both allowed again
        assert limiter.check_and_record("course1", "alice@test.com", 3, 3600)
        assert limiter.check_and_record("course1", "bob@test.com", 3, 3600)

    def test_clear_does_not_affect_other_courses(self):
        limiter = StudentRateLimiter()
        for _ in range(3):
            limiter.check_and_record("course1", "student@test.com", 3, 3600)
            limiter.check_and_record("course2", "student@test.com", 3, 3600)

        limiter.clear_course("course1")

        # course1 reset, course2 still blocked
        assert limiter.check_and_record("course1", "student@test.com", 3, 3600)
        assert not limiter.check_and_record("course2", "student@test.com", 3, 3600)

    def test_clear_nonexistent_course_no_error(self):
        limiter = StudentRateLimiter()
        limiter.clear_course("nonexistent")  # Should not raise


class TestGetCourseUsage:
    def test_empty_when_no_requests(self):
        limiter = StudentRateLimiter()
        assert limiter.get_course_usage("course1", 10, 3600) == {}

    def test_returns_per_student_usage(self):
        limiter = StudentRateLimiter()
        limiter.check_and_record("course1", "alice@test.com", 10, 3600)
        limiter.check_and_record("course1", "alice@test.com", 10, 3600)
        limiter.check_and_record("course1", "bob@test.com", 10, 3600)

        usage = limiter.get_course_usage("course1", 10, 3600)
        assert usage["alice@test.com"]["used"] == 2
        assert usage["alice@test.com"]["remaining"] == 8
        assert usage["bob@test.com"]["used"] == 1
        assert usage["bob@test.com"]["remaining"] == 9

    def test_excludes_other_courses(self):
        limiter = StudentRateLimiter()
        limiter.check_and_record("course1", "alice@test.com", 10, 3600)
        limiter.check_and_record("course2", "bob@test.com", 10, 3600)

        usage = limiter.get_course_usage("course1", 10, 3600)
        assert "alice@test.com" in usage
        assert "bob@test.com" not in usage
