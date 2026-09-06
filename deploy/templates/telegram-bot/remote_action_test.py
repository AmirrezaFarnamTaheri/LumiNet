from __future__ import annotations

import unittest
from unittest.mock import Mock

import requests

from remote_action import request_idempotent


class Response:
    def __init__(self, status_code: int, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False

    def close(self):
        self.closed = True


class RemoteActionTests(unittest.TestCase):
    def test_retries_retryable_status_and_honors_capped_retry_after(self):
        first = Response(503, {"Retry-After": "99"})
        second = Response(200)
        request = Mock(side_effect=[first, second])
        delays = []

        result = request_idempotent(
            "PATCH",
            "https://example.test/setting",
            request=request,
            sleep=delays.append,
            retry_after_cap=2,
        )

        self.assertIs(result, second)
        self.assertEqual(request.call_count, 2)
        self.assertTrue(first.closed)
        self.assertEqual(delays, [2.0])

    def test_huge_retry_after_is_capped_without_overflow(self):
        first = Response(503, {"Retry-After": "9" * 1000})
        second = Response(200)
        request = Mock(side_effect=[first, second])
        delays = []

        result = request_idempotent(
            "PATCH",
            "https://example.test/setting",
            request=request,
            sleep=delays.append,
            retry_after_cap=2,
        )

        self.assertIs(result, second)
        self.assertEqual(delays, [2.0])

    def test_retries_transport_error_but_is_bounded(self):
        request = Mock(side_effect=[requests.ConnectionError("reset"), Response(200)])
        delays = []
        result = request_idempotent(
            "PATCH",
            "https://example.test/setting",
            request=request,
            sleep=delays.append,
            base_delay=0.1,
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(delays, [0.1])

    def test_non_retryable_status_returns_immediately(self):
        request = Mock(return_value=Response(401))
        result = request_idempotent(
            "PATCH",
            "https://example.test/setting",
            request=request,
            sleep=lambda _: self.fail("must not sleep"),
        )
        self.assertEqual(result.status_code, 401)
        self.assertEqual(request.call_count, 1)


if __name__ == "__main__":
    unittest.main()
