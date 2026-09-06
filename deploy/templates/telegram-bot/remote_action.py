"""Bounded retry helper for idempotent remote control-plane mutations.

This template-local helper mirrors the daemon's remote-action invariants without
creating a runtime dependency on daemon internals. It must only be used for
operations whose repeated request converges to the same desired state.
"""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import time
from typing import Callable

import requests

_RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}
_DEFAULT_ATTEMPTS = 3
_DEFAULT_BASE_DELAY = 0.25
_DEFAULT_MAX_DELAY = 4.0
_DEFAULT_RETRY_AFTER_CAP = 30.0


def request_idempotent(
    method: str,
    url: str,
    *,
    max_attempts: int = _DEFAULT_ATTEMPTS,
    base_delay: float = _DEFAULT_BASE_DELAY,
    max_delay: float = _DEFAULT_MAX_DELAY,
    retry_after_cap: float = _DEFAULT_RETRY_AFTER_CAP,
    timeout: float = 10.0,
    request: Callable[..., requests.Response] = requests.request,
    sleep: Callable[[float], None] = time.sleep,
    **kwargs,
) -> requests.Response:
    """Execute one explicitly idempotent HTTP mutation with bounded retry."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    last_error: requests.RequestException | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            response = request(method, url, timeout=timeout, **kwargs)
        except requests.RequestException as exc:
            last_error = exc
            if attempt == max_attempts:
                raise
            sleep(_backoff_delay(attempt, base_delay, max_delay))
            continue

        if response.status_code not in _RETRYABLE_STATUS or attempt == max_attempts:
            return response

        delay = _retry_after_delay(response.headers.get("Retry-After"), retry_after_cap)
        if delay is None:
            delay = _backoff_delay(attempt, base_delay, max_delay)
        response.close()
        sleep(delay)

    if last_error is not None:
        raise last_error
    raise RuntimeError("idempotent request retry loop ended without a response")


def _backoff_delay(failed_attempt: int, base_delay: float, max_delay: float) -> float:
    base = max(base_delay, 0.0)
    cap = max(max_delay, base)
    return min(base * (2 ** max(failed_attempt - 1, 0)), cap)


def _retry_after_delay(value: str | None, cap: float) -> float | None:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        seconds = int(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        seconds = max((when - datetime.now(timezone.utc)).total_seconds(), 0.0)
    if seconds < 0:
        return None
    safe_cap = max(cap, 0.0)
    # Provider-controlled Retry-After can contain an arbitrarily large integer.
    # Cap before float conversion so it cannot raise OverflowError.
    if seconds > safe_cap:
        return safe_cap
    return float(seconds)
