"""Bounded, process-local failed-login limit for the single local demo."""

import math
import time
from collections import deque
from collections.abc import Callable
from threading import Lock

from backend.ra.auth_service import AuthenticationDenied, RAAuthenticationService


class LoginRateLimited(Exception):
    def __init__(self, retry_after: int):
        super().__init__("Too many login attempts")
        self.retry_after = retry_after


class LimitedDemoAuthentication:
    def __init__(
        self,
        service: RAAuthenticationService,
        *,
        max_failures: int = 5,
        window_seconds: float = 60,
        clock: Callable[[], float] = time.monotonic,
    ):
        if max_failures < 1 or window_seconds <= 0:
            raise ValueError("Invalid login limit")
        self._service = service
        self._max_failures = max_failures
        self._window = window_seconds
        self._clock = clock
        self._failures: deque[float] = deque()
        self._lock = Lock()

    def login(self, username: str, password: str) -> str:
        # One shared bucket prevents bypass through username/header changes.
        # Serialize attempts so concurrent password checks cannot bypass it.
        with self._lock:
            now = self._clock()
            while self._failures and self._failures[0] <= now - self._window:
                self._failures.popleft()
            if len(self._failures) >= self._max_failures:
                raise LoginRateLimited(max(
                    1, math.ceil(self._failures[0] + self._window - now)
                ))
            try:
                return self._service.login(username, password)
            except AuthenticationDenied:
                self._failures.append(self._clock())
                raise
