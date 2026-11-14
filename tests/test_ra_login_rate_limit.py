from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest

from backend.ra.auth_service import AuthenticationDenied, AuthenticationUnavailable
from backend.ra.login_rate_limit import LimitedDemoAuthentication, LoginRateLimited


def test_failed_login_limit_expires_at_window_boundary():
    now = [100.0]
    service = Mock()
    service.login.side_effect = AuthenticationDenied()
    limited = LimitedDemoAuthentication(service, max_failures=2, clock=lambda: now[0])
    for _ in range(2):
        with pytest.raises(AuthenticationDenied):
            limited.login("synthetic", "wrong")
    with pytest.raises(LoginRateLimited) as caught:
        limited.login("another-user", "wrong")
    assert caught.value.retry_after == 60
    assert service.login.call_count == 2
    now[0] = 160.0
    with pytest.raises(AuthenticationDenied):
        limited.login("synthetic", "wrong")
    assert service.login.call_count == 3


def test_success_does_not_clear_failures_and_outage_does_not_count():
    service = Mock()
    limited = LimitedDemoAuthentication(service, max_failures=1)
    service.login.side_effect = AuthenticationUnavailable()
    for _ in range(3):
        with pytest.raises(AuthenticationUnavailable):
            limited.login("synthetic", "wrong")
    service.login.side_effect = None
    service.login.return_value = "synthetic-token"
    for _ in range(3):
        assert limited.login("synthetic", "valid") == "synthetic-token"
    service.login.side_effect = AuthenticationDenied()
    with pytest.raises(AuthenticationDenied):
        limited.login("synthetic", "wrong")
    with pytest.raises(LoginRateLimited):
        limited.login("synthetic", "valid")


def test_concurrent_failed_attempts_cannot_bypass_limit():
    service = Mock()
    service.login.side_effect = AuthenticationDenied()
    limited = LimitedDemoAuthentication(service, clock=lambda: 100.0)

    def attempt(index):
        try:
            limited.login(str(index), "wrong")
        except (AuthenticationDenied, LoginRateLimited) as exc:
            return type(exc)

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(attempt, range(10)))
    assert results.count(AuthenticationDenied) == 5
    assert results.count(LoginRateLimited) == 5
    assert service.login.call_count == 5


@pytest.mark.parametrize("kwargs", [{"max_failures": 0}, {"window_seconds": 0}])
def test_invalid_limit_rejected(kwargs):
    with pytest.raises(ValueError):
        LimitedDemoAuthentication(Mock(), **kwargs)
