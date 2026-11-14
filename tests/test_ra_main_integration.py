from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)

LOGIN_URL = "/api/v1/ra/auth/login"


def test_health_endpoint_still_works():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_login_route_available_in_openapi():
    schema = app.openapi()

    assert LOGIN_URL in schema["paths"]
    assert "post" in schema["paths"][LOGIN_URL]


def test_login_remains_disabled_by_default():
    response = client.post(
        LOGIN_URL,
        json={
            "username": "demo-user",
            "password": "synthetic-password",
        },
    )

    assert response.status_code == 503
    assert "access_token" not in response.json()
    assert response.headers["cache-control"] == "no-store"


def test_disabled_login_does_not_leak_password():
    secret = "SECRET_CANARY_" + "x" * 1100

    response = client.post(
        LOGIN_URL,
        json={
            "username": "demo-user",
            "password": secret,
        },
    )

    assert response.status_code == 503
    assert secret not in response.text
    assert "access_token" not in response.json()
    assert response.headers["cache-control"] == "no-store"


def test_main_app_validation_does_not_leak_password():
    from backend.ra.login_router import get_ra_auth_service

    class ForbiddenService:
        def login(self, username, password):
            raise AssertionError(
                "Authentication must not execute for invalid input"
            )

    secret = "SECRET_CANARY_" + "x" * 1100
    previous_overrides = app.dependency_overrides.copy()

    app.dependency_overrides[get_ra_auth_service] = (
        lambda: ForbiddenService()
    )

    try:
        response = client.post(
            LOGIN_URL,
            json={
                "username": "demo-user",
                "password": secret,
            },
        )
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous_overrides)

    assert response.status_code == 422
    assert secret not in response.text
    assert "access_token" not in response.json()
    assert response.headers["cache-control"] == "no-store"