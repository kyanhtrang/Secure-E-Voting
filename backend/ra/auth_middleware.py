from starlette.datastructures import MutableHeaders

from backend.ra.login_router import NO_CACHE_HEADERS


class AuthNoStoreMiddleware:
    """Include routing errors (404/405) in the auth cache policy."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def send_no_store(message):
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message).update(NO_CACHE_HEADERS)
            await send(message)

        is_auth = scope["type"] == "http" and (
            scope["path"] == "/api/v1/ra/auth"
            or scope["path"].startswith("/api/v1/ra/auth/")
        )
        await self.app(scope, receive, send_no_store if is_auth else send)
