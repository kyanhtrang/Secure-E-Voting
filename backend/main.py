
from fastapi import FastAPI

from backend.ra.login_router import router as ra_login_router
from backend.ra.session_router import router as ra_session_router
from backend.ra.auth_middleware import AuthNoStoreMiddleware

app = FastAPI(
    title="Secure E-Voting API",
    description="Secure and Anonymous Electronic Voting System",
    version="0.1.0",
)


app.include_router(ra_login_router)
app.include_router(ra_session_router)
app.add_middleware(AuthNoStoreMiddleware)


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "ok",
        "project": "secure-evoting",
        "stage": "foundation",
    }
