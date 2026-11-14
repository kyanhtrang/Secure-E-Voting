
from fastapi import FastAPI

from backend.ra.login_router import router as ra_login_router

app = FastAPI(
    title="Secure E-Voting API",
    description="Secure and Anonymous Electronic Voting System",
    version="0.1.0",
)


app.include_router(ra_login_router)


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "ok",
        "project": "secure-evoting",
        "stage": "foundation",
    }
