
from fastapi import FastAPI

app = FastAPI(
    title="Secure E-Voting API",
    description="Secure and Anonymous Electronic Voting System",
    version="0.1.0",
)


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "ok",
        "project": "secure-evoting",
        "stage": "foundation",
    }
