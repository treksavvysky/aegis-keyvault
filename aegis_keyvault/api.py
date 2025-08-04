from fastapi import FastAPI

from .database import check_database

app = FastAPI(title="Aegis KeyVault")


@app.get("/health")
def health():
    """Return service and database health status."""
    db_available = check_database()
    return {
        "server": "ok",
        "database": "ok" if db_available else "unavailable",
    }
