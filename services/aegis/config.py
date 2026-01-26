import os

DEFAULT_DB_URL = "sqlite:///./aegis.db"


def get_database_url() -> str:
    return os.getenv("AEGIS_DATABASE_URL", DEFAULT_DB_URL)


def get_signing_key() -> str:
    key = os.getenv("AEGIS_SIGNING_KEY")
    if not key:
        raise RuntimeError("AEGIS_SIGNING_KEY is required")
    return key


def get_admin_token() -> str:
    token = os.getenv("AEGIS_ADMIN_TOKEN")
    if not token:
        raise RuntimeError("AEGIS_ADMIN_TOKEN is required")
    return token


DEFAULT_TTL_SECONDS = 900
MAX_TTL_SECONDS = 1800
