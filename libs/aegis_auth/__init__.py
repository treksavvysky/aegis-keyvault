import os
from typing import Any

import httpx
import jwt
from sqlalchemy import create_engine, text


class VerificationError(Exception):
    pass


def _get_database_url() -> str:
    return os.getenv("AEGIS_DATABASE_URL", "sqlite:///./aegis.db")


def _get_signing_key() -> str:
    key = os.getenv("AEGIS_SIGNING_KEY")
    if not key:
        raise VerificationError("AEGIS_SIGNING_KEY is required")
    return key


def is_token_revoked(jti: str, database_url: str | None = None) -> bool:
    url = database_url or _get_database_url()
    engine = create_engine(url, connect_args={"check_same_thread": False})
    with engine.connect() as conn:
        result = conn.execute(text("SELECT 1 FROM revoked_tokens WHERE jti = :jti"), {"jti": jti})
        return result.first() is not None


def verify_token(token: str, expected_aud: str) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            _get_signing_key(),
            algorithms=["HS256"],
            audience=expected_aud,
            options={"require": ["exp", "iat", "jti", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise VerificationError("Invalid token") from exc

    jti = claims.get("jti")
    if not jti:
        raise VerificationError("Missing jti")
    return claims


def require_scopes(claims: dict[str, Any], scopes: list[str]) -> None:
    token_scopes = set(claims.get("scopes", []))
    missing = [scope for scope in scopes if scope not in token_scopes]
    if missing:
        raise VerificationError(f"Missing scopes: {', '.join(missing)}")


def introspect_token(
    base_url: str,
    token: str,
    expected_aud: str | None = None,
    admin_token: str | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    if not admin_token:
        raise VerificationError("Admin token required for introspection")
    headers = {"Authorization": f"Bearer {token}", "X-Admin-Token": admin_token}
    payload: dict[str, Any] | None = None
    if expected_aud is not None:
        payload = {"expected_aud": expected_aud}
    try:
        response = httpx.post(
            f"{base_url.rstrip('/')}/v1/introspect",
            json=payload,
            headers=headers,
            timeout=timeout_seconds,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise VerificationError("Introspection failed") from exc
    return response.json()
