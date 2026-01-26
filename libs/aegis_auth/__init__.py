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


def _is_revoked(jti: str) -> bool:
    engine = create_engine(_get_database_url(), connect_args={"check_same_thread": False})
    with engine.connect() as conn:
        result = conn.execute(text("SELECT 1 FROM revoked_tokens WHERE jti = :jti"), {"jti": jti})
        return result.first() is not None


def verify_token(token: str, expected_aud: str, *, check_revocation: bool = True) -> dict[str, Any]:
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
    if check_revocation and _is_revoked(jti):
        raise VerificationError("Token revoked")
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
    timeout: float = 5.0,
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"}
    admin_token = os.getenv("AEGIS_ADMIN_TOKEN")
    if admin_token:
        headers["X-Admin-Token"] = admin_token
    payload: dict[str, Any] = {}
    if expected_aud:
        payload["expected_aud"] = expected_aud
    url = f"{base_url.rstrip('/')}/v1/introspect"
    response = httpx.post(url, json=payload, headers=headers, timeout=timeout)
    if response.status_code != 200:
        raise VerificationError(f"Introspection failed: {response.status_code}")
    return response.json()
