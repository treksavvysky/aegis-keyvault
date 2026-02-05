import datetime as dt
import secrets
import uuid

import bcrypt
import jwt
from cryptography.fernet import Fernet

from .config import DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS, get_encryption_key, get_signing_key


class TokenError(ValueError):
    pass


def generate_api_key() -> tuple[str, str, str]:
    key_id = str(uuid.uuid4())
    secret = secrets.token_urlsafe(32)
    api_key = f"{key_id}.{secret}"
    return api_key, key_id, secret


def hash_secret(secret: str) -> str:
    hashed = bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_secret(secret: str, hashed: str) -> bool:
    return bcrypt.checkpw(secret.encode("utf-8"), hashed.encode("utf-8"))


def get_cipher() -> Fernet:
    """Get Fernet cipher for secret encryption/decryption."""
    return Fernet(get_encryption_key())


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret value for storage."""
    return get_cipher().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a secret value from storage."""
    return get_cipher().decrypt(ciphertext.encode()).decode()


def parse_api_key(raw_key: str) -> tuple[str, str]:
    if "." not in raw_key:
        raise TokenError("Invalid API key format")
    key_id, secret = raw_key.split(".", 1)
    if not key_id or not secret:
        raise TokenError("Invalid API key format")
    return key_id, secret


def validate_scopes(scopes: list[str]) -> None:
    if not scopes:
        raise TokenError("scopes required")
    if any(scope.strip() == "*" for scope in scopes):
        raise TokenError("Wildcard scopes are not allowed")
    if any(not scope or scope.strip() == "" for scope in scopes):
        raise TokenError("Empty scope is not allowed")


def compute_exp(ttl_seconds: int | None) -> tuple[int, int, int]:
    ttl = DEFAULT_TTL_SECONDS if ttl_seconds is None else ttl_seconds
    if ttl <= 0:
        raise TokenError("TTL must be positive")
    if ttl > MAX_TTL_SECONDS:
        raise TokenError("TTL exceeds maximum")
    now = dt.datetime.now(dt.timezone.utc)
    exp = now + dt.timedelta(seconds=ttl)
    return int(now.timestamp()), int(exp.timestamp()), ttl


def mint_token(
    sub: str,
    scopes: list[str],
    aud: str,
    ttl_seconds: int | None,
    *,
    key_id: str | None = None,
    resource: str | None = None,
) -> tuple[str, str, int]:
    iat, exp, ttl = compute_exp(ttl_seconds)
    jti = str(uuid.uuid4())
    payload = {
        "sub": sub,
        "scopes": scopes,
        "aud": aud,
        "iat": iat,
        "exp": exp,
        "jti": jti,
    }
    if key_id:
        payload["key_id"] = key_id
    if resource:
        payload["resource"] = resource
    token = jwt.encode(payload, get_signing_key(), algorithm="HS256")
    return token, jti, ttl
