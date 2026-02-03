# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Aegis KeyVault is a **deny-by-default identity service** that issues short-lived, audience-bound JWT tokens from long-lived API keys. It serves as the trust primitive for agentic operations, enforcing explicit scope allowlists, audit logging, and revocation capabilities.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt
# Or with test dependencies:
pip install -e ".[test]"

# Configure (required)
export AEGIS_SIGNING_KEY="your-secret-key"
export AEGIS_ADMIN_TOKEN="your-admin-token"
export AEGIS_DATABASE_URL="sqlite:///./aegis.db"
export AEGIS_ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Database migrations
alembic upgrade head          # Apply all migrations
alembic downgrade -1          # Rollback one revision

# Run API (development)
uvicorn services.aegis.main:app --reload

# Run tests
pytest -q                                          # All tests
pytest tests/test_token_flow.py -v                 # Specific file
pytest tests/test_token_flow.py::test_mint_token_success -v  # Single test

# Lint
ruff check .
ruff format .
```

## Architecture

```
services/aegis/     # FastAPI service
├── main.py         # API endpoints (/v1/keys, /v1/token, /v1/introspect, /v1/revoke/*, /v1/secrets/*)
├── models.py       # SQLAlchemy ORM (Principal, ApiKey, AuditEvent, RevokedToken, Secret)
├── schemas.py      # Pydantic request/response models
├── security.py     # Token minting, API key generation, bcrypt hashing, Fernet encryption
├── audit.py        # Append-only audit event emission
├── config.py       # Environment configuration
└── db.py           # Database session factory

libs/aegis_auth/    # Verification library for downstream services
└── __init__.py     # verify_token(), require_scopes(), introspect_token()

migrations/         # Alembic migrations
tests/              # pytest suite with in-memory SQLite
```

## Key Endpoints

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| POST | `/v1/keys` | Create principal + API key | X-Admin-Token |
| POST | `/v1/token` | Mint short-lived token from API key | Bearer API_KEY |
| POST | `/v1/introspect` | Check token validity | Bearer token + X-Admin-Token |
| POST | `/v1/revoke/token` | Revoke token by jti | X-Admin-Token |
| POST | `/v1/revoke/key` | Disable/revoke API key | X-Admin-Token |
| POST | `/v1/secrets` | Store encrypted secret | X-Admin-Token |
| GET | `/v1/secrets/{name}` | Retrieve secret (resource-bound) | Bearer token with `secrets.read` scope |
| DELETE | `/v1/secrets/{name}` | Soft-delete secret | X-Admin-Token |

## Non-Negotiable Security Invariants

These rules are enforced throughout the codebase and must never be weakened:

1. **API keys never authorize actions** — only mint tokens
2. **Tokens are short-lived** (default 15m, hard max 30m)
3. **Deny-by-default** — explicit scope allowlists only
4. **Audience binding required** — `aud` claim on all tokens; services reject wrong `aud`
5. **Every privileged action is auditable** — trace_id → token_jti → action → result

## Secrets Vault

Aegis includes a token-gated secrets vault for secure credential storage and retrieval:

- **Encrypted storage**: Secrets are Fernet-encrypted at rest (requires `AEGIS_ENCRYPTION_KEY`)
- **Resource binding**: Secrets can be bound to a resource (e.g., `host:dev-server-1`)
- **Token-gated access**: Retrieval requires a token with `secrets.read` scope and matching resource
- **Use case**: Charon retrieves SSH passwords from Aegis instead of receiving them through chat

```bash
# Store a secret (admin)
curl -X POST http://localhost:8000/v1/secrets \
  -H "X-Admin-Token: $AEGIS_ADMIN_TOKEN" \
  -d '{"name": "ssh-pass:server1", "value": "password", "resource": "host:server1"}'

# Mint token with resource binding
curl -X POST http://localhost:8000/v1/token \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"aud": "aegis", "scopes": ["secrets.read"], "resource": "host:server1"}'

# Retrieve secret (token must have matching resource)
curl http://localhost:8000/v1/secrets/ssh-pass:server1 \
  -H "Authorization: Bearer $TOKEN"
```

## Key Patterns

- **API key format**: `{key_id}.{secret}` — plaintext returned only at creation
- **Scope validation**: No wildcards allowed; explicit strings like `repo.read`, `ssh.exec`, `secrets.read`
- **Resource binding**: Tokens can include a `resource` claim; secrets with resource require matching token
- **TTL bounds**: 1–1800 seconds (enforced in `security.py:compute_exp()`)
- **Trace propagation**: `X-Trace-Id` header flows through to audit metadata
- **Error responses**: 401 for auth failures, 403 for permission/scope/resource failures

## Testing

Tests use pytest with in-memory SQLite (`conftest.py` handles fixtures). Time-sensitive tests use `freezegun` for deterministic expiry behavior. Required test coverage includes token mint success/deny, scope validation, audience verification, expiry, and revocation.
