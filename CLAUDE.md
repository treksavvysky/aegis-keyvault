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

# Docker deployment
docker compose up -d                # Run on port 8001 (persists data to volume)
docker compose logs -f aegis        # View logs
```

## Architecture

```
services/aegis/     # FastAPI service
├── main.py         # API endpoints (/v1/keys, /v1/token, /v1/introspect, /v1/revoke/*, /v1/secrets/*, /v1/principals/*)
├── cli.py          # CLI tool (aegis-cli) for secure secret entry
├── models.py       # SQLAlchemy ORM (Principal w/ policy ceiling, ApiKey w/ resource binding, AuditEvent, RevokedToken, Secret)
├── schemas.py      # Pydantic request/response models
├── security.py     # Token minting, API key generation, bcrypt hashing, Fernet encryption
├── audit.py        # Append-only audit event emission
├── config.py       # Environment configuration
└── db.py           # Database session factory

libs/aegis_auth/    # Verification library for downstream services
└── __init__.py     # verify_token(), require_scopes(), introspect_token()

migrations/         # Alembic migrations
tests/              # pytest suite with in-memory SQLite
docs/               # Documentation
└── DEFERRED.md     # Deferred features and design notes
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
| GET | `/v1/secrets` | List secrets (metadata only) | X-Admin-Token |
| GET | `/v1/secrets/{name}` | Retrieve secret (resource-bound) | Bearer token with `secrets.read` scope |
| PUT | `/v1/secrets/{name}` | Rotate secret value | X-Admin-Token |
| DELETE | `/v1/secrets/{name}` | Soft-delete secret | X-Admin-Token |
| GET | `/v1/principals` | List all principals | X-Admin-Token |
| GET | `/v1/principals/{id}` | Principal detail with redacted keys | X-Admin-Token |
| PUT | `/v1/principals/{id}/policy` | Update scope/resource ceiling | X-Admin-Token |
| POST | `/v1/principals/{id}/disable` | Disable principal | X-Admin-Token |

## Non-Negotiable Security Invariants

These rules are enforced throughout the codebase and must never be weakened:

1. **API keys never authorize actions** — only mint tokens
2. **Tokens are short-lived** (default 15m, hard max 30m)
3. **Deny-by-default** — explicit scope allowlists only
4. **Audience binding required** — `aud` claim on all tokens; services reject wrong `aud`
5. **All token fields mandatory** — `aud`, `scopes`, `resource`, `ttl_seconds` required at mint time (400 if missing)
6. **Every privileged action is auditable** — trace_id → token_jti → action → result
7. **Principal ceiling is absolute** — no API key or token can exceed `max_scopes_json` / `max_resources_json` (NULL = unconstrained, `[]` = deny all)

## CLI Tool

The `aegis-cli` provides secure secret management without chat exposure:

```bash
# Configure
export AEGIS_URL=http://localhost:8001
export AEGIS_ADMIN_TOKEN=your-admin-token

# After pip install -e ., the CLI is available as:
aegis-cli secrets add ssh-pass:server1 --resource host:server1
aegis-cli secrets add mykey --type ssh-private-key --from-file ~/.ssh/id_rsa
aegis-cli secrets add github-token --type api-token
aegis-cli secrets list
aegis-cli secrets rotate ssh-pass:server1   # Atomic value rotation
aegis-cli secrets delete ssh-pass:server1
aegis-cli health
```

**Key security feature**: Secret values are entered via `getpass` (no-echo) and never appear in shell history, logs, or chat.

## Secrets Vault

Aegis includes a token-gated secrets vault for secure credential storage and retrieval:

- **Encrypted storage**: Secrets are Fernet-encrypted at rest (requires `AEGIS_ENCRYPTION_KEY`)
- **Secret types**: `password` (default), `ssh-private-key`, `api-token` (metadata only, no validation)
- **Resource binding**: Secrets can be bound to a resource (e.g., `host:dev-server-1`)
- **Token-gated access**: Retrieval requires a token with `secrets.read` scope and matching resource
- **File input**: Use `--from-file` to read multiline secrets (SSH keys) from files
- **Use case**: Charon retrieves SSH passwords from Aegis instead of receiving them through chat

```bash
# Store a secret via CLI (recommended - no chat exposure)
aegis-cli secrets add ssh-pass:server1 --resource host:server1

# Or via API (admin)
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
- **Resource binding**: Tokens can include a `resource` claim; secrets with resource require matching token; API keys can restrict allowed resources via `allowed_resources_json`
- **Principal ceiling**: `max_scopes_json` / `max_resources_json` on Principal; NULL = unconstrained, `[]` = deny all; enforced at key creation and token mint (defense-in-depth)
- **TTL bounds**: 1–1800 seconds (enforced in `security.py:compute_exp()`)
- **Trace propagation**: `X-Trace-Id` header flows through to audit metadata
- **Error responses**: 401 for auth failures, 403 for permission/scope/resource failures

## Verification Library

Downstream services use `libs/aegis_auth` to verify tokens:

```python
from libs.aegis_auth import verify_token, require_scopes, VerificationError

try:
    claims = verify_token(token, expected_aud="my-service")
    require_scopes(claims, ["repo.read"])
except VerificationError as e:
    # Handle invalid/expired/revoked token
```

## Testing

Tests use pytest with in-memory SQLite (`conftest.py` handles fixtures). Time-sensitive tests use `freezegun` for deterministic expiry behavior. Required test coverage includes token mint success/deny, scope validation, audience verification, expiry, and revocation.

## Development Status

**Completed Phases:**
- **Phase 0** — Minimal safe injection: CLI with no-echo `getpass` input
- **Phase 1** — Human-proofing: Rotation endpoint, confirmation prompts, metadata-only responses
- **Phase 2** — Operational maturity: Secret types (`password`, `ssh-private-key`, `api-token`), `--from-file` flag

**Roadmap (AuthZ hardening)** — see `docs/ROADMAP.md`:
- **Phase 0** (Core Correctness) — COMPLETE: All token fields mandatory, empty scopes rejected, resource_unbound audit flag
- **Phase 1** (Trust Boundaries) — COMPLETE: Principal policy ceiling, API key resource binding, principal management endpoints
- **Phase 2** (Delegation) — Token exchange for job-scoped authority without standing privilege
- **Phase 3** (Audit + Rotation) — Audit query API, signing/encryption key rotation

**Deferred features** (see `docs/DEFERRED.md`):
- SSH private key format validation (PEM checks)
- Client-side encryption (belt + suspenders)
