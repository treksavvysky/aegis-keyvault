# Aegis KeyVault (Aegis Core MVP)

Aegis KeyVault issues short-lived, audience-bound tokens from long-lived API keys. It is a deny-by-default trust primitive with audit logging and revocation.

## Quickstart

### Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configure

```bash
export AEGIS_SIGNING_KEY="change-me"
export AEGIS_ADMIN_TOKEN="change-me"
export AEGIS_DATABASE_URL="sqlite:///./aegis.db"
```

### Migrate

```bash
alembic upgrade head
```

### Run API

```bash
uvicorn services.aegis.main:app --reload
```

### Tests

```bash
pytest -q
```

## API Overview

- `POST /v1/keys` (admin-only) creates a principal + API key. The plaintext key is returned once.
- `POST /v1/token` mints a short-lived, audience-bound token from an API key.
- `POST /v1/introspect` (admin-token protected) checks token status without DB access.
- `POST /v1/revoke/token` revokes a token by `jti`.
- `POST /v1/revoke/key` disables or revokes an API key.

## Verification Library

Use `libs/aegis_auth` to verify tokens and enforce scopes:

```python
from libs.aegis_auth import verify_token, require_scopes

claims = verify_token(token, expected_aud="service")
require_scopes(claims, ["repo.read"])
```

## Introspection Example

```bash
curl -X POST http://localhost:8000/v1/introspect \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Admin-Token: $AEGIS_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"expected_aud":"service"}'
```
