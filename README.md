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
- `POST /v1/introspect` (admin-only in v1) validates a token and reports active status.
- `POST /v1/revoke/token` revokes a token by `jti`.
- `POST /v1/revoke/key` disables or revokes an API key.

### Introspection (v1 admin-gated)

`POST /v1/introspect` currently requires `X-Admin-Token` to avoid shipping an oracle. The upgrade
path is to replace this gate with service-to-service auth using a scoped token (for example,
`introspect.token`) so introspection can be delegated safely.

Example flow:

```bash
# Mint a token
TOKEN_RESPONSE=$(curl -sS -X POST http://localhost:8000/v1/token \
  -H "Authorization: Bearer ${AEGIS_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"aud":"payments","scopes":["repo.read"],"ttl_seconds":300}')
export TOKEN_RESPONSE

ACCESS_TOKEN=$(python - <<'PY'
import json, os, sys
payload = json.loads(os.environ["TOKEN_RESPONSE"])
print(payload["access_token"])
PY
)

# Introspect (active)
curl -sS -X POST http://localhost:8000/v1/introspect \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "X-Admin-Token: ${AEGIS_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"expected_aud":"payments"}'

# Revoke
curl -sS -X POST http://localhost:8000/v1/revoke/token \
  -H "X-Admin-Token: ${AEGIS_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"jti\":\"$(python - <<'PY'
import json, os
payload = json.loads(os.environ["TOKEN_RESPONSE"])
print(payload["jti"])
PY
)\"}"

# Introspect (inactive)
curl -sS -X POST http://localhost:8000/v1/introspect \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "X-Admin-Token: ${AEGIS_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"expected_aud":"payments"}'
```

## Verification Library

Use `libs/aegis_auth` to verify tokens and enforce scopes:

```python
from libs.aegis_auth import introspect_token, require_scopes, verify_token

claims = verify_token(token, expected_aud="service")
require_scopes(claims, ["repo.read"])

introspection = introspect_token(
    base_url="http://localhost:8000",
    token=token,
    expected_aud="service",
    admin_token="admin-token",
)
```
