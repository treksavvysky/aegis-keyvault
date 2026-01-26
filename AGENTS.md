# AGENTS.md — Aegis (Identity + Scope Authority)

This file is the operating contract for AI agents (and humans) contributing to **Aegis**: the Identity + Scope Authority used as the trust layer for all agentic operations (JCT, Charon, sandboxes, etc.).

## Mission
Build a **boringly reliable** security primitive that:
- Issues **short-lived, scoped tokens** from **long-lived API keys**
- Enforces **audience binding** (`aud`) and **deny-by-default**
- Supports **revocation** and **audit logging** with traceable lineage
- Produces a small **verification library** used by downstream services

## Non-negotiable invariants
1. **API keys never authorize actions directly** — only mint tokens.
2. **Tokens are short-lived** (default 15m; hard max per policy).
3. **Deny by default** — explicit allowlists only.
4. **Audience-bound tokens** (`aud` required; services reject wrong `aud`).
5. **Every privileged action is auditable** with causal linkage:
   `request_id/trace_id → token_jti → action → result → artifact`.

## Scope of work (v1 MVP)
Implement these capabilities first:
- Principals + API keys
- Token minting (`POST /v1/token`)
- Token verification (shared library)
- Audit events on mint/deny + example downstream action logging
- Revocation:
  - API key disable (stop minting)
  - token revoke via denylist by `jti` (fast + simple)

Defer until later (do NOT overbuild):
- Complex RBAC/ABAC engines
- UI dashboards
- Multi-tenant org models
- Attestation frameworks

## Terminology
- **Principal**: an identity (user/agent/service/worker/sandbox).
- **Scope**: a permission string (e.g., `ssh.exec`, `repo.write`).
- **Resource**: a target identifier (e.g., `repo:justkeephiking`, `server:dev-xxl`).
- **Token**: signed, short-lived credential with `sub`, `scopes`, `aud`, `exp`, `jti`.
- **API key**: long-lived secret used only to request tokens.

## Repository expectations
If the repo structure differs, follow the spirit:
- `services/aegis/` — FastAPI service
- `libs/aegis_auth/` — verification library for downstream services
- `migrations/` — Alembic migrations (or equivalent)
- `tests/` — pytest tests (unit + integration)
- `docs/` — protocol and policy docs

## Interfaces (contract)
### Token minting
`POST /v1/token`

**Input**
- API key presented via `Authorization: Bearer <API_KEY>`
- JSON body:
  - `aud`: string (required)
  - `scopes`: array of strings (requested)
  - `ttl_seconds`: int (optional; default 900)

**Rules**
- Requested scopes MUST be a subset of the API key’s allowed scopes.
- TTL MUST be <= max TTL allowed by policy and > 0.
- `aud` MUST be present and valid.

**Output**
- `access_token`: signed token
- `token_type`: `"bearer"`
- `expires_in`: seconds
- `jti`: token id (for audit/revocation)

### Token format
Signed token MUST include:
- `sub` (principal_id)
- `scopes` (granted scopes)
- `aud` (service audience)
- `exp` (epoch seconds)
- `iat` (epoch seconds)
- `jti` (unique token id)
- optional `ctx` (job_id/repo_id/sandbox_id) — for later phases

### Verification library
Downstream services MUST verify:
- signature validity
- `exp` not expired
- `aud` matches expected audience
- required scopes satisfied

The library should expose:
- `verify_token(token: str, expected_aud: str) -> Claims`
- `require_scopes(claims: Claims, scopes: list[str]) -> None`

## Data model (minimum tables)
### `principals`
- `id` (uuid or ulid)
- `type` (`user|agent|service|worker|sandbox`)
- `name`
- `status` (`active|disabled`)
- timestamps

### `api_keys`
- `id`
- `principal_id`
- `key_hash` (never store plaintext)
- `allowed_scopes` (array/json)
- `status` (`active|revoked|disabled`)
- `created_at`, `last_used_at`

### `audit_events`
Append-only.
- `id`
- `ts`
- `principal_id`
- `event_type` (`key.created|key.used|token.minted|token.denied|token.revoked|action.performed`)
- `token_jti` (nullable)
- `scope` / `scopes` (nullable)
- `resource` (nullable)
- `result` (`ok|deny|error`)
- `metadata` (json)

### `revoked_tokens` (v1)
- `jti`
- `revoked_at`
- `reason` (optional)

## Security requirements
- **Hash API keys** using a modern KDF (e.g., argon2/bcrypt/scrypt). Never log plaintext keys.
- **Never log tokens** in full. If needed, log only `jti` and principal id.
- Token signing keys must be loaded from environment/secret manager; rotate-friendly design.
- Rate-limit token minting per key/principal.
- Add a consistent `trace_id` to requests and propagate into audit metadata.

## Testing requirements
Minimum test suite:
1. Mint token success with allowed scopes.
2. Mint token denied when requesting disallowed scope.
3. Mint token denied when `aud` missing/invalid.
4. Verification fails for wrong `aud`.
5. Verification fails for expired token.
6. Revoked `jti` token is rejected.
7. Audit events emitted for mint success/deny and for revoke.

Prefer deterministic time control in tests (freeze time).

## Engineering conventions
- Keep endpoints small and explicit.
- Prefer pure functions for policy checks.
- Avoid “clever” security abstractions.
- Every decision should be explainable in one sentence.

## Work protocol for agents
When making changes:
1. **State intent**: what capability you’re adding and why.
2. **Edit smallest surface area**: do not refactor unrelated code.
3. **Add tests** for every new policy rule or security check.
4. **Update docs** (this file or `docs/`) if you change contracts.
5. **Never weaken invariants** without explicit instruction.

## Definition of done (v1)
- Aegis can mint scoped short-lived tokens from API keys.
- Downstream service can verify token + enforce audience + scopes using shared library.
- Revocation works (API key disable + token `jti` denylist).
- Audit trail exists for token mint/deny/revoke and a sample privileged action.
- CI runs tests and passes.

## “Don’t do this” list
- Don’t add new scope strings without documenting the taxonomy.
- Don’t introduce long-lived bearer tokens.
- Don’t allow wildcard scopes (e.g., `*`) in v1.
- Don’t store plaintext secrets.
- Don’t build a UI before the trust primitive is solid.

## Quickstart (fill in per repo)
> Replace these with the repo’s actual commands.
- Install: `uv sync` or `poetry install`
- Run API: `uv run uvicorn services.aegis.main:app --reload`
- Run tests: `pytest -q`
- Migrate DB: `alembic upgrade head`

---

Aegis is the trust layer. If it’s ambiguous, choose the option that is **more explicit, more auditable, and easier to revoke**.
