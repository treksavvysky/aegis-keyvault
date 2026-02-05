# Aegis KeyVault — Development Roadmap

> Vault + AuthZ server for agentic operations.
> Each phase has a **Definition of Done (DoD)** that must be provable with tests before moving on.

---

## Current State (as of 2026-02-05)

What already works:

| Capability | Status | Notes |
|---|---|---|
| Token minting with `aud` required | Done | 400 if missing |
| Scope allowlist on API keys | Done | `allowed_scopes_json` on ApiKey |
| Resource-scoped secret retrieval | Done | 403 on mismatch, tested |
| Short-lived tokens (15m default, 30m max) | Done | Enforced in `compute_exp()` |
| Fernet-encrypted secrets at rest | Done | `AEGIS_ENCRYPTION_KEY` |
| Audit event emission (12+ event types) | Done | Append-only, no query API |
| CLI with `getpass` (no-echo secrets) | Done | `aegis-cli secrets add` |
| Secret types + `--from-file` | Done | Phase 2 of original roadmap |
| Secret rotation endpoint | Done | `PUT /v1/secrets/{name}` |

What's missing, organized into the four phases below.

---

## Phase 0 — Core Correctness

**Goal**: Token minting is strict. Every field that matters is mandatory. Reading a secret is provably impossible without the right scope AND the right resource.

### 0.1 — Make `scopes`, `resource`, and `ttl_seconds` required in token mint

**Current gap**: `TokenRequest` schema defaults `scopes` to `[]`, `resource` to `None`, and `ttl_seconds` to `None`. A caller can mint a token with no scopes and no resource binding, which violates deny-by-default for any token-gated operation.

**Changes**:
- `services/aegis/schemas.py` — Remove defaults from `scopes`, `resource`, `ttl_seconds` in `TokenRequest`. All three become required fields alongside `aud`.
- `services/aegis/main.py` — Remove the server-side fallback for `ttl_seconds` (currently defaults to 900). The caller must choose explicitly.
- `services/aegis/security.py` — `mint_token()` already accepts these; no change needed, but add a guard that rejects `scopes=[]` at the security layer as defense-in-depth.

**Migration**: None (schema change only affects request validation, not DB).

### 0.2 — Reject empty-scope tokens at mint time

**Current gap**: A token can be minted with `scopes: []` if the API key's allowlist is also empty. This produces a useless but valid JWT.

**Changes**:
- `services/aegis/main.py` `/v1/token` — Return 400 if `scopes` is empty after validation, with audit event `token.denied` reason `"empty_scopes"`.
- Add test: mint with empty scopes → 400.

### 0.3 — Enforce resource on secret retrieval (harden)

**Current state**: Resource enforcement is correct — a token without a matching resource cannot read a resource-bound secret. But secrets created *without* a resource have no resource check at all.

**Decision point**: Should all secrets require a resource? Or is an unbound secret (accessible to any token with `secrets.read`) a valid use case?

**Recommendation**: Keep unbound secrets as a valid escape hatch (e.g., global config), but add an audit flag `"resource_unbound": true` to `secret.accessed` events so operators can detect over-broad access patterns.

**Changes**:
- `services/aegis/main.py` — Add `resource_unbound` metadata to audit event when an unbound secret is read.
- Add test: read unbound secret → succeeds, audit includes `resource_unbound: true`.

### 0.4 — TTL boundary enforcement tests

**Current gap**: `compute_exp()` enforces 1–1800s but there are no tests for the boundaries.

**Changes**:
- `tests/test_token_flow.py` — Add tests for `ttl_seconds=0` (reject), `ttl_seconds=1` (accept), `ttl_seconds=1800` (accept), `ttl_seconds=1801` (reject), `ttl_seconds=-1` (reject).

### DoD

> **"Read secret" is impossible without `secrets.read` + matching resource.**

Prove with tests:
- [ ] Token mint without `scopes` → 400
- [ ] Token mint without `resource` → 400
- [ ] Token mint without `ttl_seconds` → 400
- [ ] Token with `secrets.read` but wrong resource → 403
- [ ] Token with `secrets.read` and correct resource → 200
- [ ] Token without `secrets.read` scope → 403
- [ ] Unbound secret read → succeeds but audit flags it
- [ ] TTL boundaries enforced (0, 1, 1800, 1801, -1)

---

## Phase 1 — Trust Boundaries

**Goal**: Principals have identity. Policy lives at the principal level, not just on individual API keys. A principal's ceiling is defined once, and no API key can exceed it.

### 1.1 — Principal policy model

**Current gap**: The `Principal` model has `id`, `type`, `name`, `status` — no policy fields. All scope policy lives on `ApiKey.allowed_scopes_json`. This means:
- Creating a new API key for a principal can grant any scope.
- There's no way to say "this principal can never have `secrets.read`".

**Changes**:
- `services/aegis/models.py` — Add to `Principal`:
  ```python
  max_scopes_json = Column(Text, default="[]")      # Principal ceiling
  max_resources_json = Column(Text, default="[]")    # Allowed resource patterns
  ```
- `migrations/versions/0004_principal_policy.py` — Add columns with default `"[]"`.
- `services/aegis/schemas.py` — Add `max_scopes` and `max_resources` to `KeyCreateRequest` (optional, default `[]` for backward compat during migration).

### 1.2 — Enforce principal ceiling at key creation

**Changes**:
- `services/aegis/main.py` `POST /v1/keys` — When creating an API key, validate that `allowed_scopes ⊆ principal.max_scopes`. Reject with 403 if any scope exceeds the ceiling.
- Same for resources: `allowed_resources` on the key must be a subset of `principal.max_resources`.
- Add audit event `key.denied` with reason `"scope_ceiling_exceeded"`.

### 1.3 — Enforce principal ceiling at token mint

**Changes**:
- `services/aegis/main.py` `POST /v1/token` — After checking API key allowlist, also check principal ceiling. This is defense-in-depth: even if an API key somehow has a scope the principal shouldn't, the mint is denied.
- Add audit event `token.denied` with reason `"principal_ceiling_exceeded"`.

### 1.4 — Principal management endpoints

**Changes**:
- `GET /v1/principals` — List all principals (admin only). Returns id, name, type, status, max_scopes, max_resources.
- `GET /v1/principals/{id}` — Get principal detail including all API keys (redacted) and policy.
- `PUT /v1/principals/{id}/policy` — Update max_scopes and max_resources. Validates that no existing API key exceeds the new ceiling (reject or auto-disable keys that violate).
- `POST /v1/principals/{id}/disable` — Disable principal (cascades: all tokens from this principal's keys become invalid on next introspect).

### 1.5 — API key resource binding

**Current gap**: API keys have `allowed_scopes_json` but no resource restriction. A key with `secrets.read` can mint a token for any resource.

**Changes**:
- `services/aegis/models.py` — Add `allowed_resources_json` to `ApiKey`.
- `migrations/versions/0004_principal_policy.py` — Include in same migration.
- `services/aegis/main.py` `POST /v1/token` — Validate `requested_resource ∈ api_key.allowed_resources`. If key has empty allowed_resources, fall back to principal ceiling.

### DoD

> **DevOps Guide principal cannot ever obtain `secrets.read` directly.**

Prove with tests:
- [ ] Create principal with `max_scopes: ["repo.read", "ssh.exec"]` (no `secrets.read`)
- [ ] Attempt to create API key with `allowed_scopes: ["secrets.read"]` → 403
- [ ] Attempt to create API key with `allowed_scopes: ["repo.read"]` → 200
- [ ] Mint token with `scopes: ["secrets.read"]` from that key → denied (scope not on key)
- [ ] Even if key somehow has `secrets.read`, principal ceiling blocks it
- [ ] Principal policy update that would violate existing keys → rejected or keys auto-disabled
- [ ] Disabled principal → all token mints fail

---

## Phase 2 — Delegation

**Goal**: A principal (e.g., DevOps Guide) can request a token *on behalf of* another principal (e.g., Charon), with tightly scoped permissions and short TTL. No standing privilege — authority is granted per-job.

### 2.1 — Token exchange endpoint

**New endpoint**: `POST /v1/token/exchange`

**Request**:
```json
{
  "subject_token": "<caller's valid JWT>",
  "target_principal": "charon",
  "target_aud": "aegis",
  "scopes": ["secrets.read"],
  "resource": "host:server1",
  "ttl_seconds": 60
}
```

**Semantics**:
- Caller presents their own valid token (`subject_token`).
- Aegis mints a *new* token for `target_principal` with the requested scopes/resource.
- The new token's `sub` is the target principal. A `delegated_by` claim identifies the caller.
- The new token's TTL cannot exceed the caller's remaining TTL.
- Scopes must be a subset of what the target principal is allowed (principal ceiling) AND what the caller is allowed to delegate.

### 2.2 — Delegation policy

**Changes**:
- `services/aegis/models.py` — Add to `Principal`:
  ```python
  can_delegate_to_json = Column(Text, default="[]")   # List of principal IDs
  delegable_scopes_json = Column(Text, default="[]")   # Scopes this principal can delegate
  ```
- A principal can only delegate scopes that are in its own `max_scopes` AND in `delegable_scopes`.
- A principal can only delegate to principals listed in `can_delegate_to`.

### 2.3 — Delegation audit trail

**Changes**:
- New audit event type: `token.delegated` with metadata:
  ```json
  {
    "delegator_principal": "devops-guide",
    "delegator_jti": "abc123",
    "target_principal": "charon",
    "target_jti": "def456",
    "scopes": ["secrets.read"],
    "resource": "host:server1",
    "ttl_seconds": 60
  }
  ```
- Delegated tokens include `delegated_by` in JWT claims, visible on introspect.

### 2.4 — Delegation chain limits

**Safety rails**:
- Maximum delegation depth: 1 (no re-delegation of delegated tokens).
- Delegated tokens cannot be used to delegate further (check `delegated_by` claim; if present, reject exchange).
- Delegated token TTL hard max: min(caller's remaining TTL, 300s).

### DoD

> **You can authorize a job without granting standing privilege.**

Prove with tests:
- [ ] DevOps Guide mints token, exchanges for Charon token with `secrets.read` + resource → succeeds
- [ ] Charon token reads secret → succeeds
- [ ] DevOps Guide's own token cannot read secrets directly (no `secrets.read` in its ceiling)
- [ ] Delegated token cannot be re-delegated → 403
- [ ] Delegated TTL cannot exceed caller's remaining TTL
- [ ] Delegation to unauthorized principal → 403
- [ ] Delegation of unauthorized scope → 403
- [ ] `token.delegated` audit event emitted with full chain
- [ ] Introspect delegated token → shows `delegated_by` claim

---

## Phase 3 — Audit + Rotation

**Goal**: Full observability into who accessed what, when. Safe rotation of signing and encryption keys without downtime or data loss.

### 3.1 — Audit query API

**New endpoints**:
- `GET /v1/audit` — Query audit events (admin only).
  - Filters: `principal_id`, `event_type`, `result`, `resource`, `token_jti`, `after` (timestamp), `before` (timestamp).
  - Pagination: `limit` (default 100, max 1000), `offset`.
  - Sort: newest first (default).
- `GET /v1/audit/summary` — Aggregate view (admin only).
  - Group by principal, event_type, result.
  - Time window: `last_hours` (default 24).

**Changes**:
- `services/aegis/schemas.py` — Add `AuditQueryParams`, `AuditEventResponse`, `AuditSummaryResponse`.
- `services/aegis/main.py` — Implement endpoints with SQLAlchemy queries.
- Index on `audit_events(ts, principal_id, event_type)` for query performance.
- `migrations/versions/0005_audit_indexes.py` — Add composite index.

### 3.2 — Signing key rotation

**Problem**: Currently `AEGIS_SIGNING_KEY` is a single value. Rotating it invalidates all outstanding tokens instantly.

**Strategy**: Key versioning with graceful rollover.

**Changes**:
- `services/aegis/config.py` — Support `AEGIS_SIGNING_KEY` (current) and `AEGIS_SIGNING_KEY_PREVIOUS` (old, verify-only).
- `services/aegis/security.py`:
  - `mint_token()` — Always sign with current key. Add `kid` (key ID) header to JWT.
  - `decode_token()` — Try current key first. If signature fails and `kid` matches previous, try previous key. If both fail, reject.
- Rotation procedure:
  1. Set `AEGIS_SIGNING_KEY_PREVIOUS` = current key.
  2. Set `AEGIS_SIGNING_KEY` = new key.
  3. Restart/reload service.
  4. Wait for max TTL (30m) to pass.
  5. Remove `AEGIS_SIGNING_KEY_PREVIOUS`.
- Add audit event `system.key_rotated` (logged at startup if previous key is set).

### 3.3 — Encryption key rotation

**Problem**: `AEGIS_ENCRYPTION_KEY` is used for Fernet encryption of secrets. Rotating it breaks decryption of all existing secrets.

**Strategy**: Re-encryption migration with dual-key support.

**Changes**:
- `services/aegis/config.py` — Support `AEGIS_ENCRYPTION_KEY` (current) and `AEGIS_ENCRYPTION_KEY_PREVIOUS` (old, decrypt-only).
- `services/aegis/security.py`:
  - `decrypt_secret()` — Try current key. If decryption fails, try previous key. If previous succeeds, re-encrypt with current key and update DB (lazy re-encryption).
  - `encrypt_secret()` — Always use current key.
- `services/aegis/cli.py` — Add `aegis-cli admin reencrypt` command that batch re-encrypts all secrets with the current key (eager migration).
- `services/aegis/models.py` — Add `encryption_key_version` column to `Secret` to track which key was used.
- `migrations/versions/0006_encryption_key_version.py` — Add column.
- Rotation procedure:
  1. Generate new key.
  2. Set `AEGIS_ENCRYPTION_KEY_PREVIOUS` = current key.
  3. Set `AEGIS_ENCRYPTION_KEY` = new key.
  4. Restart service (lazy re-encryption starts).
  5. Run `aegis-cli admin reencrypt` (eager completion).
  6. Verify all secrets updated: `SELECT count(*) FROM secrets WHERE encryption_key_version != 'current'`.
  7. Remove `AEGIS_ENCRYPTION_KEY_PREVIOUS`.

### 3.4 — Audit completeness review

Verify every privileged action has an audit trail:

| Action | Event Type | Status |
|---|---|---|
| Create API key | `key.created` | Done |
| Revoke API key | `key.revoked` | Done |
| Disable API key | `key.disabled` | Done |
| Mint token | `token.minted` | Done |
| Deny token | `token.denied` | Done |
| Revoke token | `token.revoked` | Done |
| Introspect token | `token.introspected` | Done |
| Create secret | `secret.created` | Done |
| Read secret | `secret.accessed` | Done |
| Deny secret read | `secret.denied` | Done |
| Delete secret | `secret.deleted` | Done |
| Rotate secret | `secret.rotated` | Done |
| Delegate token | `token.delegated` | Phase 2 |
| Update principal policy | `principal.policy_updated` | Phase 1 |
| Disable principal | `principal.disabled` | Phase 1 |
| Query audit log | `audit.queried` | Phase 3 |
| Re-encrypt secrets | `system.reencrypt` | Phase 3 |
| Signing key rotation | `system.key_rotated` | Phase 3 |

### DoD

> **You can answer "who accessed what, when" and rotate keys safely.**

Prove with tests:
- [ ] `GET /v1/audit?principal_id=X&event_type=secret.accessed` returns correct events
- [ ] `GET /v1/audit?after=T1&before=T2` returns events in time window
- [ ] `GET /v1/audit/summary?last_hours=24` returns grouped counts
- [ ] Signing key rotation: mint with old key, rotate, verify old token still works, mint with new key, both tokens valid
- [ ] After max TTL passes with old key removed: old tokens rejected
- [ ] Encryption key rotation: store secret with old key, rotate, read secret (lazy re-encrypt), verify re-encrypted
- [ ] `aegis-cli admin reencrypt` batch processes all secrets
- [ ] All new event types in audit completeness table are emitted

---

## Dependency Graph

```
Phase 0 (Core Correctness)
    │
    ▼
Phase 1 (Trust Boundaries)
    │
    ├──────────────────┐
    ▼                  ▼
Phase 2 (Delegation)   Phase 3 (Audit + Rotation)
```

Phase 0 is prerequisite to all others. Phase 1 is prerequisite to Phase 2 (delegation needs principal policy). Phases 2 and 3 are independent and can be developed in parallel.

---

## Migration Plan

| Migration | Phase | Description |
|---|---|---|
| `0004_principal_policy` | 1 | Add `max_scopes_json`, `max_resources_json` to Principal; `allowed_resources_json` to ApiKey |
| `0005_audit_indexes` | 3 | Composite index on `audit_events(ts, principal_id, event_type)` |
| `0006_encryption_key_version` | 3 | Add `encryption_key_version` to Secret |
| `0007_delegation_policy` | 2 | Add `can_delegate_to_json`, `delegable_scopes_json` to Principal |

---

## File Change Summary

| File | Phase 0 | Phase 1 | Phase 2 | Phase 3 |
|---|---|---|---|---|
| `services/aegis/schemas.py` | Modify | Modify | Modify | Modify |
| `services/aegis/main.py` | Modify | Modify | Modify | Modify |
| `services/aegis/security.py` | Minor | Minor | Modify | Modify |
| `services/aegis/models.py` | — | Modify | Modify | Modify |
| `services/aegis/config.py` | — | — | — | Modify |
| `services/aegis/audit.py` | — | — | — | Minor |
| `services/aegis/cli.py` | — | — | — | Modify |
| `libs/aegis_auth/__init__.py` | — | — | Minor | Modify |
| `tests/test_token_flow.py` | Modify | Modify | Modify | Modify |
| `tests/test_secrets.py` | Modify | Modify | — | Modify |
| `tests/test_principals.py` | — | New | — | — |
| `tests/test_delegation.py` | — | — | New | — |
| `tests/test_audit_query.py` | — | — | — | New |
| `tests/test_key_rotation.py` | — | — | — | New |
| `migrations/versions/` | — | 0004 | 0007 | 0005, 0006 |
