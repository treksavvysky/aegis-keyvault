"""Tests for Phase 1 — Trust Boundaries (principal policy ceiling)."""

from services.aegis.models import ApiKey, AuditEvent
from services.aegis.security import hash_secret

ADMIN = {"X-Admin-Token": "test-admin-token"}


def _create_key(client, *, scopes=None, max_scopes=None, max_resources=None,
                allowed_resources=None, principal_id=None):
    """Create an API key, optionally with principal ceiling."""
    if scopes is None:
        scopes = ["repo.read"]
    body = {"allowed_scopes": scopes}
    if principal_id:
        body["principal_id"] = principal_id
    else:
        body["principal_name"] = "agent"
        body["principal_type"] = "service"
    if max_scopes is not None:
        body["max_scopes"] = max_scopes
    if max_resources is not None:
        body["max_resources"] = max_resources
    if allowed_resources is not None:
        body["allowed_resources"] = allowed_resources
    resp = client.post("/v1/keys", headers=ADMIN, json=body)
    return resp


def _mint_token(client, api_key, *, scopes=None, resource="any:default"):
    """Mint a token from an API key."""
    if scopes is None:
        scopes = ["repo.read"]
    resp = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"aud": "test", "scopes": scopes, "ttl_seconds": 300, "resource": resource},
    )
    return resp


# --- DoD: principal ceiling at key creation ---


def test_create_principal_with_scope_ceiling(client):
    """Key with scopes within ceiling succeeds."""
    resp = _create_key(client, scopes=["repo.read"], max_scopes=["repo.read", "ssh.exec"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["api_key"]
    assert data["principal_id"]


def test_key_denied_exceeds_scope_ceiling(client, db_session):
    """Key with scopes outside ceiling is rejected with 403."""
    resp = _create_key(client, scopes=["secrets.read"], max_scopes=["repo.read", "ssh.exec"])
    assert resp.status_code == 403
    assert resp.json()["detail"] == "scope_ceiling_exceeded"

    # Verify audit event
    event = db_session.query(AuditEvent).filter_by(event_type="key.denied").first()
    assert event is not None
    assert event.result == "deny"
    assert event.metadata_json["reason"] == "scope_ceiling_exceeded"


def test_resource_ceiling_on_key(client):
    """Key with resources outside principal ceiling is rejected."""
    # Create principal with resource ceiling
    resp = _create_key(
        client,
        scopes=["repo.read"],
        max_scopes=["repo.read"],
        max_resources=["host:a"],
        allowed_resources=["host:b"],
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "resource_ceiling_exceeded"


def test_resource_ceiling_allows_subset(client):
    """Key with resources within principal ceiling succeeds."""
    resp = _create_key(
        client,
        scopes=["repo.read"],
        max_scopes=["repo.read"],
        max_resources=["host:a", "host:b"],
        allowed_resources=["host:a"],
    )
    assert resp.status_code == 200


# --- DoD: principal ceiling at token mint (defense-in-depth) ---


def test_token_denied_by_principal_ceiling(client, db_session):
    """Even if key somehow has an out-of-ceiling scope, mint is blocked."""
    # Create principal with ceiling
    resp = _create_key(client, scopes=["repo.read"], max_scopes=["repo.read"])
    assert resp.status_code == 200
    principal_id = resp.json()["principal_id"]

    # Manually insert a key with secrets.read (bypassing ceiling check)
    from services.aegis.security import generate_api_key

    rogue_key, rogue_id, rogue_secret = generate_api_key()
    rogue = ApiKey(
        id=rogue_id,
        principal_id=principal_id,
        key_hash=hash_secret(rogue_secret),
        allowed_scopes_json=["secrets.read"],
    )
    db_session.add(rogue)
    db_session.commit()

    # Try to mint with the rogue key
    resp = _mint_token(client, rogue_key, scopes=["secrets.read"])
    assert resp.status_code == 403
    assert resp.json()["detail"] == "principal_ceiling_exceeded"

    event = db_session.query(AuditEvent).filter_by(
        event_type="token.denied",
    ).order_by(AuditEvent.ts.desc()).first()
    assert event.metadata_json["reason"] == "principal_ceiling_exceeded"


def test_unconstrained_principal_allows_any_scope(client):
    """Principal with NULL ceiling (no max_scopes) allows any scope — backward compat."""
    resp = _create_key(client, scopes=["secrets.read", "repo.read"])
    assert resp.status_code == 200
    api_key = resp.json()["api_key"]

    resp = _mint_token(client, api_key, scopes=["secrets.read"])
    assert resp.status_code == 200


def test_key_resource_binding_at_mint(client):
    """Key with allowed_resources blocks mint for non-matching resource."""
    resp = _create_key(
        client,
        scopes=["repo.read"],
        allowed_resources=["host:a"],
    )
    assert resp.status_code == 200
    api_key = resp.json()["api_key"]

    # Mint for allowed resource
    resp = _mint_token(client, api_key, resource="host:a")
    assert resp.status_code == 200

    # Mint for disallowed resource
    resp = _mint_token(client, api_key, resource="host:b")
    assert resp.status_code == 403
    assert resp.json()["detail"] == "resource not allowed"


# --- Principal management endpoints ---


def test_list_principals(client):
    """GET /v1/principals returns all principals."""
    _create_key(client, scopes=["repo.read"], max_scopes=["repo.read"])
    resp = client.get("/v1/principals", headers=ADMIN)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["principals"]) >= 1
    p = data["principals"][0]
    assert "id" in p
    assert "name" in p
    assert "max_scopes" in p


def test_get_principal_detail(client):
    """GET /v1/principals/{id} returns detail with redacted keys."""
    resp = _create_key(client, scopes=["repo.read"], max_scopes=["repo.read", "ssh.exec"])
    principal_id = resp.json()["principal_id"]

    resp = client.get(f"/v1/principals/{principal_id}", headers=ADMIN)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == principal_id
    assert data["max_scopes"] == ["repo.read", "ssh.exec"]
    assert len(data["api_keys"]) == 1
    assert "key_id" in data["api_keys"][0]
    assert "key_hash" not in data["api_keys"][0]


def test_get_principal_not_found(client):
    resp = client.get("/v1/principals/nonexistent", headers=ADMIN)
    assert resp.status_code == 404


def test_policy_update_success(client, db_session):
    """PUT /v1/principals/{id}/policy updates ceiling."""
    resp = _create_key(client, scopes=["repo.read"], max_scopes=["repo.read", "ssh.exec"])
    principal_id = resp.json()["principal_id"]

    resp = client.put(
        f"/v1/principals/{principal_id}/policy",
        headers=ADMIN,
        json={"max_scopes": ["repo.read", "ssh.exec", "deploy.run"]},
    )
    assert resp.status_code == 200

    # Verify audit event
    event = db_session.query(AuditEvent).filter_by(event_type="principal.policy_updated").first()
    assert event is not None
    assert event.result == "ok"

    # Verify stored
    resp = client.get(f"/v1/principals/{principal_id}", headers=ADMIN)
    assert resp.json()["max_scopes"] == ["repo.read", "ssh.exec", "deploy.run"]


def test_policy_update_rejected_on_conflict(client, db_session):
    """Policy narrowing that conflicts with existing keys is rejected."""
    resp = _create_key(
        client, scopes=["repo.read", "ssh.exec"], max_scopes=["repo.read", "ssh.exec"],
    )
    principal_id = resp.json()["principal_id"]

    # Try to narrow ceiling to just repo.read — key has ssh.exec
    resp = client.put(
        f"/v1/principals/{principal_id}/policy",
        headers=ADMIN,
        json={"max_scopes": ["repo.read"]},
    )
    assert resp.status_code == 409
    assert resp.json()["detail"] == "policy_conflict"

    # Audit denial
    event = db_session.query(AuditEvent).filter_by(event_type="principal.policy_denied").first()
    assert event is not None
    assert event.metadata_json["reason"] == "policy_conflict"


def test_disabled_principal_blocks_mint(client):
    """Disabled principal cannot mint tokens."""
    resp = _create_key(client, scopes=["repo.read"])
    api_key = resp.json()["api_key"]
    principal_id = resp.json()["principal_id"]

    # Disable
    resp = client.post(f"/v1/principals/{principal_id}/disable", headers=ADMIN)
    assert resp.status_code == 200

    # Try to mint — should fail
    resp = _mint_token(client, api_key)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid API key"
