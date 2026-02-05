import datetime as dt

import pytest
from freezegun import freeze_time

from services.aegis.models import AuditEvent, Secret


def _create_key(client, scopes=None):
    """Create an API key with specified scopes."""
    if scopes is None:
        scopes = ["secrets.read"]
    response = client.post(
        "/v1/keys",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"principal_name": "agent", "principal_type": "service", "allowed_scopes": scopes},
    )
    assert response.status_code == 200
    return response.json()["api_key"], response.json()["principal_id"]


def _mint_token(client, api_key, scopes=None, resource=None):
    """Mint a token with specified scopes and resource."""
    if scopes is None:
        scopes = ["secrets.read"]
    if resource is None:
        resource = "any:default"
    payload = {"aud": "aegis", "scopes": scopes, "ttl_seconds": 300, "resource": resource}
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json=payload,
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_create_secret_success(client, db_session):
    """Test creating a secret with admin token."""
    response = client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "ssh-pass:server1", "value": "secret123", "resource": "host:server1"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "ssh-pass:server1"
    assert data["resource"] == "host:server1"
    assert data["secret_type"] == "password"  # default type
    assert "id" in data

    # Verify audit event
    events = db_session.query(AuditEvent).filter_by(event_type="secret.created").all()
    assert len(events) == 1


def test_create_secret_with_type(client, db_session):
    """Test creating secrets with different types."""
    # SSH private key
    response = client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "ssh-key:server1", "value": "-----BEGIN RSA PRIVATE KEY-----\n...", "secret_type": "ssh-private-key"},
    )
    assert response.status_code == 200
    assert response.json()["secret_type"] == "ssh-private-key"

    # API token
    response = client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "github-token", "value": "ghp_xxx", "secret_type": "api-token"},
    )
    assert response.status_code == 200
    assert response.json()["secret_type"] == "api-token"


def test_create_secret_duplicate_name(client, db_session):
    """Test that duplicate secret names are rejected."""
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "duplicate", "value": "first"},
    )
    response = client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "duplicate", "value": "second"},
    )
    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]


def test_create_secret_requires_admin(client):
    """Test that creating secrets requires admin token."""
    response = client.post(
        "/v1/secrets",
        json={"name": "test", "value": "secret"},
    )
    assert response.status_code == 401


def test_get_secret_success(client, db_session):
    """Test retrieving a secret with valid token."""
    # Create secret
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "test-secret", "value": "password123"},
    )

    # Create API key and mint token
    api_key, _ = _create_key(client, scopes=["secrets.read"])
    token = _mint_token(client, api_key)

    # Retrieve secret
    response = client.get(
        "/v1/secrets/test-secret",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["value"] == "password123"
    assert response.json()["secret_type"] == "password"

    # Verify audit event
    events = db_session.query(AuditEvent).filter_by(event_type="secret.accessed").all()
    assert len(events) == 1


def test_get_secret_preserves_type(client, db_session):
    """Test that secret type is preserved on retrieval."""
    # Create SSH key secret
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "ssh-key", "value": "key-content", "secret_type": "ssh-private-key"},
    )

    api_key, _ = _create_key(client, scopes=["secrets.read"])
    token = _mint_token(client, api_key)

    response = client.get(
        "/v1/secrets/ssh-key",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["secret_type"] == "ssh-private-key"


def test_get_secret_with_resource_binding(client, db_session):
    """Test retrieving a resource-bound secret with matching token."""
    # Create secret with resource binding
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "ssh-pass:srv1", "value": "pass123", "resource": "host:srv1"},
    )

    # Create token with matching resource
    api_key, _ = _create_key(client, scopes=["secrets.read"])
    token = _mint_token(client, api_key, scopes=["secrets.read"], resource="host:srv1")

    # Retrieve secret
    response = client.get(
        "/v1/secrets/ssh-pass:srv1",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["value"] == "pass123"


def test_get_secret_resource_mismatch(client, db_session):
    """Test that resource mismatch is rejected."""
    # Create secret bound to host:server-a
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "restricted", "value": "secret", "resource": "host:server-a"},
    )

    # Get token for host:server-b
    api_key, _ = _create_key(client, scopes=["secrets.read"])
    token = _mint_token(client, api_key, scopes=["secrets.read"], resource="host:server-b")

    # Attempt retrieval
    response = client.get(
        "/v1/secrets/restricted",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert "Resource mismatch" in response.json()["detail"]

    # Verify denial was audited
    events = db_session.query(AuditEvent).filter_by(event_type="secret.denied").all()
    assert len(events) == 1


def test_get_secret_wrong_resource_in_token(client, db_session):
    """Test that token with non-matching resource cannot access resource-bound secret."""
    # Create secret with resource binding
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "bound-secret", "value": "secret", "resource": "host:test"},
    )

    # Get token with different resource
    api_key, _ = _create_key(client, scopes=["secrets.read"])
    token = _mint_token(client, api_key, scopes=["secrets.read"], resource="host:other")

    # Attempt retrieval — should fail with resource mismatch
    response = client.get(
        "/v1/secrets/bound-secret",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_get_secret_missing_scope(client, db_session):
    """Test that missing scope is rejected."""
    # Create secret
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "scope-test", "value": "secret"},
    )

    # Create token with wrong scope
    api_key, _ = _create_key(client, scopes=["repo.read"])
    token = _mint_token(client, api_key, scopes=["repo.read"])

    # Attempt retrieval
    response = client.get(
        "/v1/secrets/scope-test",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert "secrets.read" in response.json()["detail"]


def test_get_secret_expired_token(client, db_session):
    """Test that expired tokens are rejected."""
    # Create secret
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "expiry-test", "value": "secret"},
    )

    api_key, _ = _create_key(client, scopes=["secrets.read"])

    with freeze_time(dt.datetime.now(dt.timezone.utc)) as frozen:
        # Mint token with short TTL
        response = client.post(
            "/v1/token",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "aud": "aegis",
                "scopes": ["secrets.read"],
                "ttl_seconds": 1,
                "resource": "any:default",
            },
        )
        token = response.json()["access_token"]

        # Advance time past expiry
        frozen.tick(delta=dt.timedelta(seconds=120))

        # Attempt retrieval
        response = client.get(
            "/v1/secrets/expiry-test",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "expired"


def test_get_secret_not_found(client, db_session):
    """Test that non-existent secrets return 404."""
    api_key, _ = _create_key(client, scopes=["secrets.read"])
    token = _mint_token(client, api_key)

    response = client.get(
        "/v1/secrets/nonexistent",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_delete_secret_success(client, db_session):
    """Test deleting a secret."""
    # Create secret
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "to-delete", "value": "secret"},
    )

    # Delete secret
    response = client.delete(
        "/v1/secrets/to-delete",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "deleted"

    # Verify audit event
    events = db_session.query(AuditEvent).filter_by(event_type="secret.deleted").all()
    assert len(events) == 1


def test_deleted_secret_not_accessible(client, db_session):
    """Test that deleted secrets are not retrievable."""
    # Create and delete secret
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "deleted-secret", "value": "secret"},
    )
    client.delete(
        "/v1/secrets/deleted-secret",
        headers={"X-Admin-Token": "test-admin-token"},
    )

    # Attempt retrieval
    api_key, _ = _create_key(client, scopes=["secrets.read"])
    token = _mint_token(client, api_key)

    response = client.get(
        "/v1/secrets/deleted-secret",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_delete_secret_requires_admin(client):
    """Test that deleting secrets requires admin token."""
    response = client.delete("/v1/secrets/any")
    assert response.status_code == 401


def test_delete_nonexistent_secret(client):
    """Test that deleting non-existent secret returns 404."""
    response = client.delete(
        "/v1/secrets/nonexistent",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    assert response.status_code == 404


def test_token_with_resource_claim(client, db_session):
    """Test that tokens include resource claim when requested."""
    api_key, _ = _create_key(client, scopes=["secrets.read"])

    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "aud": "aegis",
            "scopes": ["secrets.read"],
            "resource": "host:test-server",
            "ttl_seconds": 300,
        },
    )
    assert response.status_code == 200

    # Verify the token was minted with resource (check audit)
    events = db_session.query(AuditEvent).filter_by(event_type="token.minted").all()
    assert len(events) == 1


def test_rotate_secret_success(client, db_session):
    """Test rotating a secret's value."""
    # Create secret
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "rotate-test", "value": "old-password", "resource": "host:srv1"},
    )

    # Rotate secret
    response = client.put(
        "/v1/secrets/rotate-test",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"value": "new-password"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "rotate-test"
    assert data["resource"] == "host:srv1"
    assert "rotated_at" in data

    # Verify the new value is retrievable
    api_key, _ = _create_key(client, scopes=["secrets.read"])
    token = _mint_token(client, api_key, scopes=["secrets.read"], resource="host:srv1")
    response = client.get(
        "/v1/secrets/rotate-test",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["value"] == "new-password"

    # Verify audit event
    events = db_session.query(AuditEvent).filter_by(event_type="secret.rotated").all()
    assert len(events) == 1


def test_rotate_secret_not_found(client):
    """Test rotating a non-existent secret returns 404."""
    response = client.put(
        "/v1/secrets/nonexistent",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"value": "new-value"},
    )
    assert response.status_code == 404


def test_rotate_secret_requires_admin(client):
    """Test that rotating secrets requires admin token."""
    response = client.put(
        "/v1/secrets/any",
        json={"value": "new-value"},
    )
    assert response.status_code == 401


def test_rotate_deleted_secret_fails(client, db_session):
    """Test that rotating a deleted secret returns 404."""
    # Create and delete secret
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "deleted-rotate", "value": "old"},
    )
    client.delete(
        "/v1/secrets/deleted-rotate",
        headers={"X-Admin-Token": "test-admin-token"},
    )

    # Attempt rotation
    response = client.put(
        "/v1/secrets/deleted-rotate",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"value": "new"},
    )
    assert response.status_code == 404


def test_secret_read_impossible_without_secrets_read_scope(client, db_session):
    """Even with matching resource, missing secrets.read scope blocks access."""
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "proof-secret", "value": "classified", "resource": "host:target"},
    )
    api_key, _ = _create_key(client, scopes=["repo.read"])
    token = _mint_token(client, api_key, scopes=["repo.read"], resource="host:target")
    response = client.get(
        "/v1/secrets/proof-secret",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert "secrets.read" in response.json()["detail"]


def test_secret_read_impossible_without_matching_resource(client, db_session):
    """secrets.read scope with wrong resource blocks access."""
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "resource-proof", "value": "classified", "resource": "host:alpha"},
    )
    api_key, _ = _create_key(client, scopes=["secrets.read"])
    token = _mint_token(client, api_key, scopes=["secrets.read"], resource="host:beta")
    response = client.get(
        "/v1/secrets/resource-proof",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert "Resource mismatch" in response.json()["detail"]


def test_secret_read_requires_both_scope_and_resource(client, db_session):
    """Only secrets.read + matching resource grants access."""
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "full-proof", "value": "success", "resource": "host:exact"},
    )
    api_key, _ = _create_key(client, scopes=["secrets.read"])
    token = _mint_token(client, api_key, scopes=["secrets.read"], resource="host:exact")
    response = client.get(
        "/v1/secrets/full-proof",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["value"] == "success"


def test_unbound_secret_audit_includes_resource_unbound(client, db_session):
    """Accessing an unbound secret logs resource_unbound: True in audit metadata."""
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "unbound-audit", "value": "test"},
    )
    api_key, _ = _create_key(client, scopes=["secrets.read"])
    token = _mint_token(client, api_key)
    response = client.get(
        "/v1/secrets/unbound-audit",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    events = db_session.query(AuditEvent).filter_by(event_type="secret.accessed").all()
    assert len(events) == 1
    assert events[0].metadata_json.get("resource_unbound") is True


def test_bound_secret_audit_no_resource_unbound(client, db_session):
    """Accessing a resource-bound secret does NOT have resource_unbound in metadata."""
    client.post(
        "/v1/secrets",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "bound-audit", "value": "test", "resource": "host:x"},
    )
    api_key, _ = _create_key(client, scopes=["secrets.read"])
    token = _mint_token(client, api_key, resource="host:x")
    response = client.get(
        "/v1/secrets/bound-audit",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    events = db_session.query(AuditEvent).filter_by(event_type="secret.accessed").all()
    assert len(events) == 1
    assert "resource_unbound" not in events[0].metadata_json
