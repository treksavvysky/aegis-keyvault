import datetime as dt

import pytest
from freezegun import freeze_time

from libs.aegis_auth import VerificationError, require_scopes, verify_token
from services.aegis.models import AuditEvent, RevokedToken


def _create_key(client):
    response = client.post(
        "/v1/keys",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"principal_name": "agent", "principal_type": "service", "allowed_scopes": ["repo.read"]},
    )
    assert response.status_code == 200
    return response.json()["api_key"], response.json()["key_id"], response.json()["principal_id"]


def test_mint_token_success(client, db_session):
    api_key, _, principal_id = _create_key(client)
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"aud": "svc", "scopes": ["repo.read"], "ttl_seconds": 60, "resource": "host:test"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 60

    events = db_session.query(AuditEvent).filter_by(event_type="token.minted").all()
    assert len(events) == 1
    assert events[0].principal_id == principal_id


def test_mint_denied_for_disallowed_scope(client, db_session):
    api_key, _, _ = _create_key(client)
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"aud": "svc", "scopes": ["repo.write"], "resource": "host:test", "ttl_seconds": 60},
    )
    assert response.status_code == 403
    events = db_session.query(AuditEvent).filter_by(event_type="token.denied").all()
    assert len(events) == 1


def test_mint_denied_when_aud_missing(client, db_session):
    api_key, _, _ = _create_key(client)
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"scopes": ["repo.read"]},
    )
    assert response.status_code == 400
    events = db_session.query(AuditEvent).filter_by(event_type="token.denied").all()
    assert len(events) == 1


def test_verify_fails_for_wrong_aud(client):
    api_key, _, _ = _create_key(client)
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"aud": "svc", "scopes": ["repo.read"], "ttl_seconds": 60, "resource": "host:test"},
    )
    token = response.json()["access_token"]
    with pytest.raises(VerificationError):
        verify_token(token, expected_aud="other")


def test_verify_fails_for_expired_token(client):
    api_key, _, _ = _create_key(client)
    with freeze_time(dt.datetime.now(dt.timezone.utc)):
        response = client.post(
            "/v1/token",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"aud": "svc", "scopes": ["repo.read"], "ttl_seconds": 1, "resource": "host:test"},
        )
        token = response.json()["access_token"]
        with freeze_time(dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=120)):
            with pytest.raises(VerificationError):
                verify_token(token, expected_aud="svc")


def test_revoked_jti_rejected(client, db_session):
    api_key, _, _ = _create_key(client)
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"aud": "svc", "scopes": ["repo.read"], "ttl_seconds": 60, "resource": "host:test"},
    )
    data = response.json()
    revoke = client.post(
        "/v1/revoke/token",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"jti": data["jti"], "reason": "test"},
    )
    assert revoke.status_code == 200
    with pytest.raises(VerificationError):
        verify_token(data["access_token"], expected_aud="svc")
    assert db_session.query(RevokedToken).filter_by(jti=data["jti"]).count() == 1


def test_audit_events_emitted_for_revoke(client, db_session):
    api_key, _, _ = _create_key(client)
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"aud": "svc", "scopes": ["repo.read"], "ttl_seconds": 60, "resource": "host:test"},
    )
    data = response.json()
    client.post(
        "/v1/revoke/token",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"jti": data["jti"], "reason": "test"},
    )
    events = db_session.query(AuditEvent).filter(AuditEvent.event_type.in_([
        "token.minted",
        "token.revoked",
    ])).all()
    event_types = {event.event_type for event in events}
    assert "token.minted" in event_types
    assert "token.revoked" in event_types


def test_require_scopes(client):
    api_key, _, _ = _create_key(client)
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"aud": "svc", "scopes": ["repo.read"], "ttl_seconds": 60, "resource": "host:test"},
    )
    claims = verify_token(response.json()["access_token"], expected_aud="svc")
    require_scopes(claims, ["repo.read"])
    with pytest.raises(VerificationError):
        require_scopes(claims, ["repo.write"])


def test_mint_denied_when_scopes_empty(client, db_session):
    """Empty scopes list is rejected."""
    api_key, _, _ = _create_key(client)
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"aud": "svc", "scopes": [], "resource": "host:test", "ttl_seconds": 60},
    )
    assert response.status_code == 400
    assert "scopes required" in response.json()["detail"]
    events = db_session.query(AuditEvent).filter_by(event_type="token.denied").all()
    assert len(events) == 1


def test_mint_denied_when_resource_missing(client, db_session):
    """Missing resource is rejected."""
    api_key, _, _ = _create_key(client)
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"aud": "svc", "scopes": ["repo.read"], "ttl_seconds": 60},
    )
    assert response.status_code == 400
    assert "resource required" in response.json()["detail"]
    events = db_session.query(AuditEvent).filter_by(event_type="token.denied").all()
    assert len(events) == 1


def test_mint_denied_when_ttl_seconds_missing(client, db_session):
    """Missing ttl_seconds is rejected."""
    api_key, _, _ = _create_key(client)
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"aud": "svc", "scopes": ["repo.read"], "resource": "host:test"},
    )
    assert response.status_code == 400
    assert "ttl_seconds required" in response.json()["detail"]
    events = db_session.query(AuditEvent).filter_by(event_type="token.denied").all()
    assert len(events) == 1


def test_mint_denied_scopes_missing_from_payload(client, db_session):
    """Omitting scopes field entirely (Pydantic default []) is also rejected."""
    api_key, _, _ = _create_key(client)
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"aud": "svc", "resource": "host:test", "ttl_seconds": 60},
    )
    assert response.status_code == 400
    assert "scopes required" in response.json()["detail"]
