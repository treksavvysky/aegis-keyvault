import datetime as dt

from freezegun import freeze_time

from services.aegis.models import AuditEvent


def _create_key(client):
    response = client.post(
        "/v1/keys",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"principal_name": "agent", "principal_type": "service", "allowed_scopes": ["repo.read"]},
    )
    assert response.status_code == 200
    return response.json()["api_key"], response.json()["key_id"], response.json()["principal_id"]


def _mint_token(client, api_key, aud="svc", ttl_seconds=60):
    response = client.post(
        "/v1/token",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "aud": aud,
            "scopes": ["repo.read"],
            "ttl_seconds": ttl_seconds,
            "resource": "host:test",
        },
    )
    assert response.status_code == 200
    return response.json()


def test_introspect_active_token(client):
    api_key, _, _ = _create_key(client)
    data = _mint_token(client, api_key)
    response = client.post(
        "/v1/introspect",
        headers={
            "Authorization": f"Bearer {data['access_token']}",
            "X-Admin-Token": "test-admin-token",
        },
        json={"expected_aud": "svc"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["active"] is True
    assert payload["jti"] == data["jti"]
    assert payload["reason"] is None


def test_introspect_revoked_token(client):
    api_key, _, _ = _create_key(client)
    data = _mint_token(client, api_key)
    revoke = client.post(
        "/v1/revoke/token",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"jti": data["jti"], "reason": "test"},
    )
    assert revoke.status_code == 200
    response = client.post(
        "/v1/introspect",
        headers={
            "Authorization": f"Bearer {data['access_token']}",
            "X-Admin-Token": "test-admin-token",
        },
        json={"expected_aud": "svc"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["active"] is False
    assert payload["reason"] == "revoked"


def test_introspect_expired_token(client):
    api_key, _, _ = _create_key(client)
    with freeze_time(dt.datetime.now(dt.timezone.utc)):
        data = _mint_token(client, api_key, ttl_seconds=1)
        with freeze_time(dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=120)):
            response = client.post(
                "/v1/introspect",
                headers={
                    "Authorization": f"Bearer {data['access_token']}",
                    "X-Admin-Token": "test-admin-token",
                },
                json={"expected_aud": "svc"},
            )
    assert response.status_code == 200
    payload = response.json()
    assert payload["active"] is False
    assert payload["reason"] == "expired"


def test_introspect_wrong_expected_aud(client):
    api_key, _, _ = _create_key(client)
    data = _mint_token(client, api_key, aud="svc")
    response = client.post(
        "/v1/introspect",
        headers={
            "Authorization": f"Bearer {data['access_token']}",
            "X-Admin-Token": "test-admin-token",
        },
        json={"expected_aud": "other"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["active"] is False
    assert payload["reason"] == "wrong_aud"


def test_introspect_requires_admin_token(client):
    api_key, _, _ = _create_key(client)
    data = _mint_token(client, api_key)
    response = client.post(
        "/v1/introspect",
        headers={"Authorization": f"Bearer {data['access_token']}"},
        json={"expected_aud": "svc"},
    )
    assert response.status_code == 401


def test_audit_event_emitted_for_introspection(client, db_session):
    api_key, _, _ = _create_key(client)
    data = _mint_token(client, api_key)
    ok_response = client.post(
        "/v1/introspect",
        headers={
            "Authorization": f"Bearer {data['access_token']}",
            "X-Admin-Token": "test-admin-token",
        },
        json={"expected_aud": "svc"},
    )
    assert ok_response.status_code == 200
    deny_response = client.post(
        "/v1/introspect",
        headers={
            "Authorization": f"Bearer {data['access_token']}",
            "X-Admin-Token": "test-admin-token",
        },
        json={"expected_aud": "wrong"},
    )
    assert deny_response.status_code == 200

    events = db_session.query(AuditEvent).filter_by(event_type="token.introspected").all()
    results = {event.result for event in events}
    reasons = {event.metadata_json.get("reason") for event in events}
    assert "ok" in results
    assert "deny" in results
    assert "wrong_aud" in reasons
