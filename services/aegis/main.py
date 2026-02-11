import datetime as dt
import uuid

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import ExpiredSignatureError, InvalidAudienceError, MissingRequiredClaimError, PyJWTError
from sqlalchemy.orm import Session

from . import schemas
from .audit import emit_audit_event
from .config import get_admin_token, get_signing_key
from .db import get_db
from .models import ApiKey, Principal, RevokedToken, Secret
from .security import (
    TokenError,
    decrypt_secret,
    encrypt_secret,
    generate_api_key,
    hash_secret,
    mint_token,
    parse_api_key,
    validate_scopes,
    verify_secret,
)

app = FastAPI(title="Aegis")

bearer_scheme = HTTPBearer(auto_error=False)


@app.middleware("http")
async def trace_middleware(request: Request, call_next):
    trace_id = request.headers.get("X-Trace-Id") or str(uuid.uuid4())
    request.state.trace_id = trace_id
    response = await call_next(request)
    response.headers["X-Trace-Id"] = trace_id
    return response


@app.get("/health")
def health() -> dict:
    return {"server": "ok"}


def require_admin(request: Request) -> None:
    token = request.headers.get("X-Admin-Token")
    if not token or token != get_admin_token():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin token required")


def _decode_access_token(
    token: str,
    *,
    expected_aud: str | None = None,
) -> tuple[dict | None, str | None]:
    options = {"require": ["exp", "iat", "jti", "aud", "sub", "scopes"]}
    try:
        if expected_aud:
            claims = jwt.decode(
                token,
                get_signing_key(),
                algorithms=["HS256"],
                audience=expected_aud,
                options=options,
            )
        else:
            claims = jwt.decode(
                token,
                get_signing_key(),
                algorithms=["HS256"],
                options=options,
            )
    except ExpiredSignatureError:
        return None, "expired"
    except InvalidAudienceError:
        return None, "wrong_aud"
    except MissingRequiredClaimError:
        return None, "missing_claim"
    except PyJWTError:
        return None, "bad_signature"

    if not claims.get("aud"):
        return None, "missing_claim"
    if not isinstance(claims.get("scopes"), list):
        return None, "missing_claim"
    return claims, None


def _evaluate_token_status(
    db: Session,
    claims: dict,
) -> str | None:
    jti = claims.get("jti")
    if jti and db.get(RevokedToken, jti):
        return "revoked"
    principal_id = claims.get("sub")
    if principal_id:
        principal = db.get(Principal, principal_id)
        if principal and principal.status != "active":
            return "disabled_principal"
    key_id = claims.get("key_id")
    if key_id:
        api_key = db.get(ApiKey, key_id)
        if api_key is None or api_key.status != "active":
            return "revoked"
    return None

@app.post("/v1/keys", response_model=schemas.KeyCreateResponse)
def create_key(
    payload: schemas.KeyCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> schemas.KeyCreateResponse:
    require_admin(request)
    if payload.principal_id is None:
        if not payload.principal_name or not payload.principal_type:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="principal_name and principal_type required",
            )
        principal = Principal(
            name=payload.principal_name,
            type=payload.principal_type,
            max_scopes_json=payload.max_scopes,
            max_resources_json=payload.max_resources,
        )
        db.add(principal)
        db.commit()
        db.refresh(principal)
    else:
        principal = db.get(Principal, payload.principal_id)
        if principal is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Principal not found")
    try:
        validate_scopes(payload.allowed_scopes)
    except TokenError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    # Enforce principal scope ceiling
    if principal.max_scopes_json is not None:
        if not set(payload.allowed_scopes).issubset(set(principal.max_scopes_json)):
            emit_audit_event(
                db,
                event_type="key.denied",
                result="deny",
                principal_id=principal.id,
                metadata={
                    "trace_id": request.state.trace_id,
                    "reason": "scope_ceiling_exceeded",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="scope_ceiling_exceeded",
            )

    # Enforce principal resource ceiling
    if payload.allowed_resources and principal.max_resources_json is not None:
        if not set(payload.allowed_resources).issubset(set(principal.max_resources_json)):
            emit_audit_event(
                db,
                event_type="key.denied",
                result="deny",
                principal_id=principal.id,
                metadata={
                    "trace_id": request.state.trace_id,
                    "reason": "resource_ceiling_exceeded",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="resource_ceiling_exceeded",
            )

    api_key, key_id, secret = generate_api_key()
    key = ApiKey(
        id=key_id,
        principal_id=principal.id,
        key_hash=hash_secret(secret),
        allowed_scopes_json=payload.allowed_scopes,
        allowed_resources_json=payload.allowed_resources,
    )
    db.add(key)
    db.commit()

    emit_audit_event(
        db,
        event_type="key.created",
        result="ok",
        principal_id=principal.id,
        metadata={"trace_id": request.state.trace_id, "key_id": key_id},
    )

    return schemas.KeyCreateResponse(api_key=api_key, key_id=key_id, principal_id=principal.id)


@app.post("/v1/token", response_model=schemas.TokenResponse)
def mint_access_token(
    payload: schemas.TokenRequest,
    request: Request,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> schemas.TokenResponse:
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

    try:
        key_id, secret = parse_api_key(credentials.credentials)
    except TokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    api_key = db.get(ApiKey, key_id)
    if api_key is None or api_key.status != "active":
        emit_audit_event(
            db,
            event_type="token.denied",
            result="deny",
            principal_id=None,
            metadata={"trace_id": request.state.trace_id, "key_id": key_id},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    if not verify_secret(secret, api_key.key_hash):
        emit_audit_event(
            db,
            event_type="token.denied",
            result="deny",
            principal_id=api_key.principal_id,
            metadata={"trace_id": request.state.trace_id, "key_id": key_id},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    if not payload.aud:
        emit_audit_event(
            db,
            event_type="token.denied",
            result="deny",
            principal_id=api_key.principal_id,
            metadata={"trace_id": request.state.trace_id, "reason": "aud missing"},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="aud required")

    if not payload.scopes:
        emit_audit_event(
            db,
            event_type="token.denied",
            result="deny",
            principal_id=api_key.principal_id,
            metadata={"trace_id": request.state.trace_id, "reason": "scopes required"},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="scopes required")

    if not payload.resource:
        emit_audit_event(
            db,
            event_type="token.denied",
            result="deny",
            principal_id=api_key.principal_id,
            metadata={"trace_id": request.state.trace_id, "reason": "resource required"},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="resource required")

    if payload.ttl_seconds is None:
        emit_audit_event(
            db,
            event_type="token.denied",
            result="deny",
            principal_id=api_key.principal_id,
            metadata={"trace_id": request.state.trace_id, "reason": "ttl_seconds required"},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ttl_seconds required")

    requested_scopes = payload.scopes
    try:
        validate_scopes(requested_scopes)
    except TokenError as exc:
        emit_audit_event(
            db,
            event_type="token.denied",
            result="deny",
            principal_id=api_key.principal_id,
            metadata={"trace_id": request.state.trace_id, "reason": str(exc)},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    allowed = set(api_key.allowed_scopes_json or [])
    if not set(requested_scopes).issubset(allowed):
        emit_audit_event(
            db,
            event_type="token.denied",
            result="deny",
            principal_id=api_key.principal_id,
            metadata={"trace_id": request.state.trace_id, "reason": "scope not allowed"},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="scope not allowed")

    # Check principal is active
    principal = db.get(Principal, api_key.principal_id)
    if principal and principal.status != "active":
        emit_audit_event(
            db,
            event_type="token.denied",
            result="deny",
            principal_id=api_key.principal_id,
            metadata={"trace_id": request.state.trace_id, "reason": "disabled_principal"},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    # Defense-in-depth: enforce principal scope ceiling
    if principal and principal.max_scopes_json is not None:
        if not set(requested_scopes).issubset(set(principal.max_scopes_json)):
            emit_audit_event(
                db,
                event_type="token.denied",
                result="deny",
                principal_id=api_key.principal_id,
                metadata={
                    "trace_id": request.state.trace_id,
                    "reason": "principal_ceiling_exceeded",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="principal_ceiling_exceeded",
            )

    # Enforce principal resource ceiling
    if principal and principal.max_resources_json is not None:
        if payload.resource not in principal.max_resources_json:
            emit_audit_event(
                db,
                event_type="token.denied",
                result="deny",
                principal_id=api_key.principal_id,
                metadata={
                    "trace_id": request.state.trace_id,
                    "reason": "resource_ceiling_exceeded",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="resource_ceiling_exceeded",
            )

    # Enforce API key resource binding
    if api_key.allowed_resources_json is not None:
        if payload.resource not in api_key.allowed_resources_json:
            emit_audit_event(
                db,
                event_type="token.denied",
                result="deny",
                principal_id=api_key.principal_id,
                metadata={"trace_id": request.state.trace_id, "reason": "resource not allowed"},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="resource not allowed",
            )

    token, jti, ttl = mint_token(
        sub=api_key.principal_id,
        scopes=requested_scopes,
        aud=payload.aud,
        ttl_seconds=payload.ttl_seconds,
        key_id=api_key.id,
        resource=payload.resource,
    )

    api_key.last_used_at = dt.datetime.now(dt.timezone.utc)
    db.add(api_key)
    db.commit()

    emit_audit_event(
        db,
        event_type="token.minted",
        result="ok",
        principal_id=api_key.principal_id,
        token_jti=jti,
        metadata={
            "trace_id": request.state.trace_id,
            "aud": payload.aud,
            "scopes": requested_scopes,
        },
    )

    return schemas.TokenResponse(access_token=token, token_type="bearer", expires_in=ttl, jti=jti)


@app.post("/v1/introspect", response_model=schemas.IntrospectResponse)
def introspect_token(
    payload: schemas.IntrospectRequest,
    request: Request,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> schemas.IntrospectResponse:
    # TODO: Replace X-Admin-Token bootstrap auth with scoped service auth (introspect.token).
    require_admin(request)
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing access token")

    claims, reason = _decode_access_token(credentials.credentials, expected_aud=payload.expected_aud)
    if claims:
        status_reason = _evaluate_token_status(db, claims)
        if status_reason:
            reason = status_reason

    active = reason is None and claims is not None
    response = schemas.IntrospectResponse(
        active=active,
        sub=claims.get("sub") if claims else None,
        aud=claims.get("aud") if claims else None,
        scopes=claims.get("scopes") if claims else [],
        exp=claims.get("exp") if claims else None,
        iat=claims.get("iat") if claims else None,
        jti=claims.get("jti") if claims else None,
        reason=reason,
    )

    emit_audit_event(
        db,
        event_type="token.introspected",
        result="ok" if active else "deny",
        principal_id=claims.get("sub") if claims else None,
        token_jti=claims.get("jti") if claims else None,
        metadata={"trace_id": request.state.trace_id, "reason": reason},
    )

    return response


@app.get("/v1/demo/protected")
def protected_demo(
    request: Request,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing access token")
    claims, reason = _decode_access_token(credentials.credentials, expected_aud="jct")
    if reason:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=reason)
    status_reason = _evaluate_token_status(db, claims or {})
    if status_reason:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=status_reason)
    try:
        validate_scopes(claims.get("scopes", []))
    except TokenError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    if "tasks.enqueue" not in set(claims.get("scopes", [])):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing scope: tasks.enqueue")
    return {"status": "ok", "principal_id": claims.get("sub")}


@app.post("/v1/revoke/token")
def revoke_token(
    payload: schemas.TokenRevokeRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    require_admin(request)
    existing = db.get(RevokedToken, payload.jti)
    if existing is None:
        revoked = RevokedToken(jti=payload.jti, reason=payload.reason)
        db.add(revoked)
        db.commit()
    emit_audit_event(
        db,
        event_type="token.revoked",
        result="ok",
        principal_id=None,
        token_jti=payload.jti,
        metadata={"trace_id": request.state.trace_id, "reason": payload.reason},
    )
    return {"status": "revoked", "jti": payload.jti}


@app.post("/v1/revoke/key")
def revoke_key(
    payload: schemas.KeyRevokeRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    require_admin(request)
    api_key = db.get(ApiKey, payload.key_id)
    if api_key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    if payload.status not in {"revoked", "disabled"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")
    api_key.status = payload.status
    db.add(api_key)
    db.commit()

    emit_audit_event(
        db,
        event_type=f"key.{payload.status}",
        result="ok",
        principal_id=api_key.principal_id,
        metadata={"trace_id": request.state.trace_id, "key_id": api_key.id},
    )
    return {"status": api_key.status, "key_id": api_key.id}


@app.post("/v1/secrets", response_model=schemas.SecretCreateResponse)
def create_secret(
    payload: schemas.SecretCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> schemas.SecretCreateResponse:
    require_admin(request)

    existing = db.query(Secret).filter_by(name=payload.name).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Secret name already exists")

    # Use a system principal for admin-created secrets
    admin_principal = db.query(Principal).filter_by(name="admin", type="system").first()
    if not admin_principal:
        admin_principal = Principal(name="admin", type="system")
        db.add(admin_principal)
        db.commit()
        db.refresh(admin_principal)

    secret = Secret(
        name=payload.name,
        value_encrypted=encrypt_secret(payload.value),
        secret_type=payload.secret_type,
        resource=payload.resource,
        principal_id=admin_principal.id,
    )
    db.add(secret)
    db.commit()
    db.refresh(secret)

    emit_audit_event(
        db,
        event_type="secret.created",
        result="ok",
        principal_id=admin_principal.id,
        resource=payload.resource,
        metadata={"trace_id": request.state.trace_id, "secret_name": payload.name},
    )

    return schemas.SecretCreateResponse(
        id=secret.id,
        name=secret.name,
        secret_type=secret.secret_type,
        resource=secret.resource,
        created_at=secret.created_at.isoformat(),
    )


@app.get("/v1/secrets/{name}", response_model=schemas.SecretRetrieveResponse)
def get_secret(
    name: str,
    request: Request,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> schemas.SecretRetrieveResponse:
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing access token")

    claims, reason = _decode_access_token(credentials.credentials, expected_aud="aegis")
    if reason:
        emit_audit_event(
            db,
            event_type="secret.denied",
            result="deny",
            principal_id=None,
            metadata={"trace_id": request.state.trace_id, "secret_name": name, "reason": reason},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=reason)

    status_reason = _evaluate_token_status(db, claims or {})
    if status_reason:
        emit_audit_event(
            db,
            event_type="secret.denied",
            result="deny",
            principal_id=claims.get("sub") if claims else None,
            token_jti=claims.get("jti") if claims else None,
            metadata={"trace_id": request.state.trace_id, "secret_name": name, "reason": status_reason},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=status_reason)

    if "secrets.read" not in set(claims.get("scopes", [])):
        emit_audit_event(
            db,
            event_type="secret.denied",
            result="deny",
            principal_id=claims.get("sub"),
            token_jti=claims.get("jti"),
            metadata={"trace_id": request.state.trace_id, "secret_name": name, "reason": "missing scope"},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing scope: secrets.read")

    secret = db.query(Secret).filter_by(name=name, status="active").first()
    if secret is None:
        emit_audit_event(
            db,
            event_type="secret.denied",
            result="deny",
            principal_id=claims.get("sub"),
            token_jti=claims.get("jti"),
            metadata={"trace_id": request.state.trace_id, "secret_name": name, "reason": "not found"},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

    # Resource binding check
    token_resource = claims.get("resource")
    if secret.resource:
        if not token_resource or token_resource != secret.resource:
            emit_audit_event(
                db,
                event_type="secret.denied",
                result="deny",
                principal_id=claims.get("sub"),
                token_jti=claims.get("jti"),
                resource=secret.resource,
                metadata={
                    "trace_id": request.state.trace_id,
                    "secret_name": name,
                    "reason": "resource mismatch",
                    "expected": secret.resource,
                    "got": token_resource,
                },
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Resource mismatch")

    plaintext = decrypt_secret(secret.value_encrypted)

    access_metadata = {"trace_id": request.state.trace_id, "secret_name": name}
    if not secret.resource:
        access_metadata["resource_unbound"] = True

    emit_audit_event(
        db,
        event_type="secret.accessed",
        result="ok",
        principal_id=claims.get("sub"),
        token_jti=claims.get("jti"),
        resource=secret.resource,
        metadata=access_metadata,
    )

    return schemas.SecretRetrieveResponse(
        name=secret.name,
        value=plaintext,
        secret_type=secret.secret_type,
        resource=secret.resource,
    )


@app.delete("/v1/secrets/{name}")
def delete_secret(
    name: str,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    require_admin(request)

    secret = db.query(Secret).filter_by(name=name).first()
    if secret is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

    secret.status = "deleted"
    secret.updated_at = dt.datetime.now(dt.timezone.utc)
    db.add(secret)
    db.commit()

    emit_audit_event(
        db,
        event_type="secret.deleted",
        result="ok",
        principal_id=None,
        resource=secret.resource,
        metadata={"trace_id": request.state.trace_id, "secret_name": name},
    )

    return {"status": "deleted", "name": name}


@app.put("/v1/secrets/{name}", response_model=schemas.SecretRotateResponse)
def rotate_secret(
    name: str,
    payload: schemas.SecretRotateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> schemas.SecretRotateResponse:
    """Rotate a secret's value atomically."""
    require_admin(request)

    secret = db.query(Secret).filter_by(name=name, status="active").first()
    if secret is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

    secret.value_encrypted = encrypt_secret(payload.value)
    secret.updated_at = dt.datetime.now(dt.timezone.utc)
    db.add(secret)
    db.commit()
    db.refresh(secret)

    emit_audit_event(
        db,
        event_type="secret.rotated",
        result="ok",
        principal_id=None,
        resource=secret.resource,
        metadata={"trace_id": request.state.trace_id, "secret_name": name},
    )

    return schemas.SecretRotateResponse(
        name=secret.name,
        resource=secret.resource,
        rotated_at=secret.updated_at.isoformat(),
    )


@app.get("/v1/secrets", response_model=schemas.SecretListResponse)
def list_secrets(
    request: Request,
    db: Session = Depends(get_db),
) -> schemas.SecretListResponse:
    """List all secrets (names and metadata only, not values)."""
    require_admin(request)

    secrets = db.query(Secret).filter_by(status="active").order_by(Secret.name).all()

    return schemas.SecretListResponse(
        secrets=[
            schemas.SecretListItem(
                name=s.name,
                secret_type=s.secret_type,
                resource=s.resource,
                created_at=s.created_at.isoformat(),
            )
            for s in secrets
        ]
    )


# --- Principal management endpoints ---


@app.get("/v1/principals", response_model=schemas.PrincipalListResponse)
def list_principals(
    request: Request,
    db: Session = Depends(get_db),
) -> schemas.PrincipalListResponse:
    require_admin(request)
    principals = db.query(Principal).order_by(Principal.name).all()
    return schemas.PrincipalListResponse(
        principals=[
            schemas.PrincipalResponse(
                id=p.id,
                name=p.name,
                type=p.type,
                status=p.status,
                max_scopes=p.max_scopes_json,
                max_resources=p.max_resources_json,
                created_at=p.created_at.isoformat(),
            )
            for p in principals
        ]
    )


@app.get("/v1/principals/{principal_id}", response_model=schemas.PrincipalDetailResponse)
def get_principal(
    principal_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> schemas.PrincipalDetailResponse:
    require_admin(request)
    principal = db.get(Principal, principal_id)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Principal not found")
    return schemas.PrincipalDetailResponse(
        id=principal.id,
        name=principal.name,
        type=principal.type,
        status=principal.status,
        max_scopes=principal.max_scopes_json,
        max_resources=principal.max_resources_json,
        created_at=principal.created_at.isoformat(),
        api_keys=[
            schemas.RedactedKeyInfo(
                key_id=k.id,
                status=k.status,
                allowed_scopes=k.allowed_scopes_json or [],
                allowed_resources=k.allowed_resources_json,
                created_at=k.created_at.isoformat(),
            )
            for k in principal.api_keys
        ],
    )


@app.put("/v1/principals/{principal_id}/policy")
def update_principal_policy(
    principal_id: str,
    payload: schemas.PolicyUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    require_admin(request)
    principal = db.get(Principal, principal_id)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Principal not found")

    # Check for conflicts with existing active API keys
    new_max_scopes = payload.max_scopes
    new_max_resources = payload.max_resources
    violating_keys: list[str] = []

    if new_max_scopes is not None:
        ceiling = set(new_max_scopes)
        for k in principal.api_keys:
            if k.status == "active" and not set(k.allowed_scopes_json or []).issubset(ceiling):
                violating_keys.append(k.id)

    if new_max_resources is not None:
        resource_ceiling = set(new_max_resources)
        for k in principal.api_keys:
            if k.status == "active" and k.allowed_resources_json is not None:
                if not set(k.allowed_resources_json).issubset(resource_ceiling):
                    if k.id not in violating_keys:
                        violating_keys.append(k.id)

    if violating_keys:
        emit_audit_event(
            db,
            event_type="principal.policy_denied",
            result="deny",
            principal_id=principal.id,
            metadata={
                "trace_id": request.state.trace_id,
                "reason": "policy_conflict",
                "violating_keys": violating_keys,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="policy_conflict",
        )

    if new_max_scopes is not None:
        principal.max_scopes_json = new_max_scopes
    if new_max_resources is not None:
        principal.max_resources_json = new_max_resources
    principal.updated_at = dt.datetime.now(dt.timezone.utc)
    db.add(principal)
    db.commit()

    emit_audit_event(
        db,
        event_type="principal.policy_updated",
        result="ok",
        principal_id=principal.id,
        metadata={
            "trace_id": request.state.trace_id,
            "max_scopes": new_max_scopes,
            "max_resources": new_max_resources,
        },
    )

    return {"status": "updated", "principal_id": principal.id}


@app.post("/v1/principals/{principal_id}/disable")
def disable_principal(
    principal_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    require_admin(request)
    principal = db.get(Principal, principal_id)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Principal not found")

    principal.status = "disabled"
    principal.updated_at = dt.datetime.now(dt.timezone.utc)
    db.add(principal)
    db.commit()

    emit_audit_event(
        db,
        event_type="principal.disabled",
        result="ok",
        principal_id=principal.id,
        metadata={"trace_id": request.state.trace_id},
    )

    return {"status": "disabled", "principal_id": principal.id}
