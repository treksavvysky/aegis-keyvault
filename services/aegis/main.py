import datetime as dt
import uuid

from fastapi import Body, Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import schemas
from .audit import emit_audit_event
from .config import get_admin_token
from .db import get_db
from .models import ApiKey, Principal, RevokedToken
from .security import (
    TokenError,
    decode_token,
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
        principal = Principal(name=payload.principal_name, type=payload.principal_type)
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

    api_key, key_id, secret = generate_api_key()
    key = ApiKey(
        id=key_id,
        principal_id=principal.id,
        key_hash=hash_secret(secret),
        allowed_scopes_json=payload.allowed_scopes,
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

    token, jti, ttl = mint_token(
        sub=api_key.principal_id,
        scopes=requested_scopes,
        aud=payload.aud,
        ttl_seconds=payload.ttl_seconds,
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
def introspect_access_token(
    request: Request,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    payload: schemas.IntrospectRequest | None = Body(default=None),
) -> schemas.IntrospectResponse:
    admin_token = request.headers.get("X-Admin-Token")
    if not admin_token or admin_token != get_admin_token():
        emit_audit_event(
            db,
            event_type="token.introspected",
            result="deny",
            principal_id=None,
            metadata={"trace_id": request.state.trace_id, "reason": "admin_required"},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin token required")

    if credentials is None or not credentials.credentials:
        emit_audit_event(
            db,
            event_type="token.introspected",
            result="deny",
            principal_id=None,
            metadata={"trace_id": request.state.trace_id, "reason": "missing_token"},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing access token")

    expected_aud = payload.expected_aud if payload else None
    try:
        claims = decode_token(credentials.credentials, expected_aud=expected_aud)
    except TokenError as exc:
        reason = exc.code or "invalid_token"
        emit_audit_event(
            db,
            event_type="token.introspected",
            result="deny",
            principal_id=None,
            metadata={"trace_id": request.state.trace_id, "reason": reason},
        )
        return schemas.IntrospectResponse(active=False, reason=reason)

    jti = claims.get("jti")
    if jti and db.get(RevokedToken, jti) is not None:
        emit_audit_event(
            db,
            event_type="token.introspected",
            result="deny",
            principal_id=claims.get("sub"),
            token_jti=jti,
            metadata={"trace_id": request.state.trace_id, "reason": "revoked"},
        )
        return schemas.IntrospectResponse(
            active=False,
            sub=claims.get("sub"),
            aud=claims.get("aud"),
            scopes=claims.get("scopes", []),
            exp=claims.get("exp"),
            iat=claims.get("iat"),
            jti=jti,
            reason="revoked",
        )

    emit_audit_event(
        db,
        event_type="token.introspected",
        result="ok",
        principal_id=claims.get("sub"),
        token_jti=jti,
        metadata={
            "trace_id": request.state.trace_id,
            "aud": claims.get("aud"),
            "scopes": claims.get("scopes", []),
        },
    )
    return schemas.IntrospectResponse(
        active=True,
        sub=claims.get("sub"),
        aud=claims.get("aud"),
        scopes=claims.get("scopes", []),
        exp=claims.get("exp"),
        iat=claims.get("iat"),
        jti=jti,
        reason=None,
    )


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
