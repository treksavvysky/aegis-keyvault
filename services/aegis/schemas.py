from pydantic import BaseModel, Field


class KeyCreateRequest(BaseModel):
    principal_id: str | None = None
    principal_name: str | None = None
    principal_type: str | None = None
    allowed_scopes: list[str] = Field(default_factory=list)
    allowed_resources: list[str] | None = None
    max_scopes: list[str] | None = None
    max_resources: list[str] | None = None


class KeyCreateResponse(BaseModel):
    api_key: str
    key_id: str
    principal_id: str


class TokenRequest(BaseModel):
    aud: str | None = None
    scopes: list[str] = Field(default_factory=list)
    ttl_seconds: int | None = None
    resource: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    jti: str


class TokenRevokeRequest(BaseModel):
    jti: str
    reason: str | None = None


class KeyRevokeRequest(BaseModel):
    key_id: str
    status: str = "revoked"


class IntrospectRequest(BaseModel):
    expected_aud: str | None = None


class IntrospectResponse(BaseModel):
    active: bool
    sub: str | None = None
    aud: str | None = None
    scopes: list[str] = Field(default_factory=list)
    exp: int | None = None
    iat: int | None = None
    jti: str | None = None
    reason: str | None = None


class SecretCreateRequest(BaseModel):
    name: str
    value: str
    secret_type: str = "password"  # password, ssh-private-key, api-token
    resource: str | None = None


class SecretCreateResponse(BaseModel):
    id: str
    name: str
    secret_type: str
    resource: str | None
    created_at: str


class SecretRetrieveResponse(BaseModel):
    name: str
    value: str
    secret_type: str
    resource: str | None


class SecretListItem(BaseModel):
    name: str
    secret_type: str
    resource: str | None
    created_at: str


class SecretListResponse(BaseModel):
    secrets: list[SecretListItem]


class SecretRotateRequest(BaseModel):
    value: str


class SecretRotateResponse(BaseModel):
    name: str
    resource: str | None
    rotated_at: str


# --- Principal management schemas ---


class PrincipalResponse(BaseModel):
    id: str
    name: str
    type: str
    status: str
    max_scopes: list[str] | None
    max_resources: list[str] | None
    created_at: str


class RedactedKeyInfo(BaseModel):
    key_id: str
    status: str
    allowed_scopes: list[str]
    allowed_resources: list[str] | None
    created_at: str


class PrincipalDetailResponse(BaseModel):
    id: str
    name: str
    type: str
    status: str
    max_scopes: list[str] | None
    max_resources: list[str] | None
    created_at: str
    api_keys: list[RedactedKeyInfo]


class PrincipalListResponse(BaseModel):
    principals: list[PrincipalResponse]


class PolicyUpdateRequest(BaseModel):
    max_scopes: list[str] | None = None
    max_resources: list[str] | None = None
