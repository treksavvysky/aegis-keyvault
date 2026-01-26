import datetime as dt
from typing import Any

from sqlalchemy.orm import Session

from .models import AuditEvent


def emit_audit_event(
    db: Session,
    *,
    event_type: str,
    result: str,
    principal_id: str | None,
    token_jti: str | None = None,
    scope: str | None = None,
    resource: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        ts=dt.datetime.now(dt.timezone.utc),
        principal_id=principal_id,
        event_type=event_type,
        token_jti=token_jti,
        scope=scope,
        resource=resource,
        result=result,
        metadata_json=metadata or {},
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event
