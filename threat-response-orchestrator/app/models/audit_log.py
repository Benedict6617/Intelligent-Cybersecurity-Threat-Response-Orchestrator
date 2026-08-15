import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, JSON
from app.database import Base


def gen_id() -> str:
    return f"aud_{uuid.uuid4().hex[:12]}"


class AuditLog(Base):
    """
    Immutable-by-convention audit trail of every system and analyst action.
    This is the primary evidence source for SOC2 / ISO27001 audit reporting.
    """
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=gen_id)
    actor = Column(String, nullable=False)  # "system" or analyst username
    action = Column(String, nullable=False, index=True)
    entity_type = Column(String, nullable=True)
    entity_id = Column(String, nullable=True, index=True)
    details = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
