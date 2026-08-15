import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Text
from app.database import Base


def gen_id() -> str:
    return f"tkt_{uuid.uuid4().hex[:10]}"


class Ticket(Base):
    """Local mirror of an ITSM ticket created for an incident (see itsm_connector)."""
    __tablename__ = "tickets"

    id = Column(String, primary_key=True, default=gen_id)
    incident_id = Column(String, nullable=False, index=True)
    external_id = Column(String, nullable=True)  # ID in the external ITSM system
    queue = Column(String, default="SOC-L1")
    priority = Column(String, default="P3")
    status = Column(String, default="open")
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
