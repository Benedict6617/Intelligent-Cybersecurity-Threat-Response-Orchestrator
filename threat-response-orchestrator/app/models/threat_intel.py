import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, JSON, Float
from app.database import Base


def gen_id() -> str:
    return f"ioc_{uuid.uuid4().hex[:10]}"


class ThreatIndicator(Base):
    """A single Indicator of Compromise pulled from a threat intel feed."""
    __tablename__ = "threat_indicators"

    id = Column(String, primary_key=True, default=gen_id)
    indicator_type = Column(String, nullable=False, index=True)  # ip|domain|hash_sha256|url|email
    value = Column(String, nullable=False, index=True)
    confidence = Column(Float, default=0.5)
    source_feed = Column(String, nullable=True)
    tags = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
