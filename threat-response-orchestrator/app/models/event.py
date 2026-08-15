import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Float, JSON, Enum, Text
from app.database import Base


class EventSource(str, enum.Enum):
    SIEM = "siem"
    EDR = "edr"
    FIREWALL = "firewall"
    CLOUD = "cloud"
    IDENTITY = "identity"
    EMAIL_GATEWAY = "email_gateway"


class EventSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def gen_id() -> str:
    return f"evt_{uuid.uuid4().hex[:16]}"


class Event(Base):
    """
    A normalized security event ingested from any connector (SIEM, EDR,
    firewall, cloud audit trail, identity provider, or email gateway).

    Raw payloads are preserved in `raw_payload` for forensic fidelity;
    the top-level columns are the normalized common schema used by the
    correlation engine.
    """
    __tablename__ = "events"

    id = Column(String, primary_key=True, default=gen_id)
    source = Column(Enum(EventSource), nullable=False, index=True)
    source_product = Column(String, nullable=True)  # e.g. "Splunk", "CrowdStrike", "Palo Alto"
    event_type = Column(String, nullable=False, index=True)  # e.g. "authentication_failure"
    severity = Column(Enum(EventSeverity), nullable=False, default=EventSeverity.INFO, index=True)

    host = Column(String, nullable=True, index=True)
    user = Column(String, nullable=True, index=True)
    source_ip = Column(String, nullable=True, index=True)
    destination_ip = Column(String, nullable=True, index=True)
    process_name = Column(String, nullable=True)

    mitre_technique_id = Column(String, nullable=True, index=True)  # e.g. "T1110"
    mitre_tactic = Column(String, nullable=True)  # e.g. "Credential Access"

    description = Column(Text, nullable=True)
    raw_payload = Column(JSON, nullable=True)

    ingested_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    occurred_at = Column(DateTime, nullable=False, index=True)

    correlation_id = Column(String, nullable=True, index=True)  # set once correlated into an incident
    is_false_positive = Column(String, default="unknown")  # "unknown"|"true"|"false"
    anomaly_score = Column(Float, nullable=True)
