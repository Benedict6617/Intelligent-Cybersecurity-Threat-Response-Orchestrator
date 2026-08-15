import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, JSON, Enum, Text, Integer
from app.database import Base


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    TRIAGING = "triaging"
    CONTAINED = "contained"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def gen_id() -> str:
    return f"inc_{uuid.uuid4().hex[:12].upper()}"


class Incident(Base):
    """
    An Incident is created by the correlation engine when one or more
    events cross a correlation threshold (same actor/asset within the
    configured time window mapping to a MITRE ATT&CK chain).
    """
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=gen_id)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(IncidentSeverity), nullable=False, default=IncidentSeverity.LOW, index=True)
    status = Column(Enum(IncidentStatus), nullable=False, default=IncidentStatus.NEW, index=True)

    mitre_tactics = Column(JSON, default=list)      # ["Initial Access", "Execution", ...]
    mitre_techniques = Column(JSON, default=list)    # ["T1566.001", "T1059.001", ...]
    affected_hosts = Column(JSON, default=list)
    affected_users = Column(JSON, default=list)
    event_ids = Column(JSON, default=list)

    assigned_to = Column(String, nullable=True)
    escalation_level = Column(Integer, default=1)  # 1=L1 SOC, 2=L2, 3=IR lead, 4=CISO/exec

    confidence_score = Column(Integer, default=50)  # 0-100, correlation engine confidence
    playbook_executed = Column(String, nullable=True)
    ticket_id = Column(String, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    contained_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)

    sla_due_at = Column(DateTime, nullable=True)
