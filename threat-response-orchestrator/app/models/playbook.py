import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, JSON, Text, Boolean
from app.database import Base


def gen_id() -> str:
    return f"run_{uuid.uuid4().hex[:12]}"


class PlaybookRun(Base):
    """
    An audit record of a single playbook execution against an incident.
    Every action taken (or simulated, in dry-run mode) is logged in
    `action_log` for after-action review and compliance evidence.
    """
    __tablename__ = "playbook_runs"

    id = Column(String, primary_key=True, default=gen_id)
    playbook_name = Column(String, nullable=False, index=True)
    incident_id = Column(String, nullable=False, index=True)

    triggered_by = Column(String, default="auto")  # "auto" | analyst username
    dry_run = Column(Boolean, default=False)
    status = Column(String, default="pending")  # pending|running|completed|failed|awaiting_approval

    action_log = Column(JSON, default=list)  # [{"step": "...", "result": "...", "timestamp": "..."}]
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
