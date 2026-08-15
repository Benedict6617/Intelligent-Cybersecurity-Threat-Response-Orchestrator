from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class IncidentOut(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    affected_hosts: list[str] = []
    affected_users: list[str] = []
    escalation_level: int
    confidence_score: int
    playbook_executed: Optional[str] = None
    ticket_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    sla_due_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class IncidentStatusUpdate(BaseModel):
    status: str
    note: Optional[str] = None
    analyst: str = "unknown_analyst"


class PlaybookTriggerRequest(BaseModel):
    playbook_name: Optional[str] = None  # if omitted, auto-select best match
    dry_run: bool = True
    triggered_by: str = "analyst"
