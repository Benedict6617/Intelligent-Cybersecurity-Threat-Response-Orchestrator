"""
ITSM Integration
------------------
Coordinates incident ticket creation/updates with an external ITSM
platform (e.g. ServiceNow, Jira Service Management, Zendesk). Ships as
a safe simulator that creates a local Ticket record; swap
`_create_external_ticket` with a real API call for production use.
"""
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.incident import Incident
from app.models.ticket import Ticket

settings = get_settings()

SEVERITY_TO_PRIORITY = {
    "low": "P4",
    "medium": "P3",
    "high": "P2",
    "critical": "P1",
}


def _create_external_ticket(incident: Incident, priority: str) -> str:
    """
    Placeholder for a real ITSM API call, e.g. (ServiceNow):
        httpx.post(f"{settings.ITSM_BASE_URL}/table/incident", json={...},
                   headers={"Authorization": f"Bearer {settings.ITSM_API_TOKEN}"})
    Returns a simulated external ticket ID.
    """
    return f"SN-{abs(hash(incident.id)) % 100000:05d}"


def create_ticket(incident: Incident, priority: str | None = None) -> str:
    """
    Lightweight variant used by the playbook engine's action handler
    registry (fires-and-logs a result string, no DB write). For a
    persisted Ticket row linked to the incident, use
    `create_ticket_for_incident` from API routes instead.
    """
    priority = priority or SEVERITY_TO_PRIORITY.get(
        incident.severity.value if hasattr(incident.severity, "value") else incident.severity, "P3"
    )
    external_id = _create_external_ticket(incident, priority)
    return f"ITSM ticket {external_id} created in queue '{settings.ITSM_DEFAULT_QUEUE}' with priority {priority}."


def create_ticket_for_incident(db: Session, incident: Incident) -> Ticket:
    priority = SEVERITY_TO_PRIORITY.get(
        incident.severity.value if hasattr(incident.severity, "value") else incident.severity, "P3"
    )
    external_id = _create_external_ticket(incident, priority)
    ticket = Ticket(
        incident_id=incident.id,
        external_id=external_id,
        queue=settings.ITSM_DEFAULT_QUEUE,
        priority=priority,
        status="open",
        summary=incident.title,
    )
    db.add(ticket)
    incident.ticket_id = ticket.id
    incident.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(ticket)
    return ticket
