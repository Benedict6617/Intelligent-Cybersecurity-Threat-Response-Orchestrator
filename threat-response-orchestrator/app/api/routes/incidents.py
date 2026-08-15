from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.forensic_timeline import build_timeline
from app.core.escalation_matrix import is_sla_breached, next_escalation_on_breach, resolve_tier
from app.models.incident import Incident, IncidentStatus
from app.models.audit_log import AuditLog
from app.schemas.incident import IncidentOut, IncidentStatusUpdate

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=list[IncidentOut])
def list_incidents(status: str | None = None, severity: str | None = None, db: Session = Depends(get_db)):
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    return q.order_by(Incident.created_at.desc()).all()


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident


@router.get("/{incident_id}/timeline")
def get_incident_timeline(incident_id: str, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return build_timeline(db, incident)


@router.get("/{incident_id}/escalation")
def get_incident_escalation(incident_id: str, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    tier = resolve_tier(incident)
    breached = is_sla_breached(incident)
    next_tier = next_escalation_on_breach(incident)
    return {
        "incident_id": incident.id,
        "current_tier": {"level": tier.level, "name": tier.name, "notify": tier.notify},
        "sla_due_at": incident.sla_due_at,
        "sla_breached": breached,
        "next_tier_if_breached": ({"level": next_tier.level, "name": next_tier.name} if next_tier else None),
    }


@router.patch("/{incident_id}/status", response_model=IncidentOut)
def update_status(incident_id: str, payload: IncidentStatusUpdate, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")

    if payload.status not in [s.value for s in IncidentStatus]:
        raise HTTPException(400, f"Invalid status. Must be one of {[s.value for s in IncidentStatus]}")

    old_status = incident.status.value
    incident.status = payload.status
    incident.updated_at = datetime.now(timezone.utc)
    if payload.status == "contained" and not incident.contained_at:
        incident.contained_at = datetime.now(timezone.utc)
    if payload.status == "closed" and not incident.closed_at:
        incident.closed_at = datetime.now(timezone.utc)

    db.add(AuditLog(actor=payload.analyst, action="incident_status_changed", entity_type="incident",
                     entity_id=incident.id, details={"from": old_status, "to": payload.status, "note": payload.note}))
    db.commit()
    db.refresh(incident)
    return incident
