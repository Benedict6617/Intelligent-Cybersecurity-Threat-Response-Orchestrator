from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.incident import Incident, IncidentStatus, IncidentSeverity
from app.models.event import Event

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(
        Incident.status.notin_([IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE])
    ).count()
    critical_open = db.query(Incident).filter(
        Incident.severity == IncidentSeverity.CRITICAL,
        Incident.status.notin_([IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]),
    ).count()

    by_severity = dict(
        db.query(Incident.severity, func.count(Incident.id)).group_by(Incident.severity).all()
    )
    by_status = dict(
        db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all()
    )

    last_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    events_24h = db.query(Event).filter(Event.ingested_at >= last_24h).count()
    suppressed_24h = db.query(Event).filter(Event.ingested_at >= last_24h, Event.is_false_positive == "true").count()

    top_techniques_raw = (
        db.query(Event.mitre_technique_id, func.count(Event.id))
        .filter(Event.mitre_technique_id.isnot(None))
        .group_by(Event.mitre_technique_id)
        .order_by(func.count(Event.id).desc())
        .limit(8)
        .all()
    )

    return {
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "critical_open": critical_open,
        "incidents_by_severity": {k.value if hasattr(k, "value") else k: v for k, v in by_severity.items()},
        "incidents_by_status": {k.value if hasattr(k, "value") else k: v for k, v in by_status.items()},
        "events_last_24h": events_24h,
        "false_positives_suppressed_last_24h": suppressed_24h,
        "top_mitre_techniques": [{"technique_id": t, "count": c} for t, c in top_techniques_raw],
    }
