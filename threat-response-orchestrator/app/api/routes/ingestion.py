from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.core import correlation_engine, false_positive_filter, mitre_attack, anomaly_detection
from app.core.itsm_connector import create_ticket_for_incident
from app.core.escalation_matrix import apply_escalation
from app.models.event import Event
from app.models.audit_log import AuditLog
from app.schemas.event import EventIngest, EventOut

router = APIRouter(prefix="/ingest", tags=["ingestion"])


@router.post("/event", response_model=EventOut)
def ingest_event(payload: EventIngest, db: Session = Depends(get_db)):
    """
    Normalize and store a single security event from any connector
    (SIEM, EDR, firewall, cloud, identity, email gateway). Automatically
    maps the event to a MITRE ATT&CK technique when the event_type is
    recognized, scores false-positive likelihood, and stores the result.
    """
    event = Event(
        source=payload.source,
        source_product=payload.source_product,
        event_type=payload.event_type,
        severity=payload.severity,
        host=payload.host,
        user=payload.user,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        process_name=payload.process_name,
        description=payload.description,
        occurred_at=payload.occurred_at,
        raw_payload=payload.raw_payload or {},
    )

    matches = mitre_attack.techniques_for_event_type(payload.event_type)
    if matches:
        event.mitre_technique_id = matches[0].id
        event.mitre_tactic = matches[0].tactic

    db.add(event)
    db.flush()

    fp_rate = false_positive_filter.compute_historical_fp_rate(db, event.event_type, event.host)
    suppression = false_positive_filter.evaluate(event, historical_fp_rate=fp_rate)
    if suppression.suppressed:
        event.is_false_positive = "true"

    db.add(AuditLog(actor="system", action="event_ingested", entity_type="event", entity_id=event.id,
                     details={"source": payload.source, "event_type": payload.event_type,
                              "suppressed": suppression.suppressed, "reason": suppression.reason}))
    db.commit()
    db.refresh(event)

    return EventOut(
        id=event.id, source=event.source.value, event_type=event.event_type,
        severity=event.severity.value, host=event.host, user=event.user,
        mitre_technique_id=event.mitre_technique_id, mitre_tactic=event.mitre_tactic,
        occurred_at=event.occurred_at, correlation_id=event.correlation_id,
        anomaly_score=event.anomaly_score,
    )


@router.post("/batch")
def ingest_batch(payloads: list[EventIngest], db: Session = Depends(get_db)):
    """Bulk ingestion endpoint used by connector polling jobs (see scripts/simulate_attack.py)."""
    created_ids = []
    for payload in payloads:
        event = Event(
            source=payload.source, source_product=payload.source_product,
            event_type=payload.event_type, severity=payload.severity,
            host=payload.host, user=payload.user, source_ip=payload.source_ip,
            destination_ip=payload.destination_ip, process_name=payload.process_name,
            description=payload.description, occurred_at=payload.occurred_at,
            raw_payload=payload.raw_payload or {},
        )
        matches = mitre_attack.techniques_for_event_type(payload.event_type)
        if matches:
            event.mitre_technique_id = matches[0].id
            event.mitre_tactic = matches[0].tactic
        db.add(event)
        db.flush()
        created_ids.append(event.id)
    db.commit()

    # Score anomalies across the freshly ingested batch
    events = db.query(Event).filter(Event.id.in_(created_ids)).all()
    for result in anomaly_detection.score_events(events):
        db.query(Event).filter(Event.id == result.event_id).update({"anomaly_score": result.anomaly_score})
    db.commit()

    # Run correlation over uncorrelated events (this batch + any prior leftovers)
    new_incidents = correlation_engine.correlate(db)

    for incident in new_incidents:
        apply_escalation(incident)
        create_ticket_for_incident(db, incident)
        db.add(AuditLog(actor="system", action="incident_created", entity_type="incident",
                         entity_id=incident.id, details={"severity": incident.severity.value,
                                                          "confidence": incident.confidence_score}))
    db.commit()

    return {
        "events_ingested": len(created_ids),
        "incidents_created": [i.id for i in new_incidents],
    }
