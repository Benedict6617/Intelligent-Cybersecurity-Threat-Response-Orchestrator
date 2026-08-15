"""
Correlation Engine
-------------------
Groups normalized events into candidate incidents by clustering on shared
entities (host, user, source IP) within a sliding time window, then scores
each cluster using MITRE ATT&CK kill-chain span, source diversity, and
severity to produce a confidence score and recommended incident severity.

This is intentionally rule + heuristic based (not a black box) so SOC
analysts can audit *why* an incident was raised, per SOC2/ISO27001 change
and detection traceability expectations.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from sqlalchemy.orm import Session

from app.config import get_settings
from app.core import mitre_attack
from app.models.event import Event, EventSeverity
from app.models.incident import Incident, IncidentSeverity

settings = get_settings()

SEVERITY_WEIGHT = {
    EventSeverity.INFO: 0,
    EventSeverity.LOW: 1,
    EventSeverity.MEDIUM: 2,
    EventSeverity.HIGH: 4,
    EventSeverity.CRITICAL: 6,
}


def _entity_key(event: Event) -> str | None:
    """The identity an event is clustered on: prefer host, then user, then source IP."""
    return event.host or event.user or event.source_ip


def cluster_events(events: list[Event], window_minutes: int) -> list[list[Event]]:
    """Group events sharing an entity key into time-windowed clusters."""
    by_entity: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        key = _entity_key(e)
        if key:
            by_entity[key].append(e)

    clusters: list[list[Event]] = []
    window = timedelta(minutes=window_minutes)

    for _entity, ev_list in by_entity.items():
        ev_list.sort(key=lambda e: e.occurred_at)
        current: list[Event] = []
        for e in ev_list:
            if not current:
                current = [e]
                continue
            if e.occurred_at - current[-1].occurred_at <= window:
                current.append(e)
            else:
                if len(current) > 1:
                    clusters.append(current)
                current = [e]
        if len(current) > 1:
            clusters.append(current)
    return clusters


def score_cluster(events: list[Event]) -> dict:
    """Compute confidence score (0-100) and recommended severity for a cluster."""
    tactics = sorted({e.mitre_tactic for e in events if e.mitre_tactic})
    techniques = sorted({e.mitre_technique_id for e in events if e.mitre_technique_id})
    sources = {e.source for e in events}

    kill_chain_score = mitre_attack.tactic_progression_score(tactics)  # 0-1
    severity_score = sum(SEVERITY_WEIGHT.get(e.severity, 0) for e in events)
    severity_score = min(severity_score / 12, 1.0)  # normalize, cap at 1
    source_diversity_score = min(len(sources) / 4, 1.0)  # correlating across sources = stronger signal

    confidence = (
        kill_chain_score * 0.5 +
        severity_score * 0.3 +
        source_diversity_score * 0.2
    ) * 100

    if kill_chain_score >= 0.5 or severity_score >= 0.8:
        rec_severity = IncidentSeverity.CRITICAL
    elif kill_chain_score >= 0.3 or severity_score >= 0.5:
        rec_severity = IncidentSeverity.HIGH
    elif kill_chain_score > 0 or severity_score >= 0.25:
        rec_severity = IncidentSeverity.MEDIUM
    else:
        rec_severity = IncidentSeverity.LOW

    return {
        "confidence": round(confidence, 1),
        "severity": rec_severity,
        "tactics": tactics,
        "techniques": techniques,
    }


def build_incident_title(events: list[Event], techniques: list[str]) -> str:
    entity = _entity_key(events[0]) or "unknown asset"
    if techniques:
        top = mitre_attack.get_technique(techniques[-1])
        chain_desc = top.name if top else techniques[-1]
    else:
        chain_desc = events[0].event_type.replace("_", " ").title()
    return f"Suspected {chain_desc} activity involving {entity}"


def correlate(db: Session, lookback_events: Iterable[Event] | None = None) -> list[Incident]:
    """
    Run correlation over recently ingested, not-yet-correlated events and
    materialize new Incident records for clusters that clear the minimum
    confidence bar. Returns the list of newly created incidents.
    """
    if lookback_events is None:
        lookback_events = (
            db.query(Event)
            .filter(Event.correlation_id.is_(None))
            .order_by(Event.occurred_at.asc())
            .all()
        )
    events = list(lookback_events)
    if not events:
        return []

    clusters = cluster_events(events, settings.CORRELATION_WINDOW_MINUTES)
    new_incidents: list[Incident] = []

    for cluster in clusters:
        result = score_cluster(cluster)
        if result["confidence"] < 20:  # below noise floor, leave uncorrelated
            continue

        incident = Incident(
            title=build_incident_title(cluster, result["techniques"]),
            description=(
                f"Correlated from {len(cluster)} events across "
                f"{sorted({e.source.value for e in cluster})} between "
                f"{cluster[0].occurred_at.isoformat()} and {cluster[-1].occurred_at.isoformat()}."
            ),
            severity=result["severity"],
            mitre_tactics=result["tactics"],
            mitre_techniques=result["techniques"],
            affected_hosts=sorted({e.host for e in cluster if e.host}),
            affected_users=sorted({e.user for e in cluster if e.user}),
            event_ids=[e.id for e in cluster],
            confidence_score=int(result["confidence"]),
        )
        db.add(incident)
        db.flush()  # get incident.id

        for e in cluster:
            e.correlation_id = incident.id

        new_incidents.append(incident)

    db.commit()
    return new_incidents
