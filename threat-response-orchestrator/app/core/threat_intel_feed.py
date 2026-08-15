"""
Threat Intelligence Feed Integration
----------------------------------------
Ingests Indicators of Compromise (IOCs) from external threat intel
sources (e.g. AlienVault OTX, MISP, commercial feeds) and matches them
against incoming events to enrich correlation confidence. Ships reading
from the bundled sample_data/threat_intel_feed.json for local
evaluation; swap `_fetch_remote_feed` with real feed API calls.
"""
import json
import os
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.threat_intel import ThreatIndicator

settings = get_settings()
SAMPLE_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "sample_data", "threat_intel_feed.json")


def _fetch_remote_feed() -> list[dict]:
    """Placeholder for a real feed pull (OTX/MISP/commercial API)."""
    if not os.path.exists(SAMPLE_PATH):
        return []
    with open(SAMPLE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def sync_feed(db: Session) -> int:
    """Pull the feed and upsert indicators into the local IOC table. Returns count synced."""
    records = _fetch_remote_feed()
    count = 0
    for rec in records:
        existing = (
            db.query(ThreatIndicator)
            .filter(ThreatIndicator.value == rec["value"], ThreatIndicator.indicator_type == rec["indicator_type"])
            .first()
        )
        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            existing.confidence = rec.get("confidence", existing.confidence)
        else:
            db.add(ThreatIndicator(
                indicator_type=rec["indicator_type"],
                value=rec["value"],
                confidence=rec.get("confidence", 0.5),
                source_feed=rec.get("source_feed", "sample_feed"),
                tags=rec.get("tags", []),
                mitre_techniques=rec.get("mitre_techniques", []),
            ))
        count += 1
    db.commit()
    return count


def match_indicator(db: Session, value: str) -> ThreatIndicator | None:
    return db.query(ThreatIndicator).filter(ThreatIndicator.value == value).first()
