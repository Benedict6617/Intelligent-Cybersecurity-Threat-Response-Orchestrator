from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.threat_intel_feed import sync_feed, match_indicator
from app.models.threat_intel import ThreatIndicator

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


@router.post("/sync")
def sync(db: Session = Depends(get_db)):
    count = sync_feed(db)
    return {"synced_indicators": count}


@router.get("/indicators")
def list_indicators(indicator_type: str | None = None, db: Session = Depends(get_db)):
    q = db.query(ThreatIndicator)
    if indicator_type:
        q = q.filter(ThreatIndicator.indicator_type == indicator_type)
    return q.order_by(ThreatIndicator.last_seen.desc()).limit(200).all()


@router.get("/indicators/lookup")
def lookup(value: str, db: Session = Depends(get_db)):
    match = match_indicator(db, value)
    return {"value": value, "matched": match is not None, "indicator": match}
