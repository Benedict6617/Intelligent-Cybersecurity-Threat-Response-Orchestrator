from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.compliance_reporter import generate_report

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/report")
def report(
    framework: str = Query("SOC2", description="SOC2 or ISO27001"),
    days: int = Query(90, description="Look-back window in days"),
    db: Session = Depends(get_db),
):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return generate_report(db, start, end, framework=framework)
