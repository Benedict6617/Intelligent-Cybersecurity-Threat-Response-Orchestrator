from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, Field


class EventIngest(BaseModel):
    source: str = Field(..., examples=["siem", "edr", "firewall", "cloud"])
    source_product: Optional[str] = None
    event_type: str
    severity: str = "info"
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    process_name: Optional[str] = None
    description: Optional[str] = None
    occurred_at: datetime
    raw_payload: Optional[dict[str, Any]] = None


class EventOut(BaseModel):
    id: str
    source: str
    event_type: str
    severity: str
    host: Optional[str] = None
    user: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    occurred_at: datetime
    correlation_id: Optional[str] = None
    anomaly_score: Optional[float] = None

    class Config:
        from_attributes = True
