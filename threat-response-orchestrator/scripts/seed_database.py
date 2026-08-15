"""
Initializes the database schema and (optionally) loads the bundled
sample data directly via the ORM - no running API server required.
Useful for CI, first-time setup, or offline demos.

Usage:
    python scripts/seed_database.py
"""
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.database import Base, engine, SessionLocal, init_db  # noqa: E402
from app.core import correlation_engine, anomaly_detection, mitre_attack  # noqa: E402
from app.core.escalation_matrix import apply_escalation  # noqa: E402
from app.core.itsm_connector import create_ticket_for_incident  # noqa: E402
from app.core.threat_intel_feed import sync_feed  # noqa: E402
from app.models.event import Event  # noqa: E402

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_data")
SOURCE_FILES = ["siem_logs.json", "edr_alerts.json", "firewall_logs.json", "cloud_audit_logs.json"]


def main():
    print("Initializing database schema...")
    init_db()

    db = SessionLocal()
    try:
        print("Syncing threat intel feed...")
        synced = sync_feed(db)
        print(f"  synced {synced} indicators")

        print("Loading sample events...")
        created_ids = []
        for filename in SOURCE_FILES:
            path = os.path.join(SAMPLE_DIR, filename)
            if not os.path.exists(path):
                print(f"  skipping missing {filename} (run generate_sample_data.py first)")
                continue
            with open(path, "r", encoding="utf-8") as f:
                for record in json.load(f):
                    event = Event(
                        source=record["source"], source_product=record.get("source_product"),
                        event_type=record["event_type"], severity=record.get("severity", "info"),
                        host=record.get("host"), user=record.get("user"),
                        source_ip=record.get("source_ip"), destination_ip=record.get("destination_ip"),
                        process_name=record.get("process_name"), description=record.get("description"),
                        occurred_at=datetime.fromisoformat(record["occurred_at"]), raw_payload=record,
                    )
                    matches = mitre_attack.techniques_for_event_type(record["event_type"])
                    if matches:
                        event.mitre_technique_id = matches[0].id
                        event.mitre_tactic = matches[0].tactic
                    db.add(event)
                    db.flush()
                    created_ids.append(event.id)
        db.commit()
        print(f"  loaded {len(created_ids)} events")

        print("Scoring anomalies...")
        events = db.query(Event).filter(Event.id.in_(created_ids)).all()
        for result in anomaly_detection.score_events(events):
            db.query(Event).filter(Event.id == result.event_id).update({"anomaly_score": result.anomaly_score})
        db.commit()

        print("Running correlation engine...")
        new_incidents = correlation_engine.correlate(db)
        print(f"  created {len(new_incidents)} incidents")

        for incident in new_incidents:
            apply_escalation(incident)
            create_ticket_for_incident(db, incident)
            print(f"    [{incident.severity.value.upper()}] {incident.id}: {incident.title}")
        db.commit()

        print("\nSeed complete. Start the API with: uvicorn app.main:app --reload")
    finally:
        db.close()


if __name__ == "__main__":
    main()
