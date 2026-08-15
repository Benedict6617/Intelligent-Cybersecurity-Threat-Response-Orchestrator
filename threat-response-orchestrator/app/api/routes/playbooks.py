from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.playbook_engine import load_playbooks, select_playbook, run_playbook
from app.models.incident import Incident
from app.models.playbook import PlaybookRun
from app.models.audit_log import AuditLog
from app.schemas.incident import PlaybookTriggerRequest

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


@router.get("")
def list_playbooks():
    return load_playbooks()


@router.post("/incidents/{incident_id}/execute")
def execute_playbook(incident_id: str, payload: PlaybookTriggerRequest, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")

    if payload.playbook_name:
        playbook = next((p for p in load_playbooks() if p.get("name") == payload.playbook_name), None)
        if not playbook:
            raise HTTPException(404, f"Playbook '{payload.playbook_name}' not found")
    else:
        playbook = select_playbook(incident)
        if not playbook:
            raise HTTPException(409, "No matching playbook found for this incident's MITRE techniques/severity")

    run = run_playbook(db, incident, playbook, triggered_by=payload.triggered_by, dry_run=payload.dry_run)

    db.add(AuditLog(actor=payload.triggered_by, action="playbook_executed", entity_type="playbook_run",
                     entity_id=run.id, details={"incident_id": incident.id, "playbook": playbook.get("name"),
                                                 "dry_run": payload.dry_run, "status": run.status}))
    db.commit()

    return {
        "run_id": run.id,
        "playbook": playbook.get("name"),
        "status": run.status,
        "dry_run": run.dry_run,
        "action_log": run.action_log,
    }


@router.get("/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db)):
    run = db.get(PlaybookRun, run_id)
    if not run:
        raise HTTPException(404, "Playbook run not found")
    return run
