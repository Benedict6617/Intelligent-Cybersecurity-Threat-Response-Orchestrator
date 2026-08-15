"""
Playbook Engine
-----------------
Loads declarative YAML playbooks (app/playbooks/*.yaml) and executes them
against an incident. Each playbook step maps to an "action handler" -
in this reference implementation the handlers are connector calls that
default to SAFE SIMULATION MODE (dry_run=True) unless explicitly
configured otherwise, so the platform is safe to demo without live
credentials to EDR/firewall/identity systems.

Design notes:
- Playbooks are matched to incidents by `trigger.mitre_techniques` and
  `trigger.min_severity`.
- Every step outcome is appended to PlaybookRun.action_log for the
  forensic timeline and compliance evidence trail.
- Steps flagged `requires_approval: true` pause the run and surface an
  approval task instead of executing automatically - appropriate for
  destructive actions (e.g. disabling a production account) in small
  teams without 24/7 SOC coverage.
"""
from __future__ import annotations

import glob
import os
from datetime import datetime, timezone
from typing import Callable

import yaml
from sqlalchemy.orm import Session

from app.connectors import cloud_connector, edr_connector, firewall_connector
from app.core import itsm_connector
from app.models.incident import Incident
from app.models.playbook import PlaybookRun

PLAYBOOK_DIR = os.path.join(os.path.dirname(__file__), "..", "playbooks")


def load_playbooks() -> list[dict]:
    playbooks = []
    for path in sorted(glob.glob(os.path.join(PLAYBOOK_DIR, "*.yaml"))):
        with open(path, "r", encoding="utf-8") as f:
            playbooks.append(yaml.safe_load(f))
    return playbooks


def select_playbook(incident: Incident) -> dict | None:
    best = None
    best_overlap = 0
    for pb in load_playbooks():
        trigger = pb.get("trigger", {})
        techniques = set(trigger.get("mitre_techniques", []))
        overlap = len(techniques & set(incident.mitre_techniques or []))
        min_sev_ok = _severity_at_least(incident.severity.value, trigger.get("min_severity", "low"))
        if overlap > 0 and min_sev_ok and overlap > best_overlap:
            best = pb
            best_overlap = overlap
    return best


_SEV_ORDER = ["low", "medium", "high", "critical"]


def _severity_at_least(sev: str, minimum: str) -> bool:
    return _SEV_ORDER.index(sev) >= _SEV_ORDER.index(minimum)


# Action handler registry: action name -> callable(params, incident) -> result string
ACTION_HANDLERS: dict[str, Callable] = {
    "edr.isolate_host": lambda params, incident: edr_connector.isolate_host(
        params.get("host") or (incident.affected_hosts[0] if incident.affected_hosts else "unknown")),
    "edr.kill_process": lambda params, incident: edr_connector.kill_process(
        params.get("host"), params.get("process_name", "unknown")),
    "firewall.block_ip": lambda params, incident: firewall_connector.block_indicators(
        params.get("indicators", [])),
    "identity.disable_account": lambda params, incident: cloud_connector.disable_account(
        params.get("user") or (incident.affected_users[0] if incident.affected_users else "unknown")),
    "identity.force_password_reset": lambda params, incident: cloud_connector.force_password_reset(
        params.get("user") or (incident.affected_users[0] if incident.affected_users else "unknown")),
    "itsm.create_ticket": lambda params, incident: itsm_connector.create_ticket(incident, params.get("priority", "P3")),
    "notify.escalate": lambda params, incident: f"Escalation notification queued for {params.get('notify', [])}",
}


def run_playbook(db: Session, incident: Incident, playbook: dict, triggered_by: str = "auto",
                  dry_run: bool = True) -> PlaybookRun:
    run = PlaybookRun(
        playbook_name=playbook.get("name", "unnamed_playbook"),
        incident_id=incident.id,
        triggered_by=triggered_by,
        dry_run=dry_run,
        status="running",
    )
    db.add(run)
    db.flush()

    action_log = []
    try:
        for step in playbook.get("steps", []):
            step_name = step.get("name", step.get("action"))
            action_name = step["action"]
            params = step.get("params", {})

            if step.get("requires_approval") and triggered_by == "auto":
                action_log.append({
                    "step": step_name,
                    "result": "AWAITING_ANALYST_APPROVAL",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                run.status = "awaiting_approval"
                break

            handler = ACTION_HANDLERS.get(action_name)
            if handler is None:
                result = f"No handler registered for action '{action_name}' (simulated no-op)."
            elif dry_run:
                result = f"[DRY RUN] Would execute '{action_name}' with params={params}."
            else:
                result = handler(params, incident)

            action_log.append({
                "step": step_name,
                "action": action_name,
                "result": result,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        if run.status != "awaiting_approval":
            run.status = "completed"
            run.completed_at = datetime.now(timezone.utc)

    except Exception as exc:  # noqa: BLE001
        run.status = "failed"
        run.error = str(exc)
        action_log.append({
            "step": "error",
            "result": str(exc),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    run.action_log = action_log
    incident.playbook_executed = run.playbook_name
    db.commit()
    db.refresh(run)
    return run
