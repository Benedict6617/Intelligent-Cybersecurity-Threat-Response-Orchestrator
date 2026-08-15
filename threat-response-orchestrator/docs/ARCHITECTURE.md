# Architecture

## Overview

The orchestrator is a single FastAPI service backed by a relational database
(SQLite for local/small deployments, PostgreSQL recommended for production).
It is organized in four layers:

```
connectors/      -> pulls or receives telemetry from SIEM, EDR, firewall, cloud
core/            -> detection & response logic (correlation, ML, playbooks, ITSM, compliance)
api/routes/      -> HTTP surface (FastAPI routers)
models/          -> SQLAlchemy ORM models (source of truth schema)
```

## Data flow

```
1. Ingestion
   Connector (SIEM/EDR/FW/Cloud) --> POST /api/v1/ingest/batch
   Each event is normalized into the common Event schema and mapped to a
   MITRE ATT&CK technique/tactic where the event_type is recognized
   (app/core/mitre_attack.py).

2. False positive suppression
   Every event is scored against allowlists + historical false-positive
   frequency (app/core/false_positive_filter.py). Suppressed events are
   flagged but retained (never deleted) for audit purposes.

3. Anomaly scoring
   The batch is scored with an IsolationForest over behavioral features
   (time of day, event volume per actor, off-hours activity, host fan-out)
   in app/core/anomaly_detection.py.

4. Correlation
   Events are clustered by shared entity (host/user/IP) within a rolling
   time window, then scored by MITRE kill-chain span, severity, and source
   diversity (app/core/correlation_engine.py). Clusters that clear the
   confidence floor become Incidents.

5. Escalation
   Each new Incident is assigned an escalation tier and SLA deadline
   (app/core/escalation_matrix.py). Certain ATT&CK techniques (e.g.
   ransomware indicators) force an immediate critical escalation
   regardless of computed confidence.

6. ITSM ticketing
   A ticket is created in the configured ITSM queue for every incident
   (app/core/itsm_connector.py), keeping the SOC's ticketing system as the
   system of record for SLA tracking alongside the orchestrator.

7. Playbook execution
   Playbooks (app/playbooks/*.yaml) are matched to an incident by MITRE
   technique overlap and minimum severity, then executed step by step
   (app/core/playbook_engine.py). Steps call connector functions (EDR,
   firewall, identity) which default to a safe dry-run/simulation mode.
   Destructive steps can be flagged requires_approval: true to pause for
   analyst sign-off.

8. Forensic timeline
   At any point, GET /incidents/{id}/timeline reconstructs a chronological
   narrative combining raw events and every automated/analyst response
   action, mapped to MITRE tactics (app/core/forensic_timeline.py).

9. Compliance reporting
   GET /compliance/report generates an evidence summary mapping platform
   activity (incidents, playbook runs, audit logs, tickets) to SOC 2 /
   ISO 27001 control themes (app/core/compliance_reporter.py).
```

## Why rule + heuristic scoring instead of a black-box classifier

For a small security team, an auditable "why did this fire" answer matters
more than marginal detection lift from an opaque model. The correlation
engine's confidence score is a weighted, documented formula (kill-chain
span x0.5, severity x0.3, source diversity x0.2) that analysts can inspect
and tune. The IsolationForest anomaly model is used as one input signal,
not the sole decision-maker, and its behavioral features are simple enough
to explain in an audit interview.

## Extending the platform

- **New telemetry source**: add a connector in `app/connectors/`, normalize
  its output to the `EventIngest` schema, and either poll it on a schedule
  or POST to `/ingest/batch`.
- **New detection**: add technique/tactic mappings in `mitre_attack.py` and
  new `related_event_types` so ingestion auto-tags matching events.
- **New playbook**: drop a new YAML file in `app/playbooks/`; no code
  change required unless it needs a new action handler.
- **New action handler**: register a function in
  `app/core/playbook_engine.py::ACTION_HANDLERS` and implement the real
  API call in the relevant connector module.
