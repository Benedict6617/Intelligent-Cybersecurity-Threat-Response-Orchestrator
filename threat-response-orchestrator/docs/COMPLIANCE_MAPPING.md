# Compliance Mapping (SOC 2 / ISO 27001)

This platform is built to make it easier for a small security team to
produce audit evidence, not to replace a qualified auditor's assessment.
`GET /api/v1/compliance/report` generates a period-bound evidence summary;
this document explains what each control area maps to and where the
underlying data lives.

| Control | Framework reference | What it verifies | Evidence source in this platform |
|---|---|---|---|
| Security Incident Detection & Response | SOC 2 CC7.2 · ISO 27001 A.5.24 | The organization has a process to detect and respond to security incidents. | `incidents` table — every correlated incident with its MITRE mapping and timestamps. |
| Incident Response Plan Execution | SOC 2 CC7.3 · ISO 27001 A.5.26 | Incident response follows a documented, repeatable process. | `playbook_runs` table — every playbook execution with a full, timestamped action log. |
| Post-Incident Learning | SOC 2 CC7.4 · ISO 27001 A.5.27 | Incidents are reviewed and lessons captured after closure. | Closed incidents + forensic timeline (`/incidents/{id}/timeline`) available for after-action review. |
| Monitoring Activities | SOC 2 CC6.1 · ISO 27001 A.8.16 | Logs from systems and networks are collected and monitored. | `audit_logs` table — immutable-by-convention record of every system and analyst action. |
| Third-Party / Ticketing Coordination | SOC 2 CC9.2 · ISO 27001 A.5.19 | Security incidents are tracked to resolution via a service management process. | `tickets` table, linked 1:1 to incidents via `incident.ticket_id`. |

Control IDs above reference the publicly published AICPA Trust Services
Criteria and ISO/IEC 27001:2022 Annex A control themes; no proprietary
standards text is reproduced here — only the mapping of platform
activity to each control's stated intent.

## Preparing for an audit

1. Run `GET /compliance/report?framework=SOC2&days=365` (or `ISO27001`)
   for the audit period your assessor requests.
2. Export the incident list and forensic timelines for any incidents the
   auditor samples (`/incidents/{id}/timeline`).
3. Export the relevant slice of `audit_logs` to demonstrate monitoring
   coverage and non-repudiation of analyst actions.
4. Retain the underlying database (or a nightly export) per your
   organization's evidence retention policy — typically the full audit
   period plus one year.

## Limitations

- This is a reference implementation, not a certified GRC platform. Field
  names and control mappings should be reviewed with your auditor before
  first use.
- SLA compliance percentages are computed from `contained_at` vs.
  `sla_due_at`; make sure your escalation matrix (`app/core/
  escalation_matrix.py`) reflects your organization's actual documented
  SLAs before relying on this figure as audit evidence.
