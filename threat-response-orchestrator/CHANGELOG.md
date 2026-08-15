# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] - 2026-08-13

### Added
- Initial release: event ingestion API for SIEM/EDR/firewall/cloud sources.
- MITRE ATT&CK-based correlation engine with explainable confidence scoring.
- False positive suppression (allowlist + historical frequency heuristics).
- ML-based anomaly detection (IsolationForest) over behavioral event features.
- Incident escalation matrix with SLA tracking and auto-escalation on breach.
- YAML-driven playbook engine with four bundled response playbooks
  (ransomware containment, phishing response, brute force lockout,
  malware isolation).
- ITSM ticket coordination (simulated connector, ready for a real ITSM API).
- Threat intelligence feed ingestion and IOC matching.
- Forensic timeline reconstruction per incident.
- SOC 2 / ISO 27001 compliance evidence reporting.
- Static analyst dashboard (SOC console UI).
- Realistic bundled sample data with two full attack narratives
  (phishing-to-exfiltration, brute-force-to-ransomware).
- Test suite covering correlation, false-positive filtering, escalation,
  and playbook selection logic.
