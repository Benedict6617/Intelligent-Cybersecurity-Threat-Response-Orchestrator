# Security Policy

This project is a reference SOAR platform. If you discover a
vulnerability in the platform itself (not in your own deployment
configuration), please report it privately rather than opening a public
GitHub issue, so it can be fixed before disclosure.

**To report a vulnerability:** open a private security advisory on this
repository (GitHub → Security → Advisories → Report a vulnerability), or
contact the maintainer listed on the repository profile directly.

## Operational security notes for deployers

- This reference implementation does not ship an authentication layer.
  Do not expose the API or dashboard outside a trusted network without
  adding SSO/auth in front of it (see `docs/DEPLOYMENT.md`).
- Connector modules (`app/connectors/*.py`) default to a safe simulation
  mode. Review and test thoroughly in a staging environment before
  connecting real EDR/firewall/identity credentials capable of taking
  destructive action (host isolation, account disablement, etc).
- Treat `audit_logs`, `incidents`, and `events` tables as sensitive data —
  they contain details about your organization's security posture and
  active investigations.
