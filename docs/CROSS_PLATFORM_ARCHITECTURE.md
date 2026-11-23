# Cross-platform GODMAN architecture

## Mission
GODMAN is intended to be a cross-platform defensive security and system-maintenance assistant. Windows is the first implementation target, not the product boundary.

## Design: core plus platform adapters
- **Core:** policy, risk classification, evidence format, scoring, reporting, privacy, approvals, audit, test harness and update mechanisms.
- **Platform adapters:** operating-system-specific collectors and controls. Each adapter declares supported OS/version, prerequisites, collection scope, limits and evidence provenance.
- **Integrations:** vendor security tools and open-source engines through narrow, reviewed interfaces; never assume an adapter is present.
- **Unified findings:** stable finding schema containing rule ID, severity, confidence, affected asset, evidence, source, timestamp, remediation, verification status and uncertainty.

## Platform roadmap
### Windows
Defender, firewall, event logs, persistence (Run keys, tasks, services), software inventory, hardening, patch and CVE matching.

### Linux
Distribution/package inventory, kernel and patch status, systemd services and timers, SSH posture, sudo configuration, permissions, firewall signals, auth/audit logs, persistence and package vulnerability matching. Support major families (Debian/Ubuntu, Fedora/RHEL, Arch) through adapters rather than assumptions.

### macOS
System extensions and security posture signals, Gatekeeper/XProtect status where observable, launch agents/daemons, unified logs, firewall, SIP status, software inventory and update status. Respect privacy controls and platform restrictions.

### Servers and cloud
Authorized configuration assessment, identity and access posture, exposed services, inventory, cloud resource configuration and audit-log integration. Connectors must use least-privilege scopes and explicit consent.

### Network
Passive log/telemetry analysis first. Active inventory or scanning must be limited to explicit owner-authorized ranges, rate limited and clearly disclosed.

## Quality and safety
- Collection is read-only by default.
- Findings are evidence-backed and distinguish observations from inference.
- Remediation is a proposed change, previewed, approved, bounded, logged, and independently verified; rollback where possible.
- Every adapter has mockable tests, fixture-based integration tests, time/output/resource bounds and a graceful unsupported-platform result.
- Do not execute unknown samples. Malware scanning is delegated to trusted engines or isolated analysis environments.
- Do not upload user data or samples to third-party services without explicit consent and disclosure.

## Target capability maturity
1. Point-in-time collectors and reports.
2. Cross-platform software inventory and vulnerability matching.
3. Correlation, baselines and user-configured monitoring.
4. Approved maintenance workflows with rollback and verification.
5. Optional integrations and dashboards.

GODMAN does not claim to replace dedicated EDR, SIEM, incident response teams, or enterprise security operations.
