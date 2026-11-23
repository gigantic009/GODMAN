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

## Adaptive defense: immune-system model
GODMAN should evolve from point-in-time inspection toward a defensive feedback loop, inspired by biological immune systems. This is a design goal; it is not yet a claim that adaptive response is implemented.

1. **Sense (antigen discovery):** collect bounded, authorized telemetry and artifacts; normalize observations into evidence-backed indicators. Avoid treating a single heuristic as proof.
2. **Identify:** correlate indicators across process, file, persistence, event, network and vulnerability context; attach confidence, provenance and uncertainty.
3. **Learn safely (immune memory):** retain user-approved, privacy-minimized fingerprints, rule outcomes and false-positive feedback. Prefer deterministic, explainable rule updates and signed rule packs. Do not silently train on sensitive user data or turn unverified observations into global threat claims.
4. **Contain locally:** response profiles may block a local connection/indicator, quarantine a file (with restore path), stop a confirmed malicious process, disable a suspicious local persistence entry, isolate an owned endpoint through an authorized platform control, or revoke/rotate a compromised local credential through an explicitly authorized integration. Actions must be scoped, reversible where possible, rate-limited and audited.
5. **Root-cause resolution:** investigate the chain and contributing conditions—not just the alert. Identify entry point, persistence, execution, affected assets, lateral movement evidence, exploited weakness and configuration gap; build a remediation plan; remove/repair identified local artifacts; patch or harden; restore from trusted sources; and verify with a follow-up scan. Report unresolved uncertainties and require approval for high-impact changes.
6. **Recover and verify:** preserve evidence, checkpoint where practical, apply approved actions, verify the result independently and provide rollback/recovery steps.
7. **Adapt:** update local detection baselines and response recommendations based on verified outcomes and explicit feedback, with rule provenance, versioning, expiry and rollback.

### Response boundaries
GODMAN may defend assets the user owns or is explicitly authorized to administer. Its meaning of **retaliation is defensive response**, not hack-back: it must not attack, exploit, DDoS, infiltrate, surveil or damage an attacker's device, infrastructure or account, nor pursue targets based on attribution guesses. Remote threat infrastructure may be reported to providers or authorities through user-approved workflows. Active network actions require explicit target scope and rate limits. High-impact containment and remediation require approval unless a user has separately configured a narrow, documented emergency policy.
