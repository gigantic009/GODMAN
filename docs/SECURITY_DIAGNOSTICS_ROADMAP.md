# GODMAN Security and Diagnostics Roadmap

This roadmap is prioritized around usable, measurable defensive capabilities across Windows, Linux, macOS, servers, and authorized cloud/network environments. See [Cross-platform architecture](CROSS_PLATFORM_ARCHITECTURE.md). Features are not considered complete until tests and documentation are updated.

## P0 — Stability and safety foundation
- [x] Implement initial Defensive Core foundation: normalized Event/EventBus, evidence-linked Finding/Evidence, default-deny action-intent policy, deterministic detection rules and bus attachment (unit tests added; CI verification pending).
- [ ] Verify audit-branch changes with full test suite and Windows CI.
- [ ] Add Windows test matrix for supported Python versions.
- [ ] Establish Ruff linting, type-checking baseline and coverage reporting.
- [ ] Add dependency vulnerability scanning and secret scanning in CI.
- [ ] Add reproducible fixtures for Windows PowerShell collectors.
- [ ] Improve schema validation to reject unsupported schema constructs and excessive payloads.
- [ ] Add resource/time/output limits for every subprocess and external adapter.
- [ ] Document data flow, storage, retention, API transmission and opt-out.
- [ ] Add configuration validation and diagnostics for missing permissions/dependencies.

## P1 — Diagnostics
- [ ] CPU, memory, storage and system uptime snapshot with historical trends.
- [ ] Process inventory with safe filtering and clear permission limitations.
- [ ] Service inventory and startup configuration review (read-only).
- [ ] Windows reliability events and crash summaries.
- [ ] SMART/storage health where supported, clearly labeling unavailable data.
- [ ] Battery, power and thermal signals where supported.
- [ ] Diagnostic bundle export with privacy review, redaction and user preview.
- [ ] Baseline snapshots and diffs.

## P2 — Vulnerability management
- [ ] Build software inventory from Windows registry/package managers, Linux package managers, and macOS inventory sources.
- [ ] Identify product/version/platform with confidence and evidence.
- [ ] Match against NVD CVE feeds and CISA KEV; include vendor advisories.
- [ ] Include source, publication/update timestamps, CVSS version/vector, KEV status, affected-range evidence and uncertainty.
- [ ] Deduplicate and prioritize by exposure, exploit status, severity, asset context and confidence.
- [ ] Separate confirmed matches from possible matches and false-positive candidates.
- [ ] Produce remediation guidance from vendor sources.
- [ ] Track remediation state and verify version/configuration changes.
- [ ] Cache feeds safely, validate data, enforce freshness and support offline operation.
- [ ] Never claim a CVE applies without match evidence.

## P3 — Threat knowledge core
- [ ] Create normalized threat-technique catalog linked to MITRE ATT&CK, telemetry, platform coverage and mitigations.
- [ ] Integrate vetted threat-indicator feeds with source, timestamps, expiry, confidence and safe caching.
- [ ] Add curated, signed/versioned YARA/Sigma-compatible detection content and fixture regression tests.
- [ ] Build technique-to-detection-to-containment-to-remediation-to-verification mapping.
- [ ] Store safe malware metadata, hashes, analysis summaries and indicators; do not execute samples in the core.
- [ ] Any optional sample analysis must be isolated, disposable, credential-free, network-controlled and separately reviewed.
- [ ] Update threat content atomically, validate, roll back and provide coverage/false-positive metrics.

## P4 — Threat analysis and adaptive defense
- [ ] Build an evidence-backed detection-to-response pipeline (observe, correlate, classify, respond, verify) with confidence and provenance.
- [ ] Implement root-cause case analysis across indicators, execution, persistence, vulnerabilities, affected assets and configuration gaps.
- [ ] Add response profiles with dry-run, scoped local containment, approval, audit, rollback and independent verification.
- [ ] Add privacy-minimized local threat memory, verified feedback, versioned rule updates, expiry and rollback; avoid silent learning from sensitive data.
- [ ] Define emergency-response policy controls, narrow allow-lists, action budgets, safeguards and kill switch.
- [ ] Explicitly prohibit hack-back, offensive actions against attacker infrastructure and attribution-based targeting.

## P3 — Threat analysis
- [ ] Improve URL triage: IDNA/homograph signals, parsing edge cases, offline-only mode.
- [ ] Add optional reputable reputation sources with privacy disclosure and consent.
- [ ] Add static scanning adapters (ClamAV/YARA-compatible) with isolation and resource limits.
- [ ] Add Sigma rule validation and fixture-driven event correlation.
- [x] Add bounded, read-only Windows persistence inventory (Run keys, scheduled tasks, services) with heuristic triage and explicit limitations.
- [ ] Add evidence timeline and case notes with immutable evidence hashes.
- [ ] Add artifact provenance and chain-of-custody export.

## P5 — User exposure and account protection
- [ ] Opt-in account/email exposure monitoring through reputable provider APIs and authorized sources.
- [ ] Privacy-preserving breached-password checks (hash-prefix/k-anonymity protocol where supported); never ingest or store plaintext credentials.
- [ ] Provide breach-context alerts, affected data categories and actionable account recovery steps (password change, MFA/passkeys, session revocation, recovery review).
- [ ] Add user-owned domain exposure and impersonation checks with scope/consent and conservative evidence handling.
- [ ] Minimize notification disclosure and redact exposure data from logs.

## P6 — Network and cloud security
- [ ] Authorized local asset inventory with explicit CIDR allow-list and confirmation.
- [ ] Passive telemetry ingestion (e.g., Zeek/Suricata formats) and anomaly summaries.
- [ ] Protocol metadata inspection and bounded packet-file analysis.
- [ ] Cloud posture adapters only after explicit connector scope and credential protections.
- [ ] No exploit payloads, stealth, persistence or unauthorized scanning.

## P7 — Safe remediation and operations
- [ ] Remediation proposals with risk, evidence, prerequisites and rollback.
- [ ] Dry-run and diff before changes.
- [ ] Step-up confirmation for privileged operations.
- [ ] Recovery checkpoints and failure rollback.
- [ ] Kill switch, audit provenance and independent verification.
- [ ] Optional scheduled monitoring, opt-in scope, rate limits and notifications.
- [ ] Define autonomous modes (observe, guard, approval-based response, narrowly configured emergency response) with action budgets, expiry, lockout safeguards and kill switch.

## P8 — UX, community and releases
- [ ] Interactive terminal UX and guided first-run checkup.
- [ ] Dashboard for health, findings, priorities, evidence and status.
- [ ] Exportable reports that do not leak secrets.
- [ ] Signed releases, SBOM and release checklist.
- [ ] Contribution guide, issue templates, roadmap and security disclosure instructions.
- [ ] Screenshots/demo with synthetic data and privacy-safe examples.
- [ ] Accessibility, localization and performance review.

## Acceptance
No feature is advertised as implemented before it is verified. Scanning and remediation must be owner-authorized, bounded and transparent.

## P4 — Adaptive firewall (planned)
- [ ] Define a normalized firewall policy/rule model, evidence references, expiry, severity, confidence, scope and rollback.
- [ ] Implement read-only firewall posture and policy/event collectors behind platform adapters (Windows first; Linux nftables/ufw and macOS PF capability detection next).
- [ ] Build a rule proposal engine: explainable evidence, narrowly scoped blocks/restrictions, conflict and lockout checks, TTL and audit.
- [ ] Simulate rule decisions against synthetic traffic/event fixtures; add regression cases for false positives and essential connectivity.
- [ ] Implement signed, versioned, compatibility-checked rule packs with atomic updates, freshness checks and rollback.
- [ ] Add staged/guarded enforcement with explicit policy, action budget, kill switch, recovery path and independent verification.
- [ ] Connect verified incident feedback to rule tuning; never auto-promote untrusted telemetry or feed arbitrary content directly into enforcement.
- [ ] Test platform adapters, permission failures, rollback, update failure, lockout protection and graceful unsupported-platform behavior.


## P3 — Continuous global defensive knowledge updates (planned)
- [ ] Build a configurable source registry for reputable researchers, vendor advisories, CERT/CSIRT, standards bodies and approved community sources.
- [ ] Implement bounded feed/API retrieval, source provenance, freshness, attribution, licensing/terms review and rate limits.
- [ ] Normalize advisories, indicators, mitigations, detection rules and defensive technique records.
- [ ] Treat all fetched content as untrusted data; never allow it to issue agent/tool instructions.
- [ ] Verify signatures/integrity where available, deduplicate, track superseded content and surface conflicts/uncertainty.
- [ ] Enrich with platform applicability, ATT&CK mappings, telemetry, mitigations and confidence.
- [ ] Extract defensive knowledge only; do not operationalize runnable offensive payloads, arbitrary commands or exploit code.
- [ ] Generate candidate detection/mitigation updates and synthetic regression fixtures.
- [ ] Test candidate rules for compatibility, false positives, performance and rollback in fixtures/lab.
- [ ] Implement signed/versioned staged updates, atomic promotion, expiry, audit, changelog and rollback.
- [ ] Permit autonomous promotion only for explicitly configured low-impact, validated defensive updates; require approval for high-impact changes.
- [ ] Separate local incident feedback from shared knowledge; privacy-minimize and require consent before data sharing.
- [ ] Establish a community contribution review and provenance workflow.
