# GODMAN Capability Discovery — Open-source research sweep (2026-11-23)

**Status:** research shortlist and design candidates, not a security audit of the referenced projects. Repositories and claims must be rechecked before adoption. This is not exhaustive: GitHub and the wider internet are too large and change continuously.

## Method and limitations
A web research sweep and GitHub repository/topic searches examined current open-source endpoint protection, threat intelligence, network monitoring, agent security, ransomware protection, and incident-response projects. Public repository descriptions were used for discovery; not every repository was cloned, code-audited, built, benchmarked, or license-checked. Treat candidates as leads, not endorsements. Before dependency or integration decisions, inspect code, license, maintenance, threat model, release history, issues, supply chain, and platform support.

## Highest-value feature opportunities

### 1. Unified telemetry and event normalization
**Opportunity:** common event schema for process start/exit, parent-child process relationships, files, sockets, DNS, authentication, persistence, service/task changes, firewall events, package/software inventory, and OS audit signals; timeline and correlation.
**Candidates:** osquery (SQL-based OS instrumentation); Wazuh (endpoint/XDR/SIEM and FIM/vulnerability/configuration monitoring); Velociraptor (DFIR collection and hunting); native ETW, Event Log, auditd, eBPF, FSEvents/Endpoint Security APIs depending on platform.
**Integration principle:** adapter-first; don't copy entire engines prematurely. Use least-privilege, local-first collection, opt-in queries, bounded output and privacy filtering.

### 2. File integrity and ransomware protection
- Baselines for sensitive paths, system binaries, startup/persistence locations and GODMAN components.
- Real-time filesystem watchers where platform supports them.
- Canary/honey files and bounded burst/change-rate detection.
- Recovery-oriented snapshots/backup integration and restore verification.
- Safe quarantine with metadata, hash, encryption, restore and audit trail.
**Research leads:** Wazuh FIM; PRX-SD; TPT-AV; cross-platform endpoint-security-agent projects.

### 3. Cross-platform malware and file analysis
- Hash reputation and locally cached signatures.
- YARA/YARA-X rule validation and scan integration.
- ClamAV engine integration when installed/appropriate.
- File-format metadata and static triage.
- Isolated sandbox integration (separate research environment).
- Encrypted quarantine and restore.
**Research lead:** PRX-SD reports hash/YARA/heuristic/optional ML, real-time monitoring, ransomware response and platform-specific limitations; ClamAV and YARA/X are established integration candidates.
**Caution:** evaluate licenses, platform gaps and resource requirements. Do not treat a vendor claim as verified efficacy.

### 4. Network detection and adaptive firewall
- Read-only policy inventory and drift detection.
- Listening services/ports and process attribution.
- DNS telemetry and conservative reputation enrichment.
- Passive IDS integration (Suricata/Zeek; consider deployment footprint).
- Rule proposal/simulation, TTL, staged application, health checks and rollback.
- Ransomware/C2/anomaly correlation, with explainable confidence and false-positive safeguards.
**Research leads:** Suricata, Zeek, native firewall APIs, threat-cull/feed aggregators and endpoint firewall projects such as TPT-AV.

### 5. Threat intelligence and knowledge graph
- Feed registry with source provenance, license, freshness, confidence and status.
- STIX/TAXII support where appropriate.
- MISP/OpenCTI-compatible interchange.
- Indicator deduplication, context, expiration, false-positive feedback and correlation.
- ATT&CK mapping and technique → telemetry → detection → response → verification links.
- Local knowledge cache and signed/versioned packs.
**Research leads:** MISP, OpenCTI, community threat-feed repositories, Pharos-style RSS/LLM enrichment, threat-feed aggregators.
**Caution:** IOC feeds are noisy; scoring and expiry matter, and an IP/domain must not automatically trigger a high-impact response.

### 6. Vulnerability and patch intelligence
- Software inventory and version normalization.
- CVE/CISA KEV/vendor advisory correlation.
- Applicability evidence and false-positive uncertainty.
- Prioritization by exposure, exploitability, asset context and remediation cost.
- Safe patch proposal, preview, rollback and verification.
- Dependency and SBOM scanning for GODMAN itself.
**Research leads:** Wazuh vulnerability detection; Trivy; vendor advisories; NVD and CISA KEV.

### 7. Incident case engine and playbooks
- Incident timeline and evidence provenance.
- Correlation across process, file, DNS, network, identity, persistence and vulnerability data.
- Explainable hypotheses with confidence and alternative explanations.
- Local playbooks for safe containment, recovery and verification.
- Dry-run, approval gates, action budgets and replayable audit.
- Playbook simulation and synthetic incident fixtures.
**Research leads:** Wazuh/SOAR ecosystem, open-source SOC projects and agentic SOC research. Avoid adopting agents that have unconstrained privileged actions.

### 8. AI-agent self-protection
Because GODMAN itself is an agent with tools, it needs an independent execution security layer:
- Tool permission registry and pre-dispatch authorization.
- Capability scopes, action budgets, risk gates and time limits.
- Prompt-injection-resistant handling of fetched files, web pages and feeds as untrusted data.
- Separate retrieval from execution; no arbitrary content-to-shell path.
- Tool output sanitization and secrets/PII redaction.
- External action receipt/audit, policy checks, kill switch and session isolation.
- Agent network egress mediation and DLP/SSRF checks.
**Research leads:** Pipelock (agent egress/MCP/A2A mediation and prompt-injection/exfiltration detection); Adrian (runtime agent action monitoring); agentic-suite control/approval tooling. Re-evaluate scope and maturity before integration.

### 9. Privacy-preserving exposure monitoring
- Opt-in email/domain/account exposure checks via reputable providers.
- K-anonymity breached-password lookup where supported; never accept/store plaintext passwords.
- Notification and account recovery workflow.
- User-controlled local data and explicit sharing consent.

### 10. Self-health, resilience and recovery
- Integrity protection for GODMAN binaries, configuration, rules and update manifest.
- Component health and capability checks.
- Safe crash recovery and known-good configuration.
- Signed updates, SBOM, provenance, dependency pinning, rollback.
- Resource budgets and watchdogs with anti-loop safeguards.
- Backups, restore test, incident-safe shutdown, kill switch and uninstall restoration.
- Offline mode and graceful failure when external sources unavailable.

### 11. User experience and operability
- Dashboard: system posture, incidents, coverage, freshness, action history and health.
- CLI with dry-run and explanations.
- Notifications with severity and dedup/cooldown.
- Local-only mode, privacy dashboard, data retention and export/delete controls.
- Accessibility, telemetry opt-in and transparent capability limitations.

## Research leads and source URLs

- osquery: https://github.com/osquery/osquery — SQL-based OS instrumentation.
- Wazuh: https://github.com/wazuh/wazuh — XDR/SIEM, FIM, vulnerability and configuration assessment.
- PRX-SD: https://github.com/openprx/prx-sd — cross-platform scanner research lead (hash/YARA/heuristics/ML and response; inspect platform maturity).
- TPT-AV: https://github.com/tpt-solutions/tpt-av — endpoint suite research lead (firewall, FIM, ransomware, feeds, quarantine, backup; early-stage).
- MISP: https://github.com/MISP/MISP — structured threat-intelligence sharing.
- Pipelock: https://github.com/pipelab-org/pipelock — agent traffic mediation and agent-security controls.
- Adrian: https://github.com/secureagentics/Adrian — runtime AI-agent security monitoring/control.
- Vajra: https://github.com/VajraSecurity/vajra — endpoint, detection, vulnerability and device control research lead.
- Kizashi: https://github.com/kizashi-labs/kizashi — Windows EDR/telemetry and Sigma pipeline research lead (check edition limitations).
- Rustinel: https://github.com/Karib0u/rustinel — cross-platform native telemetry and rule integration research lead.
- Cross-platform endpoint-security-agent: https://github.com/DoradoDevs/endpoint-security-agent — posture, realtime monitoring, ransomware shield and remediation research lead (verify license, maturity and capabilities).
- Pharos: https://github.com/nullvaluefound/pharos — feed aggregation, enrichment and clustering research lead.
- Threat feeds collection: https://github.com/kraloveckey/threat-intelligence-feeds — feed discovery reference (review each source independently).
- Suricata: https://github.com/OISF/suricata — IDS/IPS and network security monitoring.
- Zeek: https://github.com/zeek/zeek — network telemetry and analysis.

## Suggested priority for GODMAN
**P0:** execution-policy boundary, event schema, audit, integrity, update/rollback, privacy and test harness.
**P1:** software/system inventory; persistence; baseline/FIM; process/network/DNS telemetry; security health.
**P2:** threat feed registry + IOC normalization/expiry; vulnerability intelligence; YARA/ClamAV adapter; detection rule test harness.
**P3:** adaptive firewall proposal/simulation/staging/rollback; ransomware signal correlation; incident timeline/case engine.
**P4:** validated local playbooks; recovery/backup integration; exposure monitoring.
**P5:** optional network IDS, cloud integrations, advanced ML and isolated research lab.
**P6:** dashboard, usability, release automation, wider platform adapters.

## Adopt, integrate, or learn — not copy
Use established engines and standards via adapters where practical. Do not blindly copy source code, rules, data, or licenses. Every proposed dependency should have a written evaluation, license compatibility check, threat-model review, tests, resource measurements, platform matrix and rollback plan.

## Next research iteration
1. Inspect actual GODMAN implementation and gaps against this list.
2. Deep-inspect top candidate repositories and license/maturity/architecture, not just README.
3. Produce a feature-by-feature comparison with implementation, integration and dependency decisions.
4. Prioritize one tested capability at a time; maintain a feature matrix and CI acceptance tests.
