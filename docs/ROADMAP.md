# GODMAN Development Roadmap

## Phase 1 — Conversational foundation
- [x] Python project structure and configuration
- [x] OpenAI Responses API chat
- [x] Bounded session context and input validation
- [x] API error handling

## Phase 2 — Local awareness
- [x] Read-only operating-system diagnostics
- [x] Disk capacity reporting
- [x] Workspace-scoped file listing and reading
- [x] Path traversal and file-size limits

## Phase 3 — Controlled actions
- [x] Explicit tool registry and strict JSON schemas
- [x] Model function-calling loop
- [x] Risk classification and interactive approval
- [x] Workspace file creation without overwrite
- [x] Allow-listed application launcher
- [x] SQLite audit log and audit inspection command
- [ ] Broader app/browser automation (deferred until dedicated review)

## Phase 4 — Voice interface
- [x] Optional push-to-talk audio capture
- [x] Local faster-whisper transcription
- [x] Local text-to-speech
- [ ] Wake-word detection and interruption handling
- [ ] Desktop voice activity indicator

## Phase 5 — Persistent memory
- [x] SQLite notes with category and timestamp
- [x] Keyword search and explicit deletion
- [x] Persistent conversation history
- [x] Recent saved notes injected as untrusted context
- [x] Model-accessible memory search/save/delete tools with approval on writes
- [ ] Semantic/embedding retrieval (future enhancement)

## Verification
- [x] Offline unit tests authored for core, memory, and tools
- [x] GitHub Actions workflow added for compile checks and unit tests
- [ ] Confirm CI run passes on GitHub
- [ ] Run and verify on the owner's Windows laptop

## Next
Phase 6 should add a desktop UI and screen understanding only after the Windows installation and Phase 1–5 tests are verified.

## Cybersecurity Division foundation (added after Phase 5)
- [x] Broad cybersecurity domain map and analyst response policy
- [x] Authorization-first defensive security guidance
- [x] Workspace-bounded log triage with explainable heuristic findings
- [x] Candidate IOC extraction without external lookups
- [x] Local SHA-256 hashing without file execution or upload
- [x] Static file metadata, magic-byte, and entropy inspection without execution
- [x] Cybersecurity reference stack documented
- [x] Offline tests authored for IOC parsing, log triage, path safety, and hashing
- [ ] Execute and verify all tests on Windows and GitHub Actions
- [ ] Add current CVE/advisory retrieval with source/date/confidence
- [ ] Add YARA-based static scanning in an isolated workflow
- [ ] Add Sigma rule parsing and test fixtures
- [ ] Add opt-in Wazuh integration
- [ ] Add OWASP ZAP integration with explicit target allow-lists and safe scan profiles
- [ ] Add network telemetry ingestion and packet analysis
- [ ] Add forensics workflows with evidence integrity and chain-of-custody records


## GODMAN Intelligence Platform — expanded mission

### Cybersecurity operations (defensive, owner-authorized)
- [ ] Windows endpoint inventory and hardening assessment (read-only first)
- [ ] Network asset discovery and passive telemetry ingestion
- [ ] Packet capture parsing and protocol anomaly detection
- [ ] Endpoint event collection and process-tree investigation
- [ ] SIEM connector and Sigma rule validation
- [ ] YARA-X evaluation for static sample scanning in isolation
- [ ] Threat intelligence enrichment with source, timestamp, confidence, and expiry
- [ ] CVE/KEV and vendor advisory correlation against software inventory
- [ ] Incident case management, evidence hashing, timeline, and chain of custody
- [ ] Safe containment playbooks with per-action confirmation and rollback plan
- [ ] Cloud posture and identity configuration assessment
- [ ] Vulnerability scanning limited to explicitly allow-listed owned assets


### Platform reliability and governance
- [ ] Run complete unit suite locally and verify GitHub Actions
- [ ] Add integration tests with recorded/synthetic fixtures and no live side effects
- [ ] Add secrets redaction, retention controls, and per-tool audit provenance
- [ ] Add monitoring scheduler with opt-in scopes, rate limits, and kill switch
- [ ] Add plugin/provider health checks and stale-data alarms


## Defensive baseline milestone
- [x] Build attack-surface/threat-family catalogue (phishing, malicious files, archive bombs, resource exhaustion, ransomware, identity, network, browser, exploit, persistence, supply chain, data theft, physical, cloud, insider, availability)
- [x] Document control mapping, response priorities, limitations, and security acceptance gates
- [x] Review major open-source projects and define adapter-first integration strategy
- [x] Add read-only Windows Defender, Firewall, BitLocker, and hotfix posture snapshot
- [x] Add bounded ZIP metadata inspection for likely archive bombs and unsafe member paths (no extraction)
- [x] Add unit tests for posture collector behavior (mocked PowerShell; no machine changes)
- [x] Add Python 3.10–3.12 GitHub Actions test workflow
- [ ] Verify the workflow passes on GitHub
- [ ] Run posture assessment on the owner's Windows device and review each result
- [ ] Add event collection (Defender/Sysmon) with explicit privacy and retention controls
- [ ] Add safe phishing URL/file triage with reputation source provenance
- [ ] Add bounded archive-bomb/resource-exhaustion inspection
- [ ] Add YARA-X/ClamAV static scanning in an isolated, resource-limited workflow
- [ ] Add Sigma rule validation and mapped Windows event coverage
- [ ] Add passive network telemetry ingestion (Zeek/Suricata)
- [ ] Add threat-intelligence enrichment (CVE/KEV, MISP/OpenCTI)
- [ ] Add incident case/evidence chain-of-custody workflows
- [ ] Add approved remediation playbooks with dry-run, confirmation, and rollback


## Autonomous personal cyber-defence programme

### Implemented in this increment
- [x] Add a consolidated, read-only `/checkup` command combining Defender posture, firewall inventory, and selected Windows event review
- [x] Add event-ID-based triage summaries with explicit severity labels and point-in-time limitations
- [x] Add a Windows first-run checkup guide with safe commands and privacy guidance
- [x] Add an opt-in Microsoft Defender custom scan for a file or subfolder inside the configured GODMAN workspace
- [x] Classify the Defender scan as a system-risk action requiring interactive approval
- [x] Use fixed executable arguments, `shell=False`, path containment, and a bounded timeout
- [x] Add mocked unit tests for path rejection, fixed invocation, and timeout handling
- [ ] Execute the complete test suite and verify GitHub Actions; no passing run is claimed yet

### Required before unattended operation
- [ ] Windows event ingestion (Defender, Security, System, and optional Sysmon) with bounded queries, redaction, retention, and tamper-evident audit
- [ ] Full-device scheduled Defender scans using native Windows scheduling, with explicit owner opt-in, resource windows, notifications, and cancellation
- [ ] File-system change monitoring with exclusions, backpressure, sensor-health checks, and no automatic execution of files
- [ ] Safe phishing triage: URL parsing, IDN/homograph warnings, redirect/reputation lookups with privacy controls, attachment metadata, and no auto-opening
- [ ] Password exposure monitoring through approved provider breach-alert APIs; never collect or transmit raw passwords
- [ ] Vulnerability inventory and CVE/KEV matching; remediation recommendations first, staged patches only after owner approval
- [ ] Windows Firewall profile assessment and proposed inbound-deny rules; changes require preview, approval, and rollback
- [ ] Router/firewall integration through supported vendor APIs; no guessed credentials or exposed management ports
- [ ] Passive network IDS ingestion (Zeek/Suricata) and optional IPS blocking only after false-positive validation
- [ ] Incident response orchestration: quarantine/block/disable-account proposals, evidence snapshot, approval, rollback, and post-action verification
- [ ] Secure remote access via an outbound-initiated, authenticated, encrypted channel with device identity, MFA, short-lived sessions, and no public RDP/agent listener
- [ ] Mobile notifications and secure remote status/control interface with read-only default and step-up approval for changes
- [ ] Curated threat-intelligence updater: vendor advisories, CISA KEV, NVD/CVE, CERT-In, and trusted project releases; source provenance, signature checks, freshness, and rollback
- [ ] Controlled self-update pipeline: signed artifacts, pinned dependencies, SBOM, tests, staged rollout, backup, rollback, and owner approval for privilege/security changes
- [ ] Independent security review, threat modelling, Windows integration tests, recovery drills, and documented false-positive/false-negative limits

### Autonomy boundary
GODMAN may autonomously collect approved telemetry, correlate alerts, refresh signed intelligence,
and recommend low-risk reversible actions. It must not autonomously retaliate, exploit systems,
change firewall policy, terminate arbitrary processes, delete/quarantine user files, rotate
credentials, install unsigned code, or grant itself permissions. A kill switch, audit trail,
and recovery path are mandatory.


## Research-driven implementation priorities (19 Nov 2026)

- [x] Review CERT-In AI-assisted vulnerability defence and AI-agent risk guidance
- [x] Review NIST CSF 2.0, Microsoft Windows security controls, Wazuh, Suricata, OPNsense, Tailscale, and CISA home-network/incident response material
- [x] Record adaptive firewall design, trust boundaries, autonomy policy, and implementation mapping in SECURITY_RESEARCH_BASELINE.md
- [x] Add read-only Windows Firewall profile/rule inventory and conservative baseline planner (no changes)
- [ ] Build sole-owner Windows SID binding, signed policy/configuration and protected recovery controls
- [ ] Implement firewall backup, dry-run diff, per-change owner approval, apply, verification and rollback
- [ ] Inventory the actual Windows endpoint and supported security controls; confirm Defender/Firewall/BitLocker posture on owner's machine
- [x] Add bounded read-only Windows Defender/Security/System event collection with basic message redaction (manual query only)
- [x] Add offline URL structure triage (no network/reputation lookup)
- [ ] Add continuous event collection, durable retention, correlation and alert delivery
- [ ] Evaluate and deploy Wazuh agent/manager architecture in a resource-appropriate lab; no production install until reviewed
- [ ] Identify the exact home router make/model/firmware and determine whether a supported local API exists
- [ ] Add read-only router posture/log adapter for a supported model only
- [ ] Add Suricata passive IDS sensor in a lab or supported gateway; measure traffic visibility and performance
- [ ] Add alert correlation, confidence scoring, deduplication, rate limiting, and sensor health
- [ ] Implement temporary, expiring, allow-listed block proposals with self-lockout protection and rollback
- [ ] Add secure owner-only remote status access with MFA and default read-only permissions
- [ ] Add trusted threat-intelligence updater with provenance, signature verification, freshness, tests, and rollback
