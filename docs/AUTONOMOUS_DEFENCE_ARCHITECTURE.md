# GODMAN Autonomous Defence Architecture

## Mission

Build a personal, owner-controlled defensive operations platform for a Windows endpoint
and home network. The target capability is continuous monitoring, evidence-led triage,
safe containment, recovery, secure remote status access, and curated threat-intelligence
updates. This document is a target architecture, not a claim that these services are
already deployed.

## Design principles

- Defence only: block, isolate, rate-limit, preserve evidence, alert, and recover. No
  retaliation, counter-intrusion, payload delivery, credential theft, or disruption of
  third-party infrastructure.
- Least privilege: separate the monitoring service from the privileged remediation
  broker; the AI model never receives administrator credentials.
- Default deny: network exposure and tool permissions are off unless explicitly enabled.
- Human control for high-impact actions: firewall edits, device isolation, process
  termination, quarantine/deletion, account/session revocation, and software updates
  require preview, owner approval, and a rollback plan.
- Local-first privacy: private files and raw credentials are not uploaded for analysis.
- Verifiable operation: signed components, health checks, append-only audit, evidence
  hashes, alert provenance, and tested restore paths.
- Honest uncertainty: no alert is not proof of safety; detection and prevention coverage
  are measured and limitations are visible.

## Target architecture

```text
Windows endpoint sensors ──┐
Defender / Security / Sysmon ├──> Local event broker ──> Detection + correlation
File inventory / scan status ┘             │                     │
                                           │                     ├──> Incident case
Home router / DNS / IDS logs ──────────────┘                     ├──> Owner alert
                                                                 └──> Response planner
                                                                          │
                                                          Policy + approval broker
                                                                          │
                                               Windows Firewall / Defender / account APIs
                                                                          │
                                                               Verify + rollback

Signed threat feeds ──> isolated updater ──> staged intelligence/rules database
Secure outbound tunnel ──> authenticated remote console / mobile notification
```

The model is an analyst and planner, not the security boundary. Deterministic policy,
OS permissions, signatures, and a small privileged broker enforce what can happen.

## 1. Endpoint and file protection

Target controls:
- Keep Microsoft Defender real-time protection, cloud protection, tamper protection,
  SmartScreen, and automatic security intelligence updates enabled.
- Use Defender scheduled quick scans and periodic full scans. GODMAN should schedule
  these only after the owner selects the scan window, battery/CPU policy, exclusions,
  notification policy, and cancellation behavior.
- Monitor file creation/modification events with a bounded, restartable sensor. Avoid
  recursively hashing every file on every event; use a baseline, queue limits, deduping,
  and periodic reconciliation.
- Use Defender/AMSI/SmartScreen and optional ClamAV/YARA-X adapters. Samples must never
  be executed by the triage pipeline; deeper dynamic analysis belongs in a disposable,
  isolated sandbox.
- Treat detections as evidence with engine, signature version, timestamp, file hash,
  path scope, and action status. Quarantine is a separate approved action.
- Exclude OS-managed paths only where the vendor recommends it; do not create broad
  exclusions merely to improve performance.

Current repository status: basic static file metadata/hash inspection, ZIP metadata
inspection, Windows posture snapshot, and an approval-gated Defender custom scan of a
selected GODMAN workspace file/folder. No continuous file sensor or full-device scan
scheduler is currently implemented.

## 2. Network firewall and intrusion prevention

Endpoint layer:
- Assess Windows Firewall profiles and inbound/outbound defaults.
- Generate proposed least-privilege rules with a before/after diff and explanation.
- Never silently flush rules, disable the firewall, or block arbitrary remote IPs.
- Apply changes only after approval, record the previous rule state, verify the
  management connection remains available, and provide rollback.

Home-network layer:
- Prefer a supported router/firewall platform and its authenticated management API.
- Use WPA2-AES/WPA3, unique router admin credentials, firmware updates, guest/IoT
  segmentation, disabled WPS, and no public router administration.
- Ingest router DHCP, DNS, firewall, and Wi-Fi association logs where supported.
- Start network detection in passive IDS mode with Zeek/Suricata. IPS blocking is a
  later opt-in after tuning and false-positive review.
- A host firewall cannot replace a properly configured router firewall; a router
  firewall cannot replace endpoint protection.

## 3. Vulnerability discovery and remediation

1. Inventory OS build, installed applications, services, listening sockets, drivers,
   browser extensions, and relevant configuration without collecting secrets.
2. Match exact product/version evidence to vendor advisories, NVD/CVE, CISA KEV, and
   CERT-In advisories. Preserve source URL, publication/update time, affected version
   range, confidence, and match rationale.
3. Rank by confirmed exposure, exploit activity, privilege, asset criticality, and
   compensating controls—not CVSS alone.
4. Propose a vendor-supported update or configuration change and show impact.
5. Apply only with explicit approval, backup/restore point where appropriate, and
   post-change verification.

Do not run exploit modules against the owner's live computer as a substitute for
version/configuration evidence. Active scanning must be limited to an explicit
owner-controlled asset allow-list and safe profile.

## 4. Phishing and identity protection

- Parse URLs locally first; normalize hostnames carefully and flag punycode/IDN,
  deceptive subdomains, unusual ports, IP-literal hosts, URL shorteners, and mismatched
  visible link text.
- Do not open links automatically. Reputation lookups must disclose what URL data is
  sent to which provider and require privacy-aware settings.
- Parse email headers and attachment metadata without executing attachments.
- For account security, use each provider's official security activity, sign-in alerts,
  OAuth app review, session/device list, and password-change notification mechanisms.
- For breach exposure, use an approved breach-monitoring provider or k-anonymous
  password-range lookup where appropriate. Never send raw passwords to GODMAN, ChatGPT,
  a breach-search service, or a custom endpoint. Use password-manager breach alerts,
  unique generated passwords, passkeys, MFA, and session revocation.
- GODMAN cannot know that an account password changed unless the account provider
  exposes an authorized alert/API or the owner connects an approved integration.

## 5. Remote access while the owner is away

- Prefer an outbound-initiated, mutually authenticated tunnel such as a well-reviewed
  mesh VPN (for example, Tailscale or WireGuard with a managed control plane).
- Do not expose RDP, SMB, SSH, GODMAN's local API, or router administration directly
  to the public internet.
- Bind local control services to loopback/private interfaces; enforce device identity,
  MFA, short-lived sessions, TLS, rate limits, replay protection, and revocation.
- Remote default is read-only status, alerts, and incident summaries. High-impact
  actions require step-up authentication and an explicit approval on the owner device.
- Use mobile push notifications through a reputable provider; minimize notification
  content so secrets and sensitive file paths do not leak.
- Provide a physical/local kill switch to revoke remote sessions and stop the agent.

No remote control server, mobile app, push-notification service, or VPN connector is
currently deployed in the repository.

## 6. Continuous threat learning

"Self-learning" must mean curated, verifiable intelligence ingestion—not arbitrary
internet content becoming executable policy.

Allowed pipeline:
1. Fetch from an allow-list of vendor advisories, CISA KEV, NVD/CVE, CERT-In, trusted
   security project releases, and selected research feeds.
2. Verify TLS, signatures/checksums where provided, publisher identity, schema, and
   release provenance.
3. Parse content in a low-privilege isolated worker; treat every feed as untrusted data.
4. Store source, timestamp, affected versions, confidence, expiry, license, and content
   hash. Deduplicate and expire stale indicators.
5. Convert only reviewed detection content into test fixtures/rules; run regression
   tests against benign and malicious fixtures before activation.
6. Stage updates, monitor health/false positives, and roll back automatically if
   validation or service health fails.

Never let a webpage, prompt injection, untrusted repository, or downloaded script
modify system instructions, grant privileges, execute commands, disable protections,
or update GODMAN binaries. Model weights/code updates are a separate signed release
process with SBOM, pinned dependencies, provenance, tests, backup, and rollback.
Security-sensitive updates require owner approval.

## 7. Incident response playbooks

- Suspicious file: preserve metadata/hash, request Defender scan, correlate source and
  event history, recommend quarantine; do not execute or delete it.
- Suspected ransomware: alert immediately, preserve volatile evidence where safe,
  propose network isolation, protect backups, and guide recovery from known-good media.
- Account compromise: use a clean device, official provider flow, revoke sessions/tokens,
  rotate affected credentials, verify MFA/recovery methods, and review OAuth grants.
- Network intrusion: preserve router/IDS logs, identify affected owned devices, propose
  segmentation/block rules, and verify no management path is lost.
- Confirmed vulnerability: map installed version, retrieve vendor advisory, stage
  vendor patch, verify installed version and service health.

Each case records UTC timestamps, source, confidence, evidence hashes, analyst decisions,
owner approvals, actions, results, and rollback status.

## 8. What "autonomous" is allowed to mean

Can be automatic after explicit setup:
- Scheduled posture checks and approved scans.
- Read-only event collection and alert correlation.
- Signed threat-feed refresh and detection-rule test runs.
- Notifications, stale-sensor warnings, and incident draft creation.
- Reversible low-risk actions with strict policy, rate limits, and an undo path.

Must remain approval-gated:
- Firewall/network policy changes, device isolation, process termination, quarantine,
  deletion, account/session revocation, OS/software updates, privilege changes, and
  remote-control activation.

Never allowed:
- Hacking back, counter-exploitation, malware deployment, credential capture, stealth,
  disabling security controls, arbitrary command execution, or self-granting permissions.

## 9. Release gates

A feature is not complete until it has:
- Unit, integration, Windows-specific, and failure-mode tests.
- Least-privilege review and explicit input/output bounds.
- A documented data-flow/privacy review.
- Signed/pinned dependencies and reproducible build metadata.
- False-positive/false-negative fixtures and sensor-health checks.
- Approval/rollback tests for every state-changing action.
- Recovery drill, kill-switch test, and independent security review.

GODMAN must report unknown coverage honestly. A green status dashboard is not a
certificate that the computer or network is secure.
