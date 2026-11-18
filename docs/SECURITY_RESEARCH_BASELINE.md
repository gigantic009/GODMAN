# GODMAN Security Research Baseline

Research snapshot: 19 November 2026. This is a defensive engineering synthesis for a personal Windows computer and home LAN. Product capabilities and vendor guidance change; re-check upstream documentation before each implementation or deployment.

## Executive design decision

Do not attempt to build a new antivirus, kernel firewall, IDS engine, or SIEM in the GODMAN Python process. Use mature security engines as the enforcement and telemetry layer; GODMAN should orchestrate them through narrow, authenticated, auditable adapters.

The strongest practical design for a single Windows computer plus home LAN is:

1. Windows-native controls: Microsoft Defender Antivirus, SmartScreen, Windows Firewall, Attack Surface Reduction, Controlled Folder Access, Exploit Protection, BitLocker, Windows Security events, and optional Sysmon.
2. Endpoint monitoring: evaluate Wazuh agent for file integrity monitoring, Windows event collection, system inventory, security configuration assessment, vulnerability detection, and alerting. Wazuh is an agent/server/indexer/dashboard platform, not just a Python library.
3. Network perimeter: retain the existing router's firewall as a baseline; for advanced network-wide filtering/segmentation, evaluate a dedicated OPNsense/OpenWrt-capable gateway only after hardware, ISP, Wi-Fi, and topology review.
4. Network detection: Suricata in passive IDS mode first; only consider inline IPS after tuning, throughput testing, bypass/rollback design, and explicit authorization. Zeek adds network metadata and protocol analysis; it is not itself a replacement for a firewall.
5. Threat intelligence: signed/vendor advisories, CERT-In, CISA KEV, NVD, Microsoft security response, Wazuh CTI, and trusted project release/security feeds. Keep feed content as untrusted data until validated.
6. Response: deterministic policy engine and narrow privileged broker; the LLM may summarize and propose, but it must not be the authority that changes firewall rules or executes remediation.

## Research findings and design implications

### CERT-In (India): AI-assisted vulnerability defence

CERT-In's 25 May 2026 blueprint, *Blueprint for Reducing Exposure and Defending against AI-Assisted Vulnerabilities Exploitation in Digital Infrastructure*, explicitly addresses AI-accelerated reconnaissance, vulnerability discovery, phishing, malware, adaptive evasion, continuous monitoring, vulnerability/patch management, incident response, validation, and secure AI adoption.

Implications for GODMAN:
- Maintain an asset/software inventory and map versions to advisories.
- Continuously correlate exposure and vulnerabilities; prioritize known exploited vulnerabilities and reachable attack surface.
- Include identity, supply-chain, phishing, and AI-agent misuse in the threat model.
- Test controls continuously; do not assume AI-generated conclusions are correct.
- Treat external feed content, repositories, webpages, and downloaded code as untrusted input.

CERT-In's 15 October 2026 advisory on AI agents as attack vectors is particularly relevant to GODMAN itself: agent permissions must be bounded, tools audited, secrets protected, and tool actions authorized. This is a reason to keep the model away from direct administrator credentials and arbitrary command execution.

### NIST CSF 2.0: operational lifecycle

NIST CSF 2.0 has six concurrent functions: Govern, Identify, Protect, Detect, Respond, Recover. GODMAN should track outcomes across all six. A firewall alone only covers part of Protect and Detect; it cannot replace inventory, identity protection, recovery, governance, and incident response.

### Microsoft Windows 11 security architecture

Microsoft documents built-in controls spanning network security, data protection, device management, system integrity, driver security, and threat protection. Windows 11 includes Defender Antivirus, SmartScreen, Attack Surface Reduction, Tamper Protection, Exploit Protection, Controlled Folder Access, Network Protection, Windows Firewall, Wi-Fi protection, BitLocker, and Windows event/security telemetry.

Implications:
- First assess and correctly configure native controls before installing overlapping agents.
- Prefer audit mode and controlled rollout when evaluating Attack Surface Reduction rules; a bad policy can disrupt legitimate applications.
- Preserve Defender as a primary endpoint protection engine; GODMAN should orchestrate and report, not disable or replace it.
- Use Sysmon/Windows Event Forwarding selectively with documented event coverage, storage limits, privacy rules, and sensor-health checks.

### Wazuh: endpoint monitoring and SIEM/XDR building blocks

Wazuh documentation describes an endpoint agent plus server, indexer, and dashboard. Its agent supports Windows event collection, file integrity monitoring, system inventory, security configuration assessment, vulnerability detection, and active response. FIM compares monitored file attributes/checksums against a baseline and reports additions, modifications, and deletions.

Implications:
- Wazuh is a strong candidate for the endpoint telemetry and file-integrity layer; GODMAN should consume alerts through its API rather than duplicate FIM.
- Begin with monitoring and alert-only response.
- Active response can block network access, stop processes, or delete files; Wazuh itself warns that poorly implemented responses can increase endpoint vulnerability. GODMAN must use scoped, reversible response policies and owner approval for disruptive actions.
- Wazuh deployment requires a server/manager and agent architecture; resource usage, network reachability, TLS, certificates, retention, and update security must be evaluated for a single-user deployment.

### Suricata: network intrusion prevention

Suricata supports passive IDS and inline IPS. In IPS mode it can act as a traffic filter and use drop/reject rules to block traffic. Inline mode changes packet handling and can affect performance and connectivity.

Implications:
- Start with passive monitoring and alerting; measure throughput and false positives.
- IPS is only appropriate where traffic is actually routed through or bridged by the sensor. Installing Suricata on a normal endpoint does not automatically inspect all home-network traffic.
- Never put untested inline rules into the only gateway. Keep a recovery path and local access.

### OPNsense: programmable perimeter firewall

OPNsense is a FreeBSD firewall/router platform with traffic filtering, aliases, rules, NAT, shaping, and a documented machine-to-machine firewall API.

Implications:
- A supported OPNsense gateway can provide a controllable network boundary, but it may require dedicated hardware or a carefully planned virtualized gateway.
- The router API is powerful; keep API credentials in an OS-protected secret store, use a dedicated least-privilege account if supported, limit management to a trusted LAN/VPN, and log all policy changes.
- GODMAN should generate proposed rule diffs first; only a deterministic policy broker should apply a validated rule through the supported API.
- Do not assume the user's current consumer router exposes a safe or documented API. Discover exact make/model/firmware before writing an adapter.

### Secure remote access

Tailscale documents device posture and access rules that can restrict access based on device state, and default-deny access policies. A mesh VPN such as Tailscale or WireGuard is a safer starting point for owner-only remote access than exposing RDP, SMB, GODMAN's API, or router administration to the public internet.

Implications:
- Remote console should be read-only by default.
- Require MFA, device identity, least-privilege access, short-lived sessions, revocation, and step-up approval for changes.
- Remote access is an additional attack surface and must not become a backdoor into the home network.

## Proposed control architecture

| Layer | Recommended control/engine | GODMAN's role |
|---|---|---|
| Windows endpoint prevention | Microsoft Defender, SmartScreen, Windows Firewall, ASR, Controlled Folder Access, Exploit Protection, BitLocker | Read posture, alert on drift, propose staged configuration |
| Endpoint visibility | Windows Security events, Defender events, optional Sysmon | Collect bounded events, correlate, alert |
| File integrity | Wazuh FIM or equivalent | Monitor approved critical paths, correlate changes, create cases |
| Endpoint vulnerability | Wazuh inventory + vendor advisories/CVE/KEV | Match installed products, prioritize, propose patch |
| Network boundary | Existing router firewall or dedicated OPNsense gateway | Read configuration/logs, propose scoped rule updates |
| Network detection | Suricata IDS, Zeek metadata | Ingest alerts/metadata, correlate endpoints |
| DNS/domain protection | Router or trusted DNS filtering service | Report suspicious domains and policy status; do not intercept TLS |
| Remote access | Tailscale/WireGuard | Owner-only secure status console; no public management ports |
| Threat intelligence | CERT-In, CISA KEV, NVD, vendor advisories, trusted release feeds | Verify source, timestamp, signature, relevance, expiry |
| Response | Native Defender, Windows Firewall, router firewall, Wazuh playbooks | Plan, approval, execute via narrow broker, verify, rollback |

## Adaptive firewall: safe learning and response loop

1. Observe: receive firewall, DNS, IDS, endpoint, and authentication events.
2. Normalize: parse to a typed event schema; retain source, timestamp, device, rule ID, and raw-evidence reference.
3. Enrich: compare IP/domain/hash/software evidence against validated threat feeds and local asset inventory.
4. Score: combine confidence, severity, exposure, repetition, asset criticality, and false-positive history.
5. Propose: produce a narrow rule recommendation with exact scope, expiry, rationale, and expected impact.
6. Validate: test syntax, check allow-list/deny-list conflicts, prevent self-lockout, and simulate rule ordering.
7. Enforce: apply only pre-authorized low-risk policy or require owner approval. No broad subnet blocks based on a single weak indicator.
8. Verify: confirm the target traffic is blocked, management access remains available, and legitimate services still work.
9. Expire/rollback: temporary blocks expire automatically; permanent rules require review and audit.
10. Learn: update detection thresholds/rules only from trusted, versioned data and regression tests—not from blindly trusting one attack event or arbitrary internet content.

A single failed login, IP reputation result, or IDS signature must not automatically create a permanent block. Attackers use compromised hosts, cloud relays, carrier NAT, and shared infrastructure; overbroad blocking can harm innocent users or disconnect the owner.

## Autonomous operation policy

May run unattended after owner setup:
- Read-only telemetry collection and health checks.
- Scheduled Defender/Wazuh scans within configured resource windows.
- Correlation, threat-feed refresh, detection-rule tests, alerts, incident drafts.
- Temporary blocks for high-confidence indicators only if the owner explicitly enables a bounded policy, with expiry and automatic rollback.

Must require explicit approval:
- Persistent firewall/router changes, host isolation, process termination, quarantine/deletion, account/session revocation, patch installation, privilege changes, and agent updates.
- Any action that could cut off the owner's remote access or disable a business-critical service.

Never:
- Hack back, exploit attacker infrastructure, deploy malware, steal credentials, disable security controls, execute untrusted scripts, or grant the agent new privileges.

## Sources reviewed

- CERT-In, *Blueprint for Reducing Exposure and Defending against AI-Assisted Vulnerabilities Exploitation in Digital Infrastructure* (25 May 2026): https://www.cert-in.org.in/Downloader?fileName=CIGU-2026-0002.pdf&pageid=6&type=2
- CERT-In, Security Guidelines and advisories index: https://www.cert-in.org.in/s2cMainServlet?pageid=GUIDLNVIEW01
- CERT-In, *AI Agents as Attack Vectors* advisory (15 October 2026): https://cert-in.org.in/s2cMainServlet?VLCODE=CIAD-2026-0049&pageid=PUBVLNOTES02
- NIST, *Cybersecurity Framework 2.0*: https://www.nist.gov/cyberframework
- Microsoft, Windows 11 operating system security: https://learn.microsoft.com/en-us/windows/security/operating-system-security/
- Microsoft, Attack Surface Reduction overview: https://learn.microsoft.com/en-us/defender-endpoint/overview-attack-surface-reduction
- Wazuh, components and architecture: https://documentation.wazuh.com/current/getting-started/components/index.html
- Wazuh, agent capabilities: https://documentation.wazuh.com/current/getting-started/components/wazuh-agent.html
- Wazuh, file integrity monitoring: https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
- Wazuh, vulnerability detection: https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html
- Wazuh, active response: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html
- Suricata, IPS concepts: https://docs.suricata.io/en/latest/ips/ips-concept.html
- OPNsense, firewall features: https://docs.opnsense.org/firewall.html
- OPNsense, firewall API: https://docs.opnsense.org/development/api/core/firewall.html
- Tailscale, device posture: https://tailscale.com/docs/features/device-posture
- Tailscale, access control: https://tailscale.com/docs/features/access-control
- CISA, home router security guidance: https://www.cisa.gov/sites/default/files/publications/HomeRouterSecurity2011.pdf
- CISA, remote-work/home-network guidance: https://www.cisa.gov/sites/default/files/2024-08/Federal-Mobile-Workplace-Security_508_2024-08-14.pdf
- CISA, incident and vulnerability response playbooks: https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf

This research is a design input, not a certification or proof that the selected controls prevent every attack. Confirm product version, supported platform, licensing, hardware, and upstream documentation before deployment.
