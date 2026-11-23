# GODMAN requested-feature coverage — honest status

This is the acceptance checklist for the owner's requested personal cyber-defence operator. A roadmap item is not complete merely because it has been designed or documented.

Status meanings: Implemented (limited) = narrow code exists; Designed = architecture only; Not implemented = no working feature; Requires owner/device input = needs details or on-device validation.

## Authority, ownership and scope

| Requirement | Status | Current reality |
|---|---|---|
| You are the sole final administrator | Designed; not enforced | Policy says the human owner is sole root authority. Windows SID binding, protected owner credential, secure bootstrap and authorization checks are missing. |
| GODMAN cannot silently rewrite its own code or authority policy | Not implemented | No signed runtime, protected policy store, code-integrity enforcement or independent recovery control. |
| Other people cannot access GODMAN | Not implemented | No owner-authenticated local UI/IPC boundary or secure remote identity system. |
| GODMAN must not access/control other computers | Policy scope defined; technical controls incomplete | No universal network-control layer exists. Future tools must deny other targets by default. |
| No hidden remote access/backdoors | Architectural requirement | No remote management server is implemented. |
| Owner approval for high-impact actions | Basic implementation | Console approval requires typing YES; it is not cryptographic owner authentication. |

## Windows endpoint defence — first priority

| Requirement | Status | Current reality |
|---|---|---|
| Windows Firewall visibility | Implemented (limited) | /firewall reads profiles and up to 500 enabled inbound allow rules; changes nothing. |
| Actually configure/harden Windows Firewall | Not implemented | Backup, dry-run diff, owner approval, apply, read-back verification and rollback are missing. |
| Continuous firewall tamper monitoring | Not implemented | No event subscription or scheduled monitoring loop. |
| Microsoft Defender posture | Implemented (limited) | /posture is a point-in-time snapshot. |
| Scan files for malware | Implemented (limited) | Defender custom scan only for selected file/folder inside GODMAN workspace; requires approval. |
| Whole-device scheduled scanning | Not implemented | No scheduler, full-device scope, progress/cancellation or notifications. |
| Continuous file-change monitoring | Not implemented | No FIM sensor or baseline/alert pipeline. |
| Windows security event analysis | Implemented (limited) | /events queries selected local event IDs from Defender, Security and System logs; bounded and point-in-time. |
| Ransomware/spyware/RAT/rootkit detection | Not comprehensive | Defender remains primary engine. No dedicated GODMAN behaviour sensor, memory scanner or EDR pipeline. |
| Archive-bomb inspection | Implemented (limited) | ZIP metadata only; no extraction and no general archive-format coverage. |
| Phishing URL analysis | Implemented (limited) | /url performs offline structural checks only; no reputation, redirect, DNS or page analysis. |
| Attachment/file reputation | Not implemented | No trusted reputation provider or sandbox integration. |
| Vulnerability inventory and patch recommendations | Not implemented | No software inventory/CVE matching or patch workflow; roadmap prioritizes NVD/CISA KEV/vendor advisory matching with evidence and remediation verification. |
| Incident evidence and recovery | Not implemented | No case manager, protected evidence store, chain of custody or restore workflow. |

## Network, identity, account and remote protection

| Requirement | Status | Current reality |
|---|---|---|
| Home router/Wi-Fi defence | Deferred | No router adapter or Wi-Fi management in the first phase. |
| Network IDS/IPS | Not implemented | No Zeek/Suricata sensor, packet visibility or inline enforcement. |
| Adaptive firewall and temporary blocks | Not implemented | No confidence scoring, allow-list, TTL, self-lockout guard, rollback or enforcement engine. |
| LAN visibility | Deferred / scope needs owner input | No LAN discovery/scanning. Later passive network sensor can monitor traffic at a properly configured gateway without controlling other endpoints. |
| Credential leak/account breach alerts | Not implemented | Requires approved provider APIs or breach-alert integrations. GODMAN will never ask for raw passwords. |
| Password-change/suspicious-sign-in alerts | Not implemented | Requires authorized provider notifications/API access. |
| Remote access while away | Not implemented | No VPN/mesh control channel, MFA, device identity or mobile UI. |
| Mobile alerts | Not implemented | No notification provider or event delivery service. |

## Intelligence, autonomy and self-maintenance

| Requirement | Status | Current reality |
|---|---|---|
| Trusted vulnerability/threat intelligence updates | Not implemented | Sources researched; no feed ingestion, signature/provenance checks, freshness or safe parser pipeline. |
| Learn new defensive techniques | Designed | Needs curated feeds, validation, tests and human-reviewed policy updates; never autonomous self-trust. |
| Autonomous continuous monitoring | Not implemented | Current commands are manually invoked. No background service or sensor-health scheduler. |
| Autonomous bounded response | Not implemented | No approved policy engine, reversible response adapter or action verification. |
| Controlled self-update | Not implemented | No signed releases, SBOM, dependency pinning, staged update, owner approval or rollback. |
| Safe rollback / kill switch | Not implemented | Architecture calls for these; no complete operational mechanism. |

| One-command Windows endpoint checkup | Implemented (limited) | `/checkup` aggregates point-in-time Defender posture, firewall inventory and selected events; it performs no remediation and is not continuous monitoring. |\n\nSee [SECURITY_DIAGNOSTICS_ROADMAP.md](SECURITY_DIAGNOSTICS_ROADMAP.md) for the dedicated product roadmap. Market/stock analytics are outside GODMAN's product scope.\n\n## Build order and release gates

1. Owner trust foundation: Windows account SID binding, secure bootstrap, owner-only approval, protected configuration, signed code/policy and recovery.
2. Endpoint firewall: capture effective policy, generate a reviewable diff, back up, apply one approved change, verify, and roll back on failure.
3. Endpoint telemetry: event collector, Defender events, file integrity, sensor health, alert correlation and privacy/retention.
4. Malware and phishing triage: Defender whole-device schedule, safe file/URL metadata, reputation integration and isolated scanning.
5. Vulnerability and incident operations: inventory, KEV/CVE correlation, evidence cases, recovery and approval-based remediation.
6. Autonomy: scheduler, policy engine, expiring reversible responses, kill switch and tests.
7. Only after endpoint release: router/Wi-Fi, passive LAN visibility, IDS/IPS, remote access, mobile alerts and account integrations.

No stage is production-ready until tests pass, Windows integration testing is performed on a disposable VM, rollback is demonstrated, and the owner approves the release.
