# GODMAN Defensive Threat Model and Attack-Coverage Matrix

## Purpose and scope

This document defines the threat coverage GODMAN should build for the owner's Windows
computer, home network, accounts, files, and development environment. It is a
defensive threat model—not a guarantee of immunity. Threats are grouped by attack
surface and mapped to preventive controls, telemetry, response, and current gaps.

## Threat catalogue

| Threat family | Examples and likely entry points | Defensive controls and detections |
|---|---|---|
| Social engineering | Phishing email, spear-phishing, smishing, vishing, QR phishing, fake support, OAuth consent phishing, invoice scams, impersonation | Phishing-resistant MFA/passkeys, sender/domain checks, link and attachment reputation, browser isolation, user reporting, suspicious sign-in and OAuth grant alerts |
| Malicious files | Trojanized installers, macros, scripts, shortcut files, ISO/VHD/LNK, DLL sideloading, malicious PDFs, archive/decompression bombs, polyglot files | Defender/AV, SmartScreen, mark-of-the-web, file type vs extension checks, archive expansion limits, sandboxed static/dynamic analysis, application control, download provenance |
| Resource exhaustion | ZIP bombs, recursive archive bombs, fork bombs, memory/CPU/disk exhaustion, log floods, mail bombs | Quotas, bounded decompression, process/resource limits, rate limits, disk/CPU alerts, backups, safe shutdown/recovery |
| Malware | Ransomware, wipers, spyware, keyloggers, RATs, rootkits, bootkits, worms, botnets, cryptominers, fileless/LOLBins | EDR/Defender, behavior monitoring, application control, tamper protection, least privilege, offline backups, process trees, persistence and network telemetry |
| Credential and identity attacks | Password spraying, brute force, credential stuffing, pass-the-hash, token theft, session hijack, MFA fatigue, SIM swap, browser cookie theft | Passkeys/FIDO2, MFA, unique passwords/password manager, sign-in alerts, lockout/rate limits, token/session revocation, privileged account separation |
| Network attacks | Rogue Wi-Fi, evil twin, ARP spoofing, DNS poisoning, DHCP spoofing, MITM, rogue services, exposed RDP/SMB, port scanning, lateral movement, C2, DNS tunneling, exfiltration | Host/network firewall, WPA2/3, VPN on untrusted Wi-Fi, secure DNS, disable unused listeners, segmentation, Zeek/Suricata, DNS/firewall logs, outbound anomaly detection |
| Web/browser attacks | Drive-by downloads, malicious extensions, browser exploits, malvertising, clickjacking, XSS/CSRF against web apps, malicious notifications | Browser updates, extension allow-list, site isolation, safe browsing, script protections, DNS filtering, browser download controls, web app testing only on authorized targets |
| Exploitation and privilege escalation | Unpatched OS/apps, kernel/driver flaws, insecure services, misconfigurations, local privilege escalation, insecure deserialization | Asset/software inventory, CVE/KEV correlation, patch SLA, secure configuration baselines, least privilege, vulnerability scans scoped to owned assets |
| Persistence and evasion | Run keys, scheduled tasks, services, WMI subscriptions, startup folders, boot changes, log clearing, security-control tampering | Sysmon/Defender telemetry, autorun and service baselines, tamper protection, immutable logs, configuration drift monitoring |
| Supply chain and development | Compromised dependencies, typosquatting, malicious packages, build pipeline compromise, leaked API keys, poisoned updates | Lockfiles, package provenance, dependency scanning, secret scanning, signed releases, isolated CI, least-privilege tokens, reproducible builds |
| Data theft and privacy | Browser data theft, clipboard capture, screenshots, cloud sync abuse, exfiltration, unauthorized remote access | Full-disk encryption, least privilege, DLP where appropriate, outbound telemetry, account/session controls, encrypted backups, data minimization |
| Physical and peripheral | Lost/stolen laptop, malicious USB/HID, boot from external media, shoulder surfing, unattended unlocked session | Device encryption, secure boot, screen lock, BIOS/UEFI protection, USB policy, physical custody, remote account/session revocation |
| Cloud and SaaS | Stolen cloud tokens, exposed storage, malicious OAuth apps, account takeover, insecure API keys | MFA, conditional access, least privilege, key rotation, audit logs, storage access policies, cloud posture checks |
| Insider and accidental | Unsafe scripts, mistaken deletion, oversharing, misconfiguration, untrusted remote support | Approval gates, least privilege, backups, audit trails, restore drills, safe change previews |
| Availability and resilience | DDoS against owned services, destructive malware, hardware failure, power loss | ISP/router protections, service rate limits, offline backups, recovery media, tested restore plans, incident playbooks |

## GODMAN coverage status (honest snapshot)

### Implemented in the repository
- Workspace-bounded, read-only heuristic log triage.
- ZIP central-directory inspection for expansion bombs, nested archives, path traversal member names, and symlink metadata without extracting members.
- Candidate IOC extraction without contacting indicators.
- Local SHA-256 and static file metadata/magic/entropy inspection.
- A read-only Windows posture collector for Defender, Windows Firewall profiles,
  BitLocker status, and recent hotfixes (availability depends on OS/features/permissions).
- An approval-gated Microsoft Defender custom scan for a selected workspace file or folder; it is not a whole-device or continuous scan.
- Explicit tool allow-list, path boundaries, approval for writes/system actions, and audit log.

### Not implemented by this catalogue alone
- No continuous endpoint sensor, EDR, packet capture, IDS/IPS, DNS filtering,
  phishing mail gateway, exploit prevention, vulnerability scanner, malware sandbox,
  memory forensics, browser protection, or automated containment.
- A posture snapshot does not prove that a machine is clean or uncompromised.
- A hash does not prove a file is malicious or benign without trusted reputation/context.

## Layered protection baseline

1. **Identity:** unique accounts, password manager, passkeys/FIDO2 where possible,
   MFA, recovery codes stored safely, separate admin and daily-use accounts.
2. **Endpoint:** supported Windows release, automatic security updates, Microsoft
   Defender real-time and cloud protection, tamper protection, SmartScreen, firewall
   on all profiles, application control where feasible.
3. **Disk/data:** BitLocker/device encryption, least privilege, protected backups,
   one offline/immutable backup, tested restore.
4. **Network:** WPA2-AES/WPA3, router firmware updates, unique admin password,
   disable WPS and unnecessary remote administration, guest/IoT separation,
   no exposed RDP/SMB, secure DNS.
5. **Applications:** update browsers and third-party apps, minimize extensions,
   install only from trusted sources, dependency pinning and secret scanning.
6. **Detection:** Windows Security logs, Defender events, Sysmon (carefully tuned),
   central collection, time synchronization, alerts and retention.
7. **Response:** isolate a suspected compromised device from networks, preserve
   evidence, use a known-clean device to rotate credentials, scan/rebuild from
   trusted media when warranted, and restore known-good backups.

## Integration strategy: reuse mature engines, do not copy whole projects

| Project / ecosystem | Intended role in GODMAN | Integration approach |
|---|---|---|
| Wazuh | Endpoint telemetry, file integrity, vulnerability detection, SIEM/XDR | Optional external manager/agent; consume alerts/API, do not reimplement agent |
| Microsoft Defender / Sysmon | Native Windows protection and event telemetry | Read-only status/event adapters; preserve Defender as primary protection |
| osquery | Structured endpoint inventory | Optional scheduled read-only queries |
| Velociraptor | DFIR collection and endpoint hunting | Case-scoped collection with explicit artifact allow-list |
| Sigma | Portable detection rules | Parse/validate rules and map to supported log sources |
| YARA-X | Static malware pattern matching | Isolated file scanning; no sample execution |
| ClamAV | Signature-based file scanning | Optional local scanner, quarantine only after approval |
| Zeek | Network protocol metadata and network security monitoring | Passive sensor/log ingestion, not active probing |
| Suricata | Network IDS/IPS | Start IDS-only; inline blocking only after controlled validation |
| Wireshark/tshark | Packet analysis | Offline PCAP analysis and privacy-aware capture limits |
| Greenbone/OpenVAS | Vulnerability assessment | Explicit owned-asset allow-list, safe profile, maintenance window |
| OWASP ZAP | Web application security testing | Local/staging targets only; safe passive profile by default |
| MISP / OpenCTI | Threat intelligence knowledge and IOC context | Feed ingestion with source, confidence, expiry and licensing |
| TheHive | Incident/case management | Optional case export and evidence tracking |

Before enabling any integration, review its license, update cadence, supported OS,
permissions, network exposure, telemetry sent externally, resource usage, and
security advisories. A third-party agent itself expands the attack surface.

## Security acceptance gates

- Unit and integration tests pass on a clean Windows test machine.
- Every integration is pinned/reproducible and has a documented trust boundary.
- No secrets or private user documents are uploaded by default.
- Every write, quarantine, block, firewall change, process termination, or account
  action requires a clear preview and explicit approval.
- A rollback/recovery path exists for every remediation.
- False positives, missed detections, sensor health, and stale data are visible.
- No tool claims "protected" or "clean" solely because no alert fired.


## Authoritative defensive guidance

- [NSA Cybersecurity Information Sheet: Best Practices for Cyber Hygiene (September 3, 2026)](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4590054/nsa-highlights-cyber-hygiene-best-practices-effective-against-ai-enhanced-targe/) — progressive maturity, inventory, MFA, patching, segmentation, continuous monitoring; explicitly not an exhaustive list of every attack vector. <https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4590054/nsa-highlights-cyber-hygiene-best-practices-effective-against-ai-enhanced-targe/>
- [NIST IR 8374 Rev. 1: Ransomware Risk Management (June 11, 2026)](https://csrc.nist.gov/news/2026/ransomware-risk-management-ir-8374r1) — practical ransomware prevention, response and recovery profile.
- [CISA joint guidance: Detecting and Mitigating Active Directory Compromises (September 15, 2026)](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42acb6e) — identity compromise, credential theft, privilege escalation, persistence and monitoring.
- [CISA technical approaches to uncovering malicious activity](https://www.cisa.gov/sites/default/files/publications/AA20-245A-Joint_CSA-Technical_Approaches_to_Uncovering_Malicious_Activity_508.pdf) — layered defense, allowlisting, least privilege, backups and incident readiness.
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) — governance and risk-management structure.

These references guide the architecture; they do not certify GODMAN or guarantee
that every attack can be detected or prevented.
