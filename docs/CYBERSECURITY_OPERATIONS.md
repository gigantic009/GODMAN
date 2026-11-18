# GODMAN Cybersecurity Operations Architecture

## Mission
GODMAN is intended as a personal defensive security operations assistant for systems
and networks the user owns or administers. Target domains include SOC analysis,
network defense, endpoint security, malware triage, threat intelligence,
vulnerability management, cloud and application security, cryptography, incident
response, and digital forensics.

The current implementation is only a foundation: workspace-bounded log heuristics,
candidate IOC extraction, SHA-256, and static file metadata/entropy. It is not yet an
EDR, SIEM, packet sensor, vulnerability scanner, malware sandbox, or forensic suite.

## Target architecture
1. Sensors/inventory: Windows event logs, Sysmon, Defender telemetry, firewall/router
   logs, DNS, endpoint/software inventory, and optional passive packet metadata.
2. Normalization: stable event schema, host identity, UTC timestamps, provenance,
   deduplication, retention, and integrity hashes.
3. Detection: Sigma-compatible rules, ATT&CK mapping, baselines, correlation,
   anomaly detection, and explainable suppression.
4. Investigation: process trees, log timelines, IOC enrichment, file metadata,
   static signatures, memory/disk evidence workflows, and chain of custody.
5. Response: recommend containment first; disruptive actions require explicit
   confirmation, impact preview, and recovery/rollback plan.
6. Reporting: evidence, hypothesis, confidence, severity, impact, false positives,
   and verification steps.

## Safety engineering
- Local-first and read-only collection wherever practical.
- Explicit asset allow-list and authorization record for active testing.
- No arbitrary shell execution or unattended destructive actions.
- Never execute malware samples on the host; use isolation for analysis.
- Do not collect/transmit secrets, browser credentials, private keys, or personal
  documents as telemetry.
- Every sensor/action is opt-in, auditable, bounded, and disableable.
- Preserve original evidence; analyze copies and hash evidence before/after handling.

## Tools to evaluate
Wazuh, Sysmon, Microsoft Defender, Zeek, Suricata, Wireshark/tshark, Sigma, YARA-X,
Velociraptor, osquery, OpenCTI, MISP, TheHive, and OWASP ZAP. Each integration needs
license, platform, least-privilege, resource, retention, and safe-default review.

A future protect-my-computer mode starts with inventory and read-only baseline,
then recommends fixes. It must not disable controls or modify firewall, registry,
services, accounts, or files without explicit reviewed approval.
