# GODMAN Cybersecurity Reference Stack

This file records the authoritative projects and frameworks that should guide GODMAN's defensive cybersecurity knowledge and future integrations. Review upstream documentation and licenses before embedding tools, rules, or datasets.

## Frameworks and knowledge bases

- [MITRE ATT&CK](https://attack.mitre.org/) — adversary tactics and techniques used for threat-informed defence.
- [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data) — machine-readable STIX 2.1 collections for Enterprise, Mobile, and ICS ATT&CK.
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) — organizational cybersecurity risk management outcomes.
- [NIST CSF 2.0 publication](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20) — framework background and formal publication.
- [OWASP Top 10:2025](https://top10.owasp.org/) — current awareness baseline for major web application security risks.

## Defensive detection and monitoring

- [SigmaHQ rules](https://github.com/SigmaHQ/sigma) — community-maintained, vendor-neutral detection and threat-hunting rules.
- [Sigma specification](https://github.com/SigmaHQ/sigma-specification) — formal rule and correlation specification.
- [Wazuh](https://github.com/wazuh/wazuh) and [Wazuh documentation](https://documentation.wazuh.com/current/) — open-source SIEM/XDR, endpoint monitoring, rules and vulnerability detection.
- [Suricata](https://github.com/OISF/suricata) — network threat detection engine (IDS/IPS and network security monitoring).

## Application security and malware analysis

- [OWASP ZAP](https://github.com/zaproxy/zaproxy) — open-source web application security scanner. Future integration must require an explicit target allow-list, written authorization, safe scan profile, rate limits, and an audit trail.
- [YARA](https://github.com/VirusTotal/yara) — rule-based file identification and classification. Treat samples as untrusted and analyse them in isolated environments. Check the project's maintenance guidance before selecting an engine for new work.

## Integration policy

- Prefer official documentation, signed releases, maintained repositories, and reproducible versions.
- Pin dependencies and record licenses before bundling third-party code or rule sets.
- Do not download or execute third-party rules, scripts, malware samples, or plugins automatically.
- Use passive/read-only ingestion first; require explicit scope and approval for any active test.
- Keep external scanning and remediation integrations disabled until their authorization, safety, and rollback model is reviewed.
