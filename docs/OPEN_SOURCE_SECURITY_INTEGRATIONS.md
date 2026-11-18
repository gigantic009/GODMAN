# Open-source cybersecurity project review

Reviewed as architectural references for GODMAN; this is not a recommendation to
install every component on a personal Windows laptop. Mature tools should be integrated
through narrow adapters and remain independently maintained.

| Project | Repository | Capability to reuse |
|---|---|---|
| Wazuh | https://github.com/wazuh/wazuh | SIEM/XDR manager, agents, endpoint telemetry and rules |
| Velociraptor | https://github.com/Velocidex/velociraptor | Digital forensics and incident response collection |
| osquery | https://github.com/osquery/osquery | SQL-based endpoint inventory and telemetry |
| Sigma | https://github.com/SigmaHQ/sigma | Vendor-neutral detection rule format and community rules |
| YARA-X | https://github.com/VirusTotal/yara-x | Modern YARA-compatible static pattern matching engine |
| Zeek | https://github.com/zeek/zeek | Passive network security monitoring and protocol logs |
| Suricata | https://github.com/OISF/suricata | Network IDS/IPS and protocol detection |
| Greenbone Community Edition | https://github.com/greenbone | Vulnerability management and scanning ecosystem |
| OWASP ZAP | https://github.com/zaproxy/zaproxy | Web application security testing |
| MISP | https://github.com/MISP/MISP | Threat intelligence sharing and IOC correlation |
| OpenCTI | https://github.com/OpenCTI-Platform/opencti | Threat intelligence knowledge graph and connectors |
| ClamAV | https://github.com/Cisco-Talos/clamav | Signature-based malware scanning |
| TheHive | https://github.com/TheHive-Project/TheHive | Incident response case management |
| CrowdSec | https://github.com/crowdsecurity/crowdsec | Behavioral detection and collaborative IP reputation; optional local enforcement only after review |
| Nuclei | https://github.com/projectdiscovery/nuclei | Template-based vulnerability checks; strict owned-target allow-list and safe templates only |
| Trivy | https://github.com/aquasecurity/trivy | Vulnerability, misconfiguration, and secret scanning for repositories, images and filesystems |
| Gitleaks | https://github.com/gitleaks/gitleaks | Detect accidentally committed credentials and tokens; redact findings |
| Lynis | https://github.com/CISOfy/lynis | Host security auditing and hardening checks, primarily Unix-like systems |
| Falco | https://github.com/falcosecurity/falco | Runtime threat detection for Linux/container/cloud workloads |

## Integration principles

- Do not copy entire repositories or transplant code without understanding license,
  dependencies, update cadence, threat model, and maintenance responsibility.
- Prefer official APIs, documented output formats, signed releases, and pinned versions.
- Treat each integration as an independent trust boundary with least privilege.
- Begin with read-only telemetry and passive network monitoring.
- Restrict active vulnerability assessment to assets explicitly owned/administered.
- Never run untrusted samples on the user's everyday machine.
- Evaluate dependency and supply-chain risk before adding packages or containers.
