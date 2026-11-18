"""Defensive cybersecurity analysis helpers for files inside the GODMAN workspace.

This module performs bounded, read-only triage. It does not execute samples,
probe remote hosts, exploit vulnerabilities, or modify the inspected system.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path

MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_HASH_BYTES = 100 * 1024 * 1024
ALLOWED_LOG_SUFFIXES = {".log", ".txt", ".jsonl", ".csv"}

SECURITY_DOMAINS = {
    "governance_risk_compliance": "Security governance, risk assessment, privacy, audits, policies, ISO 27001, NIST CSF, and regulatory compliance.",
    "network_security": "TCP/IP, DNS, routing, firewalls, VPN, segmentation, IDS/IPS, packet analysis, wireless security, and zero trust networking.",
    "application_security": "Secure SDLC, OWASP Top 10, API security, authentication, authorization, session security, code review, and security testing.",
    "cloud_security": "AWS, Azure, GCP, IAM, network controls, secrets, workload protection, containers, Kubernetes, and cloud posture.",
    "endpoint_security": "Windows, Linux, macOS hardening, EDR, host telemetry, patching, configuration baselines, and endpoint detection.",
    "identity_access": "IAM, MFA, SSO, OAuth 2.0, OIDC, SAML, PAM, least privilege, and identity threat detection.",
    "cryptography": "Encryption, hashing, PKI, TLS, certificates, key management, signatures, and protocol design.",
    "digital_forensics_incident_response": "Incident triage, evidence preservation, timeline analysis, containment planning, recovery, and post-incident lessons.",
    "malware_analysis": "Safe static analysis, file metadata, hashes, strings, YARA concepts, sandbox precautions, and behavioral indicators.",
    "threat_intelligence": "IOC handling, ATT&CK mapping, campaign context, threat feeds, confidence, and intelligence lifecycle.",
    "vulnerability_management": "CVE/CVSS interpretation, asset exposure, patch prioritization, configuration weaknesses, and remediation verification.",
    "security_operations": "SIEM, SOAR, log analysis, alert triage, detection engineering, threat hunting, and response playbooks.",
    "secure_engineering": "Code security, dependency risk, secrets scanning, CI/CD controls, supply-chain security, and secure architecture.",
    "iot_ot_embedded": "IoT, embedded devices, industrial control systems, OT segmentation, safety constraints, and device lifecycle security.",
}

# High-signal heuristics only. These findings are leads for analyst review,
# not proof of compromise. Keep signatures explainable and avoid auto-remediation.
LOG_PATTERNS = [
    ("repeated_auth_failure", "high", re.compile(r"(failed password|authentication failure|invalid user|login failed|logon failure)", re.I),
     "Repeated or failed authentication event", "Correlate source, account, time window, and successful logins; verify MFA and account lockout controls."),
    ("privilege_escalation_signal", "high", re.compile(r"(sudo:.*(COMMAND=|not in sudoers)|privilege escalation|runas.*administrator|new local administrator)", re.I),
     "Potential privileged action or privilege change", "Confirm the actor, change ticket, parent process, and whether the privilege change was expected."),
    ("encoded_powershell", "high", re.compile(r"(powershell[^\n]{0,160}-(enc|encodedcommand)\b|pwsh[^\n]{0,160}-(enc|encodedcommand)\b)", re.I),
     "Encoded PowerShell command observed", "Review process ancestry and decode only in an isolated analysis workflow; encoded commands are not inherently malicious."),
    ("suspicious_download_pipe", "high", re.compile(r"(curl|wget)[^\n]{0,180}\|\s*(sh|bash)\b", re.I),
     "Download piped directly into a shell", "Check initiating user, destination, script provenance, and endpoint telemetry."),
    ("web_path_traversal_probe", "medium", re.compile(r"(\.\./|%2e%2e%2f|%2e%2e/)", re.I),
     "Possible path traversal probe in request data", "Review web server route handling and correlate with response status and application logs."),
    ("web_injection_probe", "medium", re.compile(r"(union\s+select|<script\b|\bor\s+1=1\b|sleep\s*\()", re.I),
     "Possible injection or cross-site scripting probe", "Validate input handling and parameterized queries; determine whether the request reached a vulnerable sink."),
    ("persistence_location", "medium", re.compile(r"(\\currentversion\\run|\\startup\\|/etc/cron\.|crontab|systemd/system/)", re.I),
     "Reference to a common persistence location", "Determine which process or account accessed the location and whether a change occurred."),
    ("security_control_disabled", "high", re.compile(r"(windows defender.*(disabled|turned off)|firewall.*(disabled|stopped)|auditd.*stopped|logging.*disabled)", re.I),
     "Security monitoring or protection may have been disabled", "Validate service state through trusted endpoint telemetry and investigate who initiated the change."),
]

IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
HASH_RE = re.compile(r"(?i)\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b")
DOMAIN_RE = re.compile(r"(?i)(?<![@\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|in|info|biz|dev|app|xyz|ru|cn|uk|edu|gov)(?![\w-])")


def _workspace_file(workspace: str | Path, relative_path: str) -> Path:
    root = Path(workspace).expanduser().resolve()
    target = (root / relative_path).resolve()
    if target == root or root not in target.parents:
        raise ValueError("Path must identify a file inside the configured GODMAN workspace.")
    if not target.is_file():
        raise FileNotFoundError(relative_path)
    return target


def _ip_context(value: str) -> str:
    address = ipaddress.ip_address(value)
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified or address.is_reserved:
        return "reserved_or_unspecified"
    if address.is_private:
        return "private"
    return "public"


def extract_indicators(text: str) -> dict:
    """Extract candidate IOCs from supplied text without contacting them."""
    ips = sorted(set(IPV4_RE.findall(text)))
    valid_ips = []
    for value in ips:
        try:
            valid_ips.append({"value": value, "scope": _ip_context(value)})
        except ValueError:
            continue
    urls = sorted({value.rstrip(".,);]") for value in URL_RE.findall(text)})
    domains = sorted(set(DOMAIN_RE.findall(text)))
    # URLs already carry their host; retain domains as separate candidates too.
    hashes = sorted(set(HASH_RE.findall(text)))
    return {
        "note": "Candidates only. No reputation lookup or network connection was performed.",
        "ipv4": valid_ips[:100],
        "domains": domains[:100],
        "urls": urls[:100],
        "file_hashes": hashes[:100],
    }


def analyze_security_log(workspace: str | Path, relative_path: str) -> dict:
    """Run explainable, bounded heuristic triage on a workspace log file."""
    target = _workspace_file(workspace, relative_path)
    if target.suffix.lower() not in ALLOWED_LOG_SUFFIXES:
        raise ValueError(f"Unsupported log extension. Allowed: {', '.join(sorted(ALLOWED_LOG_SUFFIXES))}")
    size = target.stat().st_size
    if size > MAX_LOG_BYTES:
        raise ValueError(f"Log exceeds the {MAX_LOG_BYTES // (1024 * 1024)} MB analysis limit.")
    content = target.read_text(encoding="utf-8", errors="replace")
    findings = []
    counts = {}
    lines = content.splitlines()
    for line_number, line in enumerate(lines, 1):
        for rule_id, severity, pattern, title, recommendation in LOG_PATTERNS:
            if pattern.search(line):
                counts[rule_id] = counts.get(rule_id, 0) + 1
                if len(findings) < 100:
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "line": line_number,
                        "title": title,
                        "recommendation": recommendation,
                    })
                break
    indicators = extract_indicators(content)
    return {
        "file": target.name,
        "bytes_analyzed": size,
        "lines_analyzed": len(lines),
        "findings_count": sum(counts.values()),
        "rule_counts": counts,
        "findings": findings,
        "candidate_indicators": indicators,
        "assessment": "Heuristic triage only; findings require validation against surrounding events and trusted telemetry.",
    }


def sha256_workspace_file(workspace: str | Path, relative_path: str) -> dict:
    """Compute SHA-256 for a workspace file without executing or modifying it."""
    target = _workspace_file(workspace, relative_path)
    size = target.stat().st_size
    if size > MAX_HASH_BYTES:
        raise ValueError(f"File exceeds the {MAX_HASH_BYTES // (1024 * 1024)} MB hash limit.")
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"file": target.name, "bytes": size, "algorithm": "SHA-256", "digest": digest.hexdigest(),
            "note": "Hash calculated locally. No upload, execution, or reputation lookup was performed."}


MAGIC_SIGNATURES = [
    (b"MZ", "Windows PE executable"),
    (b"\\x7fELF", "ELF executable or object"),
    (b"%PDF-", "PDF document"),
    (b"PK\\x03\\x04", "ZIP archive or ZIP-based document"),
    (b"\\x89PNG\\r\\n\\x1a\\n", "PNG image"),
    (b"\\xff\\xd8\\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
]


def inspect_file_static(workspace: str | Path, relative_path: str) -> dict:
    """Inspect basic file metadata, magic bytes, SHA-256, and entropy; never execute."""
    target = _workspace_file(workspace, relative_path)
    size = target.stat().st_size
    if size > MAX_HASH_BYTES:
        raise ValueError(f"File exceeds the {MAX_HASH_BYTES // (1024 * 1024)} MB static-analysis limit.")
    digest = hashlib.sha256()
    frequencies = [0] * 256
    sample = bytearray()
    total = 0
    with target.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            for byte in chunk:
                frequencies[byte] += 1
            if len(sample) < 16:
                sample.extend(chunk[:16 - len(sample)])
    file_type = "Unknown or unrecognized"
    for signature, label in MAGIC_SIGNATURES:
        if sample.startswith(signature):
            file_type = label
            break
    entropy = 0.0
    if total:
        import math
        entropy = -sum((count / total) * math.log2(count / total)
                       for count in frequencies if count)
    return {
        "file": target.name,
        "extension": target.suffix.lower(),
        "bytes": size,
        "sha256": digest.hexdigest(),
        "magic_type_guess": file_type,
        "entropy_bits_per_byte": round(entropy, 4),
        "high_entropy_indicator": entropy >= 7.2,
        "assessment": "Static metadata only. High entropy can occur in compressed, encrypted, or packed files and is not proof of malware.",
        "safety": "File was opened as data only; it was not executed, uploaded, or modified.",
    }
