"""Read-only Windows Firewall inventory and hardening-plan generation.

This first firewall milestone does not modify Windows Firewall. It collects a
bounded profile/rule summary using fixed PowerShell and produces a reviewable
baseline plan. Enforcement will be a separate, owner-approved milestone.
"""
from __future__ import annotations

import json
import platform
import subprocess


_FIREWALL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
  @{ name = [string]$_.Name; enabled = [bool]$_.Enabled;
     default_inbound = [string]$_.DefaultInboundAction;
     default_outbound = [string]$_.DefaultOutboundAction;
     inbound_notifications = [bool]$_.NotifyOnListen;
     log_blocked = [bool]$_.LogBlocked;
     log_allowed = [bool]$_.LogAllowed }
})
$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow |
  Select-Object -First 500 | ForEach-Object {
    $r = $_
    $p = $r | Get-NetFirewallPortFilter
    $a = $r | Get-NetFirewallAddressFilter
    @{ name = [string]$r.DisplayName; profile = [string]$r.Profile;
       protocol = [string]$p.Protocol; local_port = [string]$p.LocalPort;
       remote_address = [string]$a.RemoteAddress; program = [string]$r.Program;
       service = [string]$r.Service; owner = [string]$r.Owner }
  })
@{ profiles = $profiles; enabled_inbound_allow_rules = $rules;
   rules_truncated = ($rules.Count -ge 500) } | ConvertTo-Json -Depth 5 -Compress
"""


def inspect_windows_firewall(timeout_seconds: int = 25) -> dict:
    """Return a read-only firewall snapshot and conservative recommendations."""
    if platform.system() != "Windows":
        raise OSError("Windows Firewall inspection is supported only on Windows.")
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
         "-Command", _FIREWALL_SCRIPT],
        capture_output=True, text=True,
        timeout=max(5, min(int(timeout_seconds), 30)),
        check=False, shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("Windows Firewall inspection failed or access was denied.")
    output = completed.stdout.strip()
    if not output or len(output) > 500_000:
        raise RuntimeError("Windows Firewall inspection returned empty or oversized output.")
    try:
        snapshot = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Windows Firewall inspection returned invalid JSON.") from exc
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("profiles"), list):
        raise RuntimeError("Windows Firewall returned an unexpected data structure.")

    findings = []
    for profile in snapshot["profiles"]:
        if not profile.get("enabled", False):
            findings.append({
                "severity": "high",
                "profile": profile.get("name", "unknown"),
                "finding": "Firewall profile is disabled",
                "recommendation": "Review and enable this profile after checking managed policy and connectivity requirements.",
            })
        if str(profile.get("default_inbound", "")).lower() not in {"block", "notconfigured"}:
            findings.append({
                "severity": "high",
                "profile": profile.get("name", "unknown"),
                "finding": "Default inbound action is not Block",
                "recommendation": "Review a default-deny inbound policy; preserve explicitly required and verified services.",
            })
        if str(profile.get("default_outbound", "")).lower() == "block":
            findings.append({
                "severity": "info",
                "profile": profile.get("name", "unknown"),
                "finding": "Default outbound action is Block",
                "recommendation": "Confirm required application and system egress rules before changing this profile.",
            })

    return {
        "platform": "Windows",
        "collection": "read_only",
        "snapshot": snapshot,
        "findings": findings,
        "baseline_plan": {
            "profiles": ["Domain", "Private", "Public"],
            "enable_firewall": True,
            "default_inbound": "Block",
            "default_outbound": "Allow",
            "preserve_existing_rules": True,
            "log_dropped_packets": True,
            "enforcement": "NOT_APPLIED",
            "approval_required": True,
        },
        "limitations": [
            "This is a point-in-time inventory, not continuous monitoring.",
            "At most 500 enabled inbound allow rules are returned; inspect the truncation flag.",
            "Group Policy or MDM may override local settings.",
            "Rule names and metadata do not establish whether a rule is safe or malicious.",
            "No firewall setting or rule is changed by this function.",
        ],
    }
