"""Read-only Windows security posture checks using fixed PowerShell queries.

No commands or arguments are accepted from the model or user. This module reads
security configuration only; it never changes settings or starts scans.
"""
from __future__ import annotations

import json
import platform
import subprocess


_WINDOWS_POSTURE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$result = [ordered]@{}
try {
  $d = Get-MpComputerStatus -ErrorAction Stop
  $result.defender = [ordered]@{
    available = $true
    antivirus_enabled = [bool]$d.AntivirusEnabled
    real_time_protection = [bool]$d.RealTimeProtectionEnabled
    behavior_monitoring = [bool]$d.BehaviorMonitorEnabled
    ioav_protection = [bool]$d.IoavProtectionEnabled
    signatures_age_days = [int]$d.AntivirusSignatureAge
    tamper_protection = if ($null -ne $d.IsTamperProtected) { [bool]$d.IsTamperProtected } else { $null }
  }
} catch {
  $result.defender = @{ available = $false; error = 'Defender status unavailable or access denied' }
}
try {
  $profiles = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
    @{ name = $_.Name; enabled = [bool]$_.Enabled; default_inbound = [string]$_.DefaultInboundAction; default_outbound = [string]$_.DefaultOutboundAction }
  })
  $result.firewall = @{ available = $true; profiles = $profiles }
} catch {
  $result.firewall = @{ available = $false; error = 'Firewall profile status unavailable or access denied' }
}
try {
  $volumes = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
    @{ mount_point = $_.MountPoint; protection_status = [string]$_.ProtectionStatus; volume_status = [string]$_.VolumeStatus; encryption_percentage = [int]$_.EncryptionPercentage }
  })
  $result.bitlocker = @{ available = $true; volumes = $volumes }
} catch {
  $result.bitlocker = @{ available = $false; error = 'BitLocker status unavailable; feature may not be present' }
}
try {
  $hotfixes = @(Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 5 | ForEach-Object {
    @{ hotfix_id = $_.HotFixID; installed_on = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { $null } }
  })
  $result.recent_hotfixes = $hotfixes
} catch {
  $result.recent_hotfixes = @()
}
$result | ConvertTo-Json -Depth 5 -Compress
"""


def collect_windows_security_posture(timeout_seconds: int = 20) -> dict:
    """Collect selected Defender, firewall, BitLocker and hotfix posture read-only."""
    if platform.system() != "Windows":
        raise OSError("This read-only posture collector currently supports Windows only.")
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
         "-Command", _WINDOWS_POSTURE_SCRIPT],
        capture_output=True, text=True, timeout=max(5, min(int(timeout_seconds), 30)),
        check=False, shell=False,
    )
    if completed.returncode != 0:
        # Never return PowerShell stderr: it can contain environment-specific details.
        raise RuntimeError("Windows posture query failed. Check PowerShell availability and permissions.")
    output = completed.stdout.strip()
    if not output or len(output) > 100_000:
        raise RuntimeError("Windows posture query returned empty or oversized output.")
    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Windows posture query returned invalid JSON.") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Windows posture query returned an unexpected data structure.")
    return {
        "platform": "Windows",
        "collection": "read_only",
        "checks": data,
        "limitations": [
            "This is a point-in-time configuration snapshot, not continuous EDR monitoring.",
            "Unavailable checks are not proof that a control is disabled.",
            "It does not test exploitability, inspect every endpoint control, or change settings.",
            "Review findings before remediation; preserve normal Windows security protections."
        ]
    }
