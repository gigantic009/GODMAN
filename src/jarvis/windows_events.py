"""Bounded, read-only Windows security event collection.

Uses fixed event channels and IDs. Event messages are untrusted evidence and are
redacted/truncated before returning. No remote log access or remediation occurs.
"""
from __future__ import annotations

import json
import platform
import re
import subprocess


_EVENT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$queries = @(
  @{ log='Microsoft-Windows-Windows Defender/Operational'; ids=@(1116,1117,5001,5007); max=80 },
  @{ log='Security'; ids=@(4624,4625,4672,4688,4720,4728,4732,1102); max=120 },
  @{ log='System'; ids=@(7045,6005,6006); max=50 }
)
$results = @()
foreach ($q in $queries) {
  try {
    $items = @(Get-WinEvent -FilterHashtable @{LogName=$q.log; Id=$q.ids} -MaxEvents $q.max -ErrorAction Stop |
      ForEach-Object {
        @{ log=$q.log; id=[int]$_.Id; time=$_.TimeCreated.ToUniversalTime().ToString('o');
           provider=[string]$_.ProviderName; level=[string]$_.LevelDisplayName;
           message=([string]$_.Message).Substring(0,[Math]::Min(2500,([string]$_.Message).Length)) }
      })
    $results += $items
  } catch {
    $results += @{ log=$q.log; unavailable=$true; reason='Log unavailable, no matching events, or access denied' }
  }
}
@{ events=$results; collected_at=[DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Depth 5 -Compress
"""


def _redact(value: str) -> str:
    value = re.sub(r'(?i)(password|passwd|token|secret|api[_-]?key)(\s*[:=]\s*)[^\s;,]+',
                   r'\1\2[REDACTED]', value)
    value = re.sub(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',
                   '[EMAIL REDACTED]', value)
    return value[:2500]


def collect_windows_security_events(timeout_seconds: int = 30) -> dict:
    """Collect a bounded set of local Defender, Security and System events."""
    if platform.system() != "Windows":
        raise OSError("Windows event collection is supported only on Windows.")
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
         "-Command", _EVENT_SCRIPT],
        capture_output=True, text=True,
        timeout=max(5, min(int(timeout_seconds), 45)),
        check=False, shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("Windows security event collection failed or access was denied.")
    output = completed.stdout.strip()
    if not output or len(output) > 750_000:
        raise RuntimeError("Windows event collection returned empty or oversized output.")
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Windows event collection returned invalid JSON.") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
        raise RuntimeError("Windows event collection returned an unexpected structure.")
    sanitized = []
    for item in payload["events"][:250]:
        if not isinstance(item, dict):
            continue
        sanitized.append({
            key: (_redact(str(value)) if key == "message" else value)
            for key, value in item.items()
            if key in {"log", "id", "time", "provider", "level", "message", "unavailable", "reason"}
        })
    return {
        "platform": "Windows",
        "collection": "read_only",
        "collected_at": payload.get("collected_at"),
        "events": sanitized,
        "limitations": [
            "Only selected local event channels and event IDs are queried.",
            "Security log access may require elevated permissions.",
            "Missing events do not prove that an activity did not occur.",
            "Event messages are untrusted and may contain incomplete or misleading context.",
            "This is a point-in-time query, not continuous monitoring or an EDR sensor.",
        ],
    }
