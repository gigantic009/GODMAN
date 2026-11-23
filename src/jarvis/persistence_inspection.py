"""Read-only Windows persistence inventory and explainable risk triage."""
from __future__ import annotations

import json
import platform
import subprocess
from typing import Any

_SCRIPT = r"""
$items = @()
$runPaths = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($p in $runPaths) {
 try {
  $props = Get-ItemProperty -Path $p -ErrorAction Stop
  foreach ($prop in $props.PSObject.Properties) {
   if ($prop.Name -notmatch '^PS') { $items += @{kind='registry_run'; location=$p; name=$prop.Name; command=[string]$prop.Value} }
  }
 } catch {}
}
try {
 Get-ScheduledTask | Select-Object -First 300 | ForEach-Object {
  $task = $_
  foreach ($action in $task.Actions) {
   $items += @{kind='scheduled_task'; location=($task.TaskPath+$task.TaskName); name=$task.TaskName; command=([string]$action.Execute+' '+[string]$action.Arguments)}
  }
 }
} catch {}
try {
 Get-CimInstance Win32_Service | Select-Object -First 500 | ForEach-Object {
  $items += @{kind='service'; location=[string]$_.Name; name=[string]$_.DisplayName; command=[string]$_.PathName; start_mode=[string]$_.StartMode; state=[string]$_.State}
 }
} catch {}
@{items=$items; collected_at=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 6 -Compress
"""

SUSPICIOUS = [
 (r'(?i)\\appdata\\local\\temp\\|\\windows\\temp\\', 'execution_from_temp', 'medium'),
 (r'(?i)\\users\\public\\', 'execution_from_public_directory', 'medium'),
 (r'(?i)(powershell|pwsh).*(-enc|encodedcommand)', 'encoded_powershell_autostart', 'high'),
 (r'(?i)(wscript|cscript|mshta|regsvr32|rundll32)', 'living_off_the_land_binary', 'medium'),
 (r'(?i)\\appdata\\|\\downloads\\', 'user_writable_autostart_path', 'medium'),
]

def _score(item: dict[str, Any]) -> list[dict[str,str]]:
 import re
 text = str(item.get('command',''))
 findings=[]
 for pattern, rule, severity in SUSPICIOUS:
  if re.search(pattern,text):
   findings.append({'rule':rule,'severity':severity,'evidence':rule.replace('_',' ')})
 return findings

def inspect_windows_persistence(timeout_seconds: int = 35) -> dict:
 """Inventory selected Run keys, scheduled task actions and services, read-only."""
 if platform.system() != 'Windows':
  raise OSError('Persistence inventory is supported only on Windows.')
 completed=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command',_SCRIPT],
  capture_output=True,text=True,timeout=max(5,min(int(timeout_seconds),45)),shell=False,check=False)
 if completed.returncode != 0: raise RuntimeError('Windows persistence inventory failed.')
 output=completed.stdout.strip()
 if not output or len(output)>1_500_000: raise RuntimeError('Persistence inventory output was empty or oversized.')
 payload=json.loads(output)
 if not isinstance(payload,dict) or not isinstance(payload.get('items'),list): raise RuntimeError('Unexpected persistence inventory format.')
 items=[]
 for raw in payload['items'][:1200]:
  if not isinstance(raw,dict): continue
  item={k:raw.get(k) for k in ('kind','location','name','command','start_mode','state') if k in raw}
  item['heuristic_findings']=_score(item)
  items.append(item)
 flagged=sum(bool(i['heuristic_findings']) for i in items)
 return {'platform':'Windows','read_only':True,'collected_at':payload.get('collected_at'),'items':items,
  'summary':{'items_reviewed':len(items),'items_flagged_by_heuristics':flagged},
  'limitations':['This is a bounded point-in-time inventory, not continuous EDR monitoring.',
   'Heuristic flags are leads, not proof of malware. Legitimate software may use these locations or binaries.',
   'Some task/service details may be unavailable without elevated permissions. No changes were made.']}
