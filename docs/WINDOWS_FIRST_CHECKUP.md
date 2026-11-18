# GODMAN — first Windows endpoint checkup

This is a **read-only first review**, not a security certification. Run it on the Windows computer you own. It does not modify firewall rules, Defender settings, services, accounts, files, or processes.

## 1. Update the local checkout

Open PowerShell in your GODMAN folder:

```powershell
git status --short
git pull
`.\.venv\Scripts\Activate.ps1`
python -m compileall -q src run.py
python -m unittest discover -s tests -v
```

If Git reports local changes, stop and preserve them before pulling. Do not overwrite work you need.

## 2. Start GODMAN

```powershell
python run.py
```

The existing application needs a valid `OPENAI_API_KEY` in the private `.env` file to start its normal interactive assistant. Never paste that key into chat, issues, logs, or screenshots.

## 3. Run the read-only checkup

At the GODMAN prompt, run:

```text
/checkup
```

It independently attempts three bounded local collectors:
- Defender, firewall, BitLocker and recent-hotfix posture
- Windows Firewall profiles and a bounded list of enabled inbound allow rules
- Selected local Defender, Security and System event IDs

A section may report unavailable if Windows permissions, policy, event retention, or a Windows feature prevents collection. That is a visibility gap, not proof of compromise.

## 4. Inspect details separately

```text
/posture
/firewall
/events
/audit
```

Use `/url https://example.com` only when you want offline URL-structure triage. It does not visit the site or check reputation.

## 5. Windows-native cross-checks

In a separate PowerShell window, these commands are read-only:

```powershell
Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureAge
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus,VolumeStatus,EncryptionPercentage
```

If a command is unavailable on your Windows edition, record that fact rather than installing or changing anything just for this check.

## 6. What to send back for review

Share the `/checkup` summary and any specific findings. Before sharing detailed output, remove usernames, email addresses, computer names, public IP addresses, device identifiers, file paths, and any unrelated personal data. Never share `.env`, API keys, passwords, recovery keys, or raw authentication tokens.

## Important limits

- No whole-device malware scan is started by `/checkup`.
- No continuous monitoring, file-integrity monitoring, or automatic blocking is running.
- The event collector reads selected event IDs only and may need elevated permissions for some Security log records.
- A clean-looking snapshot does not prove the computer is uncompromised.
- No firewall change or remediation should be attempted until the owner has reviewed the exact change, connectivity impact, backup, and rollback plan.
- Router/Wi-Fi integration remains deliberately out of scope for this endpoint-first check.
