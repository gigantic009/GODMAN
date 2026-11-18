"""One-command, read-only Windows endpoint checkup.

This aggregates existing bounded collectors. It does not scan files, change settings,
start services, block traffic, or claim continuous protection.
"""
from __future__ import annotations

import platform
from collections.abc import Callable
from typing import Any

from .security_posture import collect_windows_security_posture
from .windows_firewall import inspect_windows_firewall
from .windows_events import collect_windows_security_events


def run_endpoint_checkup(
    posture_collector: Callable[[], dict[str, Any]] = collect_windows_security_posture,
    firewall_collector: Callable[[], dict[str, Any]] = inspect_windows_firewall,
    events_collector: Callable[[], dict[str, Any]] = collect_windows_security_events,
) -> dict[str, Any]:
    """Run independent read-only collectors and return a consolidated review."""
    if platform.system() != "Windows":
        return {
            "product": "GODMAN",
            "checkup": "unsupported_platform",
            "platform": platform.system(),
            "read_only": True,
            "message": "Run this checkup on the Windows endpoint you own.",
            "actions_taken": [],
        }

    sections: dict[str, Any] = {}
    errors: list[dict[str, str]] = []
    for name, collector in (
        ("security_posture", posture_collector),
        ("firewall", firewall_collector),
        ("security_events", events_collector),
    ):
        try:
            sections[name] = collector()
        except Exception as exc:
            sections[name] = {"available": False, "error": type(exc).__name__}
            errors.append({"section": name, "error": type(exc).__name__})

    findings: list[dict[str, str]] = []
    posture = sections.get("security_posture", {})
    checks = posture.get("checks", {}) if isinstance(posture, dict) else {}
    defender = checks.get("defender", {}) if isinstance(checks, dict) else {}
    if isinstance(defender, dict) and defender.get("available"):
        for key, label in (
            ("antivirus_enabled", "Microsoft Defender antivirus is disabled"),
            ("real_time_protection", "Microsoft Defender real-time protection is disabled"),
            ("behavior_monitoring", "Microsoft Defender behavior monitoring is disabled"),
            ("ioav_protection", "Microsoft Defender downloaded-file scanning is disabled"),
        ):
            if defender.get(key) is False:
                findings.append({"severity": "high", "source": "security_posture", "finding": label})
        age = defender.get("signatures_age_days")
        if isinstance(age, int) and age > 3:
            findings.append({
                "severity": "medium", "source": "security_posture",
                "finding": f"Defender signatures are {age} days old; check for updates",
            })

    firewall = sections.get("firewall", {})
    if isinstance(firewall, dict):
        for item in firewall.get("findings", []):
            if isinstance(item, dict):
                findings.append({
                    "severity": str(item.get("severity", "info")),
                    "source": "firewall",
                    "finding": str(item.get("finding", "Unspecified firewall finding")),
                })

    event_data = sections.get("security_events", {})
    event_items = event_data.get("events", []) if isinstance(event_data, dict) else []
    event_count = len(event_items)
    event_severity = {
        1116: ("high", "Defender reported a malware detection event"),
        1102: ("high", "Windows Security audit log was cleared"),
        5001: ("high", "Defender real-time protection change/disable event recorded"),
        5007: ("medium", "Defender configuration change event recorded"),
        7045: ("medium", "A Windows service installation event was recorded"),
        1117: ("info", "Defender remediation action event recorded"),
        4625: ("info", "One or more failed sign-in events were recorded"),
    }
    for item in event_items:
        if not isinstance(item, dict):
            continue
        event_id = item.get("id")
        if event_id in event_severity:
            severity, label = event_severity[event_id]
            findings.append({
                "severity": severity, "source": "security_events",
                "finding": f"{label} (event ID {event_id}); inspect the event details and timestamp",
            })
    high_count = sum(1 for item in findings if item["severity"] == "high")
    return {
        "product": "GODMAN",
        "checkup": "completed_with_gaps" if errors else "completed",
        "platform": "Windows",
        "read_only": True,
        "summary": {
            "high_findings": high_count,
            "total_findings": len(findings),
            "events_returned": event_count,
            "collector_errors": len(errors),
        },
        "findings": findings,
        "sections": sections,
        "collector_errors": errors,
        "actions_taken": [],
        "important_limitations": [
            "Point-in-time checks only; this is not continuous monitoring or EDR.",
            "Selected event IDs only; missing events do not prove the endpoint is clean.",
            "No files were scanned and no malware verdict was produced.",
            "No firewall, Defender, account, process, or system settings were changed.",
            "Review each finding and confirm it on the device before remediation.",
        ],
        "next_step": "Review /posture, /firewall and /events output. Do not apply changes until the owner has reviewed a proposed change and its rollback.",
    }
