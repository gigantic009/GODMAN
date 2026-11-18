"""Offline phishing URL triage helpers.

Parses URL structure only. It never visits, resolves, or submits the URL to a
reputation service. Findings are heuristics, not a verdict that a URL is malicious.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly"}
_SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "work", "support", "country", "gq", "tk"}


def analyze_url_structure(url: str) -> dict:
    if not isinstance(url, str) or not url.strip() or len(url) > 4096:
        raise ValueError("Provide a URL between 1 and 4096 characters.")
    candidate = url.strip()
    if any(ord(ch) < 32 for ch in candidate):
        raise ValueError("URL contains control characters.")
    normalized = candidate if "://" in candidate else "https://" + candidate
    try:
        parsed = urlsplit(normalized)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL is malformed.") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        raise ValueError("Only absolute HTTP or HTTPS URLs are supported.")
    host_ascii = host.encode("idna").decode("ascii").lower().rstrip(".")
    labels = host_ascii.split(".")
    findings = []
    if parsed.username is not None or parsed.password is not None:
        findings.append({"severity": "high", "reason": "URL contains user-information before the hostname"})
    try:
        ipaddress.ip_address(host_ascii)
        findings.append({"severity": "medium", "reason": "URL uses a literal IP address"})
    except ValueError:
        pass
    if host_ascii in _SHORTENERS:
        findings.append({"severity": "medium", "reason": "URL uses a known link-shortening domain"})
    if len(host_ascii) > 100 or len(labels) > 5:
        findings.append({"severity": "low", "reason": "Unusually long or deeply nested hostname"})
    if any(label.startswith("xn--") for label in labels):
        findings.append({"severity": "medium", "reason": "Internationalized/punycode hostname; inspect for homograph deception"})
    if labels[-1] in _SUSPICIOUS_TLDS:
        findings.append({"severity": "low", "reason": "Hostname uses a TLD often abused in opportunistic campaigns"})
    if port and port not in {80, 443}:
        findings.append({"severity": "low", "reason": "URL uses a non-standard web port"})
    if parsed.scheme.lower() == "http":
        findings.append({"severity": "low", "reason": "Connection is not protected by HTTPS"})
    if re.search(r"(?i)(login|verify|secure|account|wallet|password|update)", parsed.path + "?" + parsed.query):
        findings.append({"severity": "info", "reason": "Path/query contains account-action terms; context matters"})
    return {
        "input": candidate,
        "scheme": parsed.scheme.lower(),
        "hostname_ascii": host_ascii,
        "port": port or (443 if parsed.scheme.lower() == "https" else 80),
        "path_present": bool(parsed.path and parsed.path != "/"),
        "query_present": bool(parsed.query),
        "findings": findings,
        "verdict": "needs_review" if findings else "no_structural_red_flags",
        "limitations": [
            "No DNS lookup, redirect following, page fetch, sandboxing, or reputation check was performed.",
            "A URL with no structural red flags can still be malicious.",
            "Do not open suspicious links to test them.",
        ],
    }
