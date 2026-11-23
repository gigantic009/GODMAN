"""Explicit, allow-listed local tools. No arbitrary shell execution exists here."""
from __future__ import annotations

import platform
from math import isfinite
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .security import ApprovalRequired, AuditLog, SecurityPolicy
from .cybersecurity import analyze_security_log, inspect_file_static, sha256_workspace_file
from .security_posture import collect_windows_security_posture
from .archive_safety import inspect_zip_safety
from .security_scanning import scan_with_microsoft_defender
from .windows_firewall import inspect_windows_firewall
from .windows_events import collect_windows_security_events
from .url_triage import analyze_url_structure


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    risk: str
    handler: Callable[..., Any]
    parameters: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}, "additionalProperties": False})


def _validate_schema(value: Any, schema: dict[str, Any], path: str = "arguments") -> None:
    """Validate the supported JSON-schema subset at the runtime tool boundary."""
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            raise ValueError(f"{path} must be an object.")
        for key in schema.get("required", []):
            if key not in value:
                raise ValueError(f"{path}.{key} is required.")
        if schema.get("additionalProperties") is False:
            extras = set(value) - set(schema.get("properties", {}))
            if extras:
                raise ValueError(f"{path} has unexpected keys.")
        for key, item in value.items():
            child = schema.get("properties", {}).get(key)
            if child is not None:
                _validate_schema(item, child, f"{path}.{key}")
    elif kind == "array":
        if not isinstance(value, list):
            raise ValueError(f"{path} must be an array.")
        item_schema = schema.get("items")
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", float("inf")):
            raise ValueError(f"{path} length is outside permitted bounds.")
        if item_schema:
            for i, item in enumerate(value):
                _validate_schema(item, item_schema, f"{path}[{i}]")
    elif kind == "string":
        if not isinstance(value, str):
            raise ValueError(f"{path} must be a string.")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", float("inf")):
            raise ValueError(f"{path} length is outside permitted bounds.")
    elif kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{path} must be an integer.")
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{path} is below the minimum.")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValueError(f"{path} is above the maximum.")
    elif kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(float(value)):
            raise ValueError(f"{path} must be a finite number.")
    elif kind == "boolean":
        if not isinstance(value, bool):
            raise ValueError(f"{path} must be a boolean.")
    elif kind is not None:
        raise ValueError(f"Unsupported schema type: {kind}.")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} is not an allowed value.")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{path} is below the minimum.")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValueError(f"{path} is above the maximum.")


class ToolRegistry:
    def __init__(self, policy: SecurityPolicy, audit: AuditLog):
        self.policy = policy
        self.audit = audit
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def describe(self) -> list[dict[str, str]]:
        return [{"name": t.name, "description": t.description, "risk": t.risk}
                for t in self._tools.values()]

    def model_tools(self) -> list[dict[str, Any]]:
        """Return OpenAI Responses API function definitions."""
        return [
            {
                "type": "function",
                "name": tool.name,
                "description": f"{tool.description} Risk level: {tool.risk}.",
                "parameters": tool.parameters,
                "strict": True,
            }
            for tool in self._tools.values()
        ]

    def execute(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        if name not in self._tools:
            raise KeyError(f"Tool is not allow-listed: {name}")
        args = arguments if arguments is not None else {}
        tool = self._tools[name]
        try:
            _validate_schema(args, tool.parameters)
            self.policy.authorize(name, args, risk=tool.risk)
            result = tool.handler(**args)
            self.audit.record(name, tool.risk, "success", "Completed")
            return result
        except ApprovalRequired as exc:
            self.audit.record(name, tool.risk, "denied", str(exc))
            raise
        except Exception as exc:
            self.audit.record(name, tool.risk, "error", type(exc).__name__)
            raise


def system_summary() -> dict[str, str]:
    return {"os": platform.platform(), "system": platform.system(),
            "release": platform.release(), "machine": platform.machine(),
            "python": platform.python_version(), "processor": platform.processor() or "Unknown"}


def disk_summary(path: str = ".") -> dict[str, int | str]:
    usage = shutil.disk_usage(path)
    return {"path": str(Path(path).resolve()),
            "total_gb": round(usage.total / (1024 ** 3), 2),
            "used_gb": round(usage.used / (1024 ** 3), 2),
            "free_gb": round(usage.free / (1024 ** 3), 2)}


def list_workspace_files(workspace: str, relative_path: str = ".") -> list[str]:
    root = Path(workspace).expanduser().resolve()
    target = (root / relative_path).resolve()
    if target != root and root not in target.parents:
        raise ValueError("Path escapes the configured workspace.")
    if not target.exists():
        raise FileNotFoundError(relative_path)
    if not target.is_dir():
        raise NotADirectoryError(relative_path)
    return sorted(p.name + ("/" if p.is_dir() else "") for p in target.iterdir())[:200]


def read_workspace_file(workspace: str, relative_path: str, max_chars: int = 12000) -> str:
    root = Path(workspace).expanduser().resolve()
    target = (root / relative_path).resolve()
    if target != root and root not in target.parents:
        raise ValueError("Path escapes the configured workspace.")
    if not target.is_file():
        raise FileNotFoundError(relative_path)
    if target.stat().st_size > 1_000_000:
        raise ValueError("File exceeds the 1 MB read limit.")
    return target.read_text(encoding="utf-8", errors="replace")[:max(1, min(max_chars, 12000))]


def create_workspace_file(workspace: str, relative_path: str, content: str) -> str:
    root = Path(workspace).expanduser().resolve()
    target = (root / relative_path).resolve()
    if target != root and root not in target.parents:
        raise ValueError("Path escapes the configured workspace.")
    if target.exists():
        raise FileExistsError("Refusing to overwrite an existing file.")
    if len(content) > 200_000:
        raise ValueError("Content exceeds the 200 KB write limit.")
    target.parent.mkdir(parents=True, exist_ok=True)
    # Re-resolve after parent creation, then create atomically without overwriting.
    target = (root / relative_path).resolve()
    if target != root and root not in target.parents:
        raise ValueError("Path escapes the configured workspace.")
    if target.exists():
        raise FileExistsError("Refusing to overwrite an existing file.")
    try:
        with target.open("x", encoding="utf-8", newline="") as handle:
            handle.write(content)
    except FileExistsError:
        raise FileExistsError("Refusing to overwrite an existing file.") from None
    return str(target)


def open_allowlisted_app(app_name: str) -> str:
    commands = {"notepad": ["notepad.exe"], "calculator": ["calc.exe"],
                "paint": ["mspaint.exe"], "vscode": ["code"]}
    key = app_name.strip().lower()
    if key not in commands:
        raise ValueError(f"App is not allow-listed. Choose: {', '.join(commands)}")
    if platform.system() != "Windows" and key != "vscode":
        raise OSError("This app launcher currently supports Windows.")
    subprocess.Popen(commands[key], shell=False, close_fds=True)
    return f"Launched {key}."


def _object(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


def build_default_registry(data_dir: str | Path, workspace: str | Path,
                           policy: SecurityPolicy | None = None) -> ToolRegistry:
    audit = AuditLog(Path(data_dir) / "audit.sqlite3")
    registry = ToolRegistry(policy or SecurityPolicy(), audit)
    registry.register(Tool("system_summary", "Read basic operating-system and Python information.", "read",
                           system_summary, _object({}, [])))
    registry.register(Tool("disk_summary", "Read disk capacity for the configured GODMAN workspace only.", "read",
                           lambda: disk_summary(str(workspace)),
                           _object({}, [])))
    registry.register(Tool("list_workspace_files", "List entries inside the configured GODMAN workspace.", "read",
                           lambda relative_path: list_workspace_files(str(workspace), relative_path),
                           _object({"relative_path": {"type": "string"}}, ["relative_path"])))
    registry.register(Tool("read_workspace_file", "Read a UTF-8 file inside the configured GODMAN workspace.", "read",
                           lambda relative_path: read_workspace_file(str(workspace), relative_path),
                           _object({"relative_path": {"type": "string"}}, ["relative_path"])))
    registry.register(Tool("create_workspace_file", "Create a new file inside the workspace; never overwrites. Requires user approval.", "write",
                           lambda relative_path, content: create_workspace_file(str(workspace), relative_path, content),
                           _object({"relative_path": {"type": "string"}, "content": {"type": "string"}}, ["relative_path", "content"])))
    registry.register(Tool("open_app", "Launch an explicitly allow-listed desktop application. Requires user approval.", "system",
                           open_allowlisted_app,
                           _object({"app_name": {"type": "string", "enum": ["notepad", "calculator", "paint", "vscode"]},}, ["app_name"])))
    registry.register(Tool(
        "analyze_security_log",
        "Run bounded defensive heuristic triage on a .log, .txt, .jsonl, or .csv file inside the GODMAN workspace. Does not prove compromise.",
        "read",
        lambda relative_path: analyze_security_log(workspace, relative_path),
        _object({"relative_path": {"type": "string"}}, ["relative_path"]),
    ))
    registry.register(Tool(
        "inspect_file_static",
        "Safely inspect file metadata, magic bytes, SHA-256, and entropy for a file inside the GODMAN workspace. Never executes or uploads the file.",
        "read",
        lambda relative_path: inspect_file_static(workspace, relative_path),
        _object({"relative_path": {"type": "string"}}, ["relative_path"]),
    ))
    registry.register(Tool(
        "sha256_workspace_file",
        "Calculate a local SHA-256 hash for a file inside the GODMAN workspace without executing or uploading it.",
        "read",
        lambda relative_path: sha256_workspace_file(workspace, relative_path),
        _object({"relative_path": {"type": "string"}}, ["relative_path"]),
    ))

    registry.register(Tool(
        "collect_windows_security_posture",
        "Read a bounded point-in-time Windows Defender, Firewall, BitLocker, and recent hotfix status snapshot. Read-only; no remediation or network scan.",
        "read",
        collect_windows_security_posture,
        _object({}, []),
    ))

    registry.register(Tool(
        "inspect_zip_safety",
        "Inspect ZIP central-directory metadata for suspicious expansion ratios, nested archives, path traversal names, and symlink entries. Never extracts or executes members.",
        "read",
        lambda relative_path: inspect_zip_safety(workspace, relative_path),
        _object({"relative_path": {"type": "string"}}, ["relative_path"]),
    ))
    registry.register(Tool(
        "inspect_windows_firewall",
        "Read Windows Firewall profiles and up to 500 enabled inbound allow rules; generate a conservative baseline plan without changing any setting.",
        "read",
        inspect_windows_firewall,
        _object({}, []),
    ))
    registry.register(Tool(
        "collect_windows_security_events",
        "Collect a bounded, read-only set of local Defender, Security, and System events with message redaction; point-in-time only.",
        "read",
        collect_windows_security_events,
        _object({}, []),
    ))
    registry.register(Tool(
        "analyze_url_structure",
        "Offline structural phishing-URL triage. Does not visit, resolve, or submit the URL; heuristic only.",
        "read",
        analyze_url_structure,
        _object({"url": {"type": "string", "minLength": 1, "maxLength": 4096}}, ["url"]),
    ))
    registry.register(Tool(
        "scan_workspace_with_defender",
        "Run an explicitly approved Microsoft Defender custom scan on a file or subfolder inside the configured GODMAN workspace. May take up to 30 minutes; does not guarantee remediation.",
        "system",
        lambda relative_path: scan_with_microsoft_defender(workspace, relative_path),
        _object({"relative_path": {"type": "string", "description": "Existing file or subfolder relative to the configured GODMAN workspace"}}, ["relative_path"]),
    ))
    return registry
