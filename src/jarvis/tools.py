"""Explicit, allow-listed local tools. No arbitrary shell execution exists here."""
from __future__ import annotations

import platform
import json
import copy
from math import isfinite
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .security import ApprovalRequired, AuditLog, SecurityPolicy
from .defense_core.policy import ActionPolicy
from .cybersecurity import analyze_security_log, inspect_file_static, sha256_workspace_file
from .security_posture import collect_windows_security_posture
from .archive_safety import inspect_zip_safety
from .security_scanning import scan_with_microsoft_defender
from .windows_firewall import inspect_windows_firewall
from .windows_events import collect_windows_security_events
from .url_triage import analyze_url_structure
from .persistence_inspection import inspect_windows_persistence


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    risk: str
    handler: Callable[..., Any]
    parameters: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}, "additionalProperties": False})


def _schema_bound(value, label, maximum=100000):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{label} must be a bounded non-negative integer.")
    return value


def _schema_number(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric.")
    try:
        numeric = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{label} must be finite and bounded.") from exc
    if not isfinite(numeric) or abs(numeric) > 1e100:
        raise ValueError(f"{label} must be finite and bounded.")
    return numeric


def _validate_schema_definition(schema: Any, depth: int = 0) -> None:
    """Validate and constrain the JSON Schema subset used for tool dispatch."""
    if depth > 8 or not isinstance(schema, dict):
        raise ValueError("Tool schemas must be bounded dictionaries.")
    kind = schema.get("type")
    supported = {"object", "array", "string", "integer", "number", "boolean"}
    if kind not in supported:
        raise ValueError("Tool schemas require a supported explicit type.")
    common = {"type", "description", "enum"}
    allowed = {
        "object": common | {"properties", "required", "additionalProperties"},
        "array": common | {"items", "minItems", "maxItems"},
        "string": common | {"minLength", "maxLength"},
        "integer": common | {"minimum", "maximum"},
        "number": common | {"minimum", "maximum"},
        "boolean": common,
    }[kind]
    if set(schema) - allowed:
        raise ValueError("Tool schema contains unsupported keywords.")
    description = schema.get("description")
    if description is not None and (not isinstance(description, str) or len(description) > 1000):
        raise ValueError("Schema description must be bounded text.")
    if "enum" in schema:
        choices = schema["enum"]
        if not isinstance(choices, list) or not 1 <= len(choices) <= 100:
            raise ValueError("Enum must contain between 1 and 100 choices.")
        for choice in choices:
            if kind == "string" and not isinstance(choice, str):
                raise ValueError("String enums must contain strings.")
            if kind == "integer" and (isinstance(choice, bool) or not isinstance(choice, int)):
                raise ValueError("Integer enums must contain integers.")
            if kind == "number" and (isinstance(choice, bool) or not isinstance(choice, (int, float))):
                raise ValueError("Number enums must contain numbers.")
            if kind in {"integer", "number"}:
                _schema_number(choice, "enum choice")
            if kind == "string" and len(choice) > 100000:
                raise ValueError("String enum choices must be bounded.")
            if kind == "boolean" and not isinstance(choice, bool):
                raise ValueError("Boolean enums must contain booleans.")
            if kind in {"object", "array"}:
                raise ValueError("Object and array enums are not supported.")
        if len({(type(choice).__name__, repr(choice)) for choice in choices}) != len(choices):
            raise ValueError("Enum choices must be unique.")
    if kind == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        schema.setdefault("properties", properties)
        schema.setdefault("required", required)
        if not isinstance(properties, dict) or len(properties) > 100:
            raise ValueError("Object properties must be a bounded dictionary.")
        if not isinstance(required, list) or len(required) > 100 or any(not isinstance(x, str) for x in required):
            raise ValueError("Object required fields must be a bounded string list.")
        if len(set(required)) != len(required) or set(required) != set(properties):
            raise ValueError("Strict tool schemas require every property exactly once.")
        if schema.get("additionalProperties") is not False:
            raise ValueError("Strict tool schemas must set additionalProperties=false.")
        for key, child in properties.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise ValueError("Schema property names must be bounded strings.")
            _validate_schema_definition(child, depth + 1)
    elif kind == "array":
        if "items" not in schema:
            raise ValueError("Array schema must define items.")
        minimum = _schema_bound(schema.get("minItems", 0), "minItems", 1000)
        maximum = _schema_bound(schema.get("maxItems", 1000), "maxItems", 1000)
        if minimum > maximum:
            raise ValueError("minItems cannot exceed maxItems.")
        _validate_schema_definition(schema["items"], depth + 1)
    elif kind == "string":
        minimum = _schema_bound(schema.get("minLength", 0), "minLength")
        maximum = _schema_bound(schema.get("maxLength", 100000), "maxLength")
        if minimum > maximum:
            raise ValueError("minLength cannot exceed maxLength.")
    elif kind in {"integer", "number"}:
        if "minimum" in schema:
            _schema_number(schema["minimum"], "minimum")
        if "maximum" in schema:
            _schema_number(schema["maximum"], "maximum")
        if "minimum" in schema and "maximum" in schema and schema["minimum"] > schema["maximum"]:
            raise ValueError("minimum cannot exceed maximum.")


def _enum_matches(value, choices, kind):
    for choice in choices:
        if kind == "string" and type(value) is str and value == choice:
            return True
        if kind == "integer" and type(value) is int and value == choice:
            return True
        if kind == "number" and type(value) in (int, float) and type(choice) in (int, float) and value == choice:
            return True
        if kind == "boolean" and type(value) is bool and value is choice:
            return True
    return False


def _validate_schema(value: Any, schema: dict[str, Any], path: str = "arguments") -> None:
    """Validate values against the registered, bounded JSON Schema subset."""
    kind = schema["type"]
    if isinstance(value, str) and len(value) > 100_000:
        raise ValueError(f"{path} exceeds the global string limit.")
    if isinstance(value, list) and len(value) > 1_000:
        raise ValueError(f"{path} exceeds the global array limit.")
    if isinstance(value, dict) and len(value) > 100:
        raise ValueError(f"{path} exceeds the global object-key limit.")
    if kind == "object":
        if not isinstance(value, dict):
            raise ValueError(f"{path} must be an object.")
        properties = schema["properties"]
        if set(value) - set(properties):
            raise ValueError(f"{path} has unexpected keys.")
        for key in schema["required"]:
            if key not in value:
                raise ValueError(f"{path}.{key} is required.")
        for key, item in value.items():
            _validate_schema(item, properties[key], f"{path}.{key}")
    elif kind == "array":
        if not isinstance(value, list):
            raise ValueError(f"{path} must be an array.")
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 1000):
            raise ValueError(f"{path} length is outside permitted bounds.")
        for i, item in enumerate(value):
            _validate_schema(item, schema["items"], f"{path}[{i}]")
    elif kind == "string":
        if not isinstance(value, str):
            raise ValueError(f"{path} must be a string.")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 100000):
            raise ValueError(f"{path} length is outside permitted bounds.")
    elif kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{path} must be an integer.")
        _schema_number(value, path)
    elif kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{path} must be a number.")
        _schema_number(value, path)
    elif kind == "boolean":
        if not isinstance(value, bool):
            raise ValueError(f"{path} must be a boolean.")
    if "minimum" in schema and value < schema["minimum"]:
        raise ValueError(f"{path} is below the minimum.")
    if "maximum" in schema and value > schema["maximum"]:
        raise ValueError(f"{path} is above the maximum.")
    if "enum" in schema and not _enum_matches(value, schema["enum"], kind):
        raise ValueError(f"{path} is not an allowed value.")




def _snapshot_tool_arguments(arguments: Any) -> dict[str, Any]:
    """Build a bounded, JSON-only dispatch snapshot before validation or approval."""
    if arguments is None:
        arguments = {}
    if type(arguments) is not dict:
        raise ValueError("Tool arguments must be a JSON object.")
    budget = {"nodes": 0, "bytes": 0}
    max_bytes = 256 * 1024

    def clone(value: Any, depth: int = 0):
        budget["nodes"] += 1
        if budget["nodes"] > 10000 or depth > 8:
            raise ValueError("Tool arguments exceed structural limits.")
        if type(value) is dict:
            if len(value) > 100:
                raise ValueError("Tool argument object exceeds the key limit.")
            result = {}
            for key, item in value.items():
                if type(key) is not str or not key or len(key) > 128:
                    raise ValueError("Tool argument keys must be bounded strings.")
                budget["bytes"] += len(key.encode("utf-8")) + 2
                result[key] = clone(item, depth + 1)
            return result
        if type(value) is list:
            if len(value) > 1000:
                raise ValueError("Tool argument array exceeds the item limit.")
            budget["bytes"] += 2
            return [clone(item, depth + 1) for item in value]
        if type(value) is str:
            if len(value) > 100000:
                raise ValueError("Tool argument string exceeds the global limit.")
            budget["bytes"] += len(value.encode("utf-8")) + 2
            return value
        if type(value) is bool or value is None:
            budget["bytes"] += 5
            return value
        if type(value) is int or type(value) is float:
            _schema_number(value, "tool argument")
            budget["bytes"] += len(repr(value))
            return value
        raise ValueError("Tool arguments must contain JSON-compatible values only.")

    snapshot = clone(arguments)
    if budget["bytes"] > max_bytes:
        raise ValueError("Tool arguments exceed the 256 KB dispatch limit.")
    try:
        encoded = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("Tool arguments could not be safely serialized.") from exc
    if len(encoded.encode("utf-8")) > max_bytes:
        raise ValueError("Tool arguments exceed the 256 KB dispatch limit.")
    return snapshot


class ToolRegistry:
    """Schema-checked tool dispatcher with a central action-policy boundary."""

    def __init__(self, policy: SecurityPolicy, audit: AuditLog, action_policy: ActionPolicy | None = None):
        self.policy = policy
        self.audit = audit
        self._default_action_policy = action_policy is None
        self.action_policy = action_policy or ActionPolicy(
            allowed_read_actions=set(), approval_actions=set(),
        )
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if not isinstance(tool, Tool):
            raise TypeError("registered item must be a Tool")
        if not isinstance(tool.name, str) or not tool.name.strip() or len(tool.name) > 128:
            raise ValueError("tool name must be non-empty and bounded")
        if not isinstance(tool.description, str) or len(tool.description) > 4096:
            raise ValueError("tool description must be bounded text")
        if tool.risk not in {"read", "write", "system", "external"}:
            raise ValueError("tool risk must be read, write, system, or external")
        if not callable(tool.handler):
            raise TypeError("tool handler must be callable")
        if not isinstance(tool.parameters, dict):
            raise TypeError("tool parameters must be a schema dictionary")
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")
        schema = copy.deepcopy(tool.parameters)
        if schema.get("type") != "object":
            raise ValueError("Tool argument schemas must have an object root.")
        _validate_schema_definition(schema)
        # Store an independent schema snapshot; caller mutation cannot alter dispatch.
        registered = Tool(tool.name, tool.description, tool.risk, tool.handler, schema)
        action = f"tool:{registered.name}"
        if self._default_action_policy:
            read_actions = set(self.action_policy.allowed_read_actions)
            approval_actions = set(self.action_policy.approval_actions)
            if registered.risk == "read":
                read_actions.add(action)
            else:
                approval_actions.add(action)
            self.action_policy = ActionPolicy(
                allowed_read_actions=read_actions,
                approval_actions=approval_actions,
                emergency_actions=self.action_policy.emergency_actions,
            )
        self._tools[registered.name] = registered

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
                "parameters": copy.deepcopy(tool.parameters),
                "strict": True,
            }
            for tool in self._tools.values()
        ]

    def execute(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        if name not in self._tools:
            raise KeyError(f"Tool is not allow-listed: {name}")
        tool = self._tools[name]
        try:
            args = _snapshot_tool_arguments(arguments)
            _validate_schema(args, tool.parameters)
            action = f"tool:{tool.name}"
            decision = self.action_policy.evaluate(action)
            if not decision.allowed and not decision.requires_approval:
                raise PermissionError(decision.reason)
            # The explicit approval callback remains a second gate for
            # write/system/external tools; an LLM cannot set this approval flag.
            if decision.requires_approval:
                if tool.risk == "read":
                    raise PermissionError("Central policy requires approval for a read action; it is denied.")
                self.policy.authorize(name, copy.deepcopy(args), risk=tool.risk)
                decision = self.action_policy.evaluate(action, approval_granted=True)
            else:
                self.policy.authorize(name, copy.deepcopy(args), risk=tool.risk)
            if not decision.allowed:
                raise PermissionError(decision.reason)
            result = tool.handler(**args)
            self.audit.record(name, tool.risk, "success", f"Completed; action={action}; policy={decision.reason}")
            return result
        except ApprovalRequired as exc:
            self.audit.record(name, tool.risk, "denied", str(exc))
            raise
        except PermissionError as exc:
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
        "inspect_windows_persistence",
        "Read-only inventory of selected Windows Run keys, scheduled task actions, and services with explainable persistence heuristics. Findings are not proof of malware.",
        "read",
        inspect_windows_persistence,
        _object({}, []),
    ))
    registry.register(Tool(
        "scan_workspace_with_defender",
        "Run an explicitly approved Microsoft Defender custom scan on a file or subfolder inside the configured GODMAN workspace. May take up to 30 minutes; does not guarantee remediation.",
        "system",
        lambda relative_path: scan_with_microsoft_defender(workspace, relative_path),
        _object({"relative_path": {"type": "string", "description": "Existing file or subfolder relative to the configured GODMAN workspace"}}, ["relative_path"]),
    ))
    return registry
