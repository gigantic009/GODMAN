"""Interactive terminal interface for GODMAN Phases 1-5."""
import json
import os
from pathlib import Path

from openai import APIConnectionError, APIStatusError, AuthenticationError, RateLimitError

from .config import get_settings
from .core import AssistantCore
from .diagnostics import collect_diagnostics
from .memory import MemoryStore
from .security import ApprovalRequired, SecurityPolicy
from .tools import Tool, build_default_registry
from .cybersecurity import SECURITY_DOMAINS


def _print_help() -> None:
    print("""
Commands:
  /help                 Show this help
  /diagnostics          Read basic system and disk information
  /cyber                Show GODMAN cybersecurity specialization areas
  /posture              Read Windows security posture (no changes)
  /markets              Explain available market analytics
  /tools                List local tools and their risk level
  /audit                Show recent local tool audit events
  /tool NAME [JSON]     Run an allow-listed tool manually
  /remember TEXT        Save a durable note in local SQLite memory
  /recall WORDS         Search saved memories
  /memories             Show recent saved memories
  /forget ID            Delete one saved memory
  /voice                Start push-to-talk voice mode (optional dependencies)
  /exit                 Quit GODMAN

Normal messages go to the AI. The AI can request registered tools.
Writes and application launches require explicit approval.
""")


def _run_voice(assistant: AssistantCore) -> None:
    from .voice import VoiceInterface, VoiceUnavailable
    try:
        voice = VoiceInterface()
    except VoiceUnavailable as exc:
        print(str(exc))
        return
    print("Voice mode: press Enter to record; type 'q' then Enter to stop.")
    while True:
        try:
            if input("Voice> ").strip().lower() == "q":
                break
            text = voice.listen_once()
            if not text:
                print("No speech detected.")
                continue
            print(f"You said: {text}")
            answer = assistant.respond(text)
            print(f"GODMAN: {answer}")
            voice.speak(answer)
        except KeyboardInterrupt:
            break


def main() -> None:
    settings = get_settings()
    if not settings.api_key or settings.api_key == "put_your_api_key_here":
        print("Setup needed: add OPENAI_API_KEY to your .env file.")
        print("Create a key at https://platform.openai.com/api-keys")
        return

    data_dir = Path(os.getenv("GODMAN_DATA_DIR", ".godman")).expanduser()
    workspace = Path(os.getenv("GODMAN_WORKSPACE", "workspace")).expanduser()
    workspace.mkdir(parents=True, exist_ok=True)
    memory = MemoryStore(data_dir / "memory.sqlite3")
    registry = build_default_registry(data_dir, workspace, SecurityPolicy())
    registry.register(Tool(
        "remember_note",
        "Save a durable user-approved note to GODMAN's local memory.",
        "write",
        lambda content: {"memory_id": memory.remember(content)},
        {"type": "object", "properties": {"content": {"type": "string"}},
         "required": ["content"], "additionalProperties": False},
    ))
    registry.register(Tool(
        "search_memories",
        "Search GODMAN's saved local notes by keyword.",
        "read",
        lambda query: memory.search(query),
        {"type": "object", "properties": {"query": {"type": "string"}},
         "required": ["query"], "additionalProperties": False},
    ))
    registry.register(Tool(
        "forget_memory",
        "Delete a saved memory by its numeric ID. Requires approval.",
        "write",
        lambda memory_id: {"deleted": memory.forget(memory_id)},
        {"type": "object", "properties": {"memory_id": {"type": "integer"}},
         "required": ["memory_id"], "additionalProperties": False},
    ))
    assistant = AssistantCore(
        api_key=settings.api_key, model=settings.model,
        assistant_name=settings.assistant_name, memory=memory,
        tool_registry=registry,
    )

    print(f"\n{settings.assistant_name} — Personal AI + Cybersecurity Division")
    print(f"Persistent data: {data_dir.resolve()}")
    print(f"Tool workspace: {workspace.resolve()}")
    print("Type /help for commands or /exit to quit.\n")

    while True:
        try:
            raw = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{settings.assistant_name}: Goodbye.")
            break
        if not raw:
            continue
        if raw.lower() in {"/exit", "exit", "quit"}:
            print(f"{settings.assistant_name}: Goodbye.")
            break
        if raw == "/help":
            _print_help()
            continue
        if raw == "/diagnostics":
            print(json.dumps(collect_diagnostics(), indent=2))
            continue
        if raw == "/cyber":
            print("GODMAN Cybersecurity Division")
            for domain, description in SECURITY_DOMAINS.items():
                print(f"- {domain.replace('_', ' ').title()}: {description}")
            print("\nAvailable local tools: analyze_security_log, inspect_file_static, sha256_workspace_file, collect_windows_security_posture, inspect_zip_safety")
            print("Testing policy: authorized assets and isolated labs only.")
            continue
        if raw == "/posture":
            try:
                print(json.dumps(registry.execute("collect_windows_security_posture"), indent=2, ensure_ascii=False))
            except Exception as exc:
                print(f"Posture check unavailable: {type(exc).__name__}: {exc}")
            continue
        if raw == "/markets":
            print("GODMAN Market Intelligence")
            print("Available model tool: analyze_market_prices (50+ chronological closes required)")
            print("Calculates moving averages, RSI, volatility, drawdown, and threshold-based price events.")
            print("No live market feed or trade execution is connected.")
            continue
        if raw == "/tools":
            print(json.dumps(registry.describe(), indent=2))
            continue
        if raw == "/audit":
            print(json.dumps(registry.audit.recent(20), indent=2, ensure_ascii=False))
            continue
        if raw.startswith("/tool "):
            parts = raw.split(" ", 2)
            try:
                args = json.loads(parts[2]) if len(parts) > 2 else {}
                if not isinstance(args, dict):
                    raise ValueError("Arguments must be a JSON object.")
                print(json.dumps(registry.execute(parts[1], args), indent=2, default=str))
            except ApprovalRequired as exc:
                print(f"Not approved: {exc}")
            except Exception as exc:
                print(f"Tool error: {type(exc).__name__}: {exc}")
            continue
        if raw.startswith("/remember "):
            try:
                print(f"Saved memory #{memory.remember(raw[len('/remember '):])}.")
            except ValueError as exc:
                print(str(exc))
            continue
        if raw.startswith("/recall "):
            print(json.dumps(memory.search(raw[len("/recall "):]), indent=2, ensure_ascii=False))
            continue
        if raw == "/memories":
            print(json.dumps(memory.recent(), indent=2, ensure_ascii=False))
            continue
        if raw.startswith("/forget "):
            try:
                memory_id = int(raw.split(maxsplit=1)[1])
                print("Memory deleted." if memory.forget(memory_id) else "Memory not found.")
            except (ValueError, IndexError):
                print("Usage: /forget ID")
            continue
        if raw == "/voice":
            _run_voice(assistant)
            continue
        if raw.startswith("/"):
            print("Unknown command. Type /help.")
            continue

        try:
            print(f"\n{settings.assistant_name}: {assistant.respond(raw)}\n")
        except ValueError as exc:
            print(f"{settings.assistant_name}: {exc}")
        except AuthenticationError:
            print("Authentication failed. Check OPENAI_API_KEY in .env.")
        except RateLimitError:
            print("API rate limit or quota reached. Check your API account.")
        except APIConnectionError:
            print("Connection failed. Check your internet connection.")
        except APIStatusError as exc:
            print(f"API error ({exc.status_code}). Check model name and API access.")
        except Exception as exc:
            print(f"Unexpected error: {type(exc).__name__}. Check configuration and retry.")
