"""Terminal user interface for Phase 1."""
from openai import APIConnectionError, APIStatusError, AuthenticationError, RateLimitError
from .config import get_settings
from .core import AssistantCore

def main() -> None:
    settings = get_settings()
    name = settings["assistant_name"] or "GODMAN"

    if not settings["api_key"] or settings["api_key"] == "put_your_api_key_here":
        print("Setup needed: add your API key to the .env file.")
        print("Create an API key at https://platform.openai.com/api-keys")
        return

    assistant = AssistantCore(
        api_key=settings["api_key"],
        model=settings["model"],
        assistant_name=name,
    )

    print(f"\\n{name} — Phase 1")
    print("Text assistant online. Type 'exit' or 'quit' to close.\\n")

    while True:
        try:
            user_text = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\\n{name}: Goodbye.")
            break

        if not user_text:
            continue
        if user_text.lower() in {"exit", "quit"}:
            print(f"{name}: Goodbye.")
            break

        try:
            print(f"\\n{name}: {assistant.respond(user_text)}\\n")
        except AuthenticationError:
            print("\\nAuthentication failed. Check OPENAI_API_KEY in .env.\\n")
        except RateLimitError:
            print("\\nAPI rate limit or available quota reached. Check your API account.\\n")
        except APIConnectionError:
            print("\\nConnection failed. Check your internet connection.\\n")
        except APIStatusError as exc:
            print(f"\\nAPI error ({exc.status_code}). Check model name and API access.\\n")
        except Exception as exc:
            print(f"\\nUnexpected error: {type(exc).__name__}: {exc}\\n")
