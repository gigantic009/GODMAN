"""Load and validate application settings from environment variables."""
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    api_key: str
    model: str
    assistant_name: str


def get_settings() -> Settings:
    """Return settings; secrets are never printed or logged."""
    return Settings(
        api_key=os.getenv("OPENAI_API_KEY", "").strip(),
        model=os.getenv("OPENAI_MODEL", "gpt-5.5").strip(),
        assistant_name=os.getenv("ASSISTANT_NAME", "GODMAN").strip() or "GODMAN",
    )
