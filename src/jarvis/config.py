"""Load application settings from environment variables."""
import os
from dotenv import load_dotenv

load_dotenv()

def get_settings() -> dict[str, str]:
    return {
        "api_key": os.getenv("OPENAI_API_KEY", "").strip(),
        "model": os.getenv("OPENAI_MODEL", "gpt-5.5").strip(),
        "assistant_name": os.getenv("ASSISTANT_NAME", "GODMAN").strip(),
    }
