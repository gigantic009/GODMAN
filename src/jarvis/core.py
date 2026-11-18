"""Conversational core. No computer-control tools are available in Phase 1."""
from openai import OpenAI

SYSTEM_INSTRUCTIONS = """
You are a helpful personal AI assistant running as a local application.
Be clear, practical, and honest about your capabilities.
This is Phase 1: text conversation only.
You cannot inspect or control the computer, run commands, access files, or perform actions.
Never claim that you completed an action on the user's computer.
When a request requires computer access, explain that this version cannot do it yet.
Prefer safe, step-by-step guidance.
"""

class AssistantCore:
    def __init__(self, api_key: str, model: str, assistant_name: str):
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.assistant_name = assistant_name
        self.history: list[dict[str, str]] = []

    def respond(self, user_text: str) -> str:
        self.history.append({"role": "user", "content": user_text})
        recent_history = self.history[-20:]
        response = self.client.responses.create(
            model=self.model,
            instructions=SYSTEM_INSTRUCTIONS,
            input=recent_history,
        )
        answer = (response.output_text or "").strip()
        if not answer:
            answer = "I didn't receive a text response. Please try again."
        self.history.append({"role": "assistant", "content": answer})
        self.history = self.history[-20:]
        return answer
