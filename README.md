# GODMAN — Personal AI Assistant

A modular hybrid personal AI assistant for Windows, built with Python.

## Vision
GODMAN combines cloud AI intelligence with controlled local computer capabilities, voice interaction, memory, and a desktop interface.

## Architecture
```text
User (voice / text)
       |
Interface (CLI -> desktop UI)
       |
Agent orchestrator
       |
Cloud AI / optional local model
       |
Task planner + tool registry
       |
Security gateway (permissions, approvals, limits)
       |
Windows / files / browser / applications
       |
Audit log + persistent memory
```

The model never receives unrestricted shell access. Computer actions are exposed through explicit tools with allow-lists, validation, logging, timeouts, and confirmation gates for sensitive operations.

## Phase 1 — Conversational Core
This milestone is intentionally text-only. It connects to the OpenAI Responses API and maintains a bounded conversation history for the current session. It does not execute commands or access local files.

### Requirements
- Python 3.10+
- OpenAI API key (API billing is separate from ChatGPT subscription)
- Internet connection

### Windows setup (PowerShell)
```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
python run.py
```

### Run offline unit tests
```powershell
python -m unittest discover -s tests -v
```

### WSL / Ubuntu setup
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
nano .env
python run.py
```

Run offline unit tests with `python -m unittest discover -s tests -v`.

Set `OPENAI_API_KEY` in `.env`. Set `OPENAI_MODEL` to a model available to your API account. Never commit `.env` or share your API key.

## Project structure
```text
GODMAN/
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
├── run.py
└── src/
    └── jarvis/
        ├── __init__.py
        ├── config.py
        ├── core.py
        └── cli.py
```

## Roadmap
1. **Phase 1:** Text assistant, API configuration, bounded session history, error handling, offline unit tests.
2. **Phase 2:** Read-only Windows diagnostics and approved file search.
3. **Phase 3:** Explicit local tools, permission gateway, confirmations, audit logs.
4. **Phase 4:** Speech-to-text, text-to-speech, optional wake word.
5. **Phase 5:** Persistent memory and project context.
6. **Phase 6:** Desktop UI, screen understanding, browser workflows.
7. **Phase 7:** Optional local-model fallback and carefully scoped proactive automations.

## Security principles
- Start with least privilege.
- No unrestricted unattended shell execution.
- Require confirmation for deletion, installation, privilege changes, external communication, and other high-impact operations.
- Validate tool inputs and constrain file paths.
- Log tool calls and outcomes without logging secrets.
- Keep credentials in environment variables; rotate exposed keys.

## License
To be selected by the repository owner.
