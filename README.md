# GODMAN — Personal AI Assistant

A modular hybrid personal AI assistant for Windows, built with Python. GODMAN combines cloud reasoning with a local, allow-listed tool layer, optional voice I/O, and persistent SQLite memory.

## Current capabilities (Phases 1–5)
- OpenAI Responses API conversation with bounded session context.
- Function/tool calling through an explicit registry (no arbitrary shell tool).
- Read-only system and disk diagnostics.
- Workspace-scoped file listing and reading.
- Workspace file creation and allow-listed app launching, with explicit approval.
- SQLite memory for saved notes and conversation history.
- Optional push-to-talk voice: local Whisper transcription and local text-to-speech.
- SQLite audit log for tool outcomes.
- Offline unit tests and GitHub Actions CI.

## Architecture
```text
Voice / Text CLI
      |
AssistantCore (Responses API + bounded context)
      |                       |
      |                  SQLite memory
      |
Model function calls
      |
Strict Tool Registry
      |
SecurityPolicy (read / write / system approvals)
      |
Workspace-scoped files | diagnostics | allow-listed app launcher
      |
SQLite audit log
```

The model cannot run arbitrary PowerShell, CMD, Python, or shell commands. Every local capability must be explicitly registered with a JSON schema and risk level. File operations are constrained to the configured workspace. Write and system actions require the user to type exactly `YES` at the approval prompt. Tool outcomes are recorded in a local audit database.

## Cybersecurity division
GODMAN includes a defensive cybersecurity specialization covering governance, network and application security, cloud, endpoint, identity, cryptography, incident response, safe malware analysis, threat intelligence, vulnerability management, SOC operations, secure engineering, and IoT/OT security. Use `/cyber` to view the coverage map.

Current local security tools:
- `analyze_security_log` — bounded, read-only heuristic triage of supported log files in the GODMAN workspace.
- `sha256_workspace_file` — local SHA-256 hashing without execution or upload.
- `inspect_file_static` — basic file-type, hash, and entropy inspection without execution.
- `collect_windows_security_posture` — read-only Windows Defender, Firewall, BitLocker, and recent hotfix snapshot; use `/posture`.

These tools are analyst aids, not a certified scanner or proof of compromise. Remote scanning, exploitation, automatic containment, malware execution, and reputation lookups are not enabled. See [`docs/DEFENSIVE_THREAT_MODEL.md`](docs/DEFENSIVE_THREAT_MODEL.md), [`docs/OPEN_SOURCE_SECURITY_INTEGRATIONS.md`](docs/OPEN_SOURCE_SECURITY_INTEGRATIONS.md), [`docs/CYBERSECURITY.md`](docs/CYBERSECURITY.md), [`docs/CYBERSECURITY_REFERENCES.md`](docs/CYBERSECURITY_REFERENCES.md), and [`docs/SECURITY.md`](docs/SECURITY.md).

## Market intelligence division

GODMAN's initial quantitative research engine calculates SMA, EMA, RSI, MACD,
Bollinger Bands, historical volatility, maximum drawdown, and configurable price-move
events from supplied chronological price data. These are descriptive analytics—not
live quotes, predictions, or trading recommendations. Timestamped market-data feeds,
fundamentals/filings/news ingestion, backtesting, portfolio risk, and live monitoring
are planned integrations. See [docs/MARKET_INTELLIGENCE.md](docs/MARKET_INTELLIGENCE.md).

## Requirements
- Python 3.10+
- OpenAI API key (API billing is separate from ChatGPT subscription)
- Internet connection for cloud model responses

## Windows setup (PowerShell)
```powershell
git clone https://github.com/gigantic009/GODMAN.git
cd GODMAN
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
python run.py
```

Set `OPENAI_API_KEY` in `.env`. Set `OPENAI_MODEL` to a model available to your API account. Keep `.env` private; it is git-ignored.

## Optional voice setup
Voice packages are intentionally separate because audio dependencies may need device-specific setup.

```powershell
pip install -r requirements-voice.txt
python run.py
```

Then enter `/voice` inside GODMAN. It uses push-to-talk recording, local faster-whisper transcription, and pyttsx3 speech. It is not an always-listening wake-word service yet.

## Commands
- `/help` — list commands
- `/diagnostics` — read-only OS and disk overview
- `/cyber` — show cybersecurity specialization areas
- `/posture` — read selected Windows security controls without changing them
- `/tools` — list registered tools and risk levels
- `/audit` — inspect recent local tool audit events
- `/remember TEXT` — save a local note
- `/recall WORDS` — search saved notes
- `/memories` — list recent notes
- `/forget ID` — delete a note
- `/voice` — optional push-to-talk voice mode
- `/tool NAME JSON` — manually invoke a registered tool

Normal messages are sent to the model. The model may request tools from the registry. Read tools run directly; writes and app launches require approval.

## Data locations
- `.godman/memory.sqlite3` — saved notes and conversation history
- `.godman/audit.sqlite3` — tool audit events
- `workspace/` — files GODMAN is allowed to read and create

Optional environment overrides:
- `GODMAN_DATA_DIR`
- `GODMAN_WORKSPACE`

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for milestone status and verification gates.

## Tests
Run the offline test suite:

```powershell
python -m unittest discover -s tests -v
python -m compileall -q src run.py
```

GitHub Actions runs compilation and unit tests on pushes and pull requests.

## Roadmap beyond Phase 5
6. Desktop UI, screen understanding, and carefully scoped browser workflows.
7. Local model fallback, wake-word voice, and scheduled automations.

## Security principles
- No unrestricted unattended shell execution.
- Require approval for writes and system-level actions.
- Never overwrite files through the initial workspace tool.
- Resolve paths and reject workspace traversal.
- Keep secrets in environment variables; never log credentials.
- Treat retrieved file contents and tool output as untrusted data.
- Review the audit log if an action behaves unexpectedly.

## Research references
Architecture ideas were reviewed from open-source projects including [NOVA](https://github.com/vincenzo-afk/NOVA), [atuldhull/JARVIS](https://github.com/atuldhull/jarvis), [Personal Jarvis](https://github.com/tbckdev/PersonalJarvis), and [mflorgar/jarvis-agent](https://github.com/mflorgar/jarvis-agent). GODMAN uses its own implementation and deliberately starts with a narrower, auditable tool surface.

## License
To be selected by the repository owner.
