# GODMAN Architecture

## Core request lifecycle

1. The user sends text or a push-to-talk voice utterance.
2. The CLI passes input to `AssistantCore`.
3. The assistant attaches bounded conversation context and recent saved notes.
4. The cloud model responds or requests a registered function.
5. The tool registry validates the tool name and strict JSON schema.
6. The security policy allows read-only operations or requests explicit approval for write/system actions.
7. The tool runs with constrained inputs; its outcome is returned to the model.
8. The assistant returns a final answer and stores the conversation locally.

## Trust boundaries

- Model output is untrusted. It can request only tools registered in `tools.py`.
- No general-purpose shell, PowerShell, CMD, Python-eval, or arbitrary subprocess tool is exposed.
- File tools resolve paths and reject traversal outside `GODMAN_WORKSPACE`.
- The initial write tool creates new files only and refuses overwrites.
- App launch accepts a fixed enum, not an executable path or command string.
- Writes and system actions pause for exact user approval.
- Tool outcomes are stored in `GODMAN_DATA_DIR/audit.sqlite3`.

## Local state

SQLite stores user-created notes, bounded conversation history, and tool audit events. The initial memory search is keyword-based. Embedding/semantic retrieval is a future enhancement; no claim of semantic memory is made.

## Voice

Voice is an optional I/O adapter, not a separate agent. It records a short utterance on user request, transcribes it locally with faster-whisper, calls the same `AssistantCore`, and speaks the response with pyttsx3. Always-on wake-word detection and interruption handling are not included yet.

## Extension rules

New tools must have a narrow purpose, strict JSON schema, declared risk class, validated inputs, no secret logging, and unit tests for success, invalid input, and denial paths.
