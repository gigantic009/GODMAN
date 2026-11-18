# GODMAN Development Roadmap

## Phase 1 — Conversational foundation
- [x] Python project structure and configuration
- [x] OpenAI Responses API chat
- [x] Bounded session context and input validation
- [x] API error handling

## Phase 2 — Local awareness
- [x] Read-only operating-system diagnostics
- [x] Disk capacity reporting
- [x] Workspace-scoped file listing and reading
- [x] Path traversal and file-size limits

## Phase 3 — Controlled actions
- [x] Explicit tool registry and strict JSON schemas
- [x] Model function-calling loop
- [x] Risk classification and interactive approval
- [x] Workspace file creation without overwrite
- [x] Allow-listed application launcher
- [x] SQLite audit log and audit inspection command
- [ ] Broader app/browser automation (deferred until dedicated review)

## Phase 4 — Voice interface
- [x] Optional push-to-talk audio capture
- [x] Local faster-whisper transcription
- [x] Local text-to-speech
- [ ] Wake-word detection and interruption handling
- [ ] Desktop voice activity indicator

## Phase 5 — Persistent memory
- [x] SQLite notes with category and timestamp
- [x] Keyword search and explicit deletion
- [x] Persistent conversation history
- [x] Recent saved notes injected as untrusted context
- [x] Model-accessible memory search/save/delete tools with approval on writes
- [ ] Semantic/embedding retrieval (future enhancement)

## Verification
- [x] Offline unit tests authored for core, memory, and tools
- [x] GitHub Actions workflow added for compile checks and unit tests
- [ ] Confirm CI run passes on GitHub
- [ ] Run and verify on the owner's Windows laptop

## Next
Phase 6 should add a desktop UI and screen understanding only after the Windows installation and Phase 1–5 tests are verified.

## Cybersecurity Division foundation (added after Phase 5)
- [x] Broad cybersecurity domain map and analyst response policy
- [x] Authorization-first defensive security guidance
- [x] Workspace-bounded log triage with explainable heuristic findings
- [x] Candidate IOC extraction without external lookups
- [x] Local SHA-256 hashing without file execution or upload
- [x] Cybersecurity reference stack documented
- [x] Offline tests authored for IOC parsing, log triage, path safety, and hashing
- [ ] Execute and verify all tests on Windows and GitHub Actions
- [ ] Add current CVE/advisory retrieval with source/date/confidence
- [ ] Add YARA-based static scanning in an isolated workflow
- [ ] Add Sigma rule parsing and test fixtures
- [ ] Add opt-in Wazuh integration
- [ ] Add OWASP ZAP integration with explicit target allow-lists and safe scan profiles
- [ ] Add network telemetry ingestion and packet analysis
- [ ] Add forensics workflows with evidence integrity and chain-of-custody records
