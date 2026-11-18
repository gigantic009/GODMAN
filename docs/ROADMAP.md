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
- [x] Static file metadata, magic-byte, and entropy inspection without execution
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


## GODMAN Intelligence Platform — expanded mission

### Cybersecurity operations (defensive, owner-authorized)
- [ ] Windows endpoint inventory and hardening assessment (read-only first)
- [ ] Network asset discovery and passive telemetry ingestion
- [ ] Packet capture parsing and protocol anomaly detection
- [ ] Endpoint event collection and process-tree investigation
- [ ] SIEM connector and Sigma rule validation
- [ ] YARA-X evaluation for static sample scanning in isolation
- [ ] Threat intelligence enrichment with source, timestamp, confidence, and expiry
- [ ] CVE/KEV and vendor advisory correlation against software inventory
- [ ] Incident case management, evidence hashing, timeline, and chain of custody
- [ ] Safe containment playbooks with per-action confirmation and rollback plan
- [ ] Cloud posture and identity configuration assessment
- [ ] Vulnerability scanning limited to explicitly allow-listed owned assets

### Financial research and market intelligence
- [x] Pure-Python technical indicators: SMA, EMA, RSI, MACD, Bollinger Bands
- [x] Historical volatility, drawdown, and threshold-based price event detection
- [x] Financial research policy: source, timestamp, uncertainty, risk, no fabricated live data
- [ ] Market-data provider abstraction with Indian and global exchange coverage
- [ ] Live/delayed quote and OHLCV ingestion with exchange timestamps
- [ ] Real-time watchlists, price/volume alerts, and market-session awareness
- [ ] Corporate actions, splits, dividends, and symbol mapping
- [ ] Company fundamentals, annual reports, earnings, and exchange filing ingestion
- [ ] News and event intelligence with entity resolution and source credibility
- [ ] Valuation models: DCF, comparables, multiples, scenario/sensitivity analysis
- [ ] Portfolio exposure, correlation, drawdown, VaR/expected shortfall research
- [ ] Backtesting engine with transaction costs, slippage, survivorship and look-ahead controls
- [ ] Research reports with bull/base/bear thesis, catalysts, risks, and citations
- [ ] Paper-trading simulation only; brokerage execution excluded until separately reviewed

### Platform reliability and governance
- [ ] Run complete unit suite locally and verify GitHub Actions
- [ ] Add integration tests with recorded/synthetic fixtures and no live side effects
- [ ] Add secrets redaction, retention controls, and per-tool audit provenance
- [ ] Add monitoring scheduler with opt-in scopes, rate limits, and kill switch
- [ ] Add plugin/provider health checks and stale-data alarms


## Defensive baseline milestone
- [x] Build attack-surface/threat-family catalogue (phishing, malicious files, archive bombs, resource exhaustion, ransomware, identity, network, browser, exploit, persistence, supply chain, data theft, physical, cloud, insider, availability)
- [x] Document control mapping, response priorities, limitations, and security acceptance gates
- [x] Review major open-source projects and define adapter-first integration strategy
- [x] Add read-only Windows Defender, Firewall, BitLocker, and hotfix posture snapshot
- [x] Add unit tests for posture collector behavior (mocked PowerShell; no machine changes)
- [x] Add Python 3.10–3.12 GitHub Actions test workflow
- [ ] Verify the workflow passes on GitHub
- [ ] Run posture assessment on the owner's Windows device and review each result
- [ ] Add event collection (Defender/Sysmon) with explicit privacy and retention controls
- [ ] Add safe phishing URL/file triage with reputation source provenance
- [ ] Add bounded archive-bomb/resource-exhaustion inspection
- [ ] Add YARA-X/ClamAV static scanning in an isolated, resource-limited workflow
- [ ] Add Sigma rule validation and mapped Windows event coverage
- [ ] Add passive network telemetry ingestion (Zeek/Suricata)
- [ ] Add threat-intelligence enrichment (CVE/KEV, MISP/OpenCTI)
- [ ] Add incident case/evidence chain-of-custody workflows
- [ ] Add approved remediation playbooks with dry-run, confirmation, and rollback
