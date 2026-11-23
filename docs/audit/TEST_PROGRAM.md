# GODMAN Test Program

This program targets owner-controlled assets and GODMAN itself. Adversarial tests should use disposable workspaces, VMs or controlled fixtures.

## Teams
| Team | Scope |
|---|---|
| Application QA | Functional, negative, regression, integration |
| AppSec | Tool boundary, path handling, inputs, secrets, threat modeling |
| Windows engineering | Native integration, permissions, cmdlets, timeouts |
| Hardware engineering | CPU, RAM, disk, thermals, audio, sleep/resume |
| Performance | Startup, latency, memory growth, sustained operation |
| Reliability | API outages, disk-full, corrupt DB, interrupted writes |
| Privacy | Data minimization, disclosures, exclusion, redaction, retention |
| Release engineering | CI, dependency review, packaging, release smoke tests |

## Scope and safety
- Test GODMAN itself, local fixtures, and authorized devices only.
- No external scanning, third-party exploitation, credential attacks or destructive testing.
- Dangerous actions should use mocked handlers or disposable VM snapshots.
- Do not represent static review as a completed penetration test.

## Test matrix

### Tool registry and policy
- Unknown tool denied; non-object arguments rejected.
- Missing required keys, extra keys, wrong types, enum/range/length validation.
- Verify handler is not called when validation fails.
- Check read/write/system risk classes, approvals, declined approval and callback errors.
- Verify audit records success, error and denial.

### Workspace boundaries
- Relative, absolute, parent traversal, drive, UNC and symlink paths.
- Symlink escape/race scenarios in platform-specific fixtures.
- File vs directory vs nonexistent targets; large files and invalid encoding.
- Permission denied, existing file overwrite refusal, concurrent creates.
- Disk-full and interrupted-write simulation.

### Memory and SQLite
- Escaped LIKE queries, result bounds, empty/oversized notes, invalid IDs.
- DB locked, corrupt, read-only and unavailable.
- Conversation ordering/history bounds and retention policy.

### Assistant core
- Empty and oversized user messages.
- Invalid tool-call JSON, non-object arguments, tool errors and approval denial.
- Tool-round limit, API timeout/connection/authentication/rate-limit failures.
- Prompt injection inside files/logs/tool output; treat content as untrusted.

### Windows integrations
- Windows/non-Windows, missing PowerShell/cmdlets, denied permissions.
- Timeout, oversized output, malformed JSON.
- Defender status, firewall, event log unavailable/no events.
- Scan target containment and approval.
- Firewall snapshot truncation.

### Security utilities
- Log extension and size limits, multiline/Unicode, indicator edge cases, invalid IPv4.
- ZIP traversal, symlinks, nested archives, expansion-ratio and size bounds.
- URL parsing: IPv6, IDNA, credentials, ports, malformed/control characters.
- File type, entropy and hash correctness.


### Performance/reliability
- Startup, peak memory, sustained conversation/history growth, SQLite growth.
- API timeout recovery, disk-full and interrupted writes.
- Voice device availability, cancellation and errors.

## Physical hardware protocol
Run locally on the owner's device and record measurements, not guesses.

| Test | Measurement |
|---|---|
| Windows build | Exact version/build |
| CPU | Model, idle and GODMAN peak usage |
| RAM | Baseline, peak and sustained |
| Storage | Workspace location, free space before/after |
| Thermals | Sensor readings if available; no unsafe stress settings |
| Power | AC/battery, suspend/resume |
| Microphone | Device selection, input level and latency |
| Audio output | Device, clipping and latency |
| Network | API connectivity and timeout behavior only |
| Permissions | Standard user; separately controlled elevated context |
| Stability | 30-minute interactive run |
| Recovery | Shutdown/restart and DB recovery |

## Exit criteria
- Critical/high findings fixed or formally accepted with rationale.
- Regression tests pass.
- Windows CI passes.
- Dependency and static-quality gates pass.
- Hardware results clearly separate measurements from assumptions.
