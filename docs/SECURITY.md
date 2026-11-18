# GODMAN Security Model

## Current protections

- No unrestricted command execution.
- Local file access is restricted to the configured workspace.
- Workspace paths are resolved before access; path traversal is rejected.
- File creation refuses to overwrite existing files.
- App launching is an enum allow-list (Notepad, Calculator, Paint, VS Code).
- Write/system actions require explicit interactive approval.
- Audit records contain tool name, risk, outcome, timestamp, and a short non-secret detail.
- API credentials are read from `.env`, which is ignored by Git.
- Retrieved file contents and model/tool outputs are treated as untrusted data.

## Approval semantics

For a write or system action, GODMAN displays the requested tool and arguments. The user must type exactly `YES`. Any other answer denies the operation. Do not approve an action you do not understand.

## Current limitations

This is an early personal project, not a hardened security product. The user runs GODMAN under their own Windows account, so Python process permissions still matter. Do not run the application as Administrator. Do not expose its local data directory to untrusted users. Do not add broad shell, credential, browser-profile, or remote-control access without a separate threat review.

## Incident response

1. Stop GODMAN.
2. Inspect the audit database.
3. Review the tool registry and recent changes.
4. Rotate any API key that may have been exposed.
5. Remove suspicious files from the configured workspace.
