# GODMAN Data Handling Notice

## Workspace file reads

GODMAN can read files inside its configured workspace and return selected file contents to the model service to answer a user request. Workspace containment is a local access boundary; it does **not** mean contents remain exclusively on the device.

- Do not place passwords, private keys, financial records, medical records, or other sensitive information in the workspace unless you intend to expose selected content to the model service.
- Use a dedicated project workspace instead of a broad home-directory or drive root.
- File-reading tools currently have size limits, but size limits are not a privacy filter.
- Audit logs should record tool names, outcomes and bounded details—not full file contents or tool arguments.

## Disk diagnostics

Disk capacity reporting is limited to the configured GODMAN workspace path rather than accepting a model-supplied arbitrary path.

## Audit logging

Audit details are centrally redacted for common credential-like patterns and email addresses. Redaction is best-effort and is not a guarantee; avoid logging sensitive data in the first place.

## Scope

This notice describes the code's intended behavior. Review the model provider's current privacy, retention and data-use terms separately.
