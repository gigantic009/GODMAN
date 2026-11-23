# Contributing to GODMAN

Thank you for helping make GODMAN safer, more reliable, and more useful.

## Before opening a PR
1. Open or link an issue describing the problem or proposal.
2. Confirm the change fits the diagnostics and defensive cybersecurity mission.
3. Keep changes small, explain threat/impact assumptions, and avoid broad privilege.
4. Add tests for normal, boundary, failure and unsafe-input cases.
5. Update documentation and feature-status claims.

## Development
- Python 3.10+ is the project baseline.
- Run `python -m unittest discover -s tests -v` and `python -m compileall -q src run.py`.
- Keep Windows integrations mockable and bounded by time/output limits.
- Never use live third-party targets in tests; use local fixtures or authorized labs.
- Never include secrets, private logs, identifying information or real malware in public test fixtures.

## Pull requests
Describe the problem, change, risks, tests, limitations and Windows verification status. Do not claim tests passed unless they ran. Reviewers should be able to reproduce your verification.

## Security
Do not disclose vulnerabilities in public issues. Follow the private reporting instructions in SECURITY.md.
