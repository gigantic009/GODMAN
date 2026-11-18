# Windows Firewall milestone 1: inventory and baseline plan

## Scope

This milestone is limited to the owner's Windows endpoint. It does not configure
the home router, Wi-Fi, other computers, or network-wide traffic.

## Implemented

- `inspect_windows_firewall` runs fixed, non-interactive PowerShell queries with
  `shell=False` and a bounded timeout.
- Reads Domain, Private, and Public profile state from the active policy store.
- Reads at most 500 enabled inbound allow rules and records whether the result was
  truncated.
- Reports disabled profiles and a non-blocking default inbound action as findings.
- Produces a conservative proposed baseline: firewall enabled, inbound default
  Block, outbound default Allow, preserve existing rules, and enable dropped-packet
  logging for review.
- `/firewall` displays the inventory and proposed baseline. It makes no changes.

## Not yet implemented

- No firewall setting is changed and no firewall rule is created or deleted.
- No continuous change monitoring, event collection, temporary block engine, or
  automatic containment exists yet.
- The tool does not decide whether every existing allow rule is safe.
- Group Policy, MDM, third-party endpoint products, and Windows edition can affect
  effective policy and available controls.

## Next enforcement milestone

Before any write operation is introduced:

1. Build an owner-identity bootstrap bound to the Windows account SID and require
   local interactive confirmation for privileged actions.
2. Capture and verify a firewall policy backup before every change.
3. Preview exact profile/rule deltas and preserve existing application/service rules.
4. Reject changes that can disable local owner access or weaken Domain policy.
5. Require a fresh, explicit owner approval for each persistent policy change.
6. Apply one bounded change at a time, read back effective policy, and verify it.
7. Restore the backup automatically if verification fails; provide a documented
   manual recovery path.
8. Add Windows integration tests on a disposable VM before enabling the feature.

## Sole-owner security model

The intended root authority is the human owner. GODMAN is a subordinate defensive
operator, not a root principal. It must not grant itself permissions, add another
owner, create hidden accounts or listeners, change its own trust policy, or use the
endpoint to access other computers. This policy text is not itself a technical
tamper-proof control: Windows administrator compromise, physical access, or control
of the GitHub account can still alter software. Technical owner binding, signed
releases, protected configuration, audit protection, and recovery controls remain
required engineering work.

## Safety notes

A default-deny inbound policy is a sensible starting point for many personal Windows
endpoints, but blindly applying it can break development tools, remote support,
file sharing, VPNs, games, or managed-device policy. Default outbound Block is not
proposed: it can disrupt Windows updates, DNS, browsers, and applications and needs
a separately engineered allow-list. Never turn off Microsoft Defender or Windows
Firewall as part of GODMAN's setup.
