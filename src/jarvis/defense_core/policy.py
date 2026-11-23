"""Central authorization boundary for planned defensive actions."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ActionDecision:
    allowed: bool
    requires_approval: bool
    reason: str
    action: str


class ActionPolicy:
    """Default-deny action policy. Evaluates intent, never executes actions."""

    SAFE_READ_ACTIONS = frozenset({
        "collect_telemetry", "inspect_file", "inspect_posture",
        "query_inventory", "analyze_event", "read_only_observation",
    })
    APPROVAL_ACTIONS = frozenset({
        "quarantine_file", "disable_service", "modify_firewall_rule",
        "restore_backup", "terminate_process", "write_tool", "system_tool",
        "external_tool",
    })

    def __init__(self, *, allowed_read_actions=None, approval_actions=None, emergency_actions=None):
        self.allowed_read_actions = frozenset(
            allowed_read_actions if allowed_read_actions is not None else self.SAFE_READ_ACTIONS
        )
        self.approval_actions = frozenset(
            approval_actions if approval_actions is not None else self.APPROVAL_ACTIONS
        )
        self.emergency_actions = frozenset(emergency_actions or ())
        if not all(isinstance(action, str) and action for action in
                   self.allowed_read_actions | self.approval_actions | self.emergency_actions):
            raise ValueError("action identifiers must be non-empty strings")
        if self.allowed_read_actions & self.approval_actions:
            raise ValueError("action categories must not overlap")
        if not self.emergency_actions <= self.approval_actions:
            raise ValueError("emergency actions must be approval-scoped actions")

    def evaluate(self, action: str, *, approval_granted=False, emergency_mode=False) -> ActionDecision:
        if not isinstance(approval_granted, bool) or not isinstance(emergency_mode, bool):
            return ActionDecision(False, False, "Approval and emergency flags must be booleans", str(action))
        if not isinstance(action, str) or not action or len(action) > 256:
            return ActionDecision(False, False, "Invalid action identifier", str(action))
        if action in self.allowed_read_actions:
            return ActionDecision(True, False, "Explicitly allow-listed read-only action", action)
        if action not in self.approval_actions:
            return ActionDecision(False, False, "Action is not allow-listed (default deny)", action)
        if emergency_mode and action in self.emergency_actions:
            return ActionDecision(True, False, "Narrow emergency policy permits action; execution remains separately guarded", action)
        if approval_granted:
            return ActionDecision(True, False, "Explicit approval supplied", action)
        return ActionDecision(False, True, "Explicit user approval required", action)
