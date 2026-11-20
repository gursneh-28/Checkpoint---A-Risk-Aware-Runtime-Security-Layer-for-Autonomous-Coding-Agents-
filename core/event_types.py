"""
Event, Decision, and lifecycle state types for Checkpoint.

These are the shared data contracts between the hook client, the service,
the pipeline, the classifier, and the dashboard.  Nothing in this file
executes any command.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class RiskTier(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN  = "UNKNOWN"   # coverage gap — never shown as safe


class ActionState(str, Enum):
    RECEIVED             = "received"
    CLASSIFIED           = "classified"
    PENDING              = "pending"
    APPROVED             = "approved"
    BACKING_UP           = "backing_up"
    BACKUP_VERIFIED      = "backup_verified"
    EXECUTION_AUTHORIZED = "execution_authorized"
    EXECUTED             = "executed"
    FAILED               = "failed"
    REJECTED             = "rejected"
    STALE                = "stale"
    OUTCOME_UNKNOWN      = "outcome_unknown"


class DecisionKind(str, Enum):
    ALLOW   = "allow"
    DENY    = "deny"
    REWRITE = "rewrite"


class ToolKind(str, Enum):
    BASH  = "Bash"
    READ  = "Read"
    EDIT  = "Edit"
    WRITE = "Write"
    OTHER = "Other"


# ---------------------------------------------------------------------------
# Event — what the agent wants to do
# ---------------------------------------------------------------------------

@dataclass
class Event:
    """Everything Checkpoint needs to evaluate one tool use."""

    # Identifiers
    session_id:    str
    tool_use_id:   str          # Claude Code's tool_use_id — idempotency key
    tool_name:     str          # e.g. "Bash", "Read", "Write"
    tool_kind:     ToolKind = ToolKind.OTHER

    # Payload (redacted where needed; full content never stored by default)
    command:       Optional[str] = None   # for Bash
    file_path:     Optional[str] = None   # for Read/Write/Edit
    content_hash:  Optional[str] = None   # SHA-256 of raw content if relevant

    # Context
    cwd:           str = ""
    prompt_id:     str = ""
    agent_id:      str = ""
    timestamp:     float = field(default_factory=time.time)

    # Version pins — recorded so a stale approval can be detected
    shell_profile_hash: str = ""
    policy_version:     str = "0"
    parser_version:     str = "0"

    def compute_input_hash(self) -> str:
        """Stable hash over the fields that an approval is bound to."""
        blob = json.dumps({
            "tool_name":    self.tool_name,
            "command":      self.command,
            "file_path":    self.file_path,
            "content_hash": self.content_hash,
            "cwd":          self.cwd,
            "shell_profile_hash": self.shell_profile_hash,
        }, sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["tool_kind"] = self.tool_kind.value
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Event":
        d = dict(d)
        d["tool_kind"] = ToolKind(d.get("tool_kind", "Other"))
        return Event(**{k: v for k, v in d.items() if k in Event.__dataclass_fields__})


# ---------------------------------------------------------------------------
# ClassifierResult — output of the risk classifier
# ---------------------------------------------------------------------------

@dataclass
class ClassifierResult:
    base_tier:       RiskTier
    source:          str        # "rule", "ml", "ml_low_confidence", "default"
    confidence:      float = 1.0
    parser_coverage: str = "full"   # "full", "partial", "unsupported", "unknown"
    rule_name:       Optional[str] = None
    model_version:   str = "0"
    rule_version:    str = "0"


# ---------------------------------------------------------------------------
# ProvenanceSignal — was untrusted content in scope?
# ---------------------------------------------------------------------------

@dataclass
class ProvenanceSignal:
    has_untrusted_input: bool = False
    sources:             List[str] = field(default_factory=list)
    escalation_reason:   str = ""


# ---------------------------------------------------------------------------
# AnomalySignal — did the pattern look suspicious?
# ---------------------------------------------------------------------------

@dataclass
class AnomalySignal:
    triggered:        bool = False
    kind:             str = ""   # "burst", "repeated_rejection", "out_of_scope", "unusual_time"
    detail:           str = ""
    escalation_reason: str = ""


# ---------------------------------------------------------------------------
# Decision — what Checkpoint tells the hook to do
# ---------------------------------------------------------------------------

@dataclass
class Decision:
    kind:            DecisionKind
    reason:          str
    action_id:       int = 0
    base_tier:       RiskTier = RiskTier.UNKNOWN
    effective_tier:  RiskTier = RiskTier.UNKNOWN
    alternative:     Optional[Dict[str, Any]] = None   # safer option chosen
    approval_token:  Optional[str] = None
    expiry:          Optional[float] = None             # epoch seconds

    def to_hook_reply(self) -> Dict[str, Any]:
        """Serialise to the hookSpecificOutput dict Claude Code expects."""
        if self.kind == DecisionKind.ALLOW:
            return {"permissionDecision": "allow",
                    "reason": self.reason}
        if self.kind == DecisionKind.REWRITE and self.alternative:
            # updatedInput replaces the FULL tool-input object
            return {"permissionDecision": "allow",
                    "updatedInput": self.alternative.get("updated_input", {}),
                    "reason": self.reason}
        return {"permissionDecision": "deny",
                "reason": self.reason}


# ---------------------------------------------------------------------------
# HardDenyReason — conditions that can NEVER be overridden by typed YES
# ---------------------------------------------------------------------------

class HardDenyReason(str, Enum):
    UNBOUNDED_DESTRUCTIVE   = "unbounded_destructive_scope"
    UNSUPPORTED_DESTRUCTIVE = "unsupported_destructive_effects"
    TAMPER_CHECKPOINT       = "tamper_with_checkpoint_enforcement"
    BACKUP_FAILURE          = "required_backup_failure"
    JOURNAL_WRITE_FAILURE   = "journal_write_failure"
    UNSUPPORTED_ENVIRONMENT = "unsupported_environment"
