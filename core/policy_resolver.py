"""
Central policy resolver for Checkpoint.

Takes a base tier (from the classifier) plus provenance, anomaly, and
hard-deny signals, and produces a deterministic effective tier with a full
audit trail of every escalation reason.

Design doc rules:
- Independent qualified signals may RAISE the tier, never lower it.
- Correlated evidence is deduplicated.
- Result is capped at CRITICAL.
- CRITICAL is an approval policy, NOT a classifier label.
- Hard-deny conditions CANNOT be overridden by typed YES.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import List, Optional, Set

from core.event_types import (
    RiskTier, HardDenyReason, ProvenanceSignal, AnomalySignal, ClassifierResult
)


TIER_ORDER = {
    RiskTier.LOW:      0,
    RiskTier.MEDIUM:   1,
    RiskTier.HIGH:     2,
    RiskTier.CRITICAL: 3,
    RiskTier.UNKNOWN:  2,   # treat unknown as HIGH-equivalent for ordering
}


@dataclass
class PolicyResolution:
    effective_tier:   RiskTier
    base_tier:        RiskTier
    escalation_reasons: List[str] = field(default_factory=list)
    hard_deny_reasons:  List[HardDenyReason] = field(default_factory=list)
    is_hard_deny:     bool = False
    requires_typed_confirmation: bool = False
    policy_version:   str  = "1"
    resolution_hash:  str  = ""  # filled in by resolve()

    @property
    def is_approvable(self) -> bool:
        """Hard-deny conditions are never approvable."""
        return not self.is_hard_deny


def _tier_max(a: RiskTier, b: RiskTier) -> RiskTier:
    if TIER_ORDER.get(a, 2) >= TIER_ORDER.get(b, 2):
        return a
    return b


# ---------------------------------------------------------------------------
# Checkpoint-protected paths — tampering with these is always hard-denied
# ---------------------------------------------------------------------------

_CHECKPOINT_PATH_MARKERS = [
    "checkpoint.db", "checkpoint-storage", ".checkpoint",
    "blob_store", "shadow_copies", "checkpoint_hook",
    "checkpoint_journal",
]


def _touches_checkpoint_storage(command: Optional[str], file_path: Optional[str]) -> bool:
    """Return True when the action seems to target Checkpoint's own files."""
    targets = []
    if command:
        targets.append(command.lower())
    if file_path:
        targets.append(file_path.lower())
    for t in targets:
        for marker in _CHECKPOINT_PATH_MARKERS:
            if marker in t:
                return True
    return False


import re

_CRITICAL_PATTERNS = [
    (re.compile(r'\b(sudo|gsudo|runas|su)\b', re.IGNORECASE), "Privilege elevation detected"),
    (re.compile(r'\b(curl|wget)\b[^|;&\n]*\|\s*(bash|sh|zsh|python|perl)\b', re.IGNORECASE), "Download and execute pipeline detected"),
    (re.compile(r'\b(mkfs|fdisk|diskpart|format)\b', re.IGNORECASE), "Destructive disk or volume operation detected"),
    (re.compile(r'\b(rm|del|remove-item)\b[^|;&\n]*\.git\b', re.IGNORECASE), "Destructive removal of repository .git directory"),
    (re.compile(r'\bgit\s+push\b[^|;&\n]*(-f|--force|\+)[^|;&\n]*(main|master|prod|production)\b', re.IGNORECASE), "Force-pushing to protected remote branch"),
]


def _is_unbounded_destructive(command: Optional[str]) -> bool:
    """
    Detect commands whose destructive scope cannot be bounded, e.g.:
      rm -rf /   dd if=/dev/zero of=/dev/sda   find / -delete
    """
    if not command:
        return False
    c = command.strip().lower()
    unbounded_patterns = [
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "dd if=/dev/zero of=/dev/sd",
        "dd if=/dev/urandom of=/dev/sd",
        "mkfs.",
        "> /dev/sda",
        "find / -delete",
        "find / -exec rm",
        ":(){ :|:& };:",   # fork bomb
        "sudo rm -rf /",
    ]
    for p in unbounded_patterns:
        if p in c:
            return True
    return False


# ---------------------------------------------------------------------------
# Main resolver
# ---------------------------------------------------------------------------

def resolve(
    classifier_result: ClassifierResult,
    command: Optional[str] = None,
    file_path: Optional[str] = None,
    provenance: Optional[ProvenanceSignal] = None,
    anomaly: Optional[AnomalySignal] = None,
    backup_failed: bool = False,
    journal_failed: bool = False,
    unsupported_environment: bool = False,
) -> PolicyResolution:
    """
    Deterministically compute the effective tier and collect all reasons.

    The caller (pipeline.evaluate) passes the results of the classifier,
    provenance tracker, and anomaly detector.  This function never executes
    any command.
    """
    base_tier = classifier_result.base_tier
    effective  = base_tier
    reasons: List[str] = []
    hard_denies: Set[HardDenyReason] = set()
    seen_reasons: Set[str] = set()   # deduplication

    def add_reason(r: str, escalate_to: Optional[RiskTier] = None):
        nonlocal effective
        if r not in seen_reasons:
            seen_reasons.add(r)
            reasons.append(r)
        if escalate_to:
            effective = _tier_max(effective, escalate_to)

    # --- Hard-deny checks (order matters: check these first) ---

    if journal_failed:
        hard_denies.add(HardDenyReason.JOURNAL_WRITE_FAILURE)
        add_reason("Journal write failed; action cannot be recorded")

    if unsupported_environment:
        hard_denies.add(HardDenyReason.UNSUPPORTED_ENVIRONMENT)
        add_reason("Unsupported environment (PowerShell, cmd, WSL, nested shell)")

    if backup_failed:
        hard_denies.add(HardDenyReason.BACKUP_FAILURE)
        add_reason("Required backup failed; blocking action per v1 policy")

    if _touches_checkpoint_storage(command, file_path):
        hard_denies.add(HardDenyReason.TAMPER_CHECKPOINT)
        add_reason("Action targets Checkpoint's own enforcement or storage")

    if _is_unbounded_destructive(command):
        hard_denies.add(HardDenyReason.UNBOUNDED_DESTRUCTIVE)
        add_reason("Command scope is unbounded or unresolvable (e.g. rm -rf /)")

    # --- CRITICAL policy checks ---
    if command:
        for pat, desc in _CRITICAL_PATTERNS:
            if pat.search(command):
                add_reason(desc, escalate_to=RiskTier.CRITICAL)

    # --- Provenance escalation ---
    if provenance and provenance.has_untrusted_input:
        for src in provenance.sources:
            add_reason(
                f"Untrusted input observed in context: {src}",
                escalate_to=_tier_max(effective, RiskTier.HIGH)
                if effective < RiskTier.HIGH else None,
            )
        # Only escalate once from provenance (correlated dedup)
        if effective < RiskTier.HIGH:
            effective = RiskTier.HIGH

    # --- Anomaly escalation ---
    if anomaly and anomaly.triggered:
        add_reason(
            f"Anomaly detected ({anomaly.kind}): {anomaly.detail}",
            escalate_to=RiskTier.CRITICAL if effective >= RiskTier.HIGH else RiskTier.HIGH,
        )

    # --- Confidence / coverage escalation ---
    if classifier_result.parser_coverage in ("unsupported", "unknown"):
        add_reason(
            f"Parser coverage is {classifier_result.parser_coverage}; "
            "treating as at least MEDIUM",
            escalate_to=RiskTier.MEDIUM,
        )

    if classifier_result.source == "ml_low_confidence":
        add_reason(
            "Model low-confidence; conservative MEDIUM applied",
            escalate_to=RiskTier.MEDIUM,
        )

    # --- Cap at CRITICAL ---
    if TIER_ORDER.get(effective, 0) > TIER_ORDER[RiskTier.CRITICAL]:
        effective = RiskTier.CRITICAL

    is_hard_deny = bool(hard_denies)
    # Hard-deny always at least HIGH for display purposes
    if is_hard_deny:
        effective = _tier_max(effective, RiskTier.HIGH)

    result = PolicyResolution(
        effective_tier=effective,
        base_tier=base_tier,
        escalation_reasons=reasons,
        hard_deny_reasons=list(hard_denies),
        is_hard_deny=is_hard_deny,
        requires_typed_confirmation=(effective == RiskTier.CRITICAL),
    )

    # Deterministic hash of this resolution (bound to approvals)
    blob = json.dumps({
        "base":    base_tier.value,
        "eff":     effective.value,
        "reasons": sorted(reasons),
        "denies":  sorted(h.value for h in hard_denies),
    }, sort_keys=True)
    result.resolution_hash = hashlib.sha256(blob.encode()).hexdigest()[:16]

    return result
