"""
core/provenance.py — Feature 10: Persistent Provenance Architecture

According to Checkpoint v2.3 (§509–575):
- Trust levels: trusted, semi_trusted, untrusted, mixed_and_unknown.
- Evidence types: strong_untrusted_link, untrusted_exposure, prompt_overlap, no_observed_untrusted_link.
- Coverage: complete, partial, unknown. Missing data or hooks give unknown, never "clean".
- Deterministic bounded entity matching (domain, host, package identifier, canonical path, IP, command).
- Stop-list prevents generic terms from producing false strong links.
- Synchronous ledger check before action execution.
- Risk escalation only:
    Base LOW + strong link -> effective MEDIUM
    Base MEDIUM + strong link -> effective HIGH
    Base HIGH + strong link -> effective CRITICAL (requires typed YES)
    Base CRITICAL stays CRITICAL.
    Weak exposure only -> tier unchanged.
- Persistent tables: context_ingestions and action_provenance_evidence.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from core.event_types import Event, ProvenanceSignal, RiskTier
from storage.db import _append_event, _connect


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    UNTRUSTED = "untrusted"
    MIXED_AND_UNKNOWN = "mixed_and_unknown"


class ProvenanceCoverage(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class EvidenceType(str, Enum):
    STRONG_UNTRUSTED_LINK = "strong_untrusted_link"
    UNTRUSTED_EXPOSURE = "untrusted_exposure"
    PROMPT_OVERLAP = "prompt_overlap"
    NO_OBSERVED_UNTRUSTED_LINK = "no_observed_untrusted_link"


# Stop-list: common tooling keywords that must NEVER produce strong links on their own
STOP_WORDS: Set[str] = frozenset([
    "npm", "node", "python", "pip", "git", "build", "test", "run", "bash",
    "sh", "echo", "ls", "cd", "cat", "touch", "install", "sudo", "apt",
    "brew", "curl", "wget", "fetch", "yarn", "add", "dir", "mkdir", "rm",
    "main", "master", "origin", "head", "true", "false", "dev", "prod"
])

# Regex patterns for deterministic bounded entity extraction
_URL_RE = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
_DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|sh|dev|app|xyz|edu|gov|co|info|biz)\b', re.IGNORECASE)
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_PIPE_SHELL_RE = re.compile(r'\|\s*(sudo\s+)?(ba|z|da|k)?sh\b', re.IGNORECASE)
_PACKAGE_INSTALL_RE = re.compile(r'\b(?:npm\s+i(?:nstall)?|yarn\s+add|pip\s+install)\s+([a-zA-Z0-9_.-]+)', re.IGNORECASE)
_PACKAGE_MENTION_RE = re.compile(r'\b(?:install|package|dependency|library)\s+([a-zA-Z0-9_.-]+)', re.IGNORECASE)
_SCRIPT_PATH_RE = re.compile(r'(?:/tmp/|\./|[a-zA-Z0-9_-]+/)[a-zA-Z0-9_.-]+\.(?:sh|py|js|exe|bat|ps1)', re.IGNORECASE)


def extract_entities(text: str) -> Dict[str, List[str]]:
    """
    Extract distinctive entities from text/command.
    Returns dict mapping entity_type -> list of values.
    """
    if not text:
        return {}
    entities: Dict[str, List[str]] = {
        "url": [],
        "domain": [],
        "ip": [],
        "package": [],
        "script_path": [],
    }

    # URLs
    for url in _URL_RE.findall(text):
        entities["url"].append(url.lower().rstrip("/.,"))

    # Domains
    for dom in _DOMAIN_RE.findall(text):
        d_lower = dom.lower()
        if d_lower not in STOP_WORDS and d_lower not in entities["domain"]:
            entities["domain"].append(d_lower)

    # IPs
    for ip in _IP_RE.findall(text):
        if ip not in ("127.0.0.1", "0.0.0.0") and ip not in entities["ip"]:
            entities["ip"].append(ip)

    # Package installations & mentions
    found_pkgs = _PACKAGE_INSTALL_RE.findall(text) + _PACKAGE_MENTION_RE.findall(text)
    for pkg in found_pkgs:
        p_lower = pkg.lower()
        if p_lower not in STOP_WORDS and p_lower not in entities["package"]:
            entities["package"].append(p_lower)

    # Script paths
    for sp in _SCRIPT_PATH_RE.findall(text):
        sp_lower = sp.lower()
        if sp_lower not in entities["script_path"]:
            entities["script_path"].append(sp_lower)

    return {k: v for k, v in entities.items() if v}


# ---------------------------------------------------------------------------
# Ingestion Record & In-Memory Fast Ledger
# ---------------------------------------------------------------------------

@dataclass
class IngestionRecord:
    ingestion_id: str
    session_id: str
    event_type: str
    source_kind: str
    source_ref: str
    trust_level: str
    trust_basis: str
    content_hash: str
    entities: Dict[str, List[str]]
    timestamp: float


class ProvenanceLedger:
    """
    Synchronous per-session ledger tracking recent ingestions and entities.
    Consulted in milliseconds by interceptor before executing actions.
    """

    def __init__(self, window_seconds: float = 300.0):
        self.window_seconds = window_seconds
        # session_id -> deque of IngestionRecord
        self._sessions: Dict[str, Deque[IngestionRecord]] = {}

    def _prune(self, session_id: str):
        now = time.time()
        cutoff = now - self.window_seconds
        q = self._sessions.get(session_id, deque())
        while q and q[0].timestamp < cutoff:
            q.popleft()

    def record_ingestion(self, rec: IngestionRecord):
        sid = rec.session_id
        if sid not in self._sessions:
            self._sessions[sid] = deque()
        self._prune(sid)
        self._sessions[sid].append(rec)

    def get_session_ingestions(self, session_id: str) -> List[IngestionRecord]:
        self._prune(session_id)
        return list(self._sessions.get(session_id, []))


_ledger = ProvenanceLedger()


# ---------------------------------------------------------------------------
# Database Persistence: context_ingestions & action_provenance_evidence
# ---------------------------------------------------------------------------

def record_context_ingestion(
    session_id: str,
    event_type: str,
    source_kind: str,
    content: str,
    source_ref: str = "",
    trust_level: str = TrustLevel.UNTRUSTED.value,
    trust_basis: str = "web_or_external",
    prompt_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    tool_use_id: Optional[str] = None,
) -> str:
    """
    Record an ingestion of external/context data into database and ledger.
    """
    ingestion_id = "ingest_" + hashlib.sha256(f"{session_id}:{time.time()}:{content}".encode()).hexdigest()[:16]
    content_hash = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    entities = extract_entities(content)
    redacted_excerpt = content[:250].replace("\n", " ").strip()
    ts_now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    now_float = time.time()

    with _connect() as conn:
        conn.execute("""
            INSERT INTO context_ingestions (
                ingestion_id, session_id, prompt_id, agent_id, tool_use_id,
                event_type, source_kind, source_ref, trust_level, trust_basis,
                content_hash, extracted_entities, redacted_excerpt, capture_status,
                normalizer_version, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'captured', '1', ?)
        """, (
            ingestion_id, session_id, prompt_id, agent_id, tool_use_id,
            event_type, source_kind, source_ref, trust_level, trust_basis,
            content_hash, json.dumps(entities), redacted_excerpt, ts_now
        ))

    # Update synchronous fast ledger
    rec = IngestionRecord(
        ingestion_id=ingestion_id,
        session_id=session_id,
        event_type=event_type,
        source_kind=source_kind,
        source_ref=source_ref,
        trust_level=trust_level,
        trust_basis=trust_basis,
        content_hash=content_hash,
        entities=entities,
        timestamp=now_float,
    )
    _ledger.record_ingestion(rec)
    return ingestion_id


def evaluate_action_provenance(
    action_id: int,
    command: str,
    session_id: str,
    base_tier: RiskTier,
    tool_use_id: str = "",
) -> ProvenanceSignal:
    """
    Perform deterministic bounded entity matching between the proposed action
    and recent session ingestions.
    Computes effective tier escalation and records evidence in SQLite.
    """
    if not session_id:
        return ProvenanceSignal(
            has_untrusted_input=False,
            sources=[],
            escalation_reason="",
        )

    cmd_entities = extract_entities(command)
    ingestions = _ledger.get_session_ingestions(session_id)

    # If the command directly pipes into shell, that is an immediate strong untrusted link
    is_pipe_to_shell = bool(_PIPE_SHELL_RE.search(command))

    matched_evidence: List[Dict[str, Any]] = []
    untrusted_exposures: List[str] = []

    for ing in ingestions:
        if ing.trust_level == TrustLevel.UNTRUSTED.value:
            untrusted_exposures.append(f"{ing.source_kind} ({ing.source_ref or ing.ingestion_id})")

            # Check entity overlap between command and untrusted ingestion
            for etype, vals in cmd_entities.items():
                ing_vals = ing.entities.get(etype, [])
                for v in vals:
                    if v in ing_vals and v not in STOP_WORDS:
                        matched_evidence.append({
                            "ingestion_id": ing.ingestion_id,
                            "evidence_type": EvidenceType.STRONG_UNTRUSTED_LINK.value,
                            "entity_type": etype,
                            "entity_val": v,
                            "strength": "STRONG",
                            "source_ref": ing.source_ref,
                        })

    # Add pipe-to-shell as direct strong evidence if present
    if is_pipe_to_shell:
        matched_evidence.append({
            "ingestion_id": "direct_command",
            "evidence_type": EvidenceType.STRONG_UNTRUSTED_LINK.value,
            "entity_type": "pipe_shell",
            "entity_val": "pipe-into-shell",
            "strength": "STRONG",
            "source_ref": command[:80],
        })

    has_strong_link = len(matched_evidence) > 0
    has_untrusted_exposure = len(untrusted_exposures) > 0

    # Determine evidence type
    if has_strong_link:
        evidence_type = EvidenceType.STRONG_UNTRUSTED_LINK.value
        coverage = ProvenanceCoverage.PARTIAL.value
    elif has_untrusted_exposure:
        evidence_type = EvidenceType.UNTRUSTED_EXPOSURE.value
        coverage = ProvenanceCoverage.PARTIAL.value
    else:
        evidence_type = EvidenceType.NO_OBSERVED_UNTRUSTED_LINK.value
        coverage = ProvenanceCoverage.UNKNOWN.value

    # Compute tier escalation per v2.3 (§543-550):
    # Base LOW + strong link -> MEDIUM
    # Base MEDIUM + strong link -> HIGH
    # Base HIGH + strong link -> CRITICAL
    # Weak exposure only -> tier unchanged
    effective_tier = base_tier
    escalation_reason = ""

    if has_strong_link:
        if base_tier == RiskTier.LOW:
            effective_tier = RiskTier.MEDIUM
        elif base_tier == RiskTier.MEDIUM:
            effective_tier = RiskTier.HIGH
        elif base_tier == RiskTier.HIGH:
            effective_tier = RiskTier.CRITICAL
        # CRITICAL stays CRITICAL

        first_match = matched_evidence[0]
        escalation_reason = (
            f"Strong link to untrusted source detected: {first_match['entity_type']}='{first_match['entity_val']}' "
            f"from {first_match['source_ref']}. Tier escalated from {base_tier.value} to {effective_tier.value}."
        )
    elif has_untrusted_exposure:
        escalation_reason = (
            "Untrusted content was fetched earlier in the session, but no matching entities were found in this command. "
            "Tier unchanged (observed exposure is not proof of influence)."
        )

    # Persist evidence in database if action_id is known
    ts_now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    summary_text = escalation_reason or f"Evidence: {evidence_type}"

    if action_id > 0:
        with _connect() as conn:
            for ev in matched_evidence:
                conn.execute("""
                    INSERT INTO action_provenance_evidence (
                        action_id, ingestion_id, evidence_type, matched_entity_type,
                        matched_entity_val, strength, matcher_version, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, '1', ?)
                """, (
                    action_id, ev["ingestion_id"], ev["evidence_type"],
                    ev["entity_type"], ev["entity_val"], ev["strength"], ts_now
                ))

            # Update action row with provenance summary and coverage
            conn.execute("""
                UPDATE actions
                SET provenance_summary = ?, provenance_coverage = ?, effective_tier = ?
                WHERE id = ?
            """, (summary_text, coverage, effective_tier.value, action_id))

            # Log provenance_computed event into journal
            _append_event(conn, action_id, "provenance_computed", {
                "action_id": action_id,
                "session_id": session_id,
                "evidence_type": evidence_type,
                "coverage": coverage,
                "base_tier": base_tier.value,
                "effective_tier": effective_tier.value,
                "matches_count": len(matched_evidence),
            })

    sources = [f"{e['entity_type']}:{e['entity_val']}" for e in matched_evidence] or untrusted_exposures

    return ProvenanceSignal(
        has_untrusted_input=(has_strong_link or has_untrusted_exposure),
        sources=sources,
        escalation_reason=escalation_reason,
    )


# Backward-compatible hook calls
def record_event(event: Event) -> None:
    if not event.command or not event.session_id:
        return
    # If the command fetches external resources, record as untrusted ingestion
    lower = event.command.lower()
    if any(k in lower for k in ("curl", "wget", "pip install", "npm i", "yarn add")):
        record_context_ingestion(
            session_id=event.session_id,
            event_type="tool_execution",
            source_kind="remote_fetch",
            content=event.command,
            source_ref=event.command[:60],
            trust_level=TrustLevel.UNTRUSTED.value,
        )


def get_signal(event: Event) -> ProvenanceSignal:
    # Synchronous evaluation for backward compatibility
    return evaluate_action_provenance(
        action_id=0,
        command=event.command,
        session_id=event.session_id,
        base_tier=RiskTier.LOW,
    )
