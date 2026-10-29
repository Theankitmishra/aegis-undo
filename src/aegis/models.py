"""Persistent state models, cryptographic owner records, taint tracking, vault & schemas for AegisUndo v2."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_sha256(payload: Dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class RiskTier(str, Enum):
    READ_ONLY = "READ_ONLY"
    CONFIDENTIAL_READ = "CONFIDENTIAL_READ"
    REVERSIBLE_WRITE = "REVERSIBLE_WRITE"
    EXTERNAL_EGRESS = "EXTERNAL_EGRESS"
    IRREVERSIBLE_CRITICAL = "IRREVERSIBLE_CRITICAL"


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_OWNER_SIGNATURE = "REQUIRE_OWNER_SIGNATURE"


class SourceTrust(str, Enum):
    TRUSTED_SYSTEM = "trusted_system"
    VERIFIED_HUMAN = "verified_human"
    UNTRUSTED_EXTERNAL = "untrusted_external"


class Base(DeclarativeBase):
    pass


class OwnerKeyRecord(Base):
    """
    Registered Company Owner asymmetric identity.
    The Ed25519 PRIVATE key NEVER touches the server — only the Ed25519 PUBLIC key is stored here.
    """

    __tablename__ = "owner_keys"

    owner_id = Column(String(64), primary_key=True)
    display_name = Column(String(128), nullable=False)
    role = Column(String(64), nullable=False, default="PRIMARY_OWNER")
    ed25519_public_key_pem = Column(Text, nullable=False)
    totp_secret_b32 = Column(String(64), nullable=True)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class ConsumedNonceRecord(Base):
    """Single-use cryptographic nonces preventing replay of captured Owner signatures."""

    __tablename__ = "consumed_nonces"

    nonce = Column(String(128), primary_key=True)
    owner_id = Column(String(64), nullable=False, index=True)
    action_digest = Column(String(64), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class VaultSecretRecord(Base):
    """AES-256-GCM envelope-encrypted company sensitive records & Canary Honeytokens."""

    __tablename__ = "zero_trust_vault"

    record_id = Column(String(128), primary_key=True)
    label = Column(String(128), nullable=False)
    classification = Column(String(32), nullable=False, default="TOP_SECRET")
    nonce_b64 = Column(String(64), nullable=False)
    ciphertext_b64 = Column(Text, nullable=False)
    is_canary = Column(Boolean, nullable=False, default=False)
    canary_token_hash = Column(String(64), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class CanaryTokenRecord(Base):
    """Active honeytoken tripwires — if ever seen in agent tool args or outputs, triggers instant lockdown."""

    __tablename__ = "canary_tripwires"

    canary_id = Column(String(64), primary_key=True)
    token_value = Column(String(128), unique=True, nullable=False, index=True)
    planted_location = Column(String(128), nullable=False)
    triggered = Column(Boolean, nullable=False, default=False)
    triggered_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class SystemLockdownRecord(Base):
    """Global kill-switch tripped automatically upon canary leak or critical breach attempt."""

    __tablename__ = "system_lockdown"

    id = Column(Integer, primary_key=True)
    locked = Column(Boolean, nullable=False, default=False)
    reason = Column(String(512), nullable=True)
    triggered_by_run = Column(String(64), nullable=True)
    locked_at = Column(DateTime(timezone=True), nullable=True)
    unlocked_by_owner = Column(String(64), nullable=True)
    unlocked_at = Column(DateTime(timezone=True), nullable=True)


class AgentSessionRecord(Base):
    """Ephemeral capability token record with Lethal-Trifecta taint tracking."""

    __tablename__ = "agent_sessions"

    session_id = Column(String(64), primary_key=True)
    agent_name = Column(String(128), nullable=False)
    owner_identity = Column(String(128), nullable=False)
    token_sha256 = Column(String(64), unique=True, nullable=False, index=True)
    allowed_tools_json = Column(Text, nullable=False, default="[]")
    max_calls_per_minute = Column(Integer, nullable=False, default=30)
    total_call_budget = Column(Integer, nullable=False, default=200)
    max_confidential_reads = Column(Integer, nullable=False, default=10)
    confidential_reads_used = Column(Integer, nullable=False, default=0)
    tainted_private_read = Column(Boolean, nullable=False, default=False)
    exposed_untrusted_input = Column(Boolean, nullable=False, default=False)
    calls_made = Column(Integer, nullable=False, default=0)
    window_started_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    window_calls = Column(Integer, nullable=False, default=0)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, nullable=False, default=False)
    revoked_reason = Column(String(512), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class AuditLedgerRecord(Base):
    """Append-only SHA-256 hash-chained ledger of every intercepted agent tool execution."""

    __tablename__ = "audit_ledger"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    session_id = Column(String(64), nullable=True, index=True)
    agent_run_id = Column(String(64), nullable=False, index=True)
    provider_format = Column(String(32), nullable=False)
    tool_name = Column(String(128), nullable=False)
    risk_tier = Column(String(32), nullable=False)
    decision = Column(String(32), nullable=False)
    injection_score = Column(Float, nullable=False, default=0.0)
    ml_attack_probability = Column(Float, nullable=False, default=0.0)
    redacted_args_json = Column(Text, nullable=False)
    reasons_json = Column(Text, nullable=False, default="[]")
    owner_verified_by = Column(String(128), nullable=True)
    prev_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class DatabaseMutationRecord(Base):
    """Row-level before/after snapshots enabling surgical rollback of a compromised agent_run_id."""

    __tablename__ = "db_mutation_ledger"

    id = Column(Integer, primary_key=True, autoincrement=True)
    mutation_id = Column(String(64), unique=True, nullable=False, index=True)
    agent_run_id = Column(String(64), nullable=False, index=True)
    session_id = Column(String(64), nullable=True)
    table_name = Column(String(128), nullable=False)
    primary_key_col = Column(String(64), nullable=False, default="id")
    record_pk = Column(String(128), nullable=False, index=True)
    operation = Column(String(16), nullable=False)
    before_state_json = Column(Text, nullable=True)
    after_state_json = Column(Text, nullable=True)
    reverted = Column(Boolean, nullable=False, default=False)
    reverted_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class MemoryChunkRecord(Base):
    """Versioned RAG / agent memory chunk with enforced source provenance."""

    __tablename__ = "memory_chunks"

    memory_id = Column(String(64), primary_key=True)
    namespace = Column(String(64), nullable=False, default="default", index=True)
    content = Column(Text, nullable=False)
    source_trust = Column(String(32), nullable=False)
    source_doc_id = Column(String(128), nullable=False, index=True)
    created_by_run = Column(String(64), nullable=False, index=True)
    version = Column(Integer, nullable=False, default=1)
    quarantined = Column(Boolean, nullable=False, default=False, index=True)
    quarantine_reason = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class MemoryReadLineageRecord(Base):
    """Tracks every agent decision that retrieved a specific memory_id into prompt context."""

    __tablename__ = "memory_read_lineage"

    id = Column(Integer, primary_key=True, autoincrement=True)
    decision_id = Column(String(64), nullable=False, index=True)
    agent_run_id = Column(String(64), nullable=False, index=True)
    memory_id = Column(String(64), nullable=False, index=True)
    decision_summary = Column(String(512), nullable=False)
    tainted = Column(Boolean, nullable=False, default=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class ApprovalRequestRecord(Base):
    """Cryptographic Owner-Signed Approval queue (Ed25519 + TOTP + Action Payload Digest)."""

    __tablename__ = "approval_requests"

    approval_id = Column(String(64), primary_key=True)
    agent_run_id = Column(String(64), nullable=False, index=True)
    session_id = Column(String(64), nullable=True)
    provider_format = Column(String(32), nullable=False)
    tool_name = Column(String(128), nullable=False)
    sanitized_args_json = Column(Text, nullable=False)
    action_digest = Column(String(64), nullable=False)
    required_quorum = Column(Integer, nullable=False, default=1)
    collected_signatures_json = Column(Text, nullable=False, default="[]")
    risk_reasons_json = Column(Text, nullable=False)
    requires_oob_challenge = Column(Boolean, nullable=False, default=True)
    oob_challenge_hash = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default="PENDING")
    reviewer_identity = Column(String(128), nullable=True)
    reviewer_note = Column(String(512), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class InfraProposalRecord(Base):
    """GitOps-staged Infrastructure-as-Code proposals with deterministic policy validation & revert patch."""

    __tablename__ = "infra_proposals"

    proposal_id = Column(String(64), primary_key=True)
    agent_run_id = Column(String(64), nullable=False, index=True)
    target_path = Column(String(256), nullable=False)
    before_manifest = Column(Text, nullable=False)
    after_manifest = Column(Text, nullable=False)
    policy_passed = Column(Boolean, nullable=False)
    violations_json = Column(Text, nullable=False, default="[]")
    status = Column(String(32), nullable=False)
    git_commit_sha = Column(String(64), nullable=True)
    reverted_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


def create_db_session_factory(db_url: Optional[str] = None) -> sessionmaker[Session]:
    """Create SQLAlchemy engine & session factory with SQLite WAL concurrency enabled by default."""
    resolved_url = db_url or os.environ.get("AEGIS_DATABASE_URL")
    if not resolved_url:
        state_dir = os.path.abspath(os.environ.get("AEGIS_STATE_DIR", "./aegis_state"))
        os.makedirs(state_dir, exist_ok=True)
        resolved_url = f"sqlite:///{os.path.join(state_dir, 'aegis_control_plane.db')}"

    connect_args = {"check_same_thread": False} if resolved_url.startswith("sqlite") else {}
    engine = create_engine(resolved_url, connect_args=connect_args, future=True)

    if resolved_url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection: Any, _connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.close()

    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


# --- Pydantic Schemas for Scanner & API ---


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class NistFunction(str, Enum):
    GOVERN = "GOVERN"
    MAP = "MAP"
    MEASURE = "MEASURE"
    MANAGE = "MANAGE"


class WeaknessFinding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    nist_function: NistFunction
    threat_category: str
    file_path: str
    line_number: int
    code_snippet: str
    why_weak: str
    remediation: str
    is_undoable_once_exploited: bool


class ResidualRiskItem(BaseModel):
    threat_vector: str
    enforced_hard_constraint: str
    cryptographic_guarantee: str


class ScanReport(BaseModel):
    target_path: str
    scanned_files_count: int
    architecture_score: int = Field(ge=0, le=100)
    posture_grade: str
    summary_by_severity: Dict[str, int]
    nist_rmf_coverage: Dict[str, Dict[str, Any]]
    findings: List[WeaknessFinding]
    residual_risks: List[ResidualRiskItem]
    generated_at: str
