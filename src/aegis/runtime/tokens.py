"""Ephemeral Capability Token Broker, Lethal-Trifecta Taint State Machine & Velocity Circuit Breaker."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy.orm import Session, sessionmaker

from aegis.models import AgentSessionRecord, RiskTier, utc_now


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass
class IssuedSession:
    session_id: str
    raw_token: str
    agent_name: str
    owner_identity: str
    allowed_tools: List[str]
    expires_at: str
    max_calls_per_minute: int
    total_call_budget: int
    max_confidential_reads: int


@dataclass
class TokenVerification:
    valid: bool
    session_id: Optional[str]
    reason: str
    circuit_tripped: bool = False
    trifecta_blocked: bool = False


class TokenBroker:
    """
    Issues short-lived non-human agent tokens, enforces velocity circuit breakers,
    caps confidential read quotas, and enforces Lethal-Trifecta session taint isolation.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def issue_session(
        self,
        agent_name: str,
        owner_identity: str,
        allowed_tools: List[str],
        ttl_seconds: int = 300,
        max_calls_per_minute: int = 20,
        total_call_budget: int = 100,
        max_confidential_reads: int = 10,
    ) -> IssuedSession:
        session_id = f"sess_{secrets.token_hex(8)}"
        raw_token = f"aegis_sess_{secrets.token_urlsafe(24)}"
        expires_at = utc_now() + timedelta(seconds=ttl_seconds)

        with self._session_factory() as db:
            record = AgentSessionRecord(
                session_id=session_id,
                agent_name=agent_name,
                owner_identity=owner_identity,
                token_sha256=_hash_token(raw_token),
                allowed_tools_json=json.dumps(allowed_tools),
                max_calls_per_minute=max_calls_per_minute,
                total_call_budget=total_call_budget,
                max_confidential_reads=max_confidential_reads,
                confidential_reads_used=0,
                tainted_private_read=False,
                exposed_untrusted_input=False,
                calls_made=0,
                window_started_at=utc_now(),
                window_calls=0,
                expires_at=expires_at,
                revoked=False,
            )
            db.add(record)
            db.commit()

        return IssuedSession(
            session_id=session_id,
            raw_token=raw_token,
            agent_name=agent_name,
            owner_identity=owner_identity,
            allowed_tools=allowed_tools,
            expires_at=expires_at.isoformat(),
            max_calls_per_minute=max_calls_per_minute,
            total_call_budget=total_call_budget,
            max_confidential_reads=max_confidential_reads,
        )

    def authorize_and_consume(
        self,
        raw_token: str,
        requested_tool: str,
        risk_tier: RiskTier = RiskTier.READ_ONLY,
        has_untrusted_input: bool = False,
        has_verified_owner_override: bool = False,
    ) -> TokenVerification:
        if not raw_token or not raw_token.startswith("aegis_sess_"):
            return TokenVerification(
                valid=False,
                session_id=None,
                reason="Missing or malformed Aegis ephemeral session token.",
            )

        token_hash = _hash_token(raw_token)
        now = utc_now()

        with self._session_factory() as db:
            rec = (
                db.query(AgentSessionRecord)
                .filter(AgentSessionRecord.token_sha256 == token_hash)
                .first()
            )
            if not rec:
                return TokenVerification(valid=False, session_id=None, reason="Unknown session token.")

            if rec.revoked:
                return TokenVerification(
                    valid=False,
                    session_id=rec.session_id,
                    reason=f"Session token revoked: {rec.revoked_reason or 'Manual kill-switch'}",
                )

            if now >= _ensure_aware(rec.expires_at):
                return TokenVerification(
                    valid=False,
                    session_id=rec.session_id,
                    reason="Ephemeral session token TTL expired.",
                )

            if rec.calls_made >= rec.total_call_budget:
                rec.revoked = True
                rec.revoked_at = now
                rec.revoked_reason = (
                    f"Circuit Breaker Tripped: Exceeded total session call budget ({rec.total_call_budget})."
                )
                db.commit()
                return TokenVerification(
                    valid=False,
                    session_id=rec.session_id,
                    reason=rec.revoked_reason,
                    circuit_tripped=True,
                )

            win_start = _ensure_aware(rec.window_started_at)
            if (now - win_start).total_seconds() >= 60.0:
                rec.window_started_at = now
                rec.window_calls = 0

            if rec.window_calls >= rec.max_calls_per_minute:
                rec.revoked = True
                rec.revoked_at = now
                rec.revoked_reason = (
                    f"Velocity Circuit Breaker Tripped: >{rec.max_calls_per_minute} calls/min burst "
                    "(autonomous runaway loop protection)."
                )
                db.commit()
                return TokenVerification(
                    valid=False,
                    session_id=rec.session_id,
                    reason=rec.revoked_reason,
                    circuit_tripped=True,
                )

            allowed = json.loads(rec.allowed_tools_json)
            if "*" not in allowed and requested_tool not in allowed:
                return TokenVerification(
                    valid=False,
                    session_id=rec.session_id,
                    reason=(
                        f"Least-Privilege Violation: Tool `{requested_tool}` is outside session scope {allowed}."
                    ),
                )

            # Update taint flags BEFORE checking Lethal Trifecta egress lock
            if has_untrusted_input or requested_tool.lower() in {
                "read_untrusted_email",
                "fetch_support_ticket",
                "scrape_webpage",
            }:
                rec.exposed_untrusted_input = True

            if risk_tier == RiskTier.CONFIDENTIAL_READ:
                if rec.confidential_reads_used >= rec.max_confidential_reads and not has_verified_owner_override:
                    return TokenVerification(
                        valid=False,
                        session_id=rec.session_id,
                        reason=(
                            f"Confidential Read Quota Exceeded ({rec.max_confidential_reads} max per session) — "
                            "bulk data harvesting blocked unless Owner Ed25519 signature provided."
                        ),
                    )
                rec.tainted_private_read = True
                rec.confidential_reads_used += 1

            # HARD CONSTRAINT: Lethal-Trifecta Exfiltration Lock!
            if (
                risk_tier in {RiskTier.EXTERNAL_EGRESS, RiskTier.IRREVERSIBLE_CRITICAL}
                and rec.tainted_private_read
                and rec.exposed_untrusted_input
                and not has_verified_owner_override
            ):
                db.commit()
                return TokenVerification(
                    valid=False,
                    session_id=rec.session_id,
                    reason=(
                        "LETHAL-TRIFECTA TAINT LOCK: Session has both read CONFIDENTIAL company data "
                        "AND processed untrusted external input. All outbound network/egress tools are "
                        "deterministically locked without an offline Ed25519 Owner Signature."
                    ),
                    trifecta_blocked=True,
                )

            rec.calls_made += 1
            rec.window_calls += 1
            db.commit()
            return TokenVerification(
                valid=True,
                session_id=rec.session_id,
                reason="Authorized via scoped ephemeral session token.",
            )

    def revoke_session(self, session_id: str, reason: str = "Security operator kill-switch") -> bool:
        with self._session_factory() as db:
            rec = (
                db.query(AgentSessionRecord)
                .filter(AgentSessionRecord.session_id == session_id)
                .first()
            )
            if not rec:
                return False
            rec.revoked = True
            rec.revoked_at = utc_now()
            rec.revoked_reason = reason
            db.commit()
            return True

    def list_sessions(self) -> List[dict]:
        with self._session_factory() as db:
            rows = db.query(AgentSessionRecord).order_by(AgentSessionRecord.created_at.desc()).limit(50).all()
            return [
                {
                    "session_id": r.session_id,
                    "agent_name": r.agent_name,
                    "owner_identity": r.owner_identity,
                    "allowed_tools": json.loads(r.allowed_tools_json),
                    "calls_made": r.calls_made,
                    "total_call_budget": r.total_call_budget,
                    "tainted_private_read": r.tainted_private_read,
                    "exposed_untrusted_input": r.exposed_untrusted_input,
                    "confidential_reads": f"{r.confidential_reads_used}/{r.max_confidential_reads}",
                    "expires_at": _ensure_aware(r.expires_at).isoformat(),
                    "revoked": r.revoked,
                    "revoked_reason": r.revoked_reason,
                }
                for r in rows
            ]
