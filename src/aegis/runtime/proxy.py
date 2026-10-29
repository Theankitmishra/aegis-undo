"""Zero-Trust Multi-Provider Proxy Enforcing Canary Lockdown, Taint Trifecta, Fine-Tuned ML & Ed25519 Owner Auth."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session, sessionmaker

from aegis.crypto.owner_auth import OwnerSignatureProof, OwnerVerificationEngine
from aegis.crypto.vault import CanaryTripwireEngine
from aegis.models import (
    ApprovalRequestRecord,
    AuditLedgerRecord,
    PolicyAction,
    RiskTier,
    canonical_sha256,
    utc_now,
)
from aegis.runtime.policy import PolicyEngine
from aegis.runtime.tokens import TokenBroker

GENESIS_HASH = "0" * 64


@dataclass
class NormalizedToolCall:
    provider: str
    call_id: str
    tool_name: str
    arguments: Dict[str, Any]


class AegisProxy:
    """
    7-Layer Zero-Trust Interceptor across OpenAI, Anthropic, Gemini & MCP JSON-RPC:
      1. Global Canary Lockdown Gate
      2. Canary Honeytoken Leak Tripwire (instant workspace freeze + cascade token kill)
      3. Ephemeral Session Token, Tool Scope, Read Quota & Velocity Circuit Breaker
      4. Lethal-Trifecta Session Taint State Machine (blocks private-read + untrusted-input + egress)
      5. Deterministic Non-AI Code Policy (SSRF, SQL DDL, Egress Allowlist, PII Redaction)
      6. Fine-Tuned Adversarial Semantic ML Classifier
      7. Offline Ed25519 + RFC 6238 TOTP Cryptographic Owner Verification (single or M-of-N quorum)
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        token_broker: Optional[TokenBroker] = None,
        policy_engine: Optional[PolicyEngine] = None,
        owner_auth: Optional[OwnerVerificationEngine] = None,
        canary_engine: Optional[CanaryTripwireEngine] = None,
    ) -> None:
        self._session_factory = session_factory
        self.owner_auth = owner_auth or OwnerVerificationEngine(session_factory)
        self.canary_engine = canary_engine or CanaryTripwireEngine(session_factory, self.owner_auth)
        self.token_broker = token_broker or TokenBroker(session_factory)
        self.policy_engine = policy_engine or PolicyEngine()

    @staticmethod
    def parse_wire_payload(provider: str, payload: Dict[str, Any]) -> NormalizedToolCall:
        p = provider.lower().strip()

        if p == "openai":
            if "tool_calls" in payload and isinstance(payload["tool_calls"], list) and payload["tool_calls"]:
                tc = payload["tool_calls"][0]
            else:
                tc = payload
            fn = tc.get("function", tc)
            raw_args = fn.get("arguments", {})
            args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args or {})
            return NormalizedToolCall(
                provider="openai",
                call_id=str(tc.get("id", f"call_{secrets.token_hex(4)}")),
                tool_name=str(fn.get("name", "")),
                arguments=args,
            )

        if p == "anthropic":
            block = payload
            if "content" in payload and isinstance(payload["content"], list):
                for item in payload["content"]:
                    if isinstance(item, dict) and item.get("type") == "tool_use":
                        block = item
                        break
            return NormalizedToolCall(
                provider="anthropic",
                call_id=str(block.get("id", f"toolu_{secrets.token_hex(4)}")),
                tool_name=str(block.get("name", "")),
                arguments=dict(block.get("input") or {}),
            )

        if p == "gemini":
            fc = payload.get("functionCall")
            if not fc and "candidates" in payload:
                parts = payload["candidates"][0].get("content", {}).get("parts", [])
                for part in parts:
                    if "functionCall" in part:
                        fc = part["functionCall"]
                        break
            fc = fc or payload
            return NormalizedToolCall(
                provider="gemini",
                call_id=f"gem_{secrets.token_hex(4)}",
                tool_name=str(fc.get("name", "")),
                arguments=dict(fc.get("args") or {}),
            )

        if p == "mcp":
            params = payload.get("params", payload)
            return NormalizedToolCall(
                provider="mcp",
                call_id=str(payload.get("id", f"mcp_{secrets.token_hex(4)}")),
                tool_name=str(params.get("name", "")),
                arguments=dict(params.get("arguments") or {}),
            )

        raise ValueError(f"Unsupported provider wire format: {provider!r}.")

    def intercept(
        self,
        provider: str,
        payload: Dict[str, Any],
        agent_run_id: str,
        session_token: Optional[str] = None,
        require_token: bool = True,
        untrusted_context: Optional[str] = None,
        owner_proof: Optional[OwnerSignatureProof] = None,
        required_quorum: int = 1,
    ) -> Dict[str, Any]:
        call = self.parse_wire_payload(provider, payload)
        if not call.tool_name:
            raise ValueError("Parsed tool call has an empty tool name.")

        redacted_args, _ = self.policy_engine.redact_sensitive(call.arguments)

        # LAYER 1: Global Canary Workspace Lockdown Check
        locked, lock_reason = self.canary_engine.is_locked_down()
        if locked:
            evt = self._append_audit_entry(
                session_id=None,
                agent_run_id=agent_run_id,
                provider_format=call.provider,
                tool_name=call.tool_name,
                risk_tier=RiskTier.IRREVERSIBLE_CRITICAL.value,
                decision=PolicyAction.BLOCK.value,
                injection_score=1.0,
                ml_prob=1.0,
                redacted_args=redacted_args,
                reasons=[f"GLOBAL WORKSPACE LOCKDOWN ACTIVE: {lock_reason}"],
            )
            return {
                "allowed": False,
                "decision": PolicyAction.BLOCK.value,
                "workspace_locked": True,
                "tool_name": call.tool_name,
                "reasons": [f"GLOBAL WORKSPACE LOCKDOWN ACTIVE: {lock_reason}"],
                "audit_event_id": evt["event_id"],
                "audit_entry_hash": evt["entry_hash"],
            }

        # LAYER 2: Canary Honeytoken Leak Tripwire
        combined_raw = json.dumps(call.arguments, default=str) + "\n" + (untrusted_context or "")
        canary_alert = self.canary_engine.inspect_and_trip_if_leaked(combined_raw, agent_run_id)
        if canary_alert:
            evt = self._append_audit_entry(
                session_id=None,
                agent_run_id=agent_run_id,
                provider_format=call.provider,
                tool_name=call.tool_name,
                risk_tier=RiskTier.IRREVERSIBLE_CRITICAL.value,
                decision=PolicyAction.BLOCK.value,
                injection_score=1.0,
                ml_prob=1.0,
                redacted_args=redacted_args,
                reasons=[canary_alert],
            )
            return {
                "allowed": False,
                "decision": PolicyAction.BLOCK.value,
                "canary_tripped": True,
                "workspace_locked": True,
                "tool_name": call.tool_name,
                "reasons": [canary_alert],
                "audit_event_id": evt["event_id"],
                "audit_entry_hash": evt["entry_hash"],
            }

        # Pre-check inline Ed25519 Owner Proof if caller attached one directly
        verified_owner_id: Optional[str] = None
        if owner_proof is not None:
            ver = self.owner_auth.verify_owner_proof(
                proof=owner_proof,
                operation="TOOL_EXECUTION",
                target_resource=call.tool_name,
                canonical_params=redacted_args,
            )
            if not ver.verified:
                evt = self._append_audit_entry(
                    session_id=None,
                    agent_run_id=agent_run_id,
                    provider_format=call.provider,
                    tool_name=call.tool_name,
                    risk_tier=RiskTier.IRREVERSIBLE_CRITICAL.value,
                    decision=PolicyAction.BLOCK.value,
                    injection_score=0.0,
                    ml_prob=0.0,
                    redacted_args=redacted_args,
                    reasons=[f"Owner Signature Rejected: {ver.reason}"],
                )
                return {
                    "allowed": False,
                    "decision": PolicyAction.BLOCK.value,
                    "tool_name": call.tool_name,
                    "reasons": [f"Owner Signature Rejected: {ver.reason}"],
                    "audit_event_id": evt["event_id"],
                    "audit_entry_hash": evt["entry_hash"],
                }
            verified_owner_id = ver.owner_id

        # Classify risk tier for Taint & Quota checks
        preliminary_tier = self.policy_engine.classify_tool(call.tool_name, call.arguments)

        # LAYER 3 & 4: Ephemeral Session Token + Read Quota + Lethal-Trifecta Taint Lock
        session_id: Optional[str] = None
        if require_token:
            tok_check = self.token_broker.authorize_and_consume(
                raw_token=session_token or "",
                requested_tool=call.tool_name,
                risk_tier=preliminary_tier,
                has_untrusted_input=bool(untrusted_context),
                has_verified_owner_override=bool(verified_owner_id),
            )
            session_id = tok_check.session_id
            if not tok_check.valid:
                evt = self._append_audit_entry(
                    session_id=session_id,
                    agent_run_id=agent_run_id,
                    provider_format=call.provider,
                    tool_name=call.tool_name,
                    risk_tier=preliminary_tier.value,
                    decision=PolicyAction.BLOCK.value,
                    injection_score=0.0,
                    ml_prob=0.0,
                    redacted_args=redacted_args,
                    reasons=[tok_check.reason],
                )
                return {
                    "allowed": False,
                    "decision": PolicyAction.BLOCK.value,
                    "circuit_tripped": tok_check.circuit_tripped,
                    "trifecta_blocked": tok_check.trifecta_blocked,
                    "provider": call.provider,
                    "call_id": call.call_id,
                    "tool_name": call.tool_name,
                    "reasons": [tok_check.reason],
                    "audit_event_id": evt["event_id"],
                    "audit_entry_hash": evt["entry_hash"],
                }

        # LAYER 5 & 6: Deterministic Policy Gate + Fine-Tuned Adversarial Semantic ML Model
        eval_res = self.policy_engine.evaluate(
            tool_name=call.tool_name,
            arguments=call.arguments,
            untrusted_context=untrusted_context,
        )

        # LAYER 7: If tool requires Owner Signature and inline Ed25519 proof already passed -> ALLOW!
        final_decision = eval_res.action
        final_reasons = list(eval_res.reasons)
        if eval_res.action == PolicyAction.REQUIRE_OWNER_SIGNATURE and verified_owner_id:
            final_decision = PolicyAction.ALLOW
            final_reasons.append(f"Unlocked via verified offline Ed25519 + TOTP Owner Proof (`{verified_owner_id}`).")

        evt = self._append_audit_entry(
            session_id=session_id,
            agent_run_id=agent_run_id,
            provider_format=call.provider,
            tool_name=call.tool_name,
            risk_tier=eval_res.risk_tier.value,
            decision=final_decision.value,
            injection_score=eval_res.injection_score,
            ml_prob=eval_res.ml_attack_probability,
            redacted_args=eval_res.redacted_arguments,
            reasons=final_reasons,
            owner_verified_by=verified_owner_id,
        )

        response: Dict[str, Any] = {
            "allowed": final_decision == PolicyAction.ALLOW,
            "decision": final_decision.value,
            "risk_tier": eval_res.risk_tier.value,
            "provider": call.provider,
            "call_id": call.call_id,
            "tool_name": call.tool_name,
            "sanitized_arguments": eval_res.redacted_arguments,
            "injection_score": eval_res.injection_score,
            "ml_attack_probability": eval_res.ml_attack_probability,
            "owner_verified_by": verified_owner_id,
            "reasons": final_reasons,
            "audit_event_id": evt["event_id"],
            "audit_entry_hash": evt["entry_hash"],
        }

        if final_decision == PolicyAction.REQUIRE_OWNER_SIGNATURE:
            response["approval_request"] = self._create_owner_approval_request(
                agent_run_id=agent_run_id,
                session_id=session_id,
                provider=call.provider,
                tool_name=call.tool_name,
                sanitized_args=eval_res.redacted_arguments,
                reasons=final_reasons,
                required_quorum=required_quorum,
            )

        return response

    def _create_owner_approval_request(
        self,
        agent_run_id: str,
        session_id: Optional[str],
        provider: str,
        tool_name: str,
        sanitized_args: Dict[str, Any],
        reasons: List[str],
        required_quorum: int = 1,
    ) -> Dict[str, Any]:
        approval_id = f"own_req_{secrets.token_hex(6)}"
        oob_code = f"OOB-{secrets.randbelow(900000) + 100000}"
        oob_hash = hashlib.sha256(oob_code.encode("utf-8")).hexdigest()
        payload_digest = canonical_sha256({"tool_name": tool_name, "arguments": sanitized_args})

        with self._session_factory() as db:
            db.add(
                ApprovalRequestRecord(
                    approval_id=approval_id,
                    agent_run_id=agent_run_id,
                    session_id=session_id,
                    provider_format=provider,
                    tool_name=tool_name,
                    sanitized_args_json=json.dumps(sanitized_args, sort_keys=True, default=str),
                    action_digest=payload_digest,
                    required_quorum=required_quorum,
                    collected_signatures_json="[]",
                    risk_reasons_json=json.dumps(reasons),
                    requires_oob_challenge=True,
                    oob_challenge_hash=oob_hash,
                    status="PENDING",
                )
            )
            db.commit()

        return {
            "approval_id": approval_id,
            "status": "PENDING",
            "required_quorum": required_quorum,
            "signing_operation": "APPROVAL_RELEASE",
            "signing_target": approval_id,
            "payload_digest": payload_digest,
            "requires_ed25519_owner_signature": True,
            "oob_challenge_code_for_approver_channel": oob_code,
        }

    def resolve_approval_with_owner_signature(
        self,
        approval_id: str,
        approve: bool,
        owner_proof: OwnerSignatureProof,
        oob_challenge_code: Optional[str] = None,
        note: str = "",
    ) -> Dict[str, Any]:
        """
        Release a pending critical tool call ONLY when signed by an enrolled Owner's offline
        Ed25519 private key + valid 6-digit TOTP + exact payload digest binding.
        Supports M-of-N multi-owner quorum!
        """
        with self._session_factory() as db:
            rec = (
                db.query(ApprovalRequestRecord)
                .filter(ApprovalRequestRecord.approval_id == approval_id)
                .first()
            )
            if not rec:
                raise KeyError(f"Approval request `{approval_id}` not found.")
            if rec.status != "PENDING":
                return {"approval_id": approval_id, "status": rec.status, "already_resolved": True}

            args_dict = json.loads(rec.sanitized_args_json)
            canonical_params = {
                "approval_id": approval_id,
                "decision": "APPROVE" if approve else "REJECT",
                "tool_name": rec.tool_name,
                "arguments": args_dict,
            }

            ver = self.owner_auth.verify_owner_proof(
                proof=owner_proof,
                operation="APPROVAL_RELEASE",
                target_resource=approval_id,
                canonical_params=canonical_params,
            )
            if not ver.verified:
                return {
                    "approval_id": approval_id,
                    "status": "PENDING",
                    "verified": False,
                    "error": f"Cryptographic Owner Verification Failed: {ver.reason}",
                }

            if approve and rec.requires_oob_challenge and rec.oob_challenge_hash:
                provided_hash = hashlib.sha256((oob_challenge_code or "").encode("utf-8")).hexdigest()
                if provided_hash != rec.oob_challenge_hash:
                    return {
                        "approval_id": approval_id,
                        "status": "PENDING",
                        "verified": False,
                        "error": "Anti-Deepfake OOB Challenge Code mismatch.",
                    }

            if not approve:
                rec.status = "REJECTED"
                rec.reviewer_identity = ver.owner_id
                rec.reviewer_note = note
                rec.resolved_at = utc_now()
                db.commit()
                return {
                    "approval_id": approval_id,
                    "status": "REJECTED",
                    "verified": True,
                    "signed_by_owners": [ver.owner_id],
                }

            collected: List[str] = json.loads(rec.collected_signatures_json)
            if ver.owner_id and ver.owner_id not in collected:
                collected.append(ver.owner_id)
            rec.collected_signatures_json = json.dumps(collected)

            if len(collected) >= rec.required_quorum:
                rec.status = "APPROVED"
                rec.reviewer_identity = ",".join(collected)
                rec.reviewer_note = note
                rec.resolved_at = utc_now()
            db.commit()

            return {
                "approval_id": approval_id,
                "status": rec.status,
                "verified": True,
                "signed_by_owners": collected,
                "required_quorum": rec.required_quorum,
            }

    def _append_audit_entry(
        self,
        session_id: Optional[str],
        agent_run_id: str,
        provider_format: str,
        tool_name: str,
        risk_tier: str,
        decision: str,
        injection_score: float,
        ml_prob: float,
        redacted_args: Dict[str, Any],
        reasons: List[str],
        owner_verified_by: Optional[str] = None,
    ) -> Dict[str, str]:
        event_id = f"evt_{secrets.token_hex(8)}"
        args_json = json.dumps(redacted_args, sort_keys=True, default=str)
        reasons_json = json.dumps(reasons, sort_keys=True)

        with self._session_factory() as db:
            last = db.query(AuditLedgerRecord).order_by(AuditLedgerRecord.id.desc()).first()
            prev_hash = last.entry_hash if last else GENESIS_HASH
            entry_hash = canonical_sha256(
                {
                    "event_id": event_id,
                    "session_id": session_id,
                    "agent_run_id": agent_run_id,
                    "provider_format": provider_format,
                    "tool_name": tool_name,
                    "risk_tier": risk_tier,
                    "decision": decision,
                    "ml_attack_probability": ml_prob,
                    "owner_verified_by": owner_verified_by,
                    "redacted_args_json": args_json,
                    "reasons_json": reasons_json,
                    "prev_hash": prev_hash,
                }
            )
            db.add(
                AuditLedgerRecord(
                    event_id=event_id,
                    session_id=session_id,
                    agent_run_id=agent_run_id,
                    provider_format=provider_format,
                    tool_name=tool_name,
                    risk_tier=risk_tier,
                    decision=decision,
                    injection_score=injection_score,
                    ml_attack_probability=ml_prob,
                    redacted_args_json=args_json,
                    reasons_json=reasons_json,
                    owner_verified_by=owner_verified_by,
                    prev_hash=prev_hash,
                    entry_hash=entry_hash,
                )
            )
            db.commit()
        return {"event_id": event_id, "entry_hash": entry_hash, "prev_hash": prev_hash}

    def verify_audit_chain(self) -> Tuple[bool, int, Optional[str]]:
        with self._session_factory() as db:
            rows = db.query(AuditLedgerRecord).order_by(AuditLedgerRecord.id.asc()).all()
            expected_prev = GENESIS_HASH
            for idx, r in enumerate(rows, start=1):
                if r.prev_hash != expected_prev:
                    return False, idx, f"Broken prev_hash link at event `{r.event_id}`."
                recomputed = canonical_sha256(
                    {
                        "event_id": r.event_id,
                        "session_id": r.session_id,
                        "agent_run_id": r.agent_run_id,
                        "provider_format": r.provider_format,
                        "tool_name": r.tool_name,
                        "risk_tier": r.risk_tier,
                        "decision": r.decision,
                        "ml_attack_probability": r.ml_attack_probability,
                        "owner_verified_by": r.owner_verified_by,
                        "redacted_args_json": r.redacted_args_json,
                        "reasons_json": r.reasons_json,
                        "prev_hash": r.prev_hash,
                    }
                )
                if recomputed != r.entry_hash:
                    return False, idx, f"Tampered payload hash detected at event `{r.event_id}`."
                expected_prev = r.entry_hash
            return True, len(rows), None

    def list_audit_events(self, limit: int = 40) -> List[Dict[str, Any]]:
        with self._session_factory() as db:
            rows = db.query(AuditLedgerRecord).order_by(AuditLedgerRecord.id.desc()).limit(limit).all()
            return [
                {
                    "event_id": r.event_id,
                    "session_id": r.session_id,
                    "agent_run_id": r.agent_run_id,
                    "provider": r.provider_format,
                    "tool_name": r.tool_name,
                    "risk_tier": r.risk_tier,
                    "decision": r.decision,
                    "injection_score": r.injection_score,
                    "ml_attack_probability": r.ml_attack_probability,
                    "owner_verified_by": r.owner_verified_by,
                    "arguments": json.loads(r.redacted_args_json),
                    "reasons": json.loads(r.reasons_json),
                    "entry_hash": r.entry_hash[:16] + "...",
                    "created_at": r.created_at.isoformat(),
                }
                for r in rows
            ]

    def list_approvals(self) -> List[Dict[str, Any]]:
        with self._session_factory() as db:
            rows = (
                db.query(ApprovalRequestRecord)
                .order_by(ApprovalRequestRecord.created_at.desc())
                .limit(30)
                .all()
            )
            return [
                {
                    "approval_id": r.approval_id,
                    "agent_run_id": r.agent_run_id,
                    "provider": r.provider_format,
                    "tool_name": r.tool_name,
                    "arguments": json.loads(r.sanitized_args_json),
                    "action_digest": r.action_digest,
                    "required_quorum": r.required_quorum,
                    "signed_by_owners": json.loads(r.collected_signatures_json),
                    "reasons": json.loads(r.risk_reasons_json),
                    "status": r.status,
                }
                for r in rows
            ]
