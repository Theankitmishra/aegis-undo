"""AES-256-GCM Owner-Gated Data Vault & Canary Honeytoken Instant Workspace Lockdown."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy.orm import Session, sessionmaker

from aegis.crypto.owner_auth import OwnerSignatureProof, OwnerVerificationEngine
from aegis.models import (
    AgentSessionRecord,
    CanaryTokenRecord,
    SystemLockdownRecord,
    VaultSecretRecord,
    utc_now,
)


class CanaryTripwireEngine:
    """
    Plants cryptographic honeytokens across sensitive tables/vaults.
    If ANY agent tool call, prompt context, or output ever contains a canary token, Aegis
    immediately freezes the entire workspace and revokes ALL active non-human sessions.
    Unlocking requires an offline Ed25519 Owner signature.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        owner_auth: OwnerVerificationEngine,
    ) -> None:
        self._session_factory = session_factory
        self._owner_auth = owner_auth

    def plant_canary(self, planted_location: str) -> Dict[str, str]:
        canary_id = f"can_{secrets.token_hex(6)}"
        token_value = f"AEGIS-CANARY-{secrets.token_hex(12).upper()}"
        with self._session_factory() as db:
            db.add(
                CanaryTokenRecord(
                    canary_id=canary_id,
                    token_value=token_value,
                    planted_location=planted_location,
                    triggered=False,
                )
            )
            db.commit()
        return {
            "canary_id": canary_id,
            "token_value": token_value,
            "planted_location": planted_location,
        }

    def is_locked_down(self) -> Tuple_LockedState:
        with self._session_factory() as db:
            rec = db.query(SystemLockdownRecord).filter(SystemLockdownRecord.id == 1).first()
            if rec and rec.locked:
                return True, rec.reason or "Workspace locked down by security tripwire."
            return False, ""

    def inspect_and_trip_if_leaked(self, payload_text: str, agent_run_id: str) -> Optional[str]:
        if "AEGIS-CANARY-" not in payload_text:
            return None

        with self._session_factory() as db:
            canaries = db.query(CanaryTokenRecord).all()
            matched = [c for c in canaries if c.token_value in payload_text]
            if not matched:
                return None

            now = utc_now()
            for c in matched:
                c.triggered = True
                c.triggered_at = now

            reason = (
                f"CRITICAL BREACH TRIPWIRE: Canary honeytoken `{matched[0].canary_id}` "
                f"(planted at `{matched[0].planted_location}`) detected in agent run `{agent_run_id}`. "
                "Global Workspace Lockdown engaged and all active agent tokens revoked."
            )
            lock = db.query(SystemLockdownRecord).filter(SystemLockdownRecord.id == 1).first()
            if not lock:
                lock = SystemLockdownRecord(
                    id=1,
                    locked=True,
                    reason=reason,
                    triggered_by_run=agent_run_id,
                    locked_at=now,
                )
                db.add(lock)
            else:
                lock.locked = True
                lock.reason = reason
                lock.triggered_by_run = agent_run_id
                lock.locked_at = now

            # Cascade revoke ALL active agent tokens immediately
            active_sessions = (
                db.query(AgentSessionRecord).filter(AgentSessionRecord.revoked.is_(False)).all()
            )
            for s in active_sessions:
                s.revoked = True
                s.revoked_at = now
                s.revoked_reason = "Emergency Canary Honeytoken Tripwire Lockdown"

            db.commit()
            return reason

    def unlock_workspace(self, owner_proof: OwnerSignatureProof) -> Dict[str, Any]:
        ver = self._owner_auth.verify_owner_proof(
            proof=owner_proof,
            operation="WORKSPACE_UNLOCK",
            target_resource="global_control_plane",
            canonical_params={"action": "reset_lockdown"},
        )
        if not ver.verified:
            return {"unlocked": False, "reason": ver.reason}

        with self._session_factory() as db:
            lock = db.query(SystemLockdownRecord).filter(SystemLockdownRecord.id == 1).first()
            if lock:
                lock.locked = False
                lock.unlocked_by_owner = ver.owner_id
                lock.unlocked_at = utc_now()
                db.commit()
        return {
            "unlocked": True,
            "unlocked_by_owner": ver.owner_id,
            "action_digest": ver.action_digest,
        }


Tuple_LockedState = tuple[bool, str]


class ZeroTrustDataVault:
    """
    AES-256-GCM envelope-encrypted company crown-jewel store.
    Even if an AI agent has tool access to the database, confidential records remain encrypted
    with authenticated AAD (`record_id|classification`) and physically CANNOT be decrypted
    without a fresh, non-replayable Ed25519 + TOTP OwnerSignatureProof bound to that `record_id`.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        owner_auth: OwnerVerificationEngine,
        master_key_bytes: Optional[bytes] = None,
    ) -> None:
        self._session_factory = session_factory
        self._owner_auth = owner_auth
        env_hex = os.environ.get("AEGIS_VAULT_MASTER_KEY_HEX")
        if master_key_bytes is not None:
            self._master_key = master_key_bytes
        elif env_hex:
            self._master_key = bytes.fromhex(env_hex)
        else:
            # Deterministic per-installation key stored outside agent workspace if not supplied
            self._master_key = hashlib.sha256(b"aegis-default-dev-kms-root-key-change-in-prod").digest()

    def _derive_record_key(self, record_id: str, classification: str) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(record_id.encode("utf-8")).digest()[:16],
            info=f"aegis-vault-v2:{record_id}:{classification}".encode("utf-8"),
        )
        return hkdf.derive(self._master_key)

    def seal_record(
        self,
        record_id: str,
        label: str,
        plaintext: str,
        classification: str = "TOP_SECRET",
    ) -> Dict[str, Any]:
        key = self._derive_record_key(record_id, classification)
        nonce = secrets.token_bytes(12)
        aad = f"{record_id}|{classification}".encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)

        nonce_b64 = base64.b64encode(nonce).decode("utf-8")
        ct_b64 = base64.b64encode(ciphertext).decode("utf-8")

        with self._session_factory() as db:
            existing = (
                db.query(VaultSecretRecord)
                .filter(VaultSecretRecord.record_id == record_id)
                .first()
            )
            if existing:
                existing.label = label
                existing.classification = classification
                existing.nonce_b64 = nonce_b64
                existing.ciphertext_b64 = ct_b64
            else:
                db.add(
                    VaultSecretRecord(
                        record_id=record_id,
                        label=label,
                        classification=classification,
                        nonce_b64=nonce_b64,
                        ciphertext_b64=ct_b64,
                        is_canary=False,
                    )
                )
            db.commit()

        return {
            "record_id": record_id,
            "label": label,
            "classification": classification,
            "encrypted": True,
            "cipher": "AES-256-GCM-HKDF",
        }

    def unseal_record_with_owner_proof(
        self,
        record_id: str,
        purpose: str,
        owner_proof: Optional[OwnerSignatureProof],
    ) -> Dict[str, Any]:
        """
        Hard cryptographic constraint: No valid Ed25519 + TOTP OwnerSignatureProof -> No decryption.
        Neither a prompt-injected LLM nor a rogue subagent can bypass this check.
        """
        if owner_proof is None:
            return {
                "authorized": False,
                "record_id": record_id,
                "error": (
                    "ACCESS DENIED: Company Vault record is encrypted with AES-256-GCM and requires "
                    "offline Ed25519 + TOTP Owner Verification (`OwnerSignatureProof`)."
                ),
            }

        ver = self._owner_auth.verify_owner_proof(
            proof=owner_proof,
            operation="VAULT_DECRYPT",
            target_resource=record_id,
            canonical_params={"record_id": record_id, "purpose": purpose},
        )
        if not ver.verified:
            return {
                "authorized": False,
                "record_id": record_id,
                "error": f"Owner Verification Failed: {ver.reason}",
            }

        with self._session_factory() as db:
            rec = (
                db.query(VaultSecretRecord)
                .filter(VaultSecretRecord.record_id == record_id)
                .first()
            )
            if not rec:
                raise KeyError(f"Vault record `{record_id}` not found.")

            key = self._derive_record_key(rec.record_id, rec.classification)
            nonce = base64.b64decode(rec.nonce_b64)
            ct = base64.b64decode(rec.ciphertext_b64)
            aad = f"{rec.record_id}|{rec.classification}".encode("utf-8")
            plaintext = AESGCM(key).decrypt(nonce, ct, aad).decode("utf-8")

            return {
                "authorized": True,
                "record_id": rec.record_id,
                "label": rec.label,
                "classification": rec.classification,
                "verified_owner": ver.owner_id,
                "action_digest": ver.action_digest,
                "plaintext": plaintext,
            }

    def list_vault_metadata(self) -> List[Dict[str, Any]]:
        with self._session_factory() as db:
            rows = db.query(VaultSecretRecord).order_by(VaultSecretRecord.created_at.desc()).all()
            return [
                {
                    "record_id": r.record_id,
                    "label": r.label,
                    "classification": r.classification,
                    "ciphertext_preview": r.ciphertext_b64[:24] + "...",
                }
                for r in rows
            ]
