"""Asymmetric Ed25519 + RFC 6238 TOTP + Anti-Replay Nonce Owner Verification Engine."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy.orm import Session, sessionmaker

from aegis.models import ConsumedNonceRecord, OwnerKeyRecord, canonical_sha256


@dataclass
class OwnerEnrollmentBundle:
    owner_id: str
    display_name: str
    role: str
    private_key_pem: str  # Kept OFFLINE by the Owner — NEVER stored in Aegis DB!
    public_key_pem: str
    totp_secret_b32: str
    totp_uri: str


@dataclass
class OwnerSignatureProof:
    owner_id: str
    nonce: str
    expires_at_unix: int
    signature_b64: str
    totp_code: Optional[str] = None


@dataclass
class OwnerVerificationResult:
    verified: bool
    owner_id: Optional[str]
    action_digest: str
    reason: str


class OwnerVerificationEngine:
    """
    Enforces hard cryptographic Owner authorization outside the LLM boundary.
    Because only the Owner's Ed25519 PUBLIC key resides on the server, neither a 100% jailbroken
    LLM nor an attacker with read access to agent memory can forge an approval signature.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    @staticmethod
    def compute_action_digest(
        operation: str,
        target_resource: str,
        canonical_params: Dict[str, Any],
        nonce: str,
        expires_at_unix: int,
    ) -> str:
        return canonical_sha256(
            {
                "domain": "AEGIS_OWNER_AUTH_V2",
                "operation": operation,
                "target_resource": target_resource,
                "canonical_params": canonical_params,
                "nonce": nonce,
                "expires_at_unix": int(expires_at_unix),
            }
        )

    @staticmethod
    def generate_totp(secret_b32: str, timestamp: Optional[int] = None, step: int = 30) -> str:
        """RFC 6238 6-digit HMAC-SHA1 TOTP generator."""
        ts = int(time.time()) if timestamp is None else int(timestamp)
        counter = ts // step
        key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
        return f"{code_int:06d}"

    @classmethod
    def verify_totp(
        cls, secret_b32: str, code: str, timestamp: Optional[int] = None, window: int = 1
    ) -> bool:
        if not code or not code.isdigit() or len(code) != 6:
            return False
        now_ts = int(time.time()) if timestamp is None else int(timestamp)
        for offset in range(-window, window + 1):
            candidate = cls.generate_totp(secret_b32, timestamp=now_ts + offset * 30)
            if hmac.compare_digest(candidate, code):
                return True
        return False

    def enroll_owner(
        self,
        owner_id: str,
        display_name: str,
        role: str = "PRIMARY_OWNER",
        enable_totp: bool = True,
    ) -> OwnerEnrollmentBundle:
        """
        Generates a fresh Ed25519 keypair + TOTP seed.
        Persists ONLY the Ed25519 PUBLIC key on the server and returns the PRIVATE key once to the Owner.
        """
        priv_key = Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()

        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        totp_b32 = base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")
        totp_uri = f"otpauth://totp/AegisUndo:{owner_id}?secret={totp_b32}&issuer=AegisUndo"

        with self._session_factory() as db:
            existing = db.query(OwnerKeyRecord).filter(OwnerKeyRecord.owner_id == owner_id).first()
            if existing:
                existing.display_name = display_name
                existing.role = role
                existing.ed25519_public_key_pem = pub_pem
                existing.totp_secret_b32 = totp_b32 if enable_totp else None
                existing.active = True
            else:
                db.add(
                    OwnerKeyRecord(
                        owner_id=owner_id,
                        display_name=display_name,
                        role=role,
                        ed25519_public_key_pem=pub_pem,
                        totp_secret_b32=totp_b32 if enable_totp else None,
                        active=True,
                    )
                )
            db.commit()

        return OwnerEnrollmentBundle(
            owner_id=owner_id,
            display_name=display_name,
            role=role,
            private_key_pem=priv_pem,
            public_key_pem=pub_pem,
            totp_secret_b32=totp_b32,
            totp_uri=totp_uri,
        )

    @classmethod
    def sign_action_offline(
        cls,
        private_key_pem: str,
        owner_id: str,
        operation: str,
        target_resource: str,
        canonical_params: Dict[str, Any],
        ttl_seconds: int = 120,
        totp_secret_b32: Optional[str] = None,
        totp_code: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> OwnerSignatureProof:
        """
        Client-side helper executed on the Owner's offline machine/CLI/hardware token.
        Produces a non-replayable Ed25519 signature over the exact canonical action digest.
        """
        chosen_nonce = nonce or f"nonce_{secrets.token_hex(12)}"
        expires_at = int(time.time()) + ttl_seconds
        digest = cls.compute_action_digest(
            operation=operation,
            target_resource=target_resource,
            canonical_params=canonical_params,
            nonce=chosen_nonce,
            expires_at_unix=expires_at,
        )
        priv = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise TypeError("Expected an Ed25519 private key.")
        sig_bytes = priv.sign(digest.encode("utf-8"))
        resolved_totp = totp_code or (cls.generate_totp(totp_secret_b32) if totp_secret_b32 else None)

        return OwnerSignatureProof(
            owner_id=owner_id,
            nonce=chosen_nonce,
            expires_at_unix=expires_at,
            signature_b64=base64.b64encode(sig_bytes).decode("utf-8"),
            totp_code=resolved_totp,
        )

    def verify_owner_proof(
        self,
        proof: OwnerSignatureProof,
        operation: str,
        target_resource: str,
        canonical_params: Dict[str, Any],
        require_totp: bool = True,
    ) -> OwnerVerificationResult:
        now_unix = int(time.time())
        digest = self.compute_action_digest(
            operation=operation,
            target_resource=target_resource,
            canonical_params=canonical_params,
            nonce=proof.nonce,
            expires_at_unix=proof.expires_at_unix,
        )

        if now_unix > proof.expires_at_unix:
            return OwnerVerificationResult(
                verified=False,
                owner_id=proof.owner_id,
                action_digest=digest,
                reason="Owner signature proof has expired.",
            )

        with self._session_factory() as db:
            owner = (
                db.query(OwnerKeyRecord)
                .filter(OwnerKeyRecord.owner_id == proof.owner_id, OwnerKeyRecord.active.is_(True))
                .first()
            )
            if not owner:
                return OwnerVerificationResult(
                    verified=False,
                    owner_id=proof.owner_id,
                    action_digest=digest,
                    reason=f"Unknown or deactivated owner `{proof.owner_id}`.",
                )

            # Anti-replay check
            replay = (
                db.query(ConsumedNonceRecord)
                .filter(ConsumedNonceRecord.nonce == proof.nonce)
                .first()
            )
            if replay is not None:
                return OwnerVerificationResult(
                    verified=False,
                    owner_id=proof.owner_id,
                    action_digest=digest,
                    reason="Replay Attack Blocked: Cryptographic nonce was already consumed.",
                )

            # TOTP hardware/authenticator second factor check
            if require_totp and owner.totp_secret_b32:
                if not self.verify_totp(owner.totp_secret_b32, proof.totp_code or ""):
                    return OwnerVerificationResult(
                        verified=False,
                        owner_id=proof.owner_id,
                        action_digest=digest,
                        reason="Invalid or missing 6-digit Owner TOTP authenticator code.",
                    )

            # Ed25519 asymmetric signature verification over exact payload digest
            try:
                pub = serialization.load_pem_public_key(owner.ed25519_public_key_pem.encode("utf-8"))
                if not isinstance(pub, Ed25519PublicKey):
                    raise InvalidSignature("Stored public key is not Ed25519.")
                sig_bytes = base64.b64decode(proof.signature_b64)
                pub.verify(sig_bytes, digest.encode("utf-8"))
            except (InvalidSignature, ValueError) as exc:
                return OwnerVerificationResult(
                    verified=False,
                    owner_id=proof.owner_id,
                    action_digest=digest,
                    reason=(
                        "Ed25519 Cryptographic Signature Verification FAILED: Payload was tampered "
                        f"with or signed by an unauthorized key ({exc.__class__.__name__})."
                    ),
                )

            # Consume nonce atomically so this proof can never be replayed
            db.add(
                ConsumedNonceRecord(
                    nonce=proof.nonce,
                    owner_id=proof.owner_id,
                    action_digest=digest,
                )
            )
            db.commit()

        return OwnerVerificationResult(
            verified=True,
            owner_id=proof.owner_id,
            action_digest=digest,
            reason=f"Cryptographically verified Ed25519 + TOTP proof from `{proof.owner_id}`.",
        )

    def verify_quorum(
        self,
        proofs: List[OwnerSignatureProof],
        required_quorum: int,
        operation: str,
        target_resource: str,
        canonical_params: Dict[str, Any],
        require_totp: bool = True,
    ) -> Tuple[bool, List[str], List[str]]:
        """Enforce M-of-N distinct Owner Ed25519 signatures (e.g., CEO + CISO) for crown-jewel actions."""
        verified_owners: List[str] = []
        errors: List[str] = []
        seen_owners = set()

        for p in proofs:
            if p.owner_id in seen_owners:
                errors.append(f"Duplicate signature from `{p.owner_id}` ignored for quorum.")
                continue
            res = self.verify_owner_proof(
                proof=p,
                operation=operation,
                target_resource=target_resource,
                canonical_params=canonical_params,
                require_totp=require_totp,
            )
            if res.verified and res.owner_id:
                seen_owners.add(res.owner_id)
                verified_owners.append(res.owner_id)
            else:
                errors.append(res.reason)

        return len(verified_owners) >= required_quorum, verified_owners, errors

    def list_owners(self) -> List[Dict[str, Any]]:
        with self._session_factory() as db:
            rows = db.query(OwnerKeyRecord).order_by(OwnerKeyRecord.created_at.asc()).all()
            return [
                {
                    "owner_id": r.owner_id,
                    "display_name": r.display_name,
                    "role": r.role,
                    "totp_enabled": bool(r.totp_secret_b32),
                    "active": r.active,
                    "public_key_fingerprint": hashlib.sha256(
                        r.ed25519_public_key_pem.encode("utf-8")
                    ).hexdigest()[:16],
                }
                for r in rows
            ]
