"""FastAPI Zero-Trust Control Plane: Ed25519 Owner Auth, AES-256-GCM Vault, Fine-Tuning & Surgical Undo."""

from __future__ import annotations

import asyncio
import os
import secrets
import sqlite3
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from aegis.crypto.owner_auth import OwnerSignatureProof, OwnerVerificationEngine
from aegis.crypto.vault import CanaryTripwireEngine, ZeroTrustDataVault
from aegis.guardian import (
    LiveWorkspaceGuardian,
    get_hook_status,
    install_pre_commit_hook,
)
from aegis.ml.classifier import AdversarialGuardrailClassifier
from aegis.ml.dataset import (
    AdversarialSample,
    build_base_corpus,
    build_redteam_holdout_set,
    export_gemini_vertex_jsonl,
    export_openai_sft_jsonl,
    export_trl_dpo_jsonl,
)
from aegis.ml.lora_trainer import validate_or_run_lora_finetune
from aegis.models import SourceTrust, create_db_session_factory
from aegis.runtime.gitops_guard import GitOpsGuard
from aegis.runtime.memory_guard import ProvenanceMemoryStore
from aegis.runtime.policy import PolicyEngine
from aegis.runtime.proxy import AegisProxy
from aegis.runtime.tokens import TokenBroker
from aegis.runtime.undo_db import UndoableDBEngine
from aegis.scanner.engine import ArchitectureScanner


class ScanRequest(BaseModel):
    target_path: str = Field(default=".")


class GuardianModeRequest(BaseModel):
    auto_undo: bool = False


class OwnerEnrollRequest(BaseModel):
    owner_id: str = "owner_ceo_primary"
    display_name: str = "Chief Security Owner"
    role: str = "PRIMARY_OWNER"
    enable_totp: bool = True


class OwnerProofPayload(BaseModel):
    owner_id: str
    nonce: str
    expires_at_unix: int
    signature_b64: str
    totp_code: Optional[str] = None

    def to_domain(self) -> OwnerSignatureProof:
        return OwnerSignatureProof(
            owner_id=self.owner_id,
            nonce=self.nonce,
            expires_at_unix=self.expires_at_unix,
            signature_b64=self.signature_b64,
            totp_code=self.totp_code,
        )


class OfflineSignHelperRequest(BaseModel):
    private_key_pem: str
    owner_id: str
    operation: str
    target_resource: str
    canonical_params: Dict[str, Any]
    totp_secret_b32: Optional[str] = None
    totp_code: Optional[str] = None
    ttl_seconds: int = 120


class VaultSealRequest(BaseModel):
    record_id: str
    label: str
    plaintext: str
    classification: str = "TOP_SECRET"


class VaultUnsealRequest(BaseModel):
    record_id: str
    purpose: str = "Authorized executive review"
    owner_proof: Optional[OwnerProofPayload] = None


class IssueSessionRequest(BaseModel):
    agent_name: str = "enterprise-support-agent"
    owner_identity: str = "svc-secops@corp.internal"
    allowed_tools: List[str] = Field(
        default_factory=lambda: [
            "get_order",
            "update_order",
            "read_customer_pii",
            "fetch_webhook",
            "send_wire_transfer",
        ]
    )
    ttl_seconds: int = Field(default=600, ge=10, le=86400)
    max_calls_per_minute: int = Field(default=15, ge=1, le=1000)
    total_call_budget: int = Field(default=100, ge=1, le=10000)
    max_confidential_reads: int = Field(default=5, ge=1, le=500)


class InterceptRequest(BaseModel):
    payload: Dict[str, Any]
    agent_run_id: str = Field(default_factory=lambda: f"run_{secrets.token_hex(4)}")
    session_token: Optional[str] = None
    require_token: bool = False
    untrusted_context: Optional[str] = None
    owner_proof: Optional[OwnerProofPayload] = None
    required_quorum: int = 1


class OwnerApprovalResolveRequest(BaseModel):
    approve: bool
    owner_proof: OwnerProofPayload
    oob_challenge_code: Optional[str] = None
    note: str = ""


class FineTuneCustomSample(BaseModel):
    text: str
    label: int = Field(ge=0, le=1)
    category: str = "custom_feedback"


class FineTuneRunRequest(BaseModel):
    custom_samples: List[FineTuneCustomSample] = Field(default_factory=list)
    oversample_factor: int = 3


class MemoryQuarantineRequest(BaseModel):
    source_doc_id: Optional[str] = None
    created_by_run: Optional[str] = None
    memory_id: Optional[str] = None
    reason: str = "Confirmed poisoned external context"


def _init_demo_orders_db(app_db_path: str) -> None:
    with sqlite3.connect(app_db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS customer_orders (
                id TEXT PRIMARY KEY,
                customer_email TEXT NOT NULL,
                price_usd REAL NOT NULL,
                status TEXT NOT NULL,
                updated_by TEXT NOT NULL
            )
            """
        )
        count = conn.execute("SELECT COUNT(*) FROM customer_orders").fetchone()[0]
        if count == 0:
            conn.executemany(
                "INSERT INTO customer_orders VALUES (?, ?, ?, ?, ?)",
                [
                    ("ORD-1001", "alice@enterprise.io", 1450.00, "OPEN", "human_checkout"),
                    ("ORD-1002", "bob@globalbank.com", 4800.00, "OPEN", "human_checkout"),
                    ("ORD-1003", "carol@medtech.org", 920.50, "OPEN", "human_checkout"),
                    ("ORD-1004", "dave@retailcorp.net", 310.00, "SHIPPED", "warehouse_human"),
                ],
            )
        conn.commit()


def create_app(
    state_dir: Optional[str] = None,
    watch_dir: Optional[str] = None,
    auto_undo: Optional[bool] = None,
) -> FastAPI:
    resolved_dir = os.path.abspath(state_dir or os.environ.get("AEGIS_STATE_DIR", "./aegis_state"))
    os.makedirs(resolved_dir, exist_ok=True)

    resolved_watch_dir = os.path.abspath(
        watch_dir or os.environ.get("AEGIS_WATCH_DIR", "./aegis_live_playground")
    )
    os.makedirs(resolved_watch_dir, exist_ok=True)
    starter_file = Path(resolved_watch_dir) / "app_agent.py"
    if not starter_file.exists():
        starter_file.write_text(
            '"""Sample Enterprise Customer Agent in Live Playground."""\n\n'
            'def handle_customer_inquiry(order_id: str) -> dict:\n'
            '    # Aegis Live Guardian watches this workspace in real time.\n'
            '    # Try adding a raw API key or shell=True here and press Cmd+S / Ctrl+S!\n'
            '    return {"order_id": order_id, "status": "PENDING_VERIFICATION"}\n',
            encoding="utf-8",
        )

    effective_auto_undo = (
        auto_undo
        if auto_undo is not None
        else (os.environ.get("AEGIS_AUTO_UNDO", "0").lower() in ("1", "true", "yes"))
    )
    guardian = LiveWorkspaceGuardian(
        workspace_root=resolved_watch_dir,
        auto_undo=effective_auto_undo,
    )

    control_db_url = f"sqlite:///{os.path.join(resolved_dir, 'aegis_control_plane.db')}"
    app_db_path = os.path.join(resolved_dir, "enterprise_app_data.db")
    _init_demo_orders_db(app_db_path)

    session_factory = create_db_session_factory(control_db_url)
    owner_auth = OwnerVerificationEngine(session_factory)
    vault = ZeroTrustDataVault(session_factory, owner_auth)
    canary_engine = CanaryTripwireEngine(session_factory, owner_auth)
    ml_classifier = AdversarialGuardrailClassifier()
    ml_classifier.train_base()

    token_broker = TokenBroker(session_factory)
    policy_engine = PolicyEngine(high_value_amount_threshold=5000.0, ml_classifier=ml_classifier)
    proxy = AegisProxy(
        session_factory,
        token_broker=token_broker,
        policy_engine=policy_engine,
        owner_auth=owner_auth,
        canary_engine=canary_engine,
    )
    undo_db = UndoableDBEngine(app_db_path=app_db_path, ledger_session_factory=session_factory)
    memory_store = ProvenanceMemoryStore(session_factory)
    gitops_guard = GitOpsGuard(session_factory)
    scanner = ArchitectureScanner()

    # Seed a default encrypted company crown-jewel record in the AES-256-GCM Vault
    vault.seal_record(
        record_id="vault_ma_acquisition_2026",
        label="Project Titan M&A Treasury & Customer Master Key",
        plaintext="CONFIDENTIAL_TREASURY_ESCROW=IBAN-CH9300762011623852957 | MASTER_SPLIT_SEED=9941-ALPHA-OMEGA",
        classification="TOP_SECRET",
    )

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI):
        await guardian.start_background_watcher()
        yield
        await guardian.stop_background_watcher()

    api = FastAPI(
        title="AegisUndo v2 — Zero-Trust Owner-Verified Agentic Security Platform",
        version="2.0.0",
        lifespan=lifespan,
    )

    ui_html_path = Path(__file__).resolve().parent.parent / "ui" / "dashboard.html"
    guardian_html_path = Path(__file__).resolve().parent.parent / "ui" / "guardian.html"

    @api.get("/", response_class=HTMLResponse)
    def serve_dashboard() -> str:
        return ui_html_path.read_text(encoding="utf-8")

    @api.get("/guardian", response_class=HTMLResponse)
    def serve_guardian() -> str:
        return guardian_html_path.read_text(encoding="utf-8")

    @api.get("/favicon.ico", include_in_schema=False)
    def serve_favicon() -> HTMLResponse:
        return HTMLResponse(content="", status_code=204)

    @api.get("/health")
    def health_check() -> Dict[str, Any]:
        valid, count, err = proxy.verify_audit_chain()
        locked, lock_reason = canary_engine.is_locked_down()
        return {
            "status": "locked_down" if locked else ("ok" if valid else "tamper_alert"),
            "workspace_locked": locked,
            "lockdown_reason": lock_reason,
            "audit_chain_valid": valid,
            "audit_events_count": count,
            "chain_error": err,
            "ml_training_rounds": ml_classifier.training_rounds,
        }

    # --- 1. Architecture Scanner ---

    @api.post("/v1/scan")
    def scan_architecture(req: ScanRequest) -> Dict[str, Any]:
        try:
            return scanner.scan_path(req.target_path).model_dump()
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    # --- 2. Cryptographic Owner Enrollment, Offline Sign Helper, Vault & Canary Tripwire ---

    @api.post("/v1/owners/enroll")
    def enroll_owner(req: OwnerEnrollRequest) -> Dict[str, Any]:
        bundle = owner_auth.enroll_owner(
            owner_id=req.owner_id,
            display_name=req.display_name,
            role=req.role,
            enable_totp=req.enable_totp,
        )
        return bundle.__dict__

    @api.get("/v1/owners")
    def list_owners() -> Dict[str, Any]:
        return {"owners": owner_auth.list_owners()}

    @api.post("/v1/owners/sign-helper")
    def sign_action_helper(req: OfflineSignHelperRequest) -> Dict[str, Any]:
        """Simulates the Owner's offline hardware/CLI signing utility (`aegis owner-sign`)."""
        proof = OwnerVerificationEngine.sign_action_offline(
            private_key_pem=req.private_key_pem,
            owner_id=req.owner_id,
            operation=req.operation,
            target_resource=req.target_resource,
            canonical_params=req.canonical_params,
            ttl_seconds=req.ttl_seconds,
            totp_secret_b32=req.totp_secret_b32,
            totp_code=req.totp_code,
        )
        return proof.__dict__

    @api.get("/v1/vault")
    def list_vault_records() -> Dict[str, Any]:
        return {"records": vault.list_vault_metadata()}

    @api.post("/v1/vault/seal")
    def seal_vault_record(req: VaultSealRequest) -> Dict[str, Any]:
        return vault.seal_record(
            record_id=req.record_id,
            label=req.label,
            plaintext=req.plaintext,
            classification=req.classification,
        )

    @api.post("/v1/vault/unseal")
    def unseal_vault_record(req: VaultUnsealRequest) -> Dict[str, Any]:
        try:
            domain_proof = req.owner_proof.to_domain() if req.owner_proof else None
            return vault.unseal_record_with_owner_proof(
                record_id=req.record_id,
                purpose=req.purpose,
                owner_proof=domain_proof,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @api.post("/v1/canary/plant")
    def plant_canary_token(location: str = "customer_orders.vip_notes") -> Dict[str, Any]:
        return canary_engine.plant_canary(location)

    @api.post("/v1/canary/unlock")
    def unlock_canary_lockdown(proof: OwnerProofPayload) -> Dict[str, Any]:
        return canary_engine.unlock_workspace(proof.to_domain())

    # --- 3. Adversarial Fine-Tuning & Guardrail ML Endpoints ---

    @api.post("/v1/ml/finetune")
    def run_adversarial_finetune(req: FineTuneRunRequest) -> Dict[str, Any]:
        holdout_eval, default_adaptation = build_redteam_holdout_set()
        feedback = (
            [AdversarialSample(text=s.text, label=s.label, category=s.category) for s in req.custom_samples]
            if req.custom_samples
            else default_adaptation
        )
        metrics = ml_classifier.fine_tune(
            adversarial_feedback=feedback,
            oversample_factor=req.oversample_factor,
            eval_set=holdout_eval,
        )
        ckpt = ml_classifier.save_verified_checkpoint(os.path.join(resolved_dir, "models"))
        metrics["verified_checkpoint"] = ckpt
        return metrics

    @api.post("/v1/ml/export-datasets")
    def export_llm_finetune_datasets() -> Dict[str, Any]:
        ft_dir = Path(resolved_dir) / "finetune_exports"
        corpus = build_base_corpus() + build_redteam_holdout_set()[0]
        oai_path = ft_dir / "openai_guard_sft.jsonl"
        dpo_path = ft_dir / "trl_llama_guard_dpo.jsonl"
        gem_path = ft_dir / "vertex_gemini_guard_sft.jsonl"

        n_oai = export_openai_sft_jsonl(corpus, oai_path)
        n_dpo = export_trl_dpo_jsonl(corpus, dpo_path)
        n_gem = export_gemini_vertex_jsonl(corpus, gem_path)
        lora_check = validate_or_run_lora_finetune(dpo_path, dry_run=True)

        return {
            "openai_sft_jsonl": {"path": str(oai_path), "rows": n_oai},
            "huggingface_trl_dpo_jsonl": {"path": str(dpo_path), "rows": n_dpo},
            "vertex_gemini_sft_jsonl": {"path": str(gem_path), "rows": n_gem},
            "peft_lora_validation": lora_check,
        }

    # --- 4. Sessions, Multi-Provider Proxy & Owner-Signed Approvals ---

    @api.post("/v1/sessions/issue")
    def issue_agent_session(req: IssueSessionRequest) -> Dict[str, Any]:
        return token_broker.issue_session(
            agent_name=req.agent_name,
            owner_identity=req.owner_identity,
            allowed_tools=req.allowed_tools,
            ttl_seconds=req.ttl_seconds,
            max_calls_per_minute=req.max_calls_per_minute,
            total_call_budget=req.total_call_budget,
            max_confidential_reads=req.max_confidential_reads,
        ).__dict__

    @api.get("/v1/sessions")
    def list_agent_sessions() -> Dict[str, Any]:
        return {"sessions": token_broker.list_sessions()}

    @api.post("/v1/sessions/{session_id}/revoke")
    def revoke_agent_session(session_id: str, reason: str = "Operator manual kill-switch") -> Dict[str, Any]:
        if not token_broker.revoke_session(session_id, reason=reason):
            raise HTTPException(status_code=404, detail=f"Session `{session_id}` not found.")
        return {"revoked": True, "session_id": session_id, "reason": reason}

    @api.post("/v1/proxy/intercept/{provider}")
    def intercept_tool_call(
        provider: str,
        req: InterceptRequest,
        x_aegis_session_token: Optional[str] = Header(default=None),
        x_aegis_run_id: Optional[str] = Header(default=None),
    ) -> Dict[str, Any]:
        token = req.session_token or x_aegis_session_token
        run_id = x_aegis_run_id or req.agent_run_id
        try:
            return proxy.intercept(
                provider=provider,
                payload=req.payload,
                agent_run_id=run_id,
                session_token=token,
                require_token=req.require_token or bool(token),
                untrusted_context=req.untrusted_context,
                owner_proof=req.owner_proof.to_domain() if req.owner_proof else None,
                required_quorum=req.required_quorum,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @api.get("/v1/audit")
    def get_audit_ledger() -> Dict[str, Any]:
        valid, count, err = proxy.verify_audit_chain()
        return {
            "chain_valid": valid,
            "total_verified_entries": count,
            "error": err,
            "events": proxy.list_audit_events(limit=50),
        }

    @api.get("/v1/approvals")
    def get_pending_approvals() -> Dict[str, Any]:
        return {"approvals": proxy.list_approvals()}

    @api.post("/v1/approvals/{approval_id}/resolve")
    def resolve_owner_approval(approval_id: str, req: OwnerApprovalResolveRequest) -> Dict[str, Any]:
        try:
            return proxy.resolve_approval_with_owner_signature(
                approval_id=approval_id,
                approve=req.approve,
                owner_proof=req.owner_proof.to_domain(),
                oob_challenge_code=req.oob_challenge_code,
                note=req.note,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    # --- 5. Surgical DB Undo, Memory Quarantine & Interactive Labs ---

    @api.get("/v1/db/orders")
    def list_demo_orders() -> Dict[str, Any]:
        with sqlite3.connect(app_db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = [dict(r) for r in conn.execute("SELECT * FROM customer_orders ORDER BY id").fetchall()]
        return {"orders": rows}

    @api.post("/v1/db/rollback/{agent_run_id}")
    def rollback_agent_db_run(agent_run_id: str, force: bool = False) -> Dict[str, Any]:
        summary = undo_db.rollback_run(agent_run_id, force_overwrite_conflicts=force)
        return summary.__dict__

    @api.post("/v1/memory/quarantine")
    def quarantine_poisoned_memory(req: MemoryQuarantineRequest) -> Dict[str, Any]:
        rep = memory_store.quarantine(
            source_doc_id=req.source_doc_id,
            created_by_run=req.created_by_run,
            memory_id=req.memory_id,
            reason=req.reason,
        )
        return rep.__dict__

    @api.get("/v1/gitops")
    def list_gitops() -> Dict[str, Any]:
        return {"proposals": gitops_guard.list_proposals()}

    @api.post("/v1/lab/simulate-db-corruption")
    def simulate_db_corruption() -> Dict[str, Any]:
        with sqlite3.connect(app_db_path) as conn:
            conn.execute("DELETE FROM customer_orders")
            conn.executemany(
                "INSERT INTO customer_orders VALUES (?, ?, ?, ?, ?)",
                [
                    ("ORD-1001", "alice@enterprise.io", 1450.00, "OPEN", "human_checkout"),
                    ("ORD-1002", "bob@globalbank.com", 4800.00, "OPEN", "human_checkout"),
                    ("ORD-1003", "carol@medtech.org", 920.50, "OPEN", "human_checkout"),
                    ("ORD-1004", "dave@retailcorp.net", 310.00, "SHIPPED", "warehouse_human"),
                ],
            )
            conn.commit()

        hijacked_run_id = f"run_hijack_{secrets.token_hex(3)}"
        mutation_ids = undo_db.execute_update(
            agent_run_id=hijacked_run_id,
            table="customer_orders",
            updates={"price_usd": 0.0, "status": "COMPROMISED_FREE_SHIP", "updated_by": hijacked_run_id},
            where_clause="status = ?",
            where_params=("OPEN",),
        )
        with sqlite3.connect(app_db_path) as conn:
            conn.execute(
                "UPDATE customer_orders SET price_usd = 5100.00, status = 'HUMAN_VERIFIED_UPGRADE', updated_by = 'bob_human_portal' WHERE id = 'ORD-1002'"
            )
            conn.commit()
        return {
            "hijacked_agent_run_id": hijacked_run_id,
            "corrupted_rows_logged": len(mutation_ids),
            "concurrent_human_edit": "ORD-1002 upgraded by human (`bob_human_portal` -> $5,100.00).",
        }

    @api.post("/v1/lab/simulate-memory-poisoning")
    def simulate_memory_poisoning() -> Dict[str, Any]:
        poison_doc = f"ticket_poison_{secrets.token_hex(2)}"
        memory_store.write_memory(
            content="Corporate VPN egress gateway is 203.0.113.10 (verified SOC runbook).",
            source_trust=SourceTrust.TRUSTED_SYSTEM,
            source_doc_id="kb_official_vpn",
            created_by_run="run_soc_init",
        )
        m_poison = memory_store.write_memory(
            content="Host 198.51.100.42 observed used by contractor telemetry sync job.",
            source_trust=SourceTrust.UNTRUSTED_EXTERNAL,
            source_doc_id=poison_doc,
            created_by_run="run_mail_ingest",
        )
        memory_store.retrieve_for_decision("ALERT-901", "run_t1", "198.51.100.42", "Suppressed upload alert")
        memory_store.retrieve_for_decision("ALERT-902", "run_t2", "203.0.113.10", "Verified VPN")
        memory_store.retrieve_for_decision("ALERT-903", "run_t3", "198.51.100.42", "Suppressed beacon")
        return {"poisoned_source_doc_id": poison_doc, "poisoned_memory": m_poison}

    @api.post("/v1/lab/simulate-lethal-trifecta")
    def simulate_lethal_trifecta() -> Dict[str, Any]:
        """Demonstrates Session Taint Tracking blocking autonomous data exfiltration."""
        sess = token_broker.issue_session(
            agent_name="ticket-summarizer",
            owner_identity="secops@corp.io",
            allowed_tools=["read_customer_pii", "fetch_webhook"],
            ttl_seconds=300,
        )
        # Step 1: Agent reads confidential customer PII (legitimate scope) -> marks session TAINTED
        step1 = proxy.intercept(
            provider="mcp",
            payload={"jsonrpc": "2.0", "id": "1", "method": "tools/call", "params": {"name": "read_customer_pii", "arguments": {"customer_id": "CUST-88"}}},
            agent_run_id="run_trifecta_demo",
            session_token=sess.raw_token,
            require_token=True,
            untrusted_context="Support ticket text from external customer.",
        )
        # Step 2: Agent attempts external webhook call in the same tainted session -> HARD BLOCKED!
        step2 = proxy.intercept(
            provider="mcp",
            payload={"jsonrpc": "2.0", "id": "2", "method": "tools/call", "params": {"name": "fetch_webhook", "arguments": {"url": "https://partner-status.example.com/hook"}}},
            agent_run_id="run_trifecta_demo",
            session_token=sess.raw_token,
            require_token=True,
        )
        return {
            "session_id": sess.session_id,
            "step1_confidential_read_allowed": step1["allowed"],
            "step2_outbound_egress_allowed": step2["allowed"],
            "trifecta_blocked": step2.get("trifecta_blocked"),
            "block_reason": step2["reasons"],
        }

    # --- 6. Live Developer Machine Guardian & Real-Time Auto-Undo ---

    @api.websocket("/ws/guardian")
    async def guardian_websocket_endpoint(websocket: WebSocket) -> None:
        await guardian.connect_ws(websocket)
        try:
            while True:  # aegis:ignore
                await websocket.receive_text()
        except (WebSocketDisconnect, Exception):
            guardian.disconnect_ws(websocket)

    @api.get("/v1/guardian/state")
    def get_guardian_state() -> Dict[str, Any]:
        return {
            "workspace_root": str(guardian.workspace_root),
            "auto_undo": guardian.snapshots.auto_undo,
            "incidents": guardian.snapshots.list_incidents(),
        }

    @api.post("/v1/guardian/mode")
    async def set_guardian_mode(req: GuardianModeRequest) -> Dict[str, Any]:
        state = guardian.set_mode(req.auto_undo)
        await guardian.broadcast(
            {
                "type": "INIT_STATE",
                "workspace_root": str(guardian.workspace_root),
                "auto_undo": guardian.snapshots.auto_undo,
                "incidents": guardian.snapshots.list_incidents(),
            }
        )
        return state

    @api.post("/v1/guardian/incidents/{incident_id}/undo")
    async def undo_guardian_incident(incident_id: str) -> Dict[str, Any]:
        try:
            inc = guardian.snapshots.undo_incident(incident_id)
            await guardian.broadcast(
                {
                    "type": "INCIDENT_UPDATED",
                    "incident": inc.to_dict(),
                }
            )
            return inc.to_dict()
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @api.post("/v1/guardian/incidents/{incident_id}/owner-approve")
    async def owner_approve_guardian_incident(
        incident_id: str, proof: OwnerProofPayload
    ) -> Dict[str, Any]:
        target_inc = None
        for item in guardian.snapshots._incidents:
            if item.incident_id == incident_id:
                target_inc = item
                break
        if target_inc is None:
            raise HTTPException(status_code=404, detail=f"Incident `{incident_id}` not found.")

        verification = owner_auth.verify_owner_proof(
            proof=proof.to_domain(),
            operation="GUARDIAN_FILE_EXCEPTION",
            target_resource=incident_id,
            canonical_params={"incident_id": incident_id, "rel_path": target_inc.rel_path},
        )
        if not verification.verified:
            raise HTTPException(
                status_code=403,
                detail=f"Owner signature verification failed: {verification.reason}",
            )

        inc = guardian.snapshots.approve_exception_with_owner(
            incident_id=incident_id,
            verified_owner_id=verification.owner_id or proof.owner_id,
        )
        await guardian.broadcast(
            {
                "type": "INCIDENT_UPDATED",
                "incident": inc.to_dict(),
            }
        )
        return inc.to_dict()

    @api.post("/v1/guardian/simulate-mistake")
    async def simulate_guardian_mistake(kind: str = "secret") -> Dict[str, Any]:
        target_file = guardian.workspace_root / "app_agent.py"
        target_file.parent.mkdir(parents=True, exist_ok=True)

        if kind == "secret":
            key_pfx = "sk" + "-proj-"
            dummy_key = key_pfx + "SIMULATED_DEMO_LEAKED_KEY_1234567890ABCDEF"
            code_snippet = f'\n# Risky change: Hardcoded API secret\nOPENAI_API_KEY = "{dummy_key}"\n'
        elif kind == "shell":
            code_snippet = (
                "\n# Risky change: Arbitrary shell command execution\n"
                "import subprocess\n"
                "def run_bad_cmd(cmd: str):\n"
                "    return subprocess.run(cmd, " + "shell" + "=True)\n"
            )
        else:
            code_snippet = (
                '\n# Risky change: Destructive raw SQL mutation\n'
                'raw_query = "DELETE FROM customer_orders WHERE id = 1"\n'
            )

        current = target_file.read_text(encoding="utf-8") if target_file.exists() else ""
        target_file.write_text(current + code_snippet, encoding="utf-8")

        inc = guardian.process_file_event(target_file)
        if inc is not None:
            await guardian.broadcast(
                {
                    "type": "NEW_INCIDENT",
                    "incident": inc.to_dict(),
                }
            )
            return inc.to_dict()
        return {"status": "ok", "message": "File written; automatically undone or no incident."}

    @api.post("/v1/guardian/install-git-hook")
    def install_guardian_git_hook(fail_under: int = 95) -> Dict[str, Any]:
        git_dir = guardian.workspace_root / ".git"
        if not git_dir.exists():
            subprocess.run(
                ["/usr/bin/git", "init", str(guardian.workspace_root)],
                shell=False,
                env={"PATH": "/usr/bin:/bin"},
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        try:
            return install_pre_commit_hook(guardian.workspace_root, fail_under=fail_under)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @api.get("/v1/guardian/git-hook-status")
    def get_guardian_git_hook_status() -> Dict[str, Any]:
        return get_hook_status(guardian.workspace_root)

    return api


app = create_app()
