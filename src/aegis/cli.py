"""Enterprise CLI for AegisUndo v2: Scanner, Adversarial Fine-Tuning, Ed25519 Owner Auth & Server."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import List, Optional

import typer
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aegis.crypto.owner_auth import OwnerVerificationEngine
from aegis.crypto.vault import CanaryTripwireEngine, ZeroTrustDataVault
from aegis.guardian import (
    McpStdioFirewall,
    get_hook_status,
    install_pre_commit_hook,
    uninstall_pre_commit_hook,
)
from aegis.ml.classifier import AdversarialGuardrailClassifier
from aegis.ml.dataset import (
    build_base_corpus,
    build_redteam_holdout_set,
    export_gemini_vertex_jsonl,
    export_openai_sft_jsonl,
    export_trl_dpo_jsonl,
)
from aegis.ml.lora_trainer import validate_or_run_lora_finetune
from aegis.models import SourceTrust, create_db_session_factory
from aegis.runtime.memory_guard import ProvenanceMemoryStore
from aegis.runtime.proxy import AegisProxy
from aegis.runtime.undo_db import UndoableDBEngine
from aegis.scanner.engine import ArchitectureScanner, to_markdown_report, to_sarif_report

app = typer.Typer(
    name="aegis",
    help="AegisUndo v2 — Zero-Trust Owner-Verified Agentic Security Platform with Fine-Tuning & Surgical Undo",
    add_completion=False,
)
console = Console()


@app.command("scan")
def scan_command(
    target: str = typer.Argument(".", help="Directory or file path of the AI agent project to audit"),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table | json | markdown | sarif"
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Optional path to write JSON/Markdown/SARIF report"
    ),
    fail_under: int = typer.Option(
        0, "--fail-under", help="Exit with code 1 if architecture score falls below this threshold"
    ),
) -> None:
    """Audit an AI agent repository (Python AST, MCP JSON, Dockerfile, Terraform) for security weak points."""
    scanner = ArchitectureScanner()
    report = scanner.scan_path(target)

    fmt = output_format.lower().strip()
    rendered_text: Optional[str] = None
    if fmt == "json":
        rendered_text = json.dumps(report.model_dump(), indent=2)
    elif fmt == "sarif":
        rendered_text = json.dumps(to_sarif_report(report), indent=2)
    elif fmt == "markdown":
        rendered_text = to_markdown_report(report)

    if output_file and rendered_text is not None:
        Path(output_file).write_text(rendered_text, encoding="utf-8")
        console.print(f"[green]Wrote {fmt.upper()} report to:[/green] {output_file}")
    elif rendered_text is not None:
        print(rendered_text)
    else:
        _render_rich_scan(report)
        if output_file:
            Path(output_file).write_text(to_markdown_report(report), encoding="utf-8")
            console.print(f"[green]Saved Markdown executive report to:[/green] {output_file}")

    if report.architecture_score < fail_under:
        console.print(
            f"[bold red]CI Gate Failed:[/bold red] Architecture score {report.architecture_score}/100 "
            f"is below required threshold ({fail_under})."
        )
        raise typer.Exit(code=1)


def _render_rich_scan(report) -> None:
    score_color = "green" if report.architecture_score >= 90 else ("yellow" if report.architecture_score >= 70 else "red")
    console.print(
        Panel.fit(
            f"[bold]Target:[/bold] {report.target_path}\n"
            f"[bold]Files Scanned:[/bold] {report.scanned_files_count}\n"
            f"[bold]Architecture Score:[/bold] [{score_color}]{report.architecture_score}/100 — {report.posture_grade}[/{score_color}]\n"
            f"[bold]Severity Breakdown:[/bold] "
            f"CRITICAL={report.summary_by_severity['CRITICAL']} | "
            f"HIGH={report.summary_by_severity['HIGH']} | "
            f"MEDIUM={report.summary_by_severity['MEDIUM']} | "
            f"LOW={report.summary_by_severity['LOW']}",
            title="AegisUndo v2 Enterprise Architecture Audit",
            border_style=score_color,
        )
    )

    nist_table = Table(title="NIST AI RMF 1.0 Pillar Posture")
    nist_table.add_column("Function", style="bold cyan")
    nist_table.add_column("Status")
    nist_table.add_column("Open Findings", justify="right")
    nist_table.add_column("Focus Area")
    for fn, meta in report.nist_rmf_coverage.items():
        st = meta["status"]
        badge = f"[green]{st}[/green]" if st == "PASS" else (f"[red]{st}[/red]" if st == "FAIL" else f"[yellow]{st}[/yellow]")
        nist_table.add_row(fn, badge, str(meta["open_findings"]), meta["description"])
    console.print(nist_table)

    if report.findings:
        f_table = Table(title="Detected Weak Points & Remediations", show_lines=True, expand=True)
        f_table.add_column("Rule / Severity", ratio=2, min_width=16)
        f_table.add_column("Weakness & Enterprise Fix", ratio=6, min_width=38)
        f_table.add_column("Undo?", ratio=1, min_width=8)
        for f in report.findings:
            sev_style = "bold red" if f.severity.value == "CRITICAL" else ("yellow" if f.severity.value == "HIGH" else "magenta")
            f_table.add_row(
                f"[{sev_style}]{f.severity.value}[/{sev_style}]\n[bold]{f.rule_id}[/bold]\n[dim]{f.file_path}:{f.line_number}[/dim]",
                f"[bold]{f.title}[/bold]\n[dim]{f.why_weak}[/dim]\n[green]Fix:[/green] {f.remediation}",
                "Yes" if f.is_undoable_once_exploited else "[red]Block[/red]",
            )
        console.print(f_table)
    else:
        console.print("[bold green]Zero static/config architectural weaknesses detected![/bold green]")

    r_table = Table(title="Enforced Hard Constraints & Cryptographic Guarantees", show_lines=True)
    r_table.add_column("Threat Vector", style="bold")
    r_table.add_column("Enforced Hard Constraint")
    r_table.add_column("Cryptographic Guarantee", style="green")
    for r in report.residual_risks:
        r_table.add_row(r.threat_vector, r.enforced_hard_constraint, r.cryptographic_guarantee)
    console.print(r_table)


@app.command("finetune")
def finetune_command(
    export_dir: str = typer.Option("./aegis_state/finetune", "--export-dir", help="Output directory for fine-tuned weights & JSONL"),
) -> None:
    """Train & fine-tune the Adversarial Semantic Guardrail + export OpenAI SFT, Llama LoRA DPO & Gemini JSONL."""
    out = Path(export_dir)
    out.mkdir(parents=True, exist_ok=True)

    clf = AdversarialGuardrailClassifier()
    clf.train_base()
    holdout_eval, adaptation = build_redteam_holdout_set()
    result = clf.fine_tune(adaptation, oversample_factor=4, eval_set=holdout_eval)
    ckpt = clf.save_verified_checkpoint(out / "checkpoint")

    full_corpus = build_base_corpus() + holdout_eval
    oai_count = export_openai_sft_jsonl(full_corpus, out / "openai_guard_sft.jsonl")
    dpo_path = out / "trl_llama_guard_dpo.jsonl"
    dpo_count = export_trl_dpo_jsonl(full_corpus, dpo_path)
    gem_count = export_gemini_vertex_jsonl(full_corpus, out / "vertex_gemini_sft.jsonl")
    lora_spec = validate_or_run_lora_finetune(dpo_path, dry_run=True)

    console.print(
        Panel.fit(
            f"[bold cyan]Before Fine-Tuning (Novel Red-Team Holdout):[/bold cyan] "
            f"Recall={result['before']['recall']} | F1={result['before']['f1']} | Acc={result['before']['accuracy']}\n"
            f"[bold green]After Adversarial Fine-Tuning:[/bold green]               "
            f"Recall={result['after']['recall']} | F1={result['after']['f1']} | Acc={result['after']['accuracy']}\n"
            f"[bold]Verified Checkpoint SHA-256:[/bold] {ckpt['sha256']}\n"
            f"[bold]Exported LLM Datasets:[/bold] OpenAI SFT ({oai_count}), HuggingFace TRL LoRA DPO ({dpo_count}), Gemini Vertex ({gem_count})\n"
            f"[bold]PEFT/LoRA Config Status:[/bold] {lora_spec['status']} ({lora_spec['lora_config']['base_model_id']})",
            title="AegisUndo Adversarial Fine-Tuning Pipeline Complete",
            border_style="green",
        )
    )


@app.command("demo-zero-trust")
def demo_zero_trust_command() -> None:
    """Run an end-to-end live proof of Ed25519 Owner Verification, Vault Encryption, Canary Lockdown, Trifecta & Surgical Undo."""
    with tempfile.TemporaryDirectory() as tmp:
        factory = create_db_session_factory(f"sqlite:///{tmp}/control.db")
        owner_auth = OwnerVerificationEngine(factory)
        vault = ZeroTrustDataVault(factory, owner_auth)
        canary = CanaryTripwireEngine(factory, owner_auth)
        proxy = AegisProxy(factory, owner_auth=owner_auth, canary_engine=canary)

        # 1. Enroll Owner & seal company secret in AES-256-GCM Vault
        owner = owner_auth.enroll_owner("ceo_ankit", "Company Founder", enable_totp=True)
        vault.seal_record("vault_crown_jewels", "Customer Master DB Key", "SUPER_SECRET_KEY_998877")

        # 2. Rogue LLM tries to unseal without Owner signature -> DENIED
        denied = vault.unseal_record_with_owner_proof("vault_crown_jewels", "rogue_llm", owner_proof=None)
        console.print(f"[bold red]1. Rogue LLM Vault Unseal (No Owner Signature):[/bold red] authorized={denied['authorized']} ({denied['error']})")

        # 3. Owner signs offline with Ed25519 + RFC 6238 TOTP -> UNSEALED
        proof = OwnerVerificationEngine.sign_action_offline(
            private_key_pem=owner.private_key_pem,
            owner_id=owner.owner_id,
            operation="VAULT_DECRYPT",
            target_resource="vault_crown_jewels",
            canonical_params={"record_id": "vault_crown_jewels", "purpose": "founder_audit"},
            totp_secret_b32=owner.totp_secret_b32,
        )
        ok = vault.unseal_record_with_owner_proof("vault_crown_jewels", "founder_audit", owner_proof=proof)
        console.print(f"[bold green]2. Offline Ed25519 + TOTP Owner Unseal:[/bold green] authorized={ok['authorized']} | owner={ok['verified_owner']} | plaintext={ok['plaintext']}")

        # 4. Replay attack with the exact same Owner signature -> BLOCKED
        replay = vault.unseal_record_with_owner_proof("vault_crown_jewels", "founder_audit", owner_proof=proof)
        console.print(f"[bold yellow]3. Replay Attack Using Captured Owner Signature:[/bold yellow] authorized={replay['authorized']} ({replay['error']})")

        # 5. Canary Honeytoken Tripwire -> Instant Global Workspace Lockdown -> Owner Unlock
        c_tok = canary.plant_canary("orders.honeypot_row")
        trip = proxy.intercept(
            provider="mcp",
            payload={"jsonrpc": "2.0", "id": "1", "method": "tools/call", "params": {"name": "fetch_webhook", "arguments": {"data": c_tok["token_value"]}}},
            agent_run_id="run_attacker_exfil",
            require_token=False,
        )
        console.print(f"[bold red]4. Canary Honeytoken Exfil Attempt:[/bold red] allowed={trip['allowed']} | workspace_locked={trip['workspace_locked']}")

        unlock_proof = OwnerVerificationEngine.sign_action_offline(
            private_key_pem=owner.private_key_pem,
            owner_id=owner.owner_id,
            operation="WORKSPACE_UNLOCK",
            target_resource="global_control_plane",
            canonical_params={"action": "reset_lockdown"},
            totp_secret_b32=owner.totp_secret_b32,
        )
        unlocked = canary.unlock_workspace(unlock_proof)
        console.print(f"[bold green]5. Owner Ed25519 Workspace Unlock:[/bold green] {unlocked}")


@app.command("demo-undo")
def demo_undo_command() -> None:
    """Run an end-to-end live demonstration of Surgical DB & Memory Poisoning Undo."""
    with tempfile.TemporaryDirectory() as tmp:
        ledger_factory = create_db_session_factory(f"sqlite:///{tmp}/ledger.db")
        app_db = f"{tmp}/orders.db"
        with sqlite3.connect(app_db) as conn:
            conn.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, customer TEXT, price REAL, status TEXT)")
            conn.executemany(
                "INSERT INTO orders VALUES (?, ?, ?, ?)",
                [
                    ("ORD-1", "alice@corp.com", 1200.0, "OPEN"),
                    ("ORD-2", "bob@bank.com", 4900.0, "OPEN"),
                    ("ORD-3", "carol@org.io", 750.0, "OPEN"),
                ],
            )
            conn.commit()

        undo_engine = UndoableDBEngine(app_db, ledger_factory)
        undo_engine.execute_update(
            agent_run_id="run_evil_77",
            table="orders",
            updates={"price": 0.0, "status": "FREE_SHIP"},
            where_clause="status = ?",
            where_params=("OPEN",),
        )
        with sqlite3.connect(app_db) as conn:
            conn.execute("UPDATE orders SET price = 5250.0, status = 'HUMAN_UPGRADE' WHERE id = 'ORD-2'")
            conn.commit()

        summary = undo_engine.rollback_run("run_evil_77")
        console.print(
            f"[bold green]Surgical DB Undo:[/bold green] Reverted={summary.reverted_count}, "
            f"Human Conflicts Preserved={len(summary.skipped_human_conflicts)}"
        )

        mem = ProvenanceMemoryStore(ledger_factory)
        mem.write_memory(
            content="Host 198.51.100.42 used for telemetry.",
            source_trust=SourceTrust.UNTRUSTED_EXTERNAL,
            source_doc_id="email_poison_42",
            created_by_run="run_ingest_1",
        )
        mem.retrieve_for_decision("DECISION-A1", "run_soc_1", "198.51.100.42", "Marked alert benign")
        q_rep = mem.quarantine(source_doc_id="email_poison_42")
        console.print(f"[bold green]Memory Quarantine:[/bold green] Tainted Decisions={q_rep.tainted_decisions}")


@app.command("serve")
def serve_command(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload"),
) -> None:
    """Start the AegisUndo v2 FastAPI Control Plane & Web Dashboard."""
    console.print(
        Panel.fit(
            f"[bold green]Starting AegisUndo v2 Zero-Trust Control Plane[/bold green]\n"
            f"Dashboard UI: http://{host}:{port}/\n"
            f"OpenAPI Docs: http://{host}:{port}/docs",
            border_style="green",
        )
    )
    uvicorn.run("aegis.api.app:app", host=host, port=port, reload=reload)


@app.command("watch")
def watch_command(
    target: str = typer.Argument(
        "./aegis_live_playground",
        help="Workspace directory to guard alongside the developer in real time",
    ),
    port: int = typer.Option(
        8000, "--port", "-p", help="Port for the Guardian Companion UI & WebSockets"
    ),
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind"),
    auto_undo: bool = typer.Option(
        False,
        "--auto-undo",
        help="Strict Auto-Undo Shield: automatically revert CRITICAL/HIGH mistakes in milliseconds",
    ),
) -> None:
    """Run the Live Machine Guardian alongside your editor: real-time file save inspection, native macOS alerts, live diffs & instant auto-undo."""
    resolved_target = Path(target).resolve()
    resolved_target.mkdir(parents=True, exist_ok=True)
    os.environ["AEGIS_WATCH_DIR"] = str(resolved_target)
    os.environ["AEGIS_AUTO_UNDO"] = "1" if auto_undo else "0"

    mode_label = (
        "[bold green]Strict Auto-Undo Shield (Active)[/bold green]"
        if auto_undo
        else "[bold yellow]Alert + 1-Click Undo Mode[/bold yellow]"
    )
    console.print(
        Panel.fit(
            f"[bold]Guarded Workspace:[/bold] {resolved_target}\n"
            f"[bold]Protection Mode:[/bold]   {mode_label}\n"
            f"[bold cyan]Companion UI:[/bold cyan]      http://{host}:{port}/guardian\n"
            f"[bold]SOC Dashboard:[/bold]     http://{host}:{port}/\n"
            f"[dim]Watches file saves in real time. Dispatches native desktop alerts & colorized diffs on mistakes.[/dim]",
            title="🛡️  Aegis Live Machine Guardian Armed",
            border_style="green" if auto_undo else "blue",
        )
    )
    uvicorn.run("aegis.api.app:app", host=host, port=port, log_level="warning")


@app.command("install-hook")
def install_hook_command(
    repo_dir: str = typer.Argument(".", help="Path to Git repository root"),
    fail_under: int = typer.Option(
        95, "--fail-under", help="Minimum required architecture score to allow commit"
    ),
) -> None:
    """Install an executable Git pre-commit security blocker hook (`.git/hooks/pre-commit`)."""
    try:
        res = install_pre_commit_hook(repo_dir=repo_dir, fail_under=fail_under)
        console.print(
            Panel.fit(
                f"[bold green]Armed Pre-Commit Security Blocker Hook[/bold green]\n"
                f"Hook Path:        {res['hook_path']}\n"
                f"Fail-Under Gate:  Score < {res['fail_under']}/100 aborts commit\n"
                f"[dim]Every `git commit` will now run an instant architecture audit before code is committed.[/dim]",
                title="Git Security Gate Armed",
                border_style="green",
            )
        )
    except Exception as exc:
        console.print(f"[bold red]Failed to install pre-commit hook:[/bold red] {exc}")
        raise typer.Exit(code=1)


@app.command("uninstall-hook")
def uninstall_hook_command(
    repo_dir: str = typer.Argument(".", help="Path to Git repository root")
) -> None:
    """Remove the Aegis pre-commit security hook from a Git repository."""
    res = uninstall_pre_commit_hook(repo_dir=repo_dir)
    if res["removed"]:
        console.print(f"[bold green]Removed Aegis hook from:[/bold green] {res['hook_path']}")
    else:
        console.print(f"[yellow]No active Aegis hook found at:[/yellow] {res['hook_path']}")


@app.command(
    "mcp-wrap",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def mcp_wrap_command(
    ctx: typer.Context,
    state_dir: str = typer.Option(
        "./aegis_state", "--state-dir", help="Control plane state directory for proxy logs"
    ),
) -> None:
    """Wrap any local MCP stdio server with real-time JSON-RPC inspection & desktop alerts.

    Usage:
      aegis mcp-wrap -- npx -y @modelcontextprotocol/server-filesystem@0.6.2 ./data
    """
    child_argv = ctx.args
    if not child_argv:
        console.print("[bold red]Error:[/bold red] Specify the target MCP server command after `--`.")
        console.print(
            "Example: [cyan]aegis mcp-wrap -- npx -y @modelcontextprotocol/server-filesystem@0.6.2 ./data[/cyan]"
        )
        raise typer.Exit(code=1)

    db_url = f"sqlite:///{os.path.abspath(os.path.join(state_dir, 'aegis_control_plane.db'))}"
    factory = create_db_session_factory(db_url)
    proxy = AegisProxy(factory)
    firewall = McpStdioFirewall(proxy=proxy)
    rc = firewall.run_stdio_bridge(child_argv)
    raise typer.Exit(code=rc)


@app.command("verify-ledger")
def verify_ledger_command(
    state_dir: str = typer.Option("./aegis_state", "--state-dir", help="Control plane state directory")
) -> None:
    """Cryptographically verify the SHA-256 hash chain of the Aegis audit ledger."""
    db_url = f"sqlite:///{os.path.abspath(os.path.join(state_dir, 'aegis_control_plane.db'))}"
    factory = create_db_session_factory(db_url)
    proxy = AegisProxy(factory)
    valid, total, err = proxy.verify_audit_chain()
    if valid:
        console.print(f"[bold green]VERIFIED:[/bold green] {total} hash-chained audit records intact.")
    else:
        console.print(f"[bold red]TAMPER DETECTED:[/bold red] {err}")
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
