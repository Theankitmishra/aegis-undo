"""INTENTIONALLY VULNERABLE ENTERPRISE AGENT SAMPLE — Used to benchmark `aegis scan`."""

import os
import sqlite3
import subprocess

# FLAW 1: Hardcoded static API secret accessible in agent process
OPENAI_API_KEY = "sk-proj-DEMO0000000000000000000000000000"


def build_prompt(untrusted_email_body: str) -> list[dict]:
    # FLAW 2: Interpolating untrusted external email text directly into `system` role
    return [
        {"role": "system", "content": f"You are a finance helper. Context: {untrusted_email_body}"},
    ]


def run_diagnostic_tool(cmd_from_llm: str) -> str:
    # FLAW 3 & 4: shell=True command injection + forwarding full host os.environ
    out = subprocess.run(cmd_from_llm, shell=True, env=os.environ, capture_output=True, text=True)
    return out.stdout


def mutate_orders_directly(conn: sqlite3.Connection, order_id: str, new_price: float) -> None:
    # FLAW 5: Direct un-audited SQL mutation with zero `agent_run_id` rollback snapshot
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET price = ? WHERE id = ?", (new_price, order_id))
    conn.commit()


def remember_ticket_context(vector_store, raw_ticket_chunks: list[str]) -> None:
    # FLAW 6: Unattributed RAG memory write vulnerable to Memory Poisoning
    vector_store.add_documents(raw_ticket_chunks)


def llm_safety_judge(openai_client, proposed_action: str) -> bool:
    # FLAW 7: Relying solely on probabilistic LLM-as-a-Judge without deterministic policy
    resp = openai_client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": f"Is this safe? {proposed_action}"}],
    )
    return "SAFE" in resp.choices[0].message.content


def executive_payout_tool(iban: str, amount: float, video_call_approved: bool) -> dict:
    # FLAW 8 & 9: Irreversible wire payout trusting live video call (Deepfake vulnerable) & no HITL gate
    if video_call_approved:
        return send_wire_transfer(iban=iban, amount=amount)
    return {"status": "skipped"}


def send_wire_transfer(iban: str, amount: float) -> dict:
    return {"wired": amount, "iban": iban}


def autonomous_daemon_loop(step_fn) -> None:
    # FLAW 10: Unbounded autonomous `while True` loop with no step ceiling or circuit breaker
    while True:
        step_fn()
