"""Real-Time Local MCP JSON-RPC Stdio Firewall Wrapper (`aegis mcp-wrap`)."""

from __future__ import annotations

import json
import secrets
import subprocess
import sys
import threading
from typing import Any, Dict, IO, List, Optional

from aegis.guardian.notifier import DesktopAlertNotifier
from aegis.runtime.proxy import AegisProxy


class McpStdioFirewall:
    """
    Sits inline in front of any local MCP stdio server in Claude Desktop, Cursor, or VS Code:
      `"command": "aegis", "args": ["mcp-wrap", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem@0.6.2", "./data"]`

    Inspects every JSON-RPC `tools/call` line from the IDE/LLM BEFORE forwarding to the child MCP
    server. Blocked or unverified critical calls never reach the MCP server and trigger an instant
    native desktop alert!
    """

    def __init__(
        self,
        proxy: AegisProxy,
        notifier: Optional[DesktopAlertNotifier] = None,
    ) -> None:
        self.proxy = proxy
        self.notifier = notifier or DesktopAlertNotifier()

    def evaluate_jsonrpc_line(
        self, raw_line: str, agent_run_id: Optional[str] = None
    ) -> tuple[bool, Optional[str]]:
        """
        Inspect a single JSON-RPC line.
        Returns `(forward_to_child, immediate_error_response_json_or_None)`.
        """
        stripped = raw_line.strip()
        if not stripped:
            return True, None

        try:
            msg: Dict[str, Any] = json.loads(stripped)
        except json.JSONDecodeError:
            return True, None

        if msg.get("method") != "tools/call":
            return True, None

        run_id = agent_run_id or f"mcp_stdio_{secrets.token_hex(4)}"
        gate = self.proxy.intercept(
            provider="mcp",
            payload=msg,
            agent_run_id=run_id,
            require_token=False,
        )
        if gate["allowed"]:
            return True, None

        tool_name = gate.get("tool_name", "unknown_tool")
        reason_str = "; ".join(gate.get("reasons", ["Blocked by AegisZeroTrust Policy"]))
        self.notifier.send_alert(
            title="AegisUndo Blocked MCP Tool Call",
            subtitle=f"{tool_name} ({gate.get('decision')})",
            message=reason_str,
        )

        rpc_error = {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "error": {
                "code": -32001,
                "message": f"[AegisUndo MCP Firewall] {gate.get('decision')}: {reason_str}",
                "data": {
                    "decision": gate.get("decision"),
                    "approval_request": gate.get("approval_request"),
                },
            },
        }
        return False, json.dumps(rpc_error)

    def run_stdio_bridge(
        self,
        child_argv: List[str],
        in_stream: IO[str] = sys.stdin,
        out_stream: IO[str] = sys.stdout,
    ) -> int:
        if not child_argv:
            raise ValueError("Provide the target MCP server command after `--`.")

        proc = subprocess.Popen(
            child_argv,
            shell=False,
            env={"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )

        def _forward_child_stdout() -> None:
            assert proc.stdout is not None
            for child_line in proc.stdout:
                out_stream.write(child_line)
                out_stream.flush()

        reader_thread = threading.Thread(target=_forward_child_stdout, daemon=True)
        reader_thread.start()

        try:
            for line in in_stream:
                should_forward, err_json = self.evaluate_jsonrpc_line(line)
                if should_forward:
                    if proc.stdin is not None:
                        proc.stdin.write(line if line.endswith("\n") else line + "\n")
                        proc.stdin.flush()
                elif err_json is not None:
                    out_stream.write(err_json + "\n")
                    out_stream.flush()
        finally:
            if proc.stdin:
                proc.stdin.close()
            proc.terminate()
            proc.wait(timeout=5)
        return proc.returncode or 0
