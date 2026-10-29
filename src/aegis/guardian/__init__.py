"""Real-Time Developer Machine Guardian: File Watcher, Shadow Auto-Undo, Git Hook & MCP Stdio Firewall."""

from aegis.guardian.git_hook import (
    get_hook_status,
    install_pre_commit_hook,
    uninstall_pre_commit_hook,
)
from aegis.guardian.mcp_stdio_firewall import McpStdioFirewall
from aegis.guardian.notifier import DesktopAlertNotifier
from aegis.guardian.snapshots import GuardianIncident, ShadowSnapshotStore
from aegis.guardian.watcher import LiveWorkspaceGuardian

__all__ = [
    "DesktopAlertNotifier",
    "GuardianIncident",
    "ShadowSnapshotStore",
    "LiveWorkspaceGuardian",
    "get_hook_status",
    "install_pre_commit_hook",
    "uninstall_pre_commit_hook",
    "McpStdioFirewall",
]
