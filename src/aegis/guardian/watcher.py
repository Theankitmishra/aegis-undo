"""Async Real-Time File Watcher & WebSocket Event Hub (`watchfiles.awatch`)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import WebSocket
from watchfiles import Change, awatch

from aegis.guardian.notifier import DesktopAlertNotifier
from aegis.guardian.snapshots import GuardianIncident, ShadowSnapshotStore


class LiveWorkspaceGuardian:
    """
    Runs alongside the developer on their machine:
      - Watches `workspace_root` via Rust-backed OS file events (`watchfiles.awatch`)
      - Evaluates every saved file in milliseconds via `ShadowSnapshotStore`
      - Auto-undoes `CRITICAL`/`HIGH` mistakes when `auto_undo=True`
      - Dispatches native macOS Notification Center alerts + live WebSocket diffs!
    """

    def __init__(
        self,
        workspace_root: str | Path,
        auto_undo: bool = False,
        notifier: Optional[DesktopAlertNotifier] = None,
    ) -> None:
        self.snapshots = ShadowSnapshotStore(
            workspace_root=workspace_root,
            auto_undo_high_and_critical=auto_undo,
        )
        self.notifier = notifier or DesktopAlertNotifier()
        self._clients: Set[WebSocket] = set()
        self._watch_task: Optional[asyncio.Task[None]] = None
        self._stop_event: Optional[asyncio.Event] = None

    @property
    def workspace_root(self) -> Path:
        return self.snapshots.workspace_root

    def set_mode(self, auto_undo: bool) -> Dict[str, Any]:
        self.snapshots.auto_undo = auto_undo
        return {
            "auto_undo": self.snapshots.auto_undo,
            "workspace_root": str(self.workspace_root),
        }

    def switch_workspace(self, new_root: str | Path, auto_undo: Optional[bool] = None) -> Dict[str, Any]:
        resolved = Path(new_root).resolve()
        resolved.mkdir(parents=True, exist_ok=True)
        keep_auto = self.snapshots.auto_undo if auto_undo is None else auto_undo
        self.snapshots = ShadowSnapshotStore(
            workspace_root=resolved,
            auto_undo_high_and_critical=keep_auto,
        )
        return {
            "workspace_root": str(self.workspace_root),
            "auto_undo": self.snapshots.auto_undo,
        }

    def process_file_event(self, file_path: str | Path) -> Optional[GuardianIncident]:
        inc = self.snapshots.inspect_saved_file(file_path)
        if inc is None:
            return None

        top_rule = inc.findings[0]["rule_id"] if inc.findings else "SECURITY"
        top_title = inc.findings[0]["title"] if inc.findings else "Weakness detected"

        if inc.status == "AUTO_UNDONE":
            self.notifier.send_alert(
                title="Aegis Auto-Undid Dangerous Save!",
                subtitle=f"{inc.rel_path} [{top_rule}]",
                message=f"Reverted {inc.highest_severity} mistake in {inc.elapsed_ms}ms: {top_title}",
            )
        else:
            self.notifier.send_alert(
                title=f"Aegis Security Alert ({inc.highest_severity})",
                subtitle=f"{inc.rel_path} [{top_rule}]",
                message=f"{top_title} — Click Undo in Aegis Companion!",
            )
        return inc

    async def connect_ws(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)
        await ws.send_json(
            {
                "type": "INIT_STATE",
                "workspace_root": str(self.workspace_root),
                "auto_undo": self.snapshots.auto_undo,
                "incidents": self.snapshots.list_incidents(),
            }
        )

    def disconnect_ws(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        stale: List[WebSocket] = []
        for client in list(self._clients):
            try:
                await client.send_json(message)
            except Exception:
                stale.append(client)
        for s in stale:
            self._clients.discard(s)

    async def start_background_watcher(self) -> None:
        if self._watch_task and not self._watch_task.done():
            return
        self._stop_event = asyncio.Event()
        self._watch_task = asyncio.create_task(self._watch_loop())

    async def stop_background_watcher(self) -> None:
        if self._stop_event:
            self._stop_event.set()
        if self._watch_task:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass

    async def _watch_loop(self) -> None:
        assert self._stop_event is not None
        while not self._stop_event.is_set():
            current_root = self.workspace_root
            try:
                async for changes in awatch(current_root, stop_event=self._stop_event, debounce=120):
                    if self.workspace_root != current_root:
                        break
                    for change_type, changed_path in changes:
                        if change_type in (Change.added, Change.modified):
                            inc = self.process_file_event(changed_path)
                            if inc is not None:
                                await self.broadcast({"type": "NEW_INCIDENT", "incident": inc.to_dict()})
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.5)
