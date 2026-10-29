"""Shadow File Snapshot Store & Atomic Rollback Engine for Developer Workstations."""

from __future__ import annotations

import difflib
import hashlib
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.models import Severity, WeaknessFinding, utc_now
from aegis.scanner.engine import IGNORED_DIRS, ArchitectureScanner

WATCH_IGNORED_DIRS = IGNORED_DIRS - {"aegis_live_playground"}


@dataclass
class GuardianIncident:
    incident_id: str
    rel_path: str
    abs_path: str
    highest_severity: str
    findings: List[Dict[str, Any]]
    unified_diff: str
    had_clean_baseline: bool
    status: str  # ACTIVE_ON_DISK | AUTO_UNDONE | UNDONE_BY_DEV | OWNER_APPROVED_EXCEPTION
    elapsed_ms: float
    approved_by_owner: Optional[str] = None
    created_at: str = field(default_factory=lambda: utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "rel_path": self.rel_path,
            "abs_path": self.abs_path,
            "highest_severity": self.highest_severity,
            "findings": self.findings,
            "unified_diff": self.unified_diff,
            "had_clean_baseline": self.had_clean_baseline,
            "status": self.status,
            "elapsed_ms": self.elapsed_ms,
            "approved_by_owner": self.approved_by_owner,
            "created_at": self.created_at,
        }


SEVERITY_RANK = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
}


class ShadowSnapshotStore:
    """
    Maintains in-memory last-known-clean snapshots of files in a developer's workspace.
    Detects newly saved vulnerabilities in milliseconds, computes exact unified diffs, and
    restores clean snapshots either on 1-click command or automatically (`auto_undo=True`).
    """

    def __init__(
        self,
        workspace_root: str | Path,
        auto_undo_high_and_critical: bool = False,
        scanner: Optional[ArchitectureScanner] = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.auto_undo = auto_undo_high_and_critical
        self.scanner = scanner or ArchitectureScanner()

        # rel_path -> last clean content string
        self._clean_baselines: Dict[str, str] = {}
        # rel_path -> sha256 of last content written by Aegis undo (to avoid self-trigger loops!)
        self._internal_write_hashes: Dict[str, str] = {}
        # rel_path -> sha256 of last active alerted content (avoids duplicate alerts for identical unchanged file)
        self._last_active_hashes: Dict[str, str] = {}
        # incident_id -> (rel_path, baseline_content_or_None_if_new_file)
        self._rollback_targets: Dict[str, tuple[str, Optional[str]]] = {}
        # Ordered recent incidents (newest first)
        self._incidents: List[GuardianIncident] = []
        # Owner-signed digest exceptions: sha256(rel_path + file_content) -> owner_id
        self._owner_exceptions: Dict[str, str] = {}

        self.prime_baselines()

    @staticmethod
    def _sha256_text(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def prime_baselines(self) -> int:
        """Scan workspace once at startup and cache clean files as safe rollback baselines."""
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        primed = 0
        for dirpath, dirnames, filenames in os.walk(self.workspace_root):
            dirnames[:] = [d for d in dirnames if d not in WATCH_IGNORED_DIRS]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if fpath.suffix.lower() in {".pyc", ".db", ".sqlite", ".png", ".jpg", ".whl", ".zip"}:
                    continue
                try:
                    text = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                rep = self.scanner.scan_path(fpath)
                rel = str(fpath.relative_to(self.workspace_root))
                if not rep.findings:
                    self._clean_baselines[rel] = text
                    primed += 1
        return primed

    def inspect_saved_file(self, file_path: str | Path) -> Optional[GuardianIncident]:
        t0 = time.perf_counter()
        fpath = Path(file_path).resolve()
        if not fpath.exists() or not fpath.is_file():
            return None
        try:
            rel_path = str(fpath.relative_to(self.workspace_root))
        except ValueError:
            return None

        if any(part in WATCH_IGNORED_DIRS for part in Path(rel_path).parts):
            return None

        try:
            new_content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None

        content_hash = self._sha256_text(new_content)
        # Skip event if this file save was Aegis itself restoring a clean baseline
        if self._internal_write_hashes.get(rel_path) == content_hash:
            self._internal_write_hashes.pop(rel_path, None)
            self._last_active_hashes.pop(rel_path, None)
            return None

        # Skip duplicate watcher notification if this exact unchanged content already raised an active alert
        if not self.auto_undo and self._last_active_hashes.get(rel_path) == content_hash:
            return None

        # Skip if Owner explicitly signed an exception for this exact file state
        exception_key = self._sha256_text(f"{rel_path}::{new_content}")
        if exception_key in self._owner_exceptions:
            self._last_active_hashes.pop(rel_path, None)
            return None

        report = self.scanner.scan_path(fpath)
        if not report.findings:
            # File is clean! Promote to latest clean baseline so legitimate dev progress is saved!
            self._clean_baselines[rel_path] = new_content
            self._last_active_hashes.pop(rel_path, None)
            return None

        prior_clean = self._clean_baselines.get(rel_path)
        diff_lines = list(
            difflib.unified_diff(
                (prior_clean or "").splitlines(),
                new_content.splitlines(),
                fromfile=f"clean/{rel_path}" if prior_clean is not None else "/dev/null",
                tofile=f"risky/{rel_path}",
                lineterm="",
            )
        )
        diff_text = "\n".join(diff_lines[:80])

        highest_sev = max(
            (f.severity.value for f in report.findings),
            key=lambda s: SEVERITY_RANK.get(s, 0),
        )
        incident_id = f"inc_{secrets.token_hex(6)}"
        self._rollback_targets[incident_id] = (rel_path, prior_clean)

        status = "ACTIVE_ON_DISK"
        should_auto_revert = self.auto_undo and highest_sev in {
            Severity.CRITICAL.value,
            Severity.HIGH.value,
        }
        if should_auto_revert:
            self._restore_snapshot_to_disk(rel_path, prior_clean)
            self._last_active_hashes.pop(rel_path, None)
            status = "AUTO_UNDONE"
        else:
            self._last_active_hashes[rel_path] = content_hash

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        findings_dicts = [
            self._normalize_finding_path(f, rel_path) for f in report.findings
        ]

        incident = GuardianIncident(
            incident_id=incident_id,
            rel_path=rel_path,
            abs_path=str(fpath),
            highest_severity=highest_sev,
            findings=findings_dicts,
            unified_diff=diff_text,
            had_clean_baseline=prior_clean is not None,
            status=status,
            elapsed_ms=elapsed_ms,
        )
        self._incidents.insert(0, incident)
        del self._incidents[50:]
        return incident

    @staticmethod
    def _normalize_finding_path(f: WeaknessFinding, rel_path: str) -> Dict[str, Any]:
        d = f.model_dump()
        d["file_path"] = rel_path
        return d

    def _restore_snapshot_to_disk(self, rel_path: str, prior_clean: Optional[str]) -> None:
        target = self.workspace_root / rel_path
        if prior_clean is None:
            # Newly created dangerous file (e.g., a newly dropped `.env` with raw secrets) -> remove it!
            if target.exists():
                target.unlink()
        else:
            self._internal_write_hashes[rel_path] = self._sha256_text(prior_clean)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(prior_clean, encoding="utf-8")

    def undo_incident(self, incident_id: str) -> GuardianIncident:
        target_inc = self._find_incident(incident_id)
        if target_inc.status in {"AUTO_UNDONE", "UNDONE_BY_DEV"}:
            return target_inc

        rel_path, prior_clean = self._rollback_targets[incident_id]
        self._restore_snapshot_to_disk(rel_path, prior_clean)
        self._last_active_hashes.pop(rel_path, None)
        target_inc.status = "UNDONE_BY_DEV"
        return target_inc

    def approve_exception_with_owner(self, incident_id: str, verified_owner_id: str) -> GuardianIncident:
        target_inc = self._find_incident(incident_id)
        fpath = self.workspace_root / target_inc.rel_path
        if fpath.exists():
            cur_text = fpath.read_text(encoding="utf-8", errors="ignore")
            key = self._sha256_text(f"{target_inc.rel_path}::{cur_text}")
            self._owner_exceptions[key] = verified_owner_id
            self._clean_baselines[target_inc.rel_path] = cur_text
        self._last_active_hashes.pop(target_inc.rel_path, None)

        target_inc.status = "OWNER_APPROVED_EXCEPTION"
        target_inc.approved_by_owner = verified_owner_id
        return target_inc

    def _find_incident(self, incident_id: str) -> GuardianIncident:
        for inc in self._incidents:
            if inc.incident_id == incident_id:
                return inc
        raise KeyError(f"Guardian incident `{incident_id}` not found.")

    def list_incidents(self) -> List[Dict[str, Any]]:
        return [inc.to_dict() for inc in self._incidents]
