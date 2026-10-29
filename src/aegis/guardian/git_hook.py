"""Git Pre-Commit Hard Security Blocker (`aegis install-hook`)."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Dict

HOOK_MARKER = "# AEGIS-UNDO-PRE-COMMIT-GUARD"


def install_pre_commit_hook(repo_dir: str | Path, fail_under: int = 95) -> Dict[str, object]:
    """
    Installs an executable `.git/hooks/pre-commit` firewall inside a developer's Git repository.
    Blocks `git commit` deterministically if the repository introduces security weaknesses.
    """
    root = Path(repo_dir).resolve()
    git_dir = root / ".git"
    if not git_dir.exists() or not git_dir.is_dir():
        raise FileNotFoundError(
            f"No `.git` directory found in `{root}`. Run `git init` first before installing hook."
        )

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    python_bin = sys.executable
    script = f"""#!/bin/sh
{HOOK_MARKER}
echo "🛡️  [AegisUndo Pre-Commit Guard] Scanning workspace before commit..."
"{python_bin}" -m aegis.cli scan "{root}" --fail-under {int(fail_under)}
STATUS=$?
if [ $STATUS -ne 0 ]; then
  echo ""
  echo "❌ [AegisUndo] COMMIT BLOCKED: Fix or undo the security weaknesses above before committing!"
  exit 1
fi
echo "✅ [AegisUndo] Pre-commit security check passed."
exit 0
"""
    hook_path.write_text(script, encoding="utf-8")
    current_mode = os.stat(hook_path).st_mode
    os.chmod(hook_path, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    return {
        "installed": True,
        "hook_path": str(hook_path),
        "fail_under": fail_under,
    }


def uninstall_pre_commit_hook(repo_dir: str | Path) -> Dict[str, object]:
    root = Path(repo_dir).resolve()
    hook_path = root / ".git" / "hooks" / "pre-commit"
    if hook_path.exists() and HOOK_MARKER in hook_path.read_text(encoding="utf-8", errors="ignore"):
        hook_path.unlink()
        return {"removed": True, "hook_path": str(hook_path)}
    return {"removed": False, "hook_path": str(hook_path)}


def get_hook_status(repo_dir: str | Path) -> Dict[str, object]:
    root = Path(repo_dir).resolve()
    git_dir = root / ".git"
    hook_path = git_dir / "hooks" / "pre-commit"
    installed = (
        hook_path.exists()
        and HOOK_MARKER in hook_path.read_text(encoding="utf-8", errors="ignore")
    )
    return {
        "has_git_repo": git_dir.is_dir(),
        "hook_installed": installed,
        "hook_path": str(hook_path),
    }
