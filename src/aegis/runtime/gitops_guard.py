"""GitOps Infrastructure-as-Code Gate & Instant Revert Engine."""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import secrets
from typing import Dict, List

from sqlalchemy.orm import Session, sessionmaker

from aegis.models import InfraProposalRecord, utc_now


class GitOpsGuard:
    """
    Forbids direct live cloud API mutations by agents. Validates proposed IaC diffs against
    deterministic security invariants and tracks exact `before_manifest` states for 1-click revert.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    @staticmethod
    def validate_manifest(after_manifest: str) -> List[str]:
        violations: List[str] = []
        if "0.0.0.0/0" in after_manifest:
            violations.append(
                "Deterministic IaC Block: Unrestricted `0.0.0.0/0` ingress CIDR is forbidden in agent proposals."
            )
        if re.search(r'("Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\])', after_manifest):
            violations.append(
                "Deterministic IaC Block: Wildcard IAM `Action: *` privilege escalation is forbidden."
            )
        if re.search(r"privileged\s*:\s*true", after_manifest, re.IGNORECASE):
            violations.append(
                "Deterministic IaC Block: `privileged: true` container spec is forbidden."
            )
        if re.search(r"encryption\s*=\s*false|encrypted\s*=\s*false", after_manifest, re.IGNORECASE):
            violations.append(
                "Deterministic IaC Block: Disabling storage encryption is forbidden."
            )
        return violations

    def stage_change(
        self,
        agent_run_id: str,
        target_path: str,
        before_manifest: str,
        after_manifest: str,
        auto_apply_if_clean: bool = False,
    ) -> Dict[str, object]:
        violations = self.validate_manifest(after_manifest)
        passed = len(violations) == 0
        proposal_id = f"iac_{secrets.token_hex(6)}"
        commit_sha = (
            hashlib.sha1(f"{proposal_id}:{after_manifest}".encode("utf-8")).hexdigest()[:12]
            if passed
            else None
        )
        status = "BLOCKED" if not passed else ("APPLIED" if auto_apply_if_clean else "STAGED_PR")

        diff_text = "\n".join(
            difflib.unified_diff(
                before_manifest.splitlines(),
                after_manifest.splitlines(),
                fromfile=f"a/{target_path}",
                tofile=f"b/{target_path}",
                lineterm="",
            )
        )

        with self._session_factory() as db:
            db.add(
                InfraProposalRecord(
                    proposal_id=proposal_id,
                    agent_run_id=agent_run_id,
                    target_path=target_path,
                    before_manifest=before_manifest,
                    after_manifest=after_manifest,
                    policy_passed=passed,
                    violations_json=json.dumps(violations),
                    status=status,
                    git_commit_sha=commit_sha,
                )
            )
            db.commit()

        return {
            "proposal_id": proposal_id,
            "policy_passed": passed,
            "status": status,
            "git_commit_sha": commit_sha,
            "violations": violations,
            "unified_diff": diff_text,
        }

    def revert_change(self, proposal_id: str) -> Dict[str, object]:
        with self._session_factory() as db:
            rec = (
                db.query(InfraProposalRecord)
                .filter(InfraProposalRecord.proposal_id == proposal_id)
                .first()
            )
            if not rec:
                raise KeyError(f"Infrastructure proposal `{proposal_id}` not found.")
            if rec.status == "BLOCKED":
                return {
                    "proposal_id": proposal_id,
                    "status": "BLOCKED",
                    "message": "Proposal was already blocked pre-execution; no cloud state mutated.",
                }
            rec.status = "REVERTED"
            rec.reverted_at = utc_now()
            restored = rec.before_manifest
            target = rec.target_path
            sha = rec.git_commit_sha
            db.commit()

        return {
            "proposal_id": proposal_id,
            "status": "REVERTED",
            "reverted_commit": sha,
            "target_path": target,
            "restored_manifest": restored,
        }

    def list_proposals(self) -> List[Dict[str, object]]:
        with self._session_factory() as db:
            rows = (
                db.query(InfraProposalRecord)
                .order_by(InfraProposalRecord.created_at.desc())
                .limit(30)
                .all()
            )
            return [
                {
                    "proposal_id": r.proposal_id,
                    "agent_run_id": r.agent_run_id,
                    "target_path": r.target_path,
                    "policy_passed": r.policy_passed,
                    "violations": json.loads(r.violations_json),
                    "status": r.status,
                    "git_commit_sha": r.git_commit_sha,
                }
                for r in rows
            ]
