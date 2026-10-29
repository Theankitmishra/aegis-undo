"""Provenance-Tracked Memory Store & Read-Lineage Quarantine Engine against Memory Poisoning."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from sqlalchemy.orm import Session, sessionmaker

from aegis.models import MemoryChunkRecord, MemoryReadLineageRecord, SourceTrust

POISONING_DIRECTIVE_RE = re.compile(
    r"(always\s+(ignore|mark|approve|bypass|allow)|"
    r"override\s+security\s+policy|"
    r"never\s+trigger\s+alert|"
    r"treat\s+all\s+traffic\s+to\s+.*\s+as\s+authorized)",
    re.IGNORECASE,
)


@dataclass
class QuarantineReport:
    quarantined_memory_ids: List[str] = field(default_factory=list)
    tainted_decisions: List[Dict[str, str]] = field(default_factory=list)


class ProvenanceMemoryStore:
    """
    Stores agent RAG/long-term memories with mandatory provenance tags (`source_trust`, `source_doc_id`,
    `created_by_run`) and records every downstream decision that retrieves a memory chunk so poisoned
    memories can be quarantined and tainted decisions automatically re-queued.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def write_memory(
        self,
        content: str,
        source_trust: SourceTrust,
        source_doc_id: str,
        created_by_run: str,
        namespace: str = "default",
        allow_untrusted_directives: bool = False,
    ) -> Dict[str, object]:
        if not source_doc_id.strip() or not created_by_run.strip():
            raise ValueError("Memory provenance requires non-empty `source_doc_id` and `created_by_run`.")

        # Block untrusted external inputs trying to smuggle policy-override rules into memory
        if (
            source_trust == SourceTrust.UNTRUSTED_EXTERNAL
            and not allow_untrusted_directives
            and POISONING_DIRECTIVE_RE.search(content)
        ):
            return {
                "accepted": False,
                "memory_id": None,
                "reason": (
                    "Blocked suspected Memory Poisoning payload: untrusted external source attempted "
                    "to write an imperative security-override rule into long-term memory."
                ),
            }

        memory_id = f"mem_{secrets.token_hex(8)}"
        with self._session_factory() as db:
            current_max = (
                db.query(MemoryChunkRecord)
                .filter(MemoryChunkRecord.namespace == namespace)
                .count()
            )
            rec = MemoryChunkRecord(
                memory_id=memory_id,
                namespace=namespace,
                content=content,
                source_trust=source_trust.value,
                source_doc_id=source_doc_id,
                created_by_run=created_by_run,
                version=current_max + 1,
                quarantined=False,
            )
            db.add(rec)
            db.commit()

        return {
            "accepted": True,
            "memory_id": memory_id,
            "version": current_max + 1,
            "source_trust": source_trust.value,
        }

    def retrieve_for_decision(
        self,
        decision_id: str,
        agent_run_id: str,
        query: str,
        decision_summary: str,
        namespace: str = "default",
        include_untrusted: bool = True,
        limit: int = 5,
    ) -> List[Dict[str, object]]:
        tokens = [t.lower() for t in re.findall(r"[a-zA-Z0-9_.\-]+", query) if len(t) >= 3]
        with self._session_factory() as db:
            q = db.query(MemoryChunkRecord).filter(
                MemoryChunkRecord.namespace == namespace,
                MemoryChunkRecord.quarantined.is_(False),
            )
            if not include_untrusted:
                q = q.filter(MemoryChunkRecord.source_trust != SourceTrust.UNTRUSTED_EXTERNAL.value)

            candidates = q.order_by(MemoryChunkRecord.created_at.desc()).all()
            scored: List[tuple[int, MemoryChunkRecord]] = []
            for c in candidates:
                text_l = c.content.lower()
                hits = sum(1 for tok in tokens if tok in text_l) if tokens else 1
                if hits > 0:
                    scored.append((hits, c))
            scored.sort(key=lambda pair: pair[0], reverse=True)
            selected = [c for _, c in scored[:limit]]

            results: List[Dict[str, object]] = []
            for mem in selected:
                db.add(
                    MemoryReadLineageRecord(
                        decision_id=decision_id,
                        agent_run_id=agent_run_id,
                        memory_id=mem.memory_id,
                        decision_summary=decision_summary,
                        tainted=False,
                    )
                )
                results.append(
                    {
                        "memory_id": mem.memory_id,
                        "content": mem.content,
                        "source_trust": mem.source_trust,
                        "source_doc_id": mem.source_doc_id,
                        "created_by_run": mem.created_by_run,
                        "version": mem.version,
                    }
                )
            db.commit()
            return results

    def quarantine(
        self,
        source_doc_id: Optional[str] = None,
        created_by_run: Optional[str] = None,
        memory_id: Optional[str] = None,
        reason: str = "Confirmed poisoned external context",
    ) -> QuarantineReport:
        if not any([source_doc_id, created_by_run, memory_id]):
            raise ValueError("Specify at least one of `source_doc_id`, `created_by_run`, or `memory_id`.")

        report = QuarantineReport()
        with self._session_factory() as db:
            q = db.query(MemoryChunkRecord).filter(MemoryChunkRecord.quarantined.is_(False))
            if source_doc_id:
                q = q.filter(MemoryChunkRecord.source_doc_id == source_doc_id)
            if created_by_run:
                q = q.filter(MemoryChunkRecord.created_by_run == created_by_run)
            if memory_id:
                q = q.filter(MemoryChunkRecord.memory_id == memory_id)

            targets = q.all()
            for mem in targets:
                mem.quarantined = True
                mem.quarantine_reason = reason
                report.quarantined_memory_ids.append(mem.memory_id)

            if report.quarantined_memory_ids:
                lineage_rows = (
                    db.query(MemoryReadLineageRecord)
                    .filter(MemoryReadLineageRecord.memory_id.in_(report.quarantined_memory_ids))
                    .all()
                )
                seen_decisions = set()
                for row in lineage_rows:
                    row.tainted = True
                    if row.decision_id not in seen_decisions:
                        seen_decisions.add(row.decision_id)
                        report.tainted_decisions.append(
                            {
                                "decision_id": row.decision_id,
                                "agent_run_id": row.agent_run_id,
                                "poisoned_memory_id": row.memory_id,
                                "decision_summary": row.decision_summary,
                            }
                        )
            db.commit()
        return report

    def list_memories(self) -> List[Dict[str, object]]:
        with self._session_factory() as db:
            rows = db.query(MemoryChunkRecord).order_by(MemoryChunkRecord.version.desc()).limit(50).all()
            return [
                {
                    "memory_id": r.memory_id,
                    "namespace": r.namespace,
                    "content": r.content,
                    "source_trust": r.source_trust,
                    "source_doc_id": r.source_doc_id,
                    "created_by_run": r.created_by_run,
                    "version": r.version,
                    "quarantined": r.quarantined,
                    "quarantine_reason": r.quarantine_reason,
                }
                for r in rows
            ]
