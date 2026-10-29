"""Surgical `agent_run_id` Database Mutation Wrapper & Conflict-Aware Rollback Engine."""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session, sessionmaker

from aegis.models import DatabaseMutationRecord, utc_now

IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_identifier(name: str) -> str:
    if not IDENT_RE.match(name):
        raise ValueError(f"Unsafe SQL identifier rejected: {name!r}")
    return name


@dataclass
class RollbackSummary:
    agent_run_id: str
    reverted_count: int
    skipped_human_conflicts: List[Dict[str, Any]] = field(default_factory=list)
    details: List[str] = field(default_factory=list)


class UndoableDBEngine:
    """
    Wraps application SQLite/SQL mutations so every INSERT, UPDATE, and DELETE executed by an
    AI agent records exact before/after row snapshots tagged with `agent_run_id`.
    Supports surgical rollback that preserves concurrent human edits!
    """

    def __init__(self, app_db_path: str, ledger_session_factory: sessionmaker[Session]) -> None:
        self.app_db_path = app_db_path
        self._ledger_factory = ledger_session_factory

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.app_db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def execute_insert(
        self,
        agent_run_id: str,
        table: str,
        row_data: Dict[str, Any],
        pk_col: str = "id",
        session_id: Optional[str] = None,
    ) -> str:
        _validate_identifier(table)
        _validate_identifier(pk_col)
        cols = [_validate_identifier(k) for k in row_data.keys()]
        placeholders = ", ".join(["?"] * len(cols))
        col_list = ", ".join(cols)
        values = [row_data[c] for c in cols]

        with self._connect() as conn:
            cur = conn.execute(f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})", values)
            pk_val = str(row_data.get(pk_col) if pk_col in row_data else cur.lastrowid)
            inserted = conn.execute(f"SELECT * FROM {table} WHERE {pk_col} = ?", (pk_val,)).fetchone()
            after_dict = dict(inserted) if inserted else dict(row_data)
            conn.commit()

        mutation_id = f"mut_{secrets.token_hex(8)}"
        with self._ledger_factory() as db:
            db.add(
                DatabaseMutationRecord(
                    mutation_id=mutation_id,
                    agent_run_id=agent_run_id,
                    session_id=session_id,
                    table_name=table,
                    primary_key_col=pk_col,
                    record_pk=pk_val,
                    operation="INSERT",
                    before_state_json=None,
                    after_state_json=json.dumps(after_dict, sort_keys=True, default=str),
                )
            )
            db.commit()
        return mutation_id

    def execute_update(
        self,
        agent_run_id: str,
        table: str,
        updates: Dict[str, Any],
        where_clause: str,
        where_params: tuple[Any, ...] = (),
        pk_col: str = "id",
        session_id: Optional[str] = None,
    ) -> List[str]:
        _validate_identifier(table)
        _validate_identifier(pk_col)
        if not where_clause.strip():
            raise ValueError("Refusing unbounded UPDATE without explicit WHERE filter.")
        update_cols = [_validate_identifier(k) for k in updates.keys()]
        set_expr = ", ".join(f"{c} = ?" for c in update_cols)
        set_vals = [updates[c] for c in update_cols]

        mutation_ids: List[str] = []
        captured: List[tuple[str, Dict[str, Any], Dict[str, Any]]] = []

        with self._connect() as conn:
            before_rows = conn.execute(
                f"SELECT * FROM {table} WHERE {where_clause}", where_params
            ).fetchall()
            if not before_rows:
                return []

            conn.execute(
                f"UPDATE {table} SET {set_expr} WHERE {where_clause}",
                tuple(set_vals) + tuple(where_params),
            )

            for brow in before_rows:
                bdict = dict(brow)
                pk_val = str(bdict[pk_col])
                arow = conn.execute(
                    f"SELECT * FROM {table} WHERE {pk_col} = ?", (bdict[pk_col],)
                ).fetchone()
                adict = dict(arow) if arow else {}
                captured.append((pk_val, bdict, adict))
            conn.commit()

        with self._ledger_factory() as db:
            for pk_val, bdict, adict in captured:
                mid = f"mut_{secrets.token_hex(8)}"
                mutation_ids.append(mid)
                db.add(
                    DatabaseMutationRecord(
                        mutation_id=mid,
                        agent_run_id=agent_run_id,
                        session_id=session_id,
                        table_name=table,
                        primary_key_col=pk_col,
                        record_pk=pk_val,
                        operation="UPDATE",
                        before_state_json=json.dumps(bdict, sort_keys=True, default=str),
                        after_state_json=json.dumps(adict, sort_keys=True, default=str),
                    )
                )
            db.commit()
        return mutation_ids

    def execute_delete(
        self,
        agent_run_id: str,
        table: str,
        where_clause: str,
        where_params: tuple[Any, ...] = (),
        pk_col: str = "id",
        session_id: Optional[str] = None,
    ) -> List[str]:
        _validate_identifier(table)
        _validate_identifier(pk_col)
        if not where_clause.strip():
            raise ValueError("Refusing unbounded DELETE without explicit WHERE filter.")

        mutation_ids: List[str] = []
        deleted_snapshots: List[tuple[str, Dict[str, Any]]] = []

        with self._connect() as conn:
            before_rows = conn.execute(
                f"SELECT * FROM {table} WHERE {where_clause}", where_params
            ).fetchall()
            if not before_rows:
                return []

            for brow in before_rows:
                bdict = dict(brow)
                deleted_snapshots.append((str(bdict[pk_col]), bdict))

            conn.execute(f"DELETE FROM {table} WHERE {where_clause}", where_params)
            conn.commit()

        with self._ledger_factory() as db:
            for pk_val, bdict in deleted_snapshots:
                mid = f"mut_{secrets.token_hex(8)}"
                mutation_ids.append(mid)
                db.add(
                    DatabaseMutationRecord(
                        mutation_id=mid,
                        agent_run_id=agent_run_id,
                        session_id=session_id,
                        table_name=table,
                        primary_key_col=pk_col,
                        record_pk=pk_val,
                        operation="DELETE",
                        before_state_json=json.dumps(bdict, sort_keys=True, default=str),
                        after_state_json=None,
                    )
                )
            db.commit()
        return mutation_ids

    def rollback_run(
        self, agent_run_id: str, force_overwrite_conflicts: bool = False
    ) -> RollbackSummary:
        """
        Surgically undo all mutations created by `agent_run_id` in reverse chronological order.
        Preserves concurrent human updates by comparing live row state against `after_state_json`.
        """
        summary = RollbackSummary(agent_run_id=agent_run_id, reverted_count=0)

        with self._ledger_factory() as db:
            records = (
                db.query(DatabaseMutationRecord)
                .filter(
                    DatabaseMutationRecord.agent_run_id == agent_run_id,
                    DatabaseMutationRecord.reverted.is_(False),
                )
                .order_by(DatabaseMutationRecord.id.desc())
                .all()
            )
            if not records:
                summary.details.append(f"No active un-reverted mutations found for `{agent_run_id}`.")
                return summary

            with self._connect() as conn:
                for rec in records:
                    table = _validate_identifier(rec.table_name)
                    pk_col = _validate_identifier(rec.primary_key_col)

                    if rec.operation == "INSERT":
                        after_state = json.loads(rec.after_state_json or "{}")
                        pk_typed = after_state.get(pk_col, rec.record_pk)
                        live_row = conn.execute(
                            f"SELECT * FROM {table} WHERE {pk_col} = ?", (pk_typed,)
                        ).fetchone()
                        if live_row is not None:
                            live_json = json.dumps(dict(live_row), sort_keys=True, default=str)
                            if live_json != rec.after_state_json and not force_overwrite_conflicts:
                                summary.skipped_human_conflicts.append(
                                    {
                                        "table": table,
                                        "record_pk": rec.record_pk,
                                        "reason": "Row was subsequently modified by a human/external user after agent INSERT.",
                                    }
                                )
                                continue
                            conn.execute(f"DELETE FROM {table} WHERE {pk_col} = ?", (pk_typed,))

                    elif rec.operation == "UPDATE":
                        before_state = json.loads(rec.before_state_json or "{}")
                        after_state = json.loads(rec.after_state_json or "{}")
                        pk_typed = before_state.get(pk_col, rec.record_pk)
                        live_row = conn.execute(
                            f"SELECT * FROM {table} WHERE {pk_col} = ?", (pk_typed,)
                        ).fetchone()
                        if live_row is not None:
                            live_json = json.dumps(dict(live_row), sort_keys=True, default=str)
                            if live_json != json.dumps(after_state, sort_keys=True, default=str) and not force_overwrite_conflicts:
                                summary.skipped_human_conflicts.append(
                                    {
                                        "table": table,
                                        "record_pk": rec.record_pk,
                                        "reason": "Row was subsequently edited by a human after agent UPDATE; preserved human state.",
                                    }
                                )
                                continue
                        cols = [_validate_identifier(k) for k in before_state.keys() if k != pk_col]
                        set_expr = ", ".join(f"{c} = ?" for c in cols)
                        vals = [before_state[c] for c in cols] + [pk_typed]
                        conn.execute(f"UPDATE {table} SET {set_expr} WHERE {pk_col} = ?", vals)

                    elif rec.operation == "DELETE":
                        before_state = json.loads(rec.before_state_json or "{}")
                        cols = [_validate_identifier(k) for k in before_state.keys()]
                        placeholders = ", ".join(["?"] * len(cols))
                        col_list = ", ".join(cols)
                        conn.execute(
                            f"INSERT OR IGNORE INTO {table} ({col_list}) VALUES ({placeholders})",
                            [before_state[c] for c in cols],
                        )

                    rec.reverted = True
                    rec.reverted_at = utc_now()
                    summary.reverted_count += 1
                    summary.details.append(
                        f"Reverted {rec.operation} on `{table}.{pk_col}={rec.record_pk}`"
                    )

                conn.commit()
            db.commit()

        return summary
