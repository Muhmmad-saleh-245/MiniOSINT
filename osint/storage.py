"""SQLite storage for investigations ("cases") and their lookup results."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    analyst TEXT NOT NULL,
    authorization TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    created TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_case ON results(case_id);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class Store:
    def __init__(self, path: str):
        self.path = path
        with closing(self._conn()) as c:
            c.executescript(SCHEMA)

    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _run(self, sql, params=(), fetch=None):
        with closing(self._conn()) as c:
            cur = c.execute(sql, params)
            rows = cur.fetchall() if fetch == "all" else cur.fetchone() if fetch == "one" else None
            c.commit()
            return rows if fetch else cur.lastrowid

    def create_case(self, title: str, analyst: str, authorization: str, notes: str = "") -> int:
        return self._run("INSERT INTO cases(title, analyst, authorization, notes, created) VALUES (?,?,?,?,?)",
                         (title, analyst, authorization, notes, now_iso()))

    def get_case(self, case_id: int):
        row = self._run("SELECT * FROM cases WHERE id=?", (case_id,), "one")
        return dict(row) if row else None

    def update_notes(self, case_id: int, notes: str) -> None:
        self._run("UPDATE cases SET notes=? WHERE id=?", (notes, case_id))

    def list_cases(self) -> list[dict]:
        rows = self._run(
            "SELECT c.*, (SELECT COUNT(*) FROM results r WHERE r.case_id=c.id) AS n_results "
            "FROM cases c ORDER BY c.id DESC", fetch="all")
        return [dict(r) for r in rows]

    def delete_case(self, case_id: int) -> None:
        self._run("DELETE FROM cases WHERE id=?", (case_id,))

    def add_result(self, case_id: int, kind: str, target: str, data: dict) -> int:
        return self._run("INSERT INTO results(case_id, kind, target, created, data) VALUES (?,?,?,?,?)",
                         (case_id, kind, target, now_iso(), json.dumps(data)))

    def get_results(self, case_id: int) -> list[dict]:
        rows = self._run("SELECT * FROM results WHERE case_id=? ORDER BY id", (case_id,), "all")
        out = []
        for r in rows:
            d = dict(r)
            d["data"] = json.loads(d["data"])
            out.append(d)
        return out

    def delete_result(self, case_id: int, result_id: int) -> None:
        self._run("DELETE FROM results WHERE id=? AND case_id=?", (result_id, case_id))
