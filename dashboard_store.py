"""
Shadow AI Detector — Persistent Dashboard / Incident Store (SQLite)
======================================================================
Backs /dashboard and its endpoints. Durable across restarts — a step up
from the original in-memory ring buffer. Still appropriately lightweight
for a single-instance deployment; see SECURITY.md "Known Limitations" —
this is a local file, not a shared store, so it does not survive a
multi-instance deployment without moving to a real database.

Security note (OWASP A03 — Injection): every query below is parameterized
(`?` placeholders) for all VALUES. The only string-built pieces of SQL are
(a) a `?` placeholder repeated once per item in an IN(...) list — never
user data itself — and (b) the ORDER BY clause, which is selected from the
fixed `_SORT_COLUMNS` allowlist via dict lookup, never interpolated from
the raw request parameter. Neither is user-controlled SQL.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

MAX_ALERTS_STORED = 5000   # retention cap — oldest pruned beyond this on insert

VALID_STATUSES = ("NEW", "ACKNOWLEDGED", "RESOLVED")

_SORT_COLUMNS: Dict[str, str] = {
    "time_desc":  "created_at DESC, id DESC",
    "time_asc":   "created_at ASC, id ASC",
    "score_desc": "threat_score DESC, created_at DESC",
    "score_asc":  "threat_score ASC, created_at DESC",
    "severity":   (
        "CASE threat_level "
        "WHEN 'CRITICAL' THEN 0 WHEN 'BLOCK' THEN 0 "
        "WHEN 'WARNING' THEN 1 ELSE 2 END ASC, created_at DESC"
    ),
}
DEFAULT_SORT = "time_desc"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        TEXT UNIQUE NOT NULL,
    timestamp       TEXT NOT NULL,
    log_id          TEXT,
    user_id         TEXT,
    department      TEXT,
    destination_url TEXT,
    entity_types    TEXT NOT NULL DEFAULT '[]',
    entity_count    INTEGER NOT NULL DEFAULT 0,
    threat_level    TEXT NOT NULL,
    action          TEXT,
    message         TEXT,
    remediation     TEXT,
    threat_score    INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'NEW',
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(threat_level);
CREATE INDEX IF NOT EXISTS idx_alerts_department ON alerts(department);
CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts(status);

CREATE TABLE IF NOT EXISTS scan_totals (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    scanned  INTEGER NOT NULL DEFAULT 0,
    threats  INTEGER NOT NULL DEFAULT 0,
    critical INTEGER NOT NULL DEFAULT 0
);
"""


def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _row_to_alert(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["entity_types"] = json.loads(d.get("entity_types") or "[]")
    return d


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")


class AlertStore:
    """SQLite-backed alert/incident store. One instance per DB path."""

    def __init__(self, db_path: str) -> None:
        self._path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO scan_totals (id, scanned, threats, critical) "
                "VALUES (1, 0, 0, 0)"
            )

    def _connect(self) -> sqlite3.Connection:
        # Autocommit (isolation_level=None): every statement below commits
        # immediately, no explicit conn.commit() needed. All DB access in
        # this app happens on the asyncio event-loop thread (never inside
        # run_in_executor), so there is no cross-thread contention to guard
        # against beyond what SQLite itself provides.
        conn = sqlite3.connect(self._path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def record_scan_batch(self, *, scanned: int, threats: int, critical: int) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                "UPDATE scan_totals SET scanned = scanned + ?, threats = threats + ?, "
                "critical = critical + ? WHERE id = 1",
                (scanned, threats, critical),
            )

    def record_alerts(self, alerts: Sequence[Dict[str, Any]]) -> None:
        if not alerts:
            return
        now = _utc_now_iso()
        rows = [
            (
                a.get("alert_id"), a.get("timestamp", now), a.get("log_id"),
                a.get("user_id"), a.get("department"), a.get("destination_url"),
                json.dumps(a.get("entity_types", [])),
                a.get("entity_count", len(a.get("entity_types", []))),
                a.get("threat_level", "INFO"), a.get("action"), a.get("message"),
                a.get("remediation"), a.get("threat_score", 0), now,
            )
            for a in alerts
        ]
        with closing(self._connect()) as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO alerts "
                "(alert_id, timestamp, log_id, user_id, department, destination_url, "
                " entity_types, entity_count, threat_level, action, message, remediation, "
                " threat_score, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            # Retention: keep only the MAX_ALERTS_STORED most recent rows.
            conn.execute(
                "DELETE FROM alerts WHERE id NOT IN "
                "(SELECT id FROM alerts ORDER BY id DESC LIMIT ?)",
                (MAX_ALERTS_STORED,),
            )

    def update_status(self, alert_id: str, status: str) -> Optional[Dict[str, Any]]:
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status: {status!r}. Must be one of {VALID_STATUSES}")
        with closing(self._connect()) as conn:
            conn.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
            row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            return _row_to_alert(row) if row else None

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            return _row_to_alert(row) if row else None

    def _build_filter_clause(
        self, *,
        severities: Optional[Sequence[str]],
        departments: Optional[Sequence[str]],
        statuses: Optional[Sequence[str]],
        entity_types: Optional[Sequence[str]],
        search: Optional[str],
    ) -> Tuple[str, List[Any]]:
        clauses: List[str] = []
        params: List[Any] = []

        if severities:
            clauses.append(f"threat_level IN ({','.join('?' for _ in severities)})")
            params.extend(severities)

        if departments:
            clauses.append(f"department IN ({','.join('?' for _ in departments)})")
            params.extend(departments)

        if statuses:
            clauses.append(f"status IN ({','.join('?' for _ in statuses)})")
            params.extend(statuses)

        if entity_types:
            ors = []
            for etype in entity_types:
                ors.append("entity_types LIKE ? ESCAPE '\\'")
                params.append(f'%"{_escape_like(etype)}"%')
            clauses.append("(" + " OR ".join(ors) + ")")

        if search:
            like = f"%{_escape_like(search)}%"
            clauses.append(
                "(user_id LIKE ? ESCAPE '\\' OR department LIKE ? ESCAPE '\\' "
                "OR destination_url LIKE ? ESCAPE '\\' OR message LIKE ? ESCAPE '\\')"
            )
            params.extend([like, like, like, like])

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def list_alerts(
        self, *,
        severities: Optional[Sequence[str]] = None,
        departments: Optional[Sequence[str]] = None,
        statuses: Optional[Sequence[str]] = None,
        entity_types: Optional[Sequence[str]] = None,
        search: Optional[str] = None,
        sort: str = DEFAULT_SORT,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        sort_sql = _SORT_COLUMNS.get(sort, _SORT_COLUMNS[DEFAULT_SORT])
        where, params = self._build_filter_clause(
            severities=severities, departments=departments, statuses=statuses,
            entity_types=entity_types, search=search,
        )
        limit = max(1, min(limit, 200))
        offset = max(0, offset)

        with closing(self._connect()) as conn:
            # bandit flags f-string SQL as B608 by pattern alone; `where` is
            # built exclusively from the hardcoded clause fragments in
            # _build_filter_clause() (column names, operators, and `?`
            # placeholders — never raw values, which always go through
            # `params`), and `sort_sql` is a dict-lookup against the fixed
            # _SORT_COLUMNS allowlist — the raw `sort` argument is never
            # itself placed in SQL text. Neither is user-controlled SQL.
            total = conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]  # nosec B608
            rows = conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY {sort_sql} LIMIT ? OFFSET ?",  # nosec B608
                [*params, limit, offset],
            ).fetchall()

        return {
            "items":  [_row_to_alert(r) for r in rows],
            "total":  total,
            "limit":  limit,
            "offset": offset,
        }

    def aggregate_counts(
        self, *,
        severities: Optional[Sequence[str]] = None,
        departments: Optional[Sequence[str]] = None,
        statuses: Optional[Sequence[str]] = None,
        entity_types: Optional[Sequence[str]] = None,
        search: Optional[str] = None,
    ) -> Dict[str, Dict[str, int]]:
        where, params = self._build_filter_clause(
            severities=severities, departments=departments, statuses=statuses,
            entity_types=entity_types, search=search,
        )
        with closing(self._connect()) as conn:
            # See the matching comment in list_alerts() — `where` never
            # contains raw user data, only hardcoded fragments + `?`.
            severity_counts = {
                r["threat_level"]: r["n"] for r in conn.execute(
                    f"SELECT threat_level, COUNT(*) AS n FROM alerts {where} GROUP BY threat_level",  # nosec B608
                    params,
                ).fetchall()
            }
            department_counts = {
                r["department"]: r["n"] for r in conn.execute(
                    f"SELECT department, COUNT(*) AS n FROM alerts {where} GROUP BY department",  # nosec B608
                    params,
                ).fetchall()
            }
            entity_rows = conn.execute(
                f"SELECT entity_types FROM alerts {where}", params,  # nosec B608
            ).fetchall()

        entity_counts: Dict[str, int] = {}
        for r in entity_rows:
            for etype in json.loads(r["entity_types"] or "[]"):
                entity_counts[etype] = entity_counts.get(etype, 0) + 1

        return {
            "severity_counts":   severity_counts,
            "department_counts": department_counts,
            "entity_counts":     entity_counts,
        }

    def totals(self) -> Dict[str, int]:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT scanned, threats, critical FROM scan_totals WHERE id = 1"
            ).fetchone()
            return dict(row) if row else {"scanned": 0, "threats": 0, "critical": 0}

    def alert_count(self) -> int:
        with closing(self._connect()) as conn:
            return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def is_empty(self) -> bool:
        return self.alert_count() == 0


def _default_db_path() -> str:
    from config import config
    return config.DASHBOARD_DB_PATH


dashboard_store = AlertStore(_default_db_path())
