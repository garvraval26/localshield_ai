"""Local-only history in SQLite. Stored next to the project, never sent anywhere."""
import sqlite3
from datetime import datetime
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "history.db"
MAX_STORED_TEXT = 300  # store only a short preview of what was checked


class History:
    def __init__(self, db_path=DEFAULT_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as con:
            con.execute(
                """CREATE TABLE IF NOT EXISTS history (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       created_at TEXT NOT NULL,
                       kind TEXT NOT NULL,
                       input_preview TEXT NOT NULL,
                       risk_level TEXT NOT NULL,
                       score REAL NOT NULL,
                       explanation_source TEXT NOT NULL
                   )"""
            )

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def add(self, result):
        """Save one successful analysis (the dict returned by AnalysisService.analyze)."""
        if not result.get("ok"):
            return
        det = result["detection"]
        with self._connect() as con:
            con.execute(
                "INSERT INTO history (created_at, kind, input_preview, risk_level, score, "
                "explanation_source) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    result["kind"],
                    result["input"][:MAX_STORED_TEXT],
                    det["risk_level"],
                    float(det["score"]),
                    result["explanation"]["source"],
                ),
            )

    def recent(self, limit=50):
        with self._connect() as con:
            rows = con.execute(
                "SELECT created_at, kind, input_preview, risk_level, score, explanation_source "
                "FROM history ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        keys = ("time", "type", "input", "risk", "score", "explained_by")
        return [dict(zip(keys, row)) for row in rows]

    def count(self):
        with self._connect() as con:
            return con.execute("SELECT COUNT(*) FROM history").fetchone()[0]

    def clear(self):
        with self._connect() as con:
            con.execute("DELETE FROM history")