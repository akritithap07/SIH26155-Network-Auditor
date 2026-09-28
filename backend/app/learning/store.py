from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


import sqlite3


DEFAULT_DB_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "learning.db"
)


class LearningStore:
    """
    Persistent store for human-confirmed configuration mappings.

    Only explicit confirmations are written here.
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
    ):
        self.db_path = (
            Path(db_path)
            if db_path is not None
            else DEFAULT_DB_PATH
        )

        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.db_path
        )

        connection.row_factory = sqlite3.Row

        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS confirmed_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vendor TEXT NOT NULL,
                    source_text TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    target_key TEXT NOT NULL,
                    similarity_score REAL,
                    rationale TEXT,
                    confirmed_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (
                        vendor,
                        source_text,
                        control_id,
                        target_key
                    )
                )
                """
            )

            connection.commit()

    def save_mapping(
        self,
        vendor: str,
        source_text: str,
        control_id: str,
        target_key: str,
        similarity_score: Optional[float],
        rationale: Optional[str],
        confirmed_by: str = "human",
    ) -> Dict[str, object]:
        now = datetime.now(
            timezone.utc
        ).isoformat()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO confirmed_mappings (
                    vendor,
                    source_text,
                    control_id,
                    target_key,
                    similarity_score,
                    rationale,
                    confirmed_by,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (
                    vendor,
                    source_text,
                    control_id,
                    target_key
                )
                DO UPDATE SET
                    similarity_score = excluded.similarity_score,
                    rationale = excluded.rationale,
                    confirmed_by = excluded.confirmed_by,
                    updated_at = excluded.updated_at
                """,
                (
                    vendor,
                    source_text,
                    control_id,
                    target_key,
                    similarity_score,
                    rationale,
                    confirmed_by,
                    now,
                    now,
                ),
            )

            connection.commit()

            row = connection.execute(
                """
                SELECT *
                FROM confirmed_mappings
                WHERE vendor = ?
                  AND source_text = ?
                  AND control_id = ?
                  AND target_key = ?
                """,
                (
                    vendor,
                    source_text,
                    control_id,
                    target_key,
                ),
            ).fetchone()

        if row is None:
            raise RuntimeError(
                "Failed to save confirmed mapping."
            )

        return dict(row)

    def find_by_source(
        self,
        vendor: str,
        source_text: str,
    ) -> List[Dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM confirmed_mappings
                WHERE vendor = ?
                  AND source_text = ?
                ORDER BY updated_at DESC
                """,
                (
                    vendor,
                    source_text,
                ),
            ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    def list_mappings(
        self,
        vendor: Optional[str] = None,
    ) -> List[Dict[str, object]]:
        with self._connect() as connection:
            if vendor is None:
                rows = connection.execute(
                    """
                    SELECT *
                    FROM confirmed_mappings
                    ORDER BY updated_at DESC
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT *
                    FROM confirmed_mappings
                    WHERE vendor = ?
                    ORDER BY updated_at DESC
                    """,
                    (vendor,),
                ).fetchall()

        return [
            dict(row)
            for row in rows
        ]