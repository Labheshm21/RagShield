from __future__ import annotations

import sqlite3
from pathlib import Path

from ragshield.models import DocumentInput, DocumentStatus, ScanResult
from ragshield.retrieval import RetrievedChunk, lexical_score


SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    document_id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    trust TEXT NOT NULL,
    status TEXT NOT NULL,
    risk TEXT NOT NULL,
    content TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chunks (
    chunk_id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents(document_id),
    content TEXT NOT NULL
);
"""


class SQLiteStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)

    def clear(self) -> None:
        self.connection.executescript("DELETE FROM chunks; DELETE FROM documents;")
        self.connection.commit()

    def save_document(
        self,
        document: DocumentInput,
        status: DocumentStatus,
        scan: ScanResult,
        chunks: list[str],
    ) -> None:
        self.connection.execute("DELETE FROM chunks WHERE document_id = ?", (document.document_id,))
        self.connection.execute(
            """INSERT OR REPLACE INTO documents
               (document_id, filename, trust, status, risk, content)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                document.document_id,
                document.filename,
                document.trust.value,
                status.value,
                scan.risk.value,
                document.content,
            ),
        )
        if status == DocumentStatus.INDEXED:
            self.connection.executemany(
                "INSERT INTO chunks (chunk_id, document_id, content) VALUES (?, ?, ?)",
                [
                    (f"{document.document_id}:{index}", document.document_id, content)
                    for index, content in enumerate(chunks)
                ],
            )
        self.connection.commit()

    def retrieve(self, question: str, top_k: int) -> list[RetrievedChunk]:
        rows = self.connection.execute(
            """SELECT c.chunk_id, c.document_id, c.content, d.filename
               FROM chunks c JOIN documents d ON d.document_id = c.document_id
               WHERE d.status = 'indexed'"""
        ).fetchall()
        ranked = [
            RetrievedChunk(
                chunk_id=row["chunk_id"],
                document_id=row["document_id"],
                filename=row["filename"],
                content=row["content"],
                score=lexical_score(question, row["content"]),
            )
            for row in rows
        ]
        ranked.sort(key=lambda chunk: (-chunk.score, chunk.chunk_id))
        return [chunk for chunk in ranked if chunk.score > 0][:top_k]

    def document_counts(self) -> dict[str, int]:
        rows = self.connection.execute(
            "SELECT status, COUNT(*) AS count FROM documents GROUP BY status"
        ).fetchall()
        return {row["status"]: row["count"] for row in rows}

