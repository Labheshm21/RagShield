from __future__ import annotations

import re
import time

from ragshield.models import (
    Citation,
    DocumentInput,
    DocumentStatus,
    IngestResult,
    QueryResponse,
    RiskLevel,
    SecurityMode,
    SecurityVerdict,
)
from ragshield.retrieval import RetrievedChunk, chunk_text
from ragshield.security import scan_text
from ragshield.store import SQLiteStore


ATTACK_MARKER = "RAGSHIELD_ATTACK_SUCCESS"
FACT_PATTERN = re.compile(r"(?:^|\n)FACT:\s*(.+?)(?:\n|$)", re.I)


class RAGEngine:
    def __init__(self, store: SQLiteStore, mode: SecurityMode) -> None:
        self.store = store
        self.mode = mode

    def ingest(self, document: DocumentInput) -> IngestResult:
        scan = scan_text(document.content + "\n" + " ".join(document.metadata.values()))
        should_quarantine = self.mode == SecurityMode.DEFENDED and scan.risk == RiskLevel.HIGH
        status = DocumentStatus.QUARANTINED if should_quarantine else DocumentStatus.INDEXED
        chunks = chunk_text(document.content) if status == DocumentStatus.INDEXED else []
        self.store.save_document(document, status, scan, chunks)
        return IngestResult(
            document_id=document.document_id,
            status=status,
            scan=scan,
            chunks_indexed=len(chunks),
        )

    def query(self, question: str, top_k: int = 3) -> QueryResponse:
        started = time.perf_counter()
        retrieved = self.store.retrieve(question, top_k)
        allowed: list[RetrievedChunk] = []
        blocked: list[str] = []
        findings = []

        for chunk in retrieved:
            scan = scan_text(chunk.content)
            findings.extend(scan.findings)
            if self.mode == SecurityMode.DEFENDED and scan.risk == RiskLevel.HIGH:
                blocked.append(chunk.chunk_id)
            else:
                allowed.append(chunk)

        risk = RiskLevel.HIGH if findings else RiskLevel.LOW
        answer = self._generate(question, allowed)
        citations = [
            Citation(
                document_id=chunk.document_id,
                filename=chunk.filename,
                chunk_id=chunk.chunk_id,
                score=chunk.score,
            )
            for chunk in allowed[:2]
        ]
        return QueryResponse(
            answer=answer,
            citations=citations,
            security=SecurityVerdict(
                mode=self.mode,
                risk=risk,
                blocked_chunks=blocked,
                findings=findings,
            ),
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
        )

    @staticmethod
    def _generate(question: str, chunks: list[RetrievedChunk]) -> str:
        """A deliberately vulnerable deterministic stand-in for an instruction-following LLM."""
        for chunk in chunks:
            if ATTACK_MARKER in chunk.content and scan_text(chunk.content).risk == RiskLevel.HIGH:
                return ATTACK_MARKER
        for chunk in chunks:
            match = FACT_PATTERN.search(chunk.content)
            if match:
                return match.group(1).strip()
        if not chunks:
            return "I do not have enough trusted context to answer that question."
        return "I found related context, but it does not contain a supported answer."

