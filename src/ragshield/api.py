from __future__ import annotations

import os

import uvicorn
from fastapi import FastAPI

from ragshield.engine import RAGEngine
from ragshield.models import DocumentInput, IngestResult, QueryRequest, QueryResponse, SecurityMode
from ragshield.store import SQLiteStore


def create_app(
    *,
    mode: SecurityMode | None = None,
    database: str | None = None,
) -> FastAPI:
    selected_mode = mode or SecurityMode(os.getenv("SECURITY_MODE", "baseline"))
    store = SQLiteStore(database or os.getenv("RAGSHIELD_DB", "ragshield.db"))
    engine = RAGEngine(store, selected_mode)
    app = FastAPI(title="RAGShield", version="0.1.0")
    app.state.engine = engine

    @app.get("/health")
    def health() -> dict[str, object]:
        return {"status": "ok", "security_mode": selected_mode, "documents": store.document_counts()}

    @app.post("/documents", response_model=IngestResult)
    def ingest_document(document: DocumentInput) -> IngestResult:
        return engine.ingest(document)

    @app.post("/query", response_model=QueryResponse)
    def query(request: QueryRequest) -> QueryResponse:
        return engine.query(request.question, request.top_k)

    return app


app = create_app()


def main() -> None:
    uvicorn.run("ragshield.api:app", host="0.0.0.0", port=8000, reload=False)

