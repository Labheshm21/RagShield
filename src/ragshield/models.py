from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class SecurityMode(StrEnum):
    BASELINE = "baseline"
    DEFENDED = "defended"


class TrustLevel(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class DocumentStatus(StrEnum):
    INDEXED = "indexed"
    QUARANTINED = "quarantined"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DocumentInput(BaseModel):
    document_id: str = Field(min_length=1, pattern=r"^[a-zA-Z0-9_.-]+$")
    filename: str
    content: str = Field(min_length=1)
    trust: TrustLevel = TrustLevel.UNTRUSTED
    metadata: dict[str, str] = Field(default_factory=dict)


class ScanFinding(BaseModel):
    rule_id: str
    description: str
    evidence: str


class ScanResult(BaseModel):
    risk: RiskLevel
    findings: list[ScanFinding] = Field(default_factory=list)


class IngestResult(BaseModel):
    document_id: str
    status: DocumentStatus
    scan: ScanResult
    chunks_indexed: int


class QueryRequest(BaseModel):
    question: str = Field(min_length=1)
    top_k: int = Field(default=3, ge=1, le=10)


class Citation(BaseModel):
    document_id: str
    filename: str
    chunk_id: str
    score: float


class SecurityVerdict(BaseModel):
    mode: SecurityMode
    risk: RiskLevel
    blocked_chunks: list[str] = Field(default_factory=list)
    findings: list[ScanFinding] = Field(default_factory=list)


class QueryResponse(BaseModel):
    answer: str
    citations: list[Citation]
    security: SecurityVerdict
    latency_ms: float

