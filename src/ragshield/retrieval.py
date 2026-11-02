from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


TOKEN_RE = re.compile(r"[a-zA-Z0-9_]+")


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text) if len(token) > 1]


@dataclass(frozen=True)
class RetrievedChunk:
    chunk_id: str
    document_id: str
    filename: str
    content: str
    score: float


def lexical_score(question: str, content: str) -> float:
    """Small deterministic BM25-like score suitable for the local security lab."""
    query_terms = Counter(tokenize(question))
    document_terms = Counter(tokenize(content))
    if not query_terms or not document_terms:
        return 0.0
    overlap = sum(min(count, document_terms[term]) for term, count in query_terms.items())
    coverage = overlap / sum(query_terms.values())
    density = overlap / math.sqrt(sum(document_terms.values()))
    return round(0.8 * coverage + 0.2 * density, 6)


def chunk_text(text: str, *, size: int = 900, overlap: int = 120) -> list[str]:
    normalized = "\n".join(line.strip() for line in text.splitlines() if line.strip())
    if len(normalized) <= size:
        return [normalized]
    chunks: list[str] = []
    start = 0
    while start < len(normalized):
        end = min(len(normalized), start + size)
        if end < len(normalized):
            boundary = normalized.rfind(" ", start, end)
            if boundary > start:
                end = boundary
        chunks.append(normalized[start:end].strip())
        if end == len(normalized):
            break
        start = max(start + 1, end - overlap)
    return chunks

