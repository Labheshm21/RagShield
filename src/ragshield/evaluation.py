from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from ragshield.engine import ATTACK_MARKER, RAGEngine
from ragshield.models import DocumentInput, SecurityMode
from ragshield.store import SQLiteStore


@dataclass
class CaseResult:
    case_id: str
    category: str
    mode: str
    question: str
    answer: str
    expected: str
    passed: bool
    attack_success: bool
    detected: bool
    latency_ms: float
    citations: list[str]


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def run_mode(root: Path, mode: SecurityMode) -> list[CaseResult]:
    store = SQLiteStore(":memory:")
    engine = RAGEngine(store, mode)
    flagged_documents: set[str] = set()
    for raw_document in load_jsonl(root / "datasets" / "documents.jsonl"):
        ingest = engine.ingest(DocumentInput.model_validate(raw_document))
        if ingest.scan.findings:
            flagged_documents.add(ingest.document_id)

    results: list[CaseResult] = []
    for case in load_jsonl(root / "datasets" / "cases.jsonl"):
        response = engine.query(case["question"], top_k=1)
        attack_success = ATTACK_MARKER in response.answer
        passed = (
            case["expected_answer"].lower() in response.answer.lower()
            if case["category"] == "benign"
            else not attack_success
        )
        results.append(
            CaseResult(
                case_id=case["case_id"],
                category=case["category"],
                mode=mode.value,
                question=case["question"],
                answer=response.answer,
                expected=case["expected_answer"],
                passed=passed,
                attack_success=attack_success,
                detected=bool(
                    response.security.findings
                    or response.security.blocked_chunks
                    or case["case_id"] in flagged_documents
                ),
                latency_ms=response.latency_ms,
                citations=[citation.document_id for citation in response.citations],
            )
        )
    return results


def summarize(results: list[CaseResult], mode: SecurityMode) -> dict[str, float | int | str]:
    selected = [result for result in results if result.mode == mode.value]
    attacks = [result for result in selected if result.category == "adversarial"]
    benign = [result for result in selected if result.category == "benign"]
    return {
        "mode": mode.value,
        "cases": len(selected),
        "attack_success_rate": round(sum(r.attack_success for r in attacks) / len(attacks), 3),
        "attack_detection_rate": round(sum(r.detected for r in attacks) / len(attacks), 3),
        "benign_accuracy": round(sum(r.passed for r in benign) / len(benign), 3),
        "mean_latency_ms": round(sum(r.latency_ms for r in selected) / len(selected), 3),
    }


def write_report(output: Path, results: list[CaseResult], summaries: list[dict]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    with (output / "results.jsonl").open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(asdict(result)) + "\n")
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summaries[0]))
        writer.writeheader()
        writer.writerows(summaries)

    baseline, defended = summaries
    reduction = baseline["attack_success_rate"] - defended["attack_success_rate"]
    markdown = f"""# RAGShield evaluation report

Generated: {datetime.now(timezone.utc).isoformat()}

| Metric | Baseline | Defended |
|---|---:|---:|
| Attack success rate | {baseline['attack_success_rate']:.0%} | {defended['attack_success_rate']:.0%} |
| Attack detection rate | {baseline['attack_detection_rate']:.0%} | {defended['attack_detection_rate']:.0%} |
| Benign answer accuracy | {baseline['benign_accuracy']:.0%} | {defended['benign_accuracy']:.0%} |
| Mean latency | {baseline['mean_latency_ms']} ms | {defended['mean_latency_ms']} ms |

Attack-success reduction: **{reduction:.0%}**.

This first experiment evaluates one defense: deterministic instruction-pattern scanning at ingestion and retrieval time. Results use a deterministic local model and lexical retriever, so they demonstrate the evaluation loop rather than generalize to every production LLM.
"""
    (output / "comparison.md").write_text(markdown, encoding="utf-8")


def run(root: Path, output: Path) -> list[dict]:
    results: list[CaseResult] = []
    summaries = []
    for mode in (SecurityMode.BASELINE, SecurityMode.DEFENDED):
        mode_results = run_mode(root, mode)
        results.extend(mode_results)
        summaries.append(summarize(mode_results, mode))
    write_report(output, results, summaries)
    return summaries


def main() -> None:
    parser = argparse.ArgumentParser(description="Run RAGShield baseline and defended evaluations")
    parser.add_argument("--output", type=Path, default=Path("reports"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    summaries = run(root, args.output)
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()

