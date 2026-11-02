from __future__ import annotations

import re

from ragshield.models import RiskLevel, ScanFinding, ScanResult


RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "INJ001",
        "Attempts to override prior instructions",
        re.compile(r"\b(ignore|disregard|forget)\b.{0,40}\b(instruction|prompt|rule)s?\b", re.I | re.S),
    ),
    (
        "INJ002",
        "Attempts to assign system or assistant behavior",
        re.compile(r"\b(system|assistant)\s*(message|instruction|prompt)?\s*:", re.I),
    ),
    (
        "INJ003",
        "Requests prompt or secret extraction",
        re.compile(r"\b(reveal|print|expose|leak|return)\b.{0,50}\b(secret|canary|system prompt|credentials?)\b", re.I | re.S),
    ),
    (
        "INJ004",
        "Contains the deterministic attack marker",
        re.compile(r"RAGSHIELD_ATTACK_SUCCESS", re.I),
    ),
)


def scan_text(text: str) -> ScanResult:
    findings: list[ScanFinding] = []
    for rule_id, description, pattern in RULES:
        match = pattern.search(text)
        if match:
            start = max(0, match.start() - 30)
            end = min(len(text), match.end() + 30)
            evidence = " ".join(text[start:end].split())[:160]
            findings.append(
                ScanFinding(rule_id=rule_id, description=description, evidence=evidence)
            )
    if any(f.rule_id in {"INJ001", "INJ003", "INJ004"} for f in findings):
        risk = RiskLevel.HIGH
    elif findings:
        risk = RiskLevel.MEDIUM
    else:
        risk = RiskLevel.LOW
    return ScanResult(risk=risk, findings=findings)

