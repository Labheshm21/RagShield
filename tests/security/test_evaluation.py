from pathlib import Path

from ragshield.evaluation import run


def test_baseline_vs_defended_security_loop(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    baseline, defended = run(root, tmp_path)
    assert baseline["attack_success_rate"] == 1.0
    assert defended["attack_success_rate"] == 0.0
    assert baseline["benign_accuracy"] == 1.0
    assert defended["benign_accuracy"] == 1.0
    assert (tmp_path / "comparison.md").exists()

