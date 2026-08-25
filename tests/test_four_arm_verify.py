from pathlib import Path

import pytest

from prompt_mechanism_study.four_arm_verify import verify_analysis


@pytest.mark.reviewer
def test_closed_four_arm_analysis_is_independently_recomputed() -> None:
    report = verify_analysis(
        Path("configs/formal/four-arm-study-fresh-two-family-qwen35-v2.json"),
        Path("data/formal/four-arm-study-fresh-two-family-v2-tasks.jsonl"),
        Path("data/formal/results/fresh-two-family-four-arm-qwen35-v2-analysis"),
    )

    assert report["status"] == "FOUR_ARM_ANALYSIS_VERIFIED"
    assert report["tasks"] == 60
    assert report["assignments"] == 240
