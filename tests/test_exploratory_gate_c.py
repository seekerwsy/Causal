from pathlib import Path

from secaware.config import load_config
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.io.jsonl import read_jsonl


_ROOT = Path(__file__).resolve().parents[1]


def test_gate_c_functional_contracts_are_frozen_before_generation() -> None:
    bundle = _ROOT / "data/e2e-pilot/gate-c-cwe78-cwe89-v1"
    contracts = tuple(
        read_jsonl(
            bundle / "task-functional-contracts.jsonl",
            TaskFunctionalContractRecord,
            required=True,
            allow_empty=False,
        )
    )
    assert {item.task_id for item in contracts} == {
        "cluster-22d97b466b5d2c737129",
        "cluster-b80c034159e718b8bbc9",
    }
    assert all(item.audit_pass_ids == ("A", "B") for item in contracts)
    assert all(item.audit_status.value == "consistent" for item in contracts)
    assert all(item.requirements for item in contracts)


def test_gate_c_config_freezes_exact_single_attempt_provider_budgets() -> None:
    config = load_config(_ROOT / "configs/e2e-pilot/gate-c-qwen25-coder-32b-bailian-v1.yaml")
    assert config.generation.models == ["qwen2.5-coder-32b-instruct"]
    assert config.generation.confirmation_seeds == [
        2026081511,
        2026081512,
        2026081513,
        2026081514,
    ]
    assert config.generation.confirmation_max_requests == 8
    assert config.generation.confirmation_max_total_provider_attempts == 8
    assert config.generation.openai_compatible is not None
    assert config.generation.openai_compatible.max_attempts == 1
    assert config.functional_judge.enabled is True
    assert config.functional_judge.mode == "single_pass"
    assert config.functional_judge.llm is not None
    assert config.functional_judge.llm.max_attempts == 1
