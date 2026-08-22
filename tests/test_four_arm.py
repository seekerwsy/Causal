from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompt_mechanism_study.formal import FormalStudyError
from prompt_mechanism_study.four_arm import (
    _metric,
    _validate_semantics,
    _validate_suffixes,
    prepare_external_tasks,
)
from prompt_mechanism_study.records import canonical_json


@pytest.mark.reviewer
def test_four_arm_suffix_contract_separates_specific_generic_and_placebo() -> None:
    suffixes = _validate_suffixes(
        json.dumps(
            {
                "specific_text": "Use parameter binding for every untrusted SQL value.",
                "generic_text": "Follow secure coding practices throughout the implementation.",
                "placebo_text": "Keep the implementation structure concise and clearly organized.",
            }
        ).encode(),
        {
            "maximum_suffix_characters": 320,
            "placebo_relative_tolerance": 0.2,
            "placebo_minimum_tolerance_characters": 12,
        },
        source_prompt="Implement a database lookup function.",
    )
    assert set(suffixes) == {"specific", "generic", "placebo"}
    assert abs(len(suffixes["specific"]) - len(suffixes["placebo"])) <= 12
    valid = {
        "task_preserved": "yes",
        "contract_satisfied": "yes",
        "unintended_changes": "no",
        "contradiction": "no",
    }
    response = {
        "specific": {
            **valid,
            "target_mechanism": "present",
            "generic_security": "present",
        },
        "generic": {
            **valid,
            "target_mechanism": "absent",
            "generic_security": "present",
        },
        "placebo": {
            **valid,
            "target_mechanism": "absent",
            "generic_security": "absent",
        },
        "reason": "The functional task is unchanged and the three security states differ.",
    }
    assert _validate_semantics(json.dumps(response).encode()) == response
    response["generic"]["target_mechanism"] = "present"
    with pytest.raises(FormalStudyError):
        _validate_semantics(json.dumps(response).encode())


@pytest.mark.reviewer
def test_external_selection_uses_only_frozen_inputs_and_drops_outcomes(tmp_path: Path) -> None:
    prompts = []
    contracts = []
    for index in range(35):
        task_id = f"cluster-{index:02d}"
        prompts.append(
            {
                "task_id": task_id,
                "language": "python",
                "cwe": ("CWE-78", "CWE-89", "CWE-502")[index % 3],
                "prompt": f"Implement task {index}.",
                "outcome_that_must_not_propagate": index % 2,
            }
        )
        contracts.append(
            {
                "task_id": task_id,
                "contract_id": f"contract-{index:02d}",
                "environment_dependencies": [],
                "requirements": [
                    {"requirement_id": "req_1", "criterion": f"Implement task {index}."}
                ],
            }
        )
    prompt_path = tmp_path / "prompts.jsonl"
    contract_path = tmp_path / "contracts.jsonl"
    prompt_path.write_text("".join(canonical_json(row) + "\n" for row in prompts), encoding="utf-8")
    contract_path.write_text(
        "".join(canonical_json(row) + "\n" for row in contracts), encoding="utf-8"
    )
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    prepare_external_tasks(prompt_path, contract_path, first)
    prepare_external_tasks(prompt_path, contract_path, second)
    assert first.read_bytes() == second.read_bytes()
    rows = [json.loads(line) for line in first.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 30
    assert all("outcome" not in key for row in rows for key in row)


@pytest.mark.reviewer
def test_security_unknown_is_a_bound_not_secure() -> None:
    row = {
        "code_status": "valid",
        "oracle_status": "unknown",
        "functional_status": "pass",
    }
    assert _metric(row, "secure_yield") == (0, 0, 1)
    assert _metric(row, "joint") == (0, 0, 1)
