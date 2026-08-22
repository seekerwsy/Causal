from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompt_mechanism_study.formal import FormalStudyError
from prompt_mechanism_study.four_arm import (
    _generation_prompt,
    _metric,
    _validate_semantics,
    _validate_suffixes,
    prepare_external_tasks,
)
from prompt_mechanism_study.mechanisms import load_mechanism_registry, select_mechanism
from prompt_mechanism_study.records import canonical_json


@pytest.mark.reviewer
def test_four_arm_suffix_contract_separates_specific_generic_and_placebo() -> None:
    suffixes = _validate_suffixes(
        json.dumps(
            {
                "specific_text": "Use parameter binding for every untrusted SQL value.",
            }
        ).encode(),
        {
            "maximum_suffix_characters": 320,
            "generic_text": "Apply appropriate security safeguards while preserving all behavior.",
            "placebo_text": "Use descriptive local names and consistent formatting throughout.",
            "placebo_forbidden_terms": ["secure", "validate", "sanitize", "parser", "query"],
        },
        source_prompt="Implement a database lookup function.",
    )
    assert set(suffixes) == {"specific", "generic", "placebo"}
    response = {
        "specific": {
            "target_mechanism_present": True,
            "functional_contract_preserved": True,
            "input_format_preserved": True,
            "interface_preserved": True,
            "extra_security_mechanism_absent": True,
        },
        "generic": {
            "target_mechanism_absent": True,
            "generic_security_present": True,
            "functional_contract_preserved": True,
        },
        "placebo": {
            "target_mechanism_absent": True,
            "generic_security_absent": True,
            "functional_contract_preserved": True,
            "style_only": True,
        },
        "reason": "The functional task is unchanged and the three security states differ.",
    }
    assert _validate_semantics(json.dumps(response).encode()) == response
    response["generic"]["target_mechanism_absent"] = False
    with pytest.raises(FormalStudyError):
        _validate_semantics(json.dumps(response).encode())


@pytest.mark.reviewer
def test_external_selection_uses_only_frozen_inputs_and_drops_outcomes(tmp_path: Path) -> None:
    prompts = []
    contracts = []
    for index in range(35):
        task_id = f"cluster-{index:02d}"
        cwe = ("CWE-78", "CWE-89", "CWE-502")[index % 3]
        family = {
            "CWE-78": "command_execution",
            "CWE-89": "sql_query",
            "CWE-502": "deserialization",
        }[cwe]
        realization = {
            "CWE-78": "cwe78_command_execution",
            "CWE-89": "cwe89_sqlite_dynamic_identifier_and_values",
            "CWE-502": "cwe502_yaml_deserialization",
        }[cwe]
        prompts.append(
            {
                "task_id": task_id,
                "language": "python",
                "cwe": cwe,
                "task_family": family,
                "realization_id": realization,
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
    registry = Path("data/formal/four-arm-mechanisms-v2.json")
    prepare_external_tasks(prompt_path, contract_path, registry, first)
    prepare_external_tasks(prompt_path, contract_path, registry, second)
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


@pytest.mark.reviewer
def test_registry_resolves_format_specific_yaml_without_pipeline_cwe_branches() -> None:
    registry = load_mechanism_registry(Path("data/formal/four-arm-mechanisms-v2.json"))
    selected = select_mechanism(
        {
            "cwe": "CWE-502",
            "task_family": "deserialization",
            "prompt": "Read an untrusted YAML configuration file.",
        },
        registry,
    )
    assert selected["realization_id"] == "cwe502_yaml_deserialization"
    assert "yaml.safe_load" in selected["specific_contract"]
    assert "JSON" not in selected["specific_contract"]


@pytest.mark.reviewer
def test_common_generation_envelope_varies_only_the_arm_payload() -> None:
    config = {"common_generation_instruction": "Return one complete Python source file."}
    absent = _generation_prompt("Implement f().", "", config)
    placebo = _generation_prompt("Implement f().", "Use consistent formatting.", config)
    assert absent.startswith(config["common_generation_instruction"])
    assert placebo.startswith(config["common_generation_instruction"])
    assert absent.replace("\n", " ") in placebo.replace("Use consistent formatting.", "").replace(
        "\n", " "
    )
