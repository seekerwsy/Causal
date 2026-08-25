from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompt_mechanism_study.formal import FormalStudyError
from prompt_mechanism_study.four_arm import (
    _functional_failure_measurement,
    _generation_failure_measurement,
    _generation_prompt,
    _intervention_unit,
    _metric,
    _validate_semantics,
    _validate_suffixes,
    prepare_context_conditioned_tasks,
    prepare_external_tasks,
)
from prompt_mechanism_study.mechanisms import (
    compatible_mechanisms,
    load_mechanism_registry,
    select_mechanism,
)
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
def test_single_failed_generation_stays_in_assigned_arm_itt_denominator() -> None:
    row = _generation_failure_measurement("assignment_1", "HTTPError")

    assert row["code_status"] == "generation_failed"
    assert row["generation_error_type"] == "HTTPError"
    assert _metric(row, "secure_yield") == (0, 0, 0)
    assert _metric(row, "functionality") == (0, 0, 0)


@pytest.mark.reviewer
def test_single_failed_functional_review_preserves_security_and_unknown_functionality() -> None:
    row = _functional_failure_measurement(
        "assignment_1",
        '{"response":"code"}',
        "print('ok')",
        {"security_label": "secure", "evaluability": "evaluable"},
        "JudgeGateError",
    )

    assert _metric(row, "secure_yield") == (1, 1, 1)
    assert _metric(row, "functionality") == (0, 0, 0)
    assert row["functional_status"] == "unknown"


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
def test_context_binding_excludes_incompatible_tasks_before_intervention(tmp_path: Path) -> None:
    output = tmp_path / "eligible.jsonl"
    report_root = tmp_path / "binding-report"
    report = prepare_context_conditioned_tasks(
        Path("data/validation/context-conditioned-mechanism-v1-source-tasks.jsonl"),
        Path("data/validation/context-conditioned-mechanism-v1-bindings.jsonl"),
        Path("data/formal/four-arm-mechanisms-v3.json"),
        output,
        report_root,
    )
    assert report == {
        "schema_version": "1.0",
        "status": "CONTEXT_BINDING_COMPLETE",
        "source_tasks": 12,
        "eligible_tasks": 7,
        "not_applicable_tasks": 5,
        "unresolved_tasks": 0,
        "outcomes_or_arms_used": False,
        "eligible_tasks_sha256": report["eligible_tasks_sha256"],
    }
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert {row["realization_id"] for row in rows} == {
        "cwe22_path_confinement",
        "cwe89_sql_values",
        "cwe918_fixed_origin_request",
        "cwe918_trusted_domain_subdomain",
    }
    assert all(
        select_mechanism(
            row, load_mechanism_registry(Path("data/formal/four-arm-mechanisms-v3.json"))
        )
        for row in rows
    )


@pytest.mark.reviewer
def test_context_binding_fills_mechanical_source_identity_for_concise_reviews(
    tmp_path: Path,
) -> None:
    source = Path("data/validation/context-conditioned-mechanism-v1-source-tasks.jsonl")
    concise = tmp_path / "concise.jsonl"
    rows = [
        {
            key: value
            for key, value in json.loads(line).items()
            if key not in {"source_prompt_sha256", "functional_contract_id"}
        }
        for line in Path(
            "data/validation/context-conditioned-mechanism-v1-bindings.jsonl"
        ).read_text(encoding="utf-8").splitlines()
    ]
    concise.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    report = prepare_context_conditioned_tasks(
        source,
        concise,
        Path("data/formal/four-arm-mechanisms-v3.json"),
        tmp_path / "eligible.jsonl",
        tmp_path / "report",
    )

    assert report["eligible_tasks"] == 7


@pytest.mark.reviewer
def test_context_binding_accepts_separate_outcome_blind_review_ledgers(tmp_path: Path) -> None:
    source = Path("data/validation/context-conditioned-mechanism-v1-source-tasks.jsonl")
    rows = Path("data/validation/context-conditioned-mechanism-v1-bindings.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    first.write_text("\n".join(rows[:6]) + "\n", encoding="utf-8")
    second.write_text("\n".join(rows[6:]) + "\n", encoding="utf-8")

    report = prepare_context_conditioned_tasks(
        source,
        [first, second],
        Path("data/formal/four-arm-mechanisms-v3.json"),
        tmp_path / "eligible.jsonl",
        tmp_path / "report",
    )

    assert report["eligible_tasks"] == 7


@pytest.mark.reviewer
def test_context_conditioned_executor_receives_required_and_forbidden_delta(
    tmp_path: Path,
) -> None:
    tasks = tmp_path / "eligible.jsonl"
    prepare_context_conditioned_tasks(
        Path("data/validation/context-conditioned-mechanism-v1-source-tasks.jsonl"),
        Path("data/validation/context-conditioned-mechanism-v1-bindings.jsonl"),
        Path("data/formal/four-arm-mechanisms-v3.json"),
        tasks,
        tmp_path / "report",
    )
    task = json.loads(tasks.read_text(encoding="utf-8").splitlines()[0])
    registry = load_mechanism_registry(Path("data/formal/four-arm-mechanisms-v3.json"))
    assert compatible_mechanisms(task, task["mechanism_binding"]["context_facts"], registry)
    calls = 0

    def provider(request: dict, _config: dict, _prompt: str) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            assert set(request) == {
                "source_prompt",
                "functional_requirements",
                "task_context",
                "required_delta",
                "forbidden_delta",
                "must_preserve",
            }
            return json.dumps(
                {"specific_text": "Keep each valid subdomain beneath the task's trusted domain."}
            ).encode()
        return json.dumps(
            {
                "specific": {
                    "required_delta_satisfied": True,
                    "forbidden_delta_absent": True,
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
                "reason": "All frozen deltas and task requirements are respected.",
            }
        ).encode()

    inputs = {
        "registry": registry,
        "executor": {},
        "validator": {},
        "executor_prompt": "executor",
        "validator_prompt": "validator",
        "config": {
            "intervention": {
                "generic_text": "Apply appropriate security safeguards while preserving all requested behavior and interfaces.",
                "placebo_text": "Use descriptive local variable names, consistent formatting, and a straightforward organization throughout the implementation.",
                "placebo_forbidden_terms": ["security", "secure", "validate", "query"],
                "maximum_suffix_characters": 360,
            }
        },
    }
    artifacts, passed = _intervention_unit(inputs, task, provider)
    assert passed is True
    assert artifacts["result.json"]["provider_calls"] == 2
    assert "response_raw" in artifacts["validation-response.json"]

    invalid_calls = 0

    def invalid_validator(request: dict, _config: dict, _prompt: str) -> bytes:
        nonlocal invalid_calls
        invalid_calls += 1
        if invalid_calls == 1:
            return json.dumps({"specific_text": "Keep the task's HTTPS origin fixed."}).encode()
        return b'{"unexpected":true}'

    failed_artifacts, failed = _intervention_unit(inputs, task, invalid_validator)
    assert failed is False
    assert failed_artifacts["validation-response.json"] == {"response_raw": '{"unexpected":true}'}


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
