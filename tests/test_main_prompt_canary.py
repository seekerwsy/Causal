from __future__ import annotations

import json
from pathlib import Path

from secaware.exploratory.main_prompt_canary import prepare_main_prompt_canary
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.io.jsonl import read_jsonl
from secaware.schema.records import PromptRecord

REPO_ROOT = Path(__file__).resolve().parents[1]
TASK_POOL = REPO_ROOT / "data/e2e-pilot/five-cwe-main-task-pool-frozen-20260818-07"
ESTIMAND = REPO_ROOT / "data/e2e-pilot/five-cwe-pooled-policy-estimand-frozen-20260818-08"
CONFIG = REPO_ROOT / "configs/e2e-pilot/five-cwe-main-prompt-canary-inputs-v1.json"
DISCOVERY_CONFIG = REPO_ROOT / "configs/e2e-pilot/five-cwe-randomized-discovery-inputs-v1.json"
CONFIRMATION_CONFIG = REPO_ROOT / "configs/e2e-pilot/five-cwe-held-out-policy-itt-inputs-v1.json"


def test_prepare_main_prompt_canary_is_outcome_blind_complete_and_reproducible(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    report = prepare_main_prompt_canary(
        task_pool_dir=TASK_POOL,
        estimand_dir=ESTIMAND,
        config_path=CONFIG,
        output_dir=first,
        command_argv=("prepare", "first"),
    )
    replay = prepare_main_prompt_canary(
        task_pool_dir=TASK_POOL,
        estimand_dir=ESTIMAND,
        config_path=CONFIG,
        output_dir=second,
        command_argv=("prepare", "second"),
    )

    assert report["status"] == "MAIN_PROMPT_CANARY_INPUTS_FROZEN"
    assert replay["status"] == "MAIN_PROMPT_CANARY_INPUTS_FROZEN"
    assert report["counts"] == {
        "discover_pool_tasks": 51,
        "confirm_pool_tasks": 42,
        "selected_discover_tasks": 5,
        "forbidden_confirm_tasks": 42,
        "cwes": 5,
        "prompts": 5,
        "functional_contracts": 5,
        "prompt_attestations": 0,
        "provider_calls": 0,
        "generated_code": 0,
        "outcomes_observed": 0,
        "errors": 0,
        "pending": 0,
    }
    for name in (
        "selection.json",
        "prompts.jsonl",
        "prompt-attestations.jsonl",
        "task-functional-contracts.jsonl",
        "functional-contract-provenance.jsonl",
    ):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    prompts = tuple(read_jsonl(first / "prompts.jsonl", PromptRecord, required=True))
    contracts = tuple(
        read_jsonl(
            first / "task-functional-contracts.jsonl",
            TaskFunctionalContractRecord,
            required=True,
        )
    )
    assert len(prompts) == len(contracts) == 5
    assert {item.cwe for item in prompts} == {
        "CWE-78",
        "CWE-89",
        "CWE-502",
        "CWE-328",
        "CWE-338",
    }
    assert {item.task_id for item in prompts} == {item.task_id for item in contracts}
    selection = json.loads((first / "selection.json").read_text(encoding="utf-8"))
    discover = {item["task_id"] for item in selection["tasks"] if item["split"] == "discover"}
    confirm = {item["task_id"] for item in selection["tasks"] if item["split"] == "confirm"}
    assert len(discover) == 5
    assert len(confirm) == 42
    assert not discover & confirm
    assert all(
        "outcome" not in item and "generated_code" not in item for item in selection["tasks"]
    )


def test_prepare_main_prompt_canary_freezes_all_discovery_tasks_without_confirm_leakage(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first-discovery"
    second = tmp_path / "second-discovery"
    report = prepare_main_prompt_canary(
        task_pool_dir=TASK_POOL,
        estimand_dir=ESTIMAND,
        config_path=DISCOVERY_CONFIG,
        output_dir=first,
        command_argv=("prepare", "first-discovery"),
    )
    replay = prepare_main_prompt_canary(
        task_pool_dir=TASK_POOL,
        estimand_dir=ESTIMAND,
        config_path=DISCOVERY_CONFIG,
        output_dir=second,
        command_argv=("prepare", "second-discovery"),
    )

    assert report["status"] == "RANDOMIZED_DISCOVERY_INPUTS_FROZEN"
    assert replay["status"] == "RANDOMIZED_DISCOVERY_INPUTS_FROZEN"
    assert report["counts"] == {
        "discover_pool_tasks": 51,
        "confirm_pool_tasks": 42,
        "selected_discover_tasks": 51,
        "forbidden_confirm_tasks": 42,
        "cwes": 5,
        "prompts": 51,
        "functional_contracts": 51,
        "prompt_attestations": 0,
        "provider_calls": 0,
        "generated_code": 0,
        "outcomes_observed": 0,
        "errors": 0,
        "pending": 0,
    }
    for name in (
        "selection.json",
        "prompts.jsonl",
        "prompt-attestations.jsonl",
        "task-functional-contracts.jsonl",
        "functional-contract-provenance.jsonl",
    ):
        assert (first / name).read_bytes() == (second / name).read_bytes()

    prompts = tuple(read_jsonl(first / "prompts.jsonl", PromptRecord, required=True))
    contracts = tuple(
        read_jsonl(
            first / "task-functional-contracts.jsonl",
            TaskFunctionalContractRecord,
            required=True,
        )
    )
    selection = json.loads((first / "selection.json").read_text(encoding="utf-8"))
    selected = {
        item["task_id"]
        for item in selection["tasks"]
        if item["canary_role"] == "selected_randomized_discovery"
    }
    forbidden = {
        item["task_id"]
        for item in selection["tasks"]
        if item["canary_role"] == "forbidden_confirmation"
    }
    assert len(prompts) == len(contracts) == len(selected) == 51
    assert len(forbidden) == 42
    assert not selected & forbidden
    assert {item.task_id for item in prompts} == selected
    assert {item.task_id for item in contracts} == selected
    assert all(item.split == "discover" for item in prompts)
    selected_by_cwe = report["selected_task_ids_by_cwe"]
    assert {cwe: len(task_ids) for cwe, task_ids in selected_by_cwe.items()} == {
        "CWE-78": 21,
        "CWE-89": 10,
        "CWE-502": 7,
        "CWE-328": 10,
        "CWE-338": 3,
    }
    assert all(task_ids == sorted(task_ids) for task_ids in selected_by_cwe.values())
    assert "adapter_source_sha256" in report["input_digests"]


def test_prepare_main_prompt_inputs_freezes_all_confirmation_tasks_without_discovery_leakage(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first-confirmation"
    second = tmp_path / "second-confirmation"
    report = prepare_main_prompt_canary(
        task_pool_dir=TASK_POOL,
        estimand_dir=ESTIMAND,
        config_path=CONFIRMATION_CONFIG,
        output_dir=first,
        command_argv=("prepare", "first-confirmation"),
    )
    replay = prepare_main_prompt_canary(
        task_pool_dir=TASK_POOL,
        estimand_dir=ESTIMAND,
        config_path=CONFIRMATION_CONFIG,
        output_dir=second,
        command_argv=("prepare", "second-confirmation"),
    )

    assert report["status"] == "HELD_OUT_POLICY_ITT_INPUTS_FROZEN"
    assert replay["status"] == "HELD_OUT_POLICY_ITT_INPUTS_FROZEN"
    assert report["counts"] == {
        "discover_pool_tasks": 51,
        "confirm_pool_tasks": 42,
        "selected_confirm_tasks": 42,
        "forbidden_discover_tasks": 51,
        "cwes": 5,
        "prompts": 42,
        "functional_contracts": 42,
        "prompt_attestations": 0,
        "provider_calls": 0,
        "generated_code": 0,
        "outcomes_observed": 0,
        "errors": 0,
        "pending": 0,
    }
    for name in (
        "selection.json",
        "prompts.jsonl",
        "prompt-attestations.jsonl",
        "task-functional-contracts.jsonl",
        "functional-contract-provenance.jsonl",
    ):
        assert (first / name).read_bytes() == (second / name).read_bytes()

    prompts = tuple(read_jsonl(first / "prompts.jsonl", PromptRecord, required=True))
    contracts = tuple(
        read_jsonl(
            first / "task-functional-contracts.jsonl",
            TaskFunctionalContractRecord,
            required=True,
        )
    )
    selection = json.loads((first / "selection.json").read_text(encoding="utf-8"))
    selected = {
        item["task_id"]
        for item in selection["tasks"]
        if item["canary_role"] == "selected_held_out_confirmation"
    }
    forbidden = {
        item["task_id"]
        for item in selection["tasks"]
        if item["canary_role"] == "forbidden_discovery"
    }
    assert len(prompts) == len(contracts) == len(selected) == 42
    assert len(forbidden) == 51
    assert not selected & forbidden
    assert {item.task_id for item in prompts} == selected
    assert {item.task_id for item in contracts} == selected
    assert all(item.split == "confirm" for item in prompts)
    assert {cwe: len(task_ids) for cwe, task_ids in report["selected_task_ids_by_cwe"].items()} == {
        "CWE-78": 22,
        "CWE-89": 7,
        "CWE-502": 2,
        "CWE-328": 7,
        "CWE-338": 4,
    }
