from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.datasets import (
    build_prospective_role_census,
    freeze_contracts,
    prepare_datasets,
    prepare_dedup_candidates,
)
from prompt_mechanism_study.qualification_data import prepare_qualification_source_review
from prompt_mechanism_study.source_gold_review import (
    finalize_source_gold_review,
    prepare_source_gold_adjudication,
)

pytestmark = pytest.mark.extended


def test_prepare_seven_sources_without_execution(tmp_path: Path) -> None:
    sources = _sources(tmp_path)
    output = tmp_path / "prepared"

    report = prepare_datasets(output, **sources)

    verify_bundle(output)
    records = read_json(output / "records.json")
    assert report["record_count"] == 8
    assert {item["source_dataset"] for item in records} == {
        "sallm",
        "cweval",
        "cyberseceval_instruct_prime",
        "llmseceval",
        "securityeval",
        "codesec_eval",
        "secodeplt",
    }
    decisions = read_json(output / "contract-decisions.json")
    assert [item["source_test_status"] for item in decisions].count("available") == 5
    assert {item["semantic_contract_status"] for item in decisions} == {"pending"}
    assert len(read_json(output / "contract-requests.json")) == 8
    base = next(item for item in records if item["source_item_id"].startswith("SecEvalBase:"))
    assert base["source_lineage_family"] == "securityeval"
    assert report["semantic_clustering_complete"] is False
    assert report["scientific_claim_allowed"] is False


def test_exact_cross_source_prompt_is_one_provisional_cluster(tmp_path: Path) -> None:
    sources = _sources(tmp_path, shared_prompt="Implement the same function.")
    output = tmp_path / "prepared"

    report = prepare_datasets(
        output,
        sallm_root=sources["sallm_root"],
        cyberseceval_path=sources["cyberseceval_path"],
    )

    clusters = read_json(output / "provisional-clusters.json")
    duplicate = next(item for item in clusters if len(item["record_ids"]) == 2)
    assert duplicate["evidence"] == "exact_prompt"
    assert report["cross_record_exact_duplicate_count"] == 1


def test_invalid_rows_are_counted_not_silently_dropped(tmp_path: Path) -> None:
    sources = _sources(tmp_path)
    dataset = sources["sallm_root"] / "Dataset/dataset.jsonl"
    dataset.write_text(
        dataset.read_text(encoding="utf-8")
        + json.dumps({"id": "bad_cwe89.py", "technique": "Matching", "source": "Author"})
        + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "prepared"

    report = prepare_datasets(output, sallm_root=sources["sallm_root"])

    assert report["record_count"] == 1
    assert report["excluded_record_count"] == 1
    assert read_json(output / "exclusions.json")[0]["source_locator"].endswith("#L2")


@pytest.mark.reviewer
def test_contract_freeze_and_dedup_candidates_are_separate_closed_steps(
    tmp_path: Path,
) -> None:
    prepared = tmp_path / "prepared"
    prepare_datasets(prepared, **_sources(tmp_path))
    requests = read_json(prepared / "contract-requests.json")
    responses = [
        {
            "record_id": item["record_id"],
            "source_prompt_sha256": item["source_prompt_sha256"],
            "entrypoint": None,
            "requirements": ["Implement the behavior stated in the source prompt."],
            "inputs": [],
            "outputs": [],
            "side_effects": [],
        }
        for item in requests
    ]
    responses_path = tmp_path / "responses.json"
    responses_path.write_text(json.dumps(responses), encoding="utf-8")

    contracts = tmp_path / "contracts"
    contract_report = freeze_contracts(prepared, responses_path, contracts)
    candidates = tmp_path / "dedup"
    dedup_report = prepare_dedup_candidates(prepared, candidates, minimum_jaccard=0.0)

    verify_bundle(contracts)
    verify_bundle(candidates)
    assert contract_report["contract_count"] == len(requests)
    assert dedup_report["adjudication_required"] is True
    assert dedup_report["semantic_clustering_complete"] is False


@pytest.mark.reviewer
def test_prospective_role_census_excludes_exact_and_near_legacy_leakage(
    tmp_path: Path,
) -> None:
    def candidate(task_unit_id: str, record_id: str) -> dict[str, object]:
        return {
            "arms_or_outcomes_used": False,
            "blocker_codes": [],
            "candidate_status": "READY_CONFIRMATORY",
            "final_dataset_status": "INCLUDED_FINAL_DATASET",
            "language": "python",
            "mechanism_realization_id": "mechanism-a",
            "oracle_profile_id": "oracle-a",
            "primary_cwe": "CWE-78",
            "representative_record_id": record_id,
            "source_dataset": "source-a",
            "source_lineage_family": "lineage-a",
            "task_unit_id": task_unit_id,
        }

    population = tmp_path / "population"
    write_bundle(
        population,
        {
            "ready-confirmatory-task-units.json": [
                candidate("cluster-1", "record-1"),
                candidate("cluster-2", "record-2"),
                candidate("cluster-3", "record-3"),
                candidate("cluster-4", "record-4"),
            ]
        },
    )
    clusters = tmp_path / "clusters"
    write_bundle(
        clusters,
        {
            "semantic-clusters.json": [
                {"cluster_id": f"cluster-{index}", "record_ids": [f"record-{index}"]}
                for index in range(1, 5)
            ],
            "diagnostic-semantic-edges.json": [
                {
                    "left": "record-2",
                    "right": "record-3",
                    "label": "same_cluster",
                }
            ],
        },
    )
    legacy = tmp_path / "legacy.json"
    legacy.write_text(
        json.dumps(
            {
                "bindings": [
                    {
                        "data_id": "legacy-v5",
                        "data_role": "LEGACY_ONLY",
                        "exposure_history_applies_to_all_task_units": [
                            "historical_profile_development"
                        ],
                        "task_unit_source_lineage": {
                            "cluster-1": "legacy-lineage",
                            "cluster-3": "legacy-lineage",
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    report = build_prospective_role_census(
        population,
        clusters,
        legacy,
        tmp_path / "census",
        population_target_task_units=4,
    )
    rows = {
        row["task_unit_id"]: row
        for row in read_json(tmp_path / "census/task-units.json")
    }

    assert report["candidate_task_units"] == 4
    assert report["prospective_unexposed_task_units"] == 1
    assert report["legacy_exact_overlap_count"] == 2
    assert report["legacy_near_duplicate_only_overlap_count"] == 1
    assert report["population_target_met"] is False
    assert report["formal_use_authorized"] is False
    assert rows["cluster-1"]["prospective_exclusion_reasons"] == [
        "exact_task_unit_in_legacy_only"
    ]
    assert rows["cluster-2"]["prospective_exclusion_reasons"] == [
        "near_duplicate_group_intersects_legacy_only"
    ]
    assert rows["cluster-2"]["near_duplicate_group_id"] == rows["cluster-3"][
        "near_duplicate_group_id"
    ]
    assert rows["cluster-4"]["prospective_role_eligible"] is True
    verify_bundle(tmp_path / "census")


@pytest.mark.reviewer
def test_source_only_qualification_review_candidates_are_disjoint_and_blind(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[1]
    output = tmp_path / "qualification-review"

    report = prepare_qualification_source_review(
        root / "data/dataset-curation/reviewer-task-unit-dataset-v5",
        root / "data/method/prompt-tsg-catalog-v1.json",
        root / "data/method/phase-context-policy-v3-mechanism-registry-v1.json",
        output,
        producer_commit="1" * 40,
        ranking_salt="phase-context-policy-v3-qwen37flash-qualification-review-v1",
    )

    verify_bundle(output)
    assert report["status"] == (
        "SOURCE_ONLY_REVIEW_PACKETS_READY_FORMAL_ROLE_MANIFEST_AND_GOLD_PENDING"
    )
    assert report["formal_role_assignment_frozen"] is False
    assert report["qualification_accept_attempts_authorized"] == 0
    assert report["provider_calls_authorized"] == 0
    dev = read_json(output / "qual-dev-selection.json")
    accept = read_json(output / "qual-accept-selection.json")
    dev_ids = set(dev["task_ids_in_review_order"])
    accept_ids = set(accept["task_ids_in_review_order"])
    dev_groups = {row["near_duplicate_group_id"] for row in dev["task_units"]}
    accept_groups = {row["near_duplicate_group_id"] for row in accept["task_units"]}
    assert len(dev_ids) == len(dev_groups) == 28
    assert len(accept_ids) == len(accept_groups) == 28
    assert dev_ids.isdisjoint(accept_ids)
    assert dev_groups.isdisjoint(accept_groups)
    assert all(row["exposure_history"] == [] for row in accept["task_units"])
    packet = read_json(output / "qual-accept-review-packet.json")
    serialized = json.dumps(packet, sort_keys=True)
    for forbidden in (
        "mechanism_realization_id",
        "oracle_profile_id",
        "readiness_summary_status",
        "generated_code",
    ):
        assert forbidden not in serialized
    assert packet["status"] == "AWAITING_EXTERNAL_INDEPENDENT_REVIEW"


@pytest.mark.reviewer
def test_independent_subagent_source_gold_requires_blind_third_review(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[1]
    candidates = (
        root / "data/method/qwen37flash-qualification-source-review-candidates-v1"
    )
    decisions: dict[str, list[dict[str, object]]] = {
        "reviewer-a": [],
        "reviewer-b": [],
    }
    first_key: tuple[str, str] | None = None
    first_realization: str | None = None
    for role, prefix in (("QUAL_DEV", "qual-dev"), ("QUAL_ACCEPT", "qual-accept")):
        packet = read_json(candidates / f"{prefix}-review-packet.json")
        for case in packet["cases"]:
            key = (role, case["task_id"])
            if first_key is None:
                first_key = key
                first_realization = case["candidate_realizations"][0]["realization_id"]
            for slot in decisions:
                decisions[slot].append(
                    {
                        "proposed_data_role": role,
                        "task_id": case["task_id"],
                        "expected_context": "absent_or_unresolved",
                        "expected_realization_id": None,
                        "rationale": "The source-only fixture does not assert the target context.",
                    }
                )
    assert first_key is not None and first_realization is not None
    decisions["reviewer-b"][0]["expected_context"] = "present"
    decisions["reviewer-b"][0]["expected_realization_id"] = first_realization
    decisions["reviewer-b"][0]["rationale"] = "The source-only fixture asserts the target context."

    attestation = {
        "forked_without_prior_turns": True,
        "only_exact_review_packets_read": True,
        "prohibited_inputs_read": False,
        "arms_or_outcomes_used": False,
    }
    decision_paths = {}
    for slot, cases in decisions.items():
        path = tmp_path / f"{slot}.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "protocol_id": "isolated_dual_source_gold_review_with_blind_third_decision_v1",
                    "reviewer_slot": slot,
                    "independence_attestation": attestation,
                    "cases": cases,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        decision_paths[slot] = path

    adjudication = tmp_path / "adjudication"
    report = prepare_source_gold_adjudication(
        candidates,
        decision_paths["reviewer-a"],
        decision_paths["reviewer-b"],
        adjudication,
    )
    assert report["agreements"] == 55
    assert report["disagreements"] == 1
    third_path = tmp_path / "reviewer-c.json"
    third_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "protocol_id": "isolated_dual_source_gold_review_with_blind_third_decision_v1",
                "reviewer_slot": "reviewer-c",
                "independence_attestation": attestation,
                "cases": [
                    {
                        "proposed_data_role": first_key[0],
                        "task_id": first_key[1],
                        "expected_context": "absent",
                        "expected_realization_id": None,
                        "rationale": "The source-only fixture does not require the target context.",
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    final = tmp_path / "final"
    final_report = finalize_source_gold_review(
        tmp_path,
        candidates,
        decision_paths["reviewer-a"],
        decision_paths["reviewer-b"],
        adjudication,
        third_path,
        final,
    )
    verify_bundle(final)
    assert final_report["independent_gold_complete"] is True
    assert final_report["blind_third_review_count"] == 1
    assert final_report["formal_role_assignment_frozen"] is False
    assert read_json(final / "qual-dev-gold.json")["cases"][0][
        "expected_context"
    ] == "absent"
    receipt = read_json(final / "review-execution-receipt.json")
    assert receipt["human_external_review"] is False
    assert receipt["root_agent_made_semantic_decisions"] is False
    assert read_json(final / "reviewer-c-decisions.json")["reviewer_slot"] == "reviewer-c"


@pytest.mark.reviewer
def test_prospective_flash_qual_dev_plan_closes_inputs_and_budget() -> None:
    root = Path(__file__).parents[1]
    plan = read_json(
        root / "data/method/prompt-contract-qwen37flash-prospective-qual-dev-v1-plan.json"
    )
    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["formal_five_role_manifest_frozen"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["model_policy"]["fixed_snapshot_model_id"] == "qwen3.7-flash-2026-07-15"
    assert plan["model_policy"]["fallback_model_ids"] == []
    assert plan["automatic_retry_ceiling"] == 0
    for name, artifact in plan["inputs"].items():
        path = root / artifact["path"]
        if name == "canary_input_bundle":
            verify_bundle(path)
            assert file_sha256(path / "manifest.json") == artifact["manifest_sha256"]
        else:
            assert file_sha256(path) == artifact["sha256"]
    canary_root = root / plan["inputs"]["canary_input_bundle"]["path"]
    canary_tasks = read_json(canary_root / "canary-tasks.json")
    canary_selection = read_json(canary_root / "canary-selection.json")
    canary_gold = read_json(canary_root / "canary-gold.json")
    canary_ids = [task["task_id"] for task in canary_tasks]
    assert len(canary_ids) == 3
    assert canary_selection["task_ids"] == canary_ids
    assert [case["task_id"] for case in canary_gold["cases"]] == canary_ids
    assert plan["maximum_provider_calls"] == 6 + 56
    assert plan["maximum_cost_microunits"] == 62 * 4916
    accounting = plan["pre_call_budget_accounting"]
    assert accounting["cumulative_maximum_after_plan_microunits"] == (
        accounting["prior_conservative_spend_microunits"]
        + plan["maximum_cost_microunits"]
    )
    assert accounting["minimum_remaining_after_plan_microunits"] == (
        accounting["authorized_total_microunits"]
        - accounting["cumulative_maximum_after_plan_microunits"]
    )


@pytest.mark.reviewer
def test_targeted_flash_qual_dev_v2_plan_preserves_gold_and_budget() -> None:
    root = Path(__file__).parents[1]
    plan = read_json(
        root / "data/method/prompt-contract-qwen37flash-prospective-qual-dev-v2-plan.json"
    )
    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["response_protocol_id"] == "task_keyed_prompt_contract_json_schema_v5"
    assert plan["formal_use_authorized"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["automatic_retry_ceiling"] == 0
    assert plan["model_policy"]["fallback_model_ids"] == []
    for name, artifact in plan["inputs"].items():
        path = root / artifact["path"]
        if name == "canary_input_bundle":
            verify_bundle(path)
            assert file_sha256(path / "manifest.json") == artifact["manifest_sha256"]
        else:
            assert file_sha256(path) == artifact["sha256"]

    source_gold = read_json(root / plan["inputs"]["source_qual_dev_gold"]["path"])
    candidate_gold = read_json(root / plan["inputs"]["qual_dev_gold"]["path"])
    assert candidate_gold["cases"] == source_gold["cases"]
    assert candidate_gold["qualification_rule"] == source_gold["qualification_rule"]
    assert plan["gold_lineage"]["semantic_label_changes"] == 0
    assert plan["gold_lineage"]["threshold_changes"] == 0

    canary_root = root / plan["inputs"]["canary_input_bundle"]["path"]
    canary_tasks = read_json(canary_root / "canary-tasks.json")
    canary_selection = read_json(canary_root / "canary-selection.json")
    assert [task["task_id"] for task in canary_tasks] == canary_selection["task_ids"]
    assert plan["execution"]["canary"]["development_diagnostic_scoring_authorized"] is True
    assert plan["execution"]["canary"]["formal_qualification_scoring_authorized"] is False

    assert plan["maximum_provider_calls"] == 6 + 56
    assert plan["maximum_cost_microunits"] == 62 * 4916
    accounting = plan["pre_call_budget_accounting"]
    assert accounting["cumulative_maximum_after_plan_microunits"] == (
        accounting["prior_conservative_spend_microunits"]
        + plan["maximum_cost_microunits"]
    )
    assert accounting["minimum_remaining_after_plan_microunits"] == (
        accounting["authorized_total_microunits"]
        - accounting["cumulative_maximum_after_plan_microunits"]
    )


@pytest.mark.reviewer
def test_flash_qual_dev_v3_restores_transport_without_changing_gold() -> None:
    root = Path(__file__).parents[1]
    plan = read_json(
        root / "data/method/prompt-contract-qwen37flash-prospective-qual-dev-v3-plan.json"
    )
    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["response_protocol_id"] == "task_keyed_prompt_contract_json_schema_v4"
    assert plan["formal_use_authorized"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["automatic_retry_ceiling"] == 0
    assert plan["development_lineage"]["transport_failure_parent"][
        "semantic_responses_returned"
    ] == 0
    for name, artifact in plan["inputs"].items():
        path = root / artifact["path"]
        if name == "canary_input_bundle":
            verify_bundle(path)
            assert file_sha256(path / "manifest.json") == artifact["manifest_sha256"]
        else:
            assert file_sha256(path) == artifact["sha256"]

    source_gold = read_json(root / plan["inputs"]["source_qual_dev_gold"]["path"])
    candidate_gold = read_json(root / plan["inputs"]["qual_dev_gold"]["path"])
    assert candidate_gold["cases"] == source_gold["cases"]
    assert candidate_gold["qualification_rule"] == source_gold["qualification_rule"]
    assert plan["gold_lineage"]["semantic_label_changes"] == 0
    assert plan["gold_lineage"]["threshold_changes"] == 0

    assert plan["maximum_provider_calls"] == 62
    assert plan["maximum_cost_microunits"] == 62 * 4916
    accounting = plan["pre_call_budget_accounting"]
    assert accounting["cumulative_maximum_after_plan_microunits"] == (
        accounting["prior_conservative_spend_microunits"]
        + plan["maximum_cost_microunits"]
    )
    assert accounting["minimum_remaining_after_plan_microunits"] == (
        accounting["authorized_total_microunits"]
        - accounting["cumulative_maximum_after_plan_microunits"]
    )


@pytest.mark.reviewer
def test_final_prompt_only_qual_dev_plan_is_fail_closed() -> None:
    root = Path(__file__).parents[1]
    plan = read_json(
        root / "data/method/prompt-contract-qwen37flash-prospective-qual-dev-v4-plan.json"
    )
    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["final_prompt_only_iteration"] is True
    assert "stop Prompt-only tuning" in plan["development_lineage"]["failure_rule"]
    assert plan["formal_use_authorized"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["automatic_retry_ceiling"] == 0
    for name, artifact in plan["inputs"].items():
        path = root / artifact["path"]
        if name == "canary_input_bundle":
            verify_bundle(path)
            assert file_sha256(path / "manifest.json") == artifact["manifest_sha256"]
        else:
            assert file_sha256(path) == artifact["sha256"]
    source_gold = read_json(root / plan["inputs"]["source_qual_dev_gold"]["path"])
    candidate_gold = read_json(root / plan["inputs"]["qual_dev_gold"]["path"])
    assert candidate_gold["cases"] == source_gold["cases"]
    assert candidate_gold["qualification_rule"] == source_gold["qualification_rule"]
    accounting = plan["pre_call_budget_accounting"]
    assert plan["maximum_provider_calls"] == 62
    assert plan["maximum_cost_microunits"] == 62 * 4916
    assert accounting["cumulative_maximum_after_plan_microunits"] == (
        accounting["prior_conservative_spend_microunits"]
        + plan["maximum_cost_microunits"]
    )
    assert accounting["minimum_remaining_after_plan_microunits"] == (
        accounting["authorized_total_microunits"]
        - accounting["cumulative_maximum_after_plan_microunits"]
    )


@pytest.mark.reviewer
def test_prospective_qual_dev_failure_archive_and_budget_close() -> None:
    root = Path(__file__).parents[1]
    archive = (
        root
        / "data/method/qwen37flash-prospective-qual-dev-development-evidence-v1"
    )
    index = read_json(archive / "archive-index.json")
    assert index["formal_use_authorized"] is False
    assert index["qualification_accept_consumed"] is False
    for bundle in index["bundles"]:
        bundle_root = archive / bundle["path"]
        verify_bundle(bundle_root)
        assert file_sha256(bundle_root / "manifest.json") == bundle["manifest_sha256"]

    receipt = read_json(
        root
        / "data/method/prompt-contract-qwen37flash-prospective-qual-dev-v4-execution.json"
    )
    assert receipt["status"] == "FINAL_PROMPT_ONLY_CANDIDATE_FAILED_CLOSED"
    assert receipt["qual_dev_full_started"] is False
    assert receipt["qualification_accept_consumed"] is False
    assert receipt["budget"]["actual_provider_calls"] == 6

    ledger = read_json(
        root / "data/method/qwen37flash-prospective-qual-dev-execution-ledger-v1.json"
    )
    attempt_calls = sum(attempt["actual_provider_calls"] for attempt in ledger["attempts"])
    attempt_cost = sum(
        attempt["actual_conservative_cost_microunits"] for attempt in ledger["attempts"]
    )
    assert attempt_calls == ledger["prospective_actual_provider_calls"]
    assert attempt_cost == ledger["prospective_conservative_spend_microunits"]
    assert ledger["conservative_cumulative_spend_microunits"] == (
        ledger["pre_prospective_conservative_spend_microunits"] + attempt_cost
    )
    assert ledger["minimum_remaining_microunits"] == (
        ledger["authorized_total_microunits"]
        - ledger["conservative_cumulative_spend_microunits"]
    )
    assert ledger["qualification_accept_provider_calls"] == 0


def _sources(tmp_path: Path, *, shared_prompt: str | None = None) -> dict[str, Path]:
    sallm = tmp_path / "sallm"
    sallm_data = sallm / "Dataset"
    sallm_task = sallm_data / "Matching/Author"
    sallm_task.mkdir(parents=True)
    sallm_prompt = shared_prompt or "Implement a safe deserializer."
    sallm_row = {
        "id": "Matching_Author_A_cwe502_0.py",
        "technique": "Matching",
        "source": "Author",
        "prompt": sallm_prompt,
        "insecure_code": "pass",
    }
    (sallm_data / "dataset.jsonl").write_text(
        json.dumps(sallm_row) + "\n",
        encoding="utf-8",
    )
    (sallm_task / "test_A_cwe502_0.py").write_text("def test_it(): pass\n", encoding="utf-8")
    (sallm_task / "A_cwe502_0_Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")

    cweval = tmp_path / "cweval"
    cweval_tasks = cweval / "benchmark/core/py"
    cweval_tasks.mkdir(parents=True)
    (cweval_tasks / "cwe_078_0_task.py").write_text(
        "def list_dir(path):\n    # BEGIN SOLUTION\n    return ''\n",
        encoding="utf-8",
    )
    (cweval_tasks / "cwe_078_0_test.py").write_text(
        "def test_it(): pass\n",
        encoding="utf-8",
    )

    cyber = tmp_path / "instruct.json"
    cyber.write_text(
        json.dumps(
            [
                {
                    "repo": "owner/repo",
                    "file_path": "sample.py",
                    "line_number": 1,
                    "pattern_id": "rule",
                    "language": "python",
                    "cwe_identifier": "CWE-502",
                    "test_case_prompt": shared_prompt or "Parse an uploaded document.",
                }
            ]
        ),
        encoding="utf-8",
    )

    llmseceval = tmp_path / "llmseceval"
    llm_data = llmseceval / "Dataset"
    llm_data.mkdir(parents=True)
    (llm_data / "LLMSecEval-Prompts_dataset.json").write_text(
        json.dumps(
            [
                {
                    "Prompt ID": "CWE-89_SQI-1a",
                    "CWE Name": "SQL Injection",
                    "LLM-generated NL Prompt": "Query a user by name.",
                    "Manually-fixed NL Prompt": "Query a user by account name.",
                    "Filename": "sample.py",
                    "Language": "Python",
                }
            ]
        ),
        encoding="utf-8",
    )

    securityeval = tmp_path / "securityeval"
    securityeval.mkdir()
    (securityeval / "dataset.jsonl").write_text(
        json.dumps(
            {
                "ID": "CWE-078_author_1.py",
                "Prompt": "def execute(command):\n    pass",
                "Insecure_code": "def execute(command):\n    return command",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    codeseceval = tmp_path / "codeseceval"
    for split in ("SecEvalBase", "SecEvalPlus"):
        directory = codeseceval / "data" / split
        directory.mkdir(parents=True)
        (directory / "test.jsonl").write_text(
            json.dumps(
                {
                    "ID": f"CWE-89_{split}.py",
                    "Problem": f"Implement the {split} query function.",
                    "Test": "def check(candidate): assert callable(candidate)",
                    "Entry_Point": "query",
                }
            )
            + "\n",
            encoding="utf-8",
        )

    secodeplt = tmp_path / "secodeplt"
    secode_data = secodeplt / "generate_dataset/data/338"
    secode_data.mkdir(parents=True)
    metadata = {
        "CVE_ID": "CVE-test",
        "CWE_ID": "338",
        "task_description": {
            "function_name": "generate_token",
            "description": "Write generate_token(length).",
            "security_policy": "Use a secure PRNG.",
            "arguments": "length: int",
            "return": "a token string",
            "raise": "None",
        },
    }
    secode_task = (
        "## START METADATA ##\n"
        + json.dumps(metadata)
        + "\n## END METADATA ##\n"
        + "## START TESTCASES ##\ndef check(candidate): pass\n## END TESTCASES ##\n"
    )
    (secode_data / "succeed_python_list.json").write_text(
        json.dumps([secode_task]),
        encoding="utf-8",
    )
    return {
        "sallm_root": sallm,
        "cweval_root": cweval,
        "cyberseceval_path": cyber,
        "llmseceval_root": llmseceval,
        "securityeval_root": securityeval,
        "codeseceval_root": codeseceval,
        "secodeplt_root": secodeplt,
    }
