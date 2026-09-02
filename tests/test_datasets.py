from __future__ import annotations

import json
from collections import Counter
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
from prompt_mechanism_study.records import content_hash
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
    assert len(index["bundles"]) == 10
    for bundle in index["bundles"]:
        bundle_root = archive / bundle["path"]
        verify_bundle(bundle_root)
        assert file_sha256(bundle_root / "manifest.json") == bundle["manifest_sha256"]

    receipt = read_json(
        root
        / "data/method/prompt-contract-qwen37flash-prospective-qual-dev-v5-execution.json"
    )
    assert receipt["status"] == "EVIDENCE_AWARE_REDESIGN_CANARY_FAILED_CLOSED"
    assert receipt["qual_dev_full_started"] is False
    assert receipt["qualification_accept_consumed"] is False
    assert receipt["formal_use_authorized"] is False
    assert receipt["scientific_claim_allowed"] is False
    assert receipt["budget"]["actual_provider_calls"] == 6
    assert receipt["budget"]["actual_conservative_cost_microunits"] == 6 * 4916
    assert receipt["canary"]["development_replay"]["matched_task_units"] == 2
    assert receipt["canary"]["development_replay"]["mismatched_task_units"] == 1
    assert receipt["plan_sha256"] == file_sha256(root / receipt["plan_path"])
    archived_manifests = {bundle["manifest_sha256"] for bundle in index["bundles"]}
    assert receipt["canary"]["extraction_bundle_manifest_sha256"] in archived_manifests
    assert receipt["canary"]["qualification_bundle_manifest_sha256"] in archived_manifests

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
    assert ledger["status"] == "PROSPECTIVE_REDESIGN_CANARY_FAILED_NOT_READY"


@pytest.mark.reviewer
def test_prompt_contract_error_attribution_replays_archived_signals() -> None:
    root = Path(__file__).parents[1]
    audit = read_json(
        root / "data/method/qwen37flash-prompt-contract-error-attribution-audit-v1.json"
    )
    assert audit["status"] == "ZERO_NETWORK_ERROR_ATTRIBUTION_COMPLETE_NON_AUTHORIZING"
    assert audit["audit_method"]["provider_calls"] == 0
    assert audit["audit_method"]["root_agent_added_or_changed_qualification_gold"] is False
    assert audit["scientific_claim_allowed"] is False
    assert audit["arms_or_outcomes_used"] is False

    for name, binding in audit["input_bindings"].items():
        path = root / binding["path"]
        if name == "catalog":
            assert file_sha256(path) == binding["sha256"]
        else:
            verify_bundle(path)
            assert file_sha256(path / "manifest.json") == binding["manifest_sha256"]

    archive = root / "data/method/qwen37flash-prospective-qual-dev-development-evidence-v1"
    case_results = read_json(archive / "v1-qualification-run/case-results.json")
    mismatches = {row["task_id"]: row for row in case_results if not row["matched"]}
    attributed = {row["task_id"]: row for row in audit["case_attributions"]}
    assert set(attributed) == set(mismatches)
    assert len(case_results) == audit["full_qual_dev_v1"]["task_units"] == 28
    assert len(mismatches) == audit["full_qual_dev_v1"]["mismatched_task_units"] == 11
    assert sum(row["matched"] for row in case_results) == 17
    for task_id, row in attributed.items():
        source = mismatches[task_id]
        assert row["expected_context"] == source["expected_context"]
        assert row["expected_realization_id"] == source["expected_realization_id"]
        assert row["observed_context"] == source["actual_context"]

    responses = {
        row["task_id"]: row
        for row in read_json(archive / "v1-qual-dev-run/responses.json")
    }
    contracts = {
        row["task_id"]: row
        for row in read_json(archive / "v1-qual-dev-run/contracts.json")
    }
    disagreement = set()
    shared_abstention = set()
    evidence_demotion = set()
    unanimous_false_negative = set()
    for task_id, result in mismatches.items():
        response = responses[task_id]
        proposer = json.loads(response["proposer_response_text"])["semantic_decisions"]
        reviewer = json.loads(response["reviewer_response_text"])["semantic_decisions"]
        consensus = {
            row["semantic_id"]: row for row in contracts[task_id]["semantic_decisions"]
        }
        pairs = {
            semantic_id: (proposer[semantic_id]["state"], reviewer[semantic_id]["state"])
            for semantic_id in consensus
        }
        if any(left != right for left, right in pairs.values()):
            disagreement.add(task_id)
        if any(left == right == "unresolved" for left, right in pairs.values()):
            shared_abstention.add(task_id)
        if any(
            left == right == "present" and consensus[semantic_id]["state"] == "unresolved"
            for semantic_id, (left, right) in pairs.items()
        ):
            evidence_demotion.add(task_id)
        if (
            result["expected_context"] == "present"
            and result["actual_context"] == "absent"
            and any(left == right == "absent" for left, right in pairs.values())
        ):
            unanimous_false_negative.add(task_id)

    code_sets = {
        code: {
            row["task_id"]
            for row in audit["case_attributions"]
            if code in row["attribution_codes"]
        }
        for code in (
            "MODEL_CLASSIFICATION_DISAGREEMENT",
            "MODEL_SHARED_ABSTENTION",
            "EVIDENCE_VALIDATION_DEMOTION",
            "UNANIMOUS_SEMANTIC_FALSE_NEGATIVE",
        )
    }
    assert code_sets["MODEL_CLASSIFICATION_DISAGREEMENT"] == disagreement
    assert code_sets["MODEL_SHARED_ABSTENTION"] == shared_abstention
    assert code_sets["EVIDENCE_VALIDATION_DEMOTION"] == evidence_demotion
    assert code_sets["UNANIMOUS_SEMANTIC_FALSE_NEGATIVE"] == unanimous_false_negative
    summary = audit["mechanical_signal_summary"]
    assert summary["cases_with_model_classification_disagreement"] == len(disagreement) == 8
    assert summary["cases_with_model_shared_abstention"] == len(shared_abstention) == 3
    assert summary["cases_with_evidence_validation_demotion"] == len(evidence_demotion) == 4
    assert summary["cases_with_unanimous_semantic_false_negative"] == (
        len(unanimous_false_negative)
    ) == 1

    assert summary["dominant_layer_counts"] == dict(
        sorted(Counter(row["dominant_layer"] for row in attributed.values()).items())
    )
    tier_counts = {tier: 0 for tier in audit["inference_tier_definitions"]}
    tier_counts.update(Counter(row["inference_tier"] for row in attributed.values()))
    assert summary["inference_tier_counts"] == tier_counts

    cross_run = {row["task_id"]: row for row in audit["cross_run_canary"]}
    for version in ("v3", "v4", "v5"):
        version_results = read_json(
            archive / f"{version}-canary-qualification/case-results.json"
        )
        assert {
            row["task_id"]: row["actual_context"] for row in version_results
        } == {
            task_id: row["states"][version] for task_id, row in cross_run.items()
        }

    identity = audit["request_identity_check"]
    v4_requests = archive / "v4-canary-run/requests.json"
    v5_requests = archive / "v5-canary-run/requests.json"
    assert v4_requests.read_bytes() == v5_requests.read_bytes()
    assert file_sha256(v4_requests) == identity["v4_task_requests_sha256"]
    assert file_sha256(v5_requests) == identity["v5_task_requests_sha256"]
    for version in ("v4", "v5"):
        plan = read_json(
            root
            / f"data/method/prompt-contract-qwen37flash-prospective-qual-dev-{version}-plan.json"
        )
        assert plan["model_policy"]["fixed_snapshot_model_id"] == identity["model_id"]
        assert plan["automatic_retry_ceiling"] == identity["automatic_retry_ceiling"]
        assert file_sha256(root / plan["inputs"]["proposer_prompt"]["path"]) == identity[
            "proposer_prompt_sha256"
        ]
        assert file_sha256(root / plan["inputs"]["reviewer_prompt"]["path"]) == identity[
            "reviewer_prompt_sha256"
        ]
        proposer_evaluator = read_json(root / plan["inputs"]["proposer_evaluator"]["path"])
        reviewer_evaluator = read_json(root / plan["inputs"]["reviewer_evaluator"]["path"])
        assert proposer_evaluator["temperature"] == reviewer_evaluator["temperature"] == identity[
            "temperature"
        ]
        assert proposer_evaluator["top_p"] == reviewer_evaluator["top_p"] == identity[
            "top_p"
        ]
        assert proposer_evaluator["seed"] == identity["proposer_seed"]
        assert reviewer_evaluator["seed"] == identity["reviewer_seed"]
        assert proposer_evaluator["max_attempts"] == reviewer_evaluator["max_attempts"] == 1
    v4_responses = read_json(archive / "v4-canary-run/responses.json")
    v5_responses = read_json(archive / "v5-canary-run/responses.json")
    archive_task_id = next(
        task_id
        for task_id, row in attributed.items()
        if "UNANIMOUS_SEMANTIC_FALSE_NEGATIVE" in row["attribution_codes"]
    )
    for responses_for_version in (v4_responses, v5_responses):
        archive_response = next(
            row for row in responses_for_version if row["task_id"] == archive_task_id
        )
        assert archive_response["response_format_sha256"] == identity[
            "archive_case_response_format_sha256"
        ]


@pytest.mark.reviewer
def test_archive_boundary_stability_diagnostic_inputs_are_frozen() -> None:
    root = Path(__file__).parents[1]
    bundle = root / "data/method/archive-boundary-stability-diagnostic-v1-inputs"
    verify_bundle(bundle)
    tasks = read_json(bundle / "diagnostic-tasks.json")
    selection = read_json(bundle / "diagnostic-selection.json")
    design = read_json(bundle / "diagnostic-design.json")
    assert selection["task_ids"] == [row["task_id"] for row in tasks]
    assert selection["source_tasks_sha256"] == file_sha256(
        bundle / "diagnostic-tasks.json"
    )
    assert design["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert design["scientific_claim_allowed"] is False
    assert design["arms_or_outcomes_used"] is False
    assert design["execution"] == {
        "adaptive_retry_allowed": False,
        "calls_per_run": 8,
        "calls_per_task": 2,
        "maximum_provider_calls": 24,
        "replicate_runs": 3,
        "run_order": ["replicate-1", "replicate-2", "replicate-3"],
        "task_order": "diagnostic-selection order",
        "task_workers": 1,
        "within_task_order": "proposer_then_reviewer",
    }
    variants = {row["task_id"]: row for row in design["variants"]}
    assert set(variants) == set(selection["task_ids"])
    for task in tasks:
        assert variants[task["task_id"]]["prompt_content_sha256"] == content_hash(
            task["prompt"]
        )

    original = next(row for row in tasks if row["diagnostic_variant_id"] == "original_ambiguous")
    prior_tasks = read_json(
        root / "data/method/qwen37flash-prospective-qual-dev-v5-inputs/canary-tasks.json"
    )
    prior_archive = next(row for row in prior_tasks if row["cwe"] == "CWE-22")
    assert original["prompt"] == prior_archive["prompt"]
    external_untrusted = next(
        row for row in tasks if row["diagnostic_variant_id"] == "explicit_external_untrusted"
    )
    external_trusted = next(
        row for row in tasks if row["diagnostic_variant_id"] == "explicit_external_trusted"
    )
    internal_trusted = next(
        row for row in tasks if row["diagnostic_variant_id"] == "explicit_internal_trusted"
    )
    assert "externally supplied and must be treated as untrusted" in external_untrusted["prompt"]
    assert "externally supplied" in external_trusted["prompt"]
    assert "do not treat the members as untrusted" in external_trusted["prompt"]
    assert "generated internally from fixed trusted files" in internal_trusted["prompt"]

    diagnostic_evaluators = [
        read_json(
            root
            / f"data/method/prompt-contract-{role}-qwen37flash-archive-boundary-diagnostic-v1.json"
        )
        for role in ("proposer", "reviewer")
    ]
    v5_evaluators = [
        read_json(root / f"data/method/prompt-contract-{role}-qwen37flash-v5.json")
        for role in ("proposer", "reviewer")
    ]
    for diagnostic, v5 in zip(diagnostic_evaluators, v5_evaluators, strict=True):
        assert {
            key: value for key, value in diagnostic.items() if key != "candidate_id"
        } == {key: value for key, value in v5.items() if key != "candidate_id"}


@pytest.mark.reviewer
def test_archive_boundary_stability_diagnostic_plan_closes_budget() -> None:
    root = Path(__file__).parents[1]
    plan = read_json(
        root / "data/method/archive-boundary-stability-diagnostic-v1-plan.json"
    )
    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["formal_use_authorized"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["scientific_claim_allowed"] is False
    assert plan["automatic_retry_ceiling"] == 0
    assert plan["decision_rule"]["method_change_after_result_authorized"] is False
    assert plan["execution"]["replicate_runs"] == 3
    assert plan["execution"]["task_units_per_replicate"] == 4
    assert plan["execution"]["calls_per_task"] == 2
    assert plan["execution"]["task_workers"] == 1
    assert plan["maximum_provider_calls"] == 24
    assert plan["maximum_cost_microunits"] == 24 * 4916
    for name, artifact in plan["inputs"].items():
        path = root / artifact["path"]
        if name == "diagnostic_input_bundle":
            verify_bundle(path)
            assert file_sha256(path / "manifest.json") == artifact["manifest_sha256"]
        else:
            assert file_sha256(path) == artifact["sha256"]
    design = read_json(root / plan["inputs"]["diagnostic_design"]["path"])
    assert design["decision_rule"]["ordered_rules"]
    assert design["decision_rule"]["target_semantic_id"] == (
        "source.untrusted_archive_member"
    )
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
def test_evidence_aware_qual_dev_v5_plan_closes_redesign_and_budget() -> None:
    root = Path(__file__).parents[1]
    plan = read_json(
        root / "data/method/prompt-contract-qwen37flash-prospective-qual-dev-v5-plan.json"
    )
    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["contract_protocol_id"] == (
        "task_context_contract_v3_evidence_aware_dual_consensus"
    )
    assert plan["consensus_policy_id"] == "unanimous_presence_valid_evidence_v1"
    assert plan["consensus_policy"]["evidence_and_classification_separated"] is True
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
    replay = read_json(root / plan["inputs"]["offline_redesign_replay"]["path"])
    assert replay["provider_calls"] == 0
    assert replay["matched_task_units"] == replay["task_units"] == 3

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
