import hashlib
import json
import re
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import file_sha256, verify_bundle
from prompt_mechanism_study.prompt_contract import (
    RelationDecision,
    SemanticDecision,
    TaskContextContract,
    compile_task_context_contract,
    task_context_contract_from_record,
    task_context_contract_record,
    task_context_scope,
)
from prompt_mechanism_study.prompt_contract_extract import (
    PromptContractExtractionError,
    contract_decision_request,
    contract_from_response,
    contract_response_format,
    evidence_aware_consensus_contract,
    extract_contract_task_file,
)
from prompt_mechanism_study.prompt_contract_qualification import (
    qualify_prompt_contract_extractor,
)
from prompt_mechanism_study.prompt_tsg import (
    PromptTSGError,
    QueryState,
    catalog_sha256,
    load_catalog,
    prompt_tsg_from_record,
    prompt_tsg_record,
    query_context,
)
from prompt_mechanism_study.records import content_hash


ROOT = Path(__file__).parents[1]
TASKS_PATH = ROOT / "data/method/prompt-tsg-external-qualification-tasks-v4.json"
CATALOG_PATH = ROOT / "data/method/prompt-tsg-catalog-v11.json"


@pytest.mark.reviewer
def test_flash_qual_dev_plan_closes_inputs_and_budget() -> None:
    plan = json.loads(
        (
            ROOT / "data/method/prompt-contract-qwen37flash-qual-dev-v1-plan.json"
        ).read_text(encoding="utf-8")
    )

    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["data_role"] == "LEGACY_EXPOSED_DEVELOPMENT_REGRESSION"
    assert plan["formal_use_authorized"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["model_policy"]["fixed_snapshot_model_id"] == (
        "qwen3.7-flash-2026-07-15"
    )
    assert plan["model_policy"]["fallback_model_ids"] == []
    assert plan["automatic_retry_ceiling"] == 0
    assert plan["maximum_provider_calls"] == 62
    assert plan["maximum_cost_microunits"] == (
        plan["maximum_provider_calls"]
        * plan["model_policy"]["maximum_cost_microunits_per_call"]
    )
    for name, value in plan["inputs"].items():
        if name == "extractor_implementation":
            assert len(value["sha256"]) == 64
            continue
        path = ROOT / value["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == value["sha256"]
    pilot = plan["execution"]["provider_compatibility_pilot"]
    for prefix in ("tasks", "selection"):
        path = ROOT / pilot[f"{prefix}_path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == pilot[f"{prefix}_sha256"]


@pytest.mark.reviewer
def test_flash_failure_diagnostic_is_single_attempt_and_non_scientific() -> None:
    plan = json.loads(
        (
            ROOT
            / "data/method/prompt-contract-qwen37flash-failure-diagnostic-v1-plan.json"
        ).read_text(encoding="utf-8")
    )

    assert plan["status"] == "FROZEN_BEFORE_DIAGNOSTIC_REPLAY"
    assert plan["data_role"] == "LEGACY_EXPOSED_DEVELOPMENT_DIAGNOSTIC"
    assert plan["formal_use_authorized"] is False
    assert plan["scientific_claim_allowed"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["arms_or_outcomes_used"] is False
    assert plan["maximum_provider_calls"] == 2
    assert plan["automatic_retry_ceiling"] == 0
    assert plan["maximum_cost_microunits"] == (
        plan["maximum_provider_calls"]
        * plan["model_policy"]["maximum_cost_microunits_per_call"]
    )
    assert plan["execution"]["task_units"] == 1
    assert plan["execution"]["task_workers"] == 1
    assert plan["execution"]["output_must_close_before_fail_stop"] is True
    for name, value in plan["inputs"].items():
        if name == "extractor_implementation":
            assert len(value["sha256"]) == 64
            continue
        path = ROOT / value["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == value["sha256"]


@pytest.mark.reviewer
def test_flash_compatibility_gate_v2_closes_expansion_and_budget() -> None:
    plan = json.loads(
        (
            ROOT / "data/method/prompt-contract-qwen37flash-compatibility-gate-v2-plan.json"
        ).read_text(encoding="utf-8")
    )

    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["data_role"] == "LEGACY_EXPOSED_DEVELOPMENT_COMPATIBILITY_GATE"
    assert plan["formal_use_authorized"] is False
    assert plan["scientific_claim_allowed"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["arms_or_outcomes_used"] is False
    assert plan["maximum_provider_calls"] == 6
    assert plan["automatic_retry_ceiling"] == 0
    assert plan["maximum_cost_microunits"] == (
        plan["maximum_provider_calls"]
        * plan["model_policy"]["maximum_cost_microunits_per_call"]
    )
    accounting = plan["pre_call_budget_accounting"]
    assert accounting["cumulative_maximum_after_gate_microunits"] == (
        accounting["prior_conservative_spend_microunits"]
        + plan["maximum_cost_microunits"]
    )
    assert accounting["minimum_remaining_after_gate_microunits"] == (
        accounting["authorized_total_microunits"]
        - accounting["cumulative_maximum_after_gate_microunits"]
    )
    assert plan["execution"]["task_units"] == 3
    assert plan["execution"]["task_workers"] == 1
    assert plan["execution"]["output_must_close_before_fail_stop"] is True
    for value in plan["inputs"].values():
        path = ROOT / value["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == value["sha256"]
    assert plan["implementation"]["commit"] == plan["trigger"][
        "failure_closure_fix_commit"
    ]
    assert len(plan["implementation"]["extractor_sha256"]) == 64


@pytest.mark.reviewer
def test_flash_compatibility_gate_v3_freezes_schema_repair_only() -> None:
    plan = json.loads(
        (
            ROOT / "data/method/prompt-contract-qwen37flash-compatibility-gate-v3-plan.json"
        ).read_text(encoding="utf-8")
    )

    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["response_protocol_id"] == "task_keyed_prompt_contract_json_schema_v2"
    assert plan["formal_use_authorized"] is False
    assert plan["scientific_claim_allowed"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["arms_or_outcomes_used"] is False
    assert plan["maximum_provider_calls"] == 6
    assert plan["automatic_retry_ceiling"] == 0
    assert plan["maximum_cost_microunits"] == (
        plan["maximum_provider_calls"]
        * plan["model_policy"]["maximum_cost_microunits_per_call"]
    )
    accounting = plan["pre_call_budget_accounting"]
    assert accounting["cumulative_maximum_after_gate_microunits"] == (
        accounting["prior_conservative_spend_microunits"]
        + plan["maximum_cost_microunits"]
    )
    assert accounting["minimum_remaining_after_gate_microunits"] == (
        accounting["authorized_total_microunits"]
        - accounting["cumulative_maximum_after_gate_microunits"]
    )
    diagnosis = plan["trigger"]["closed_failure_diagnosis"]
    assert diagnosis["predecessor_transport_schema_had_maximum"] is False
    assert all(
        length > diagnosis["local_frozen_maximum_utf8_bytes"]
        for length in diagnosis["violating_rationale_character_lengths"]
    )
    assert plan["implementation"]["commit"] == "406058dd0184dc89b5074d504316979f464134e5"
    assert len(plan["implementation"]["extractor_sha256"]) == 64
    for value in plan["inputs"].values():
        path = ROOT / value["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == value["sha256"]


@pytest.mark.reviewer
def test_flash_qual_dev_regression_v2_rebinds_only_candidate_identity() -> None:
    plan = json.loads(
        (
            ROOT / "data/method/prompt-contract-qwen37flash-qual-dev-regression-v2-plan.json"
        ).read_text(encoding="utf-8")
    )
    source_gold = json.loads(
        (ROOT / plan["gold_binding"]["source_gold_path"]).read_text(encoding="utf-8")
    )
    bound_gold = json.loads(
        (ROOT / plan["gold_binding"]["candidate_bound_gold_path"]).read_text(
            encoding="utf-8"
        )
    )
    source_candidate = source_gold.pop("extractor_candidate_id")
    bound_candidate = bound_gold.pop("extractor_candidate_id")

    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["response_protocol_id"] == "task_keyed_prompt_contract_json_schema_v2"
    assert plan["data_role"] == "LEGACY_EXPOSED_DEVELOPMENT_REGRESSION"
    assert plan["formal_use_authorized"] is False
    assert plan["scientific_claim_allowed"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["arms_or_outcomes_used"] is False
    assert plan["maximum_provider_calls"] == 56
    assert plan["automatic_retry_ceiling"] == 0
    assert plan["maximum_cost_microunits"] == (
        plan["maximum_provider_calls"]
        * plan["model_policy"]["maximum_cost_microunits_per_call"]
    )
    accounting = plan["pre_call_budget_accounting"]
    assert accounting["cumulative_maximum_after_regression_microunits"] == (
        accounting["prior_conservative_spend_microunits"]
        + plan["maximum_cost_microunits"]
    )
    assert accounting["minimum_remaining_after_regression_microunits"] == (
        accounting["authorized_total_microunits"]
        - accounting["cumulative_maximum_after_regression_microunits"]
    )
    assert source_gold == bound_gold
    assert "qwen37max-v4" in source_candidate
    assert bound_candidate == (
        "dual-blind-consensus:prompt-contract-proposer-qwen37flash-v1"
        "+prompt-contract-reviewer-qwen37flash-v1"
    )
    assert plan["gold_binding"]["labels_thresholds_selection_and_execution_changed"] is False
    for value in plan["inputs"].values():
        path = ROOT / value["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == value["sha256"]


@pytest.mark.reviewer
def test_flash_transport_v3_gate_is_single_task_and_bounded() -> None:
    plan = json.loads(
        (
            ROOT / "data/method/prompt-contract-qwen37flash-compatibility-gate-v4-plan.json"
        ).read_text(encoding="utf-8")
    )

    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["response_protocol_id"] == "task_keyed_prompt_contract_json_schema_v3"
    assert plan["formal_use_authorized"] is False
    assert plan["scientific_claim_allowed"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["arms_or_outcomes_used"] is False
    assert plan["maximum_provider_calls"] == 2
    assert plan["automatic_retry_ceiling"] == 0
    assert plan["maximum_cost_microunits"] == (
        plan["maximum_provider_calls"]
        * plan["model_policy"]["maximum_cost_microunits_per_call"]
    )
    accounting = plan["pre_call_budget_accounting"]
    assert accounting["cumulative_maximum_after_gate_microunits"] == (
        accounting["prior_conservative_spend_microunits"]
        + plan["maximum_cost_microunits"]
    )
    assert accounting["minimum_remaining_after_gate_microunits"] == (
        accounting["authorized_total_microunits"]
        - accounting["cumulative_maximum_after_gate_microunits"]
    )
    assert plan["execution"]["task_units"] == 1
    assert plan["execution"]["task_workers"] == 1
    assert plan["execution"]["output_must_close_before_fail_stop"] is True
    for value in plan["inputs"].values():
        path = ROOT / value["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == value["sha256"]


@pytest.mark.reviewer
def test_flash_qual_dev_regression_v3_is_frozen_after_transport_gate() -> None:
    plan = json.loads(
        (
            ROOT / "data/method/prompt-contract-qwen37flash-qual-dev-regression-v3-plan.json"
        ).read_text(encoding="utf-8")
    )

    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["response_protocol_id"] == "task_keyed_prompt_contract_json_schema_v3"
    assert plan["data_role"] == "LEGACY_EXPOSED_DEVELOPMENT_REGRESSION"
    assert plan["formal_use_authorized"] is False
    assert plan["scientific_claim_allowed"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["arms_or_outcomes_used"] is False
    assert plan["maximum_provider_calls"] == 56
    assert plan["automatic_retry_ceiling"] == 0
    assert plan["maximum_cost_microunits"] == (
        plan["maximum_provider_calls"]
        * plan["model_policy"]["maximum_cost_microunits_per_call"]
    )
    accounting = plan["pre_call_budget_accounting"]
    assert accounting["cumulative_maximum_after_regression_microunits"] == (
        accounting["prior_conservative_spend_microunits"]
        + plan["maximum_cost_microunits"]
    )
    assert accounting["minimum_remaining_after_regression_microunits"] == (
        accounting["authorized_total_microunits"]
        - accounting["cumulative_maximum_after_regression_microunits"]
    )
    assert plan["trigger"]["transport_gate_status"] == (
        "PROMPT_CONTRACT_EXTRACTION_COMPLETE"
    )
    assert plan["execution"]["task_units"] == 28
    assert plan["execution"]["task_workers"] == 4
    for value in plan["inputs"].values():
        path = ROOT / value["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == value["sha256"]


@pytest.mark.reviewer
def test_flash_qual_dev_regression_v4_binds_evidence_replay_and_budget() -> None:
    plan = json.loads(
        (
            ROOT / "data/method/prompt-contract-qwen37flash-qual-dev-regression-v4-plan.json"
        ).read_text(encoding="utf-8")
    )

    assert plan["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert plan["response_protocol_id"] == "task_keyed_prompt_contract_json_schema_v4"
    assert plan["data_role"] == "LEGACY_EXPOSED_DEVELOPMENT_REGRESSION"
    assert plan["formal_use_authorized"] is False
    assert plan["scientific_claim_allowed"] is False
    assert plan["qualification_accept_consumed"] is False
    assert plan["arms_or_outcomes_used"] is False
    assert plan["maximum_provider_calls"] == 56
    assert plan["automatic_retry_ceiling"] == 0
    assert plan["maximum_cost_microunits"] == (
        plan["maximum_provider_calls"]
        * plan["model_policy"]["maximum_cost_microunits_per_call"]
    )
    accounting = plan["pre_call_budget_accounting"]
    assert accounting["cumulative_maximum_after_regression_microunits"] == (
        accounting["prior_conservative_spend_microunits"]
        + plan["maximum_cost_microunits"]
    )
    assert accounting["minimum_remaining_after_regression_microunits"] == (
        accounting["authorized_total_microunits"]
        - accounting["cumulative_maximum_after_regression_microunits"]
    )
    assert plan["trigger"]["predecessor_qualification_status"] == (
        "QUALIFICATION_FAILED"
    )
    replay = plan["trigger"]["zero_call_development_replay"]
    assert replay["provider_calls"] == 0
    assert replay["exact_context_accuracy"] >= plan["qualification_rule"][
        "minimum_exact_context_accuracy"
    ]
    assert replay["present_recall"] >= plan["qualification_rule"][
        "minimum_present_recall"
    ]
    assert replay["false_positive_present"] == 0
    assert replay["wrong_realization"] == 0
    assert replay["scientific_claim_allowed"] is False
    for value in plan["inputs"].values():
        path = ROOT / value["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == value["sha256"]


@pytest.mark.reviewer
def test_flash_preexperiment_ledger_closes_cost_and_evidence_boundaries() -> None:
    ledger = json.loads(
        (ROOT / "data/method/qwen37flash-preexperiment-ledger-v1.json").read_text(
            encoding="utf-8"
        )
    )
    totals = ledger["totals"]
    attempts = ledger["attempts"]

    assert ledger["status"] == (
        "EXPOSED_DEVELOPMENT_REGRESSIONS_COMPLETE_FRESH_ROLE_QUALIFICATION_PENDING"
    )
    assert ledger["model_policy"]["fixed_snapshot_model_id"] == (
        "qwen3.7-flash-2026-07-15"
    )
    assert ledger["model_policy"]["credential_execution"] == (
        "REMOTE_SERVER_ENVIRONMENT_ONLY"
    )
    assert ledger["model_policy"]["credential_material_recorded"] is False
    assert totals["provider_calls_closed"] == sum(
        attempt["provider_calls_closed"] for attempt in attempts
    )
    assert totals["provider_calls_reserved_unclosed"] == sum(
        attempt["provider_calls_reserved_unclosed"] for attempt in attempts
    )
    assert totals["provider_calls_conservative_total"] == (
        totals["provider_calls_closed"] + totals["provider_calls_reserved_unclosed"]
    )
    assert totals["conservative_total_cost_microunits"] == sum(
        attempt["conservative_cost_microunits"] for attempt in attempts
    )
    assert totals["minimum_remaining_authorized_cost_microunits"] == (
        ledger["budget_authorization"]["maximum_total_cost_microunits"]
        - totals["conservative_total_cost_microunits"]
    )
    assert totals["conservative_total_cost_cny"] == (
        totals["conservative_total_cost_microunits"] / 1_000_000
    )
    assert totals["minimum_remaining_authorized_cost_cny"] == (
        totals["minimum_remaining_authorized_cost_microunits"] / 1_000_000
    )
    for attempt in attempts:
        assert attempt["scientific_claim_allowed"] is False
        for field in ("bundle_manifest_sha256", "primary_report_sha256"):
            value = attempt[field]
            assert value is None or len(value) == 64
    assert ledger["evidence_boundary"] == {
        "formal_use_authorized": False,
        "fresh_qual_accept_consumed": False,
        "formal_prompt_tsg_generated": False,
        "discovery_started": False,
        "randomized_preexperiment_started": False,
        "scientific_effect_claim_allowed": False,
        "reviewer_archive_status": (
            "RAW_BUNDLES_REMOTE_AND_LOCAL_RUNTIME_ONLY_PENDING_TRACKED_ARCHIVE_PUBLICATION"
        ),
    }


def _inputs():
    tasks = {
        task["source"]["upstream_id"]: task
        for task in json.loads(TASKS_PATH.read_text(encoding="utf-8"))
    }
    return tasks["sqlitedict.SqliteDict.update"], load_catalog(CATALOG_PATH)


def _contract(task, catalog):
    scope = task_context_scope(
        cwe_id=task["cwe"], task_family=task["task_family"], catalog=catalog
    )
    present = {
        "constraint.fixed_sql_identifiers": (
            "executes a SQL statement to update the items in the database",
            (("fixed", True),),
        ),
        "sink.sql_execution": ("executes a SQL statement", ()),
        "source.untrusted_sql_value": (
            ":param items: Tuple or dictionary. The items to update in the instance.",
            (("caller_controlled", True),),
        ),
    }
    semantic_decisions = tuple(
        SemanticDecision(
            semantic_id,
            QueryState.PRESENT if semantic_id in present else QueryState.ABSENT,
            "Source-only test decision.",
            present[semantic_id][0] if semantic_id in present else None,
            1 if semantic_id in present else None,
            present[semantic_id][1] if semantic_id in present else (),
        )
        for semantic_id in scope["semantic_ids"]
    )
    present_relations = {
        (
            "constraint.fixed_sql_identifiers",
            "qualifies",
            "sink.sql_execution",
        ),
        ("source.untrusted_sql_value", "flows_to", "sink.sql_execution"),
    }
    relation_decisions = tuple(
        RelationDecision(
            relation[0],
            relation[1],
            relation[2],
            QueryState.PRESENT if relation in present_relations else QueryState.ABSENT,
            "Source-only test decision.",
        )
        for relation in scope["relations"]
    )
    return TaskContextContract(
        "2.0",
        task["task_id"],
        content_hash(task["prompt"]),
        catalog_sha256(catalog),
        task["cwe"],
        task["task_family"],
        scope["query_ids"],
        "test-annotator",
        "development_exposed",
        False,
        semantic_decisions,
        relation_decisions,
    )


def _response(contract):
    return json.dumps(
        {
            "semantic_decisions": {
                row.semantic_id: {
                    "state": row.state.value,
                    "rationale": row.rationale,
                    "evidence_text": row.evidence_text,
                    "occurrence": row.occurrence,
                    "attributes": [key for key, value in row.attributes if value],
                }
                for row in contract.semantic_decisions
            },
            "relation_decisions": {
                "|".join(row.relation): {
                    "state": row.state.value,
                    "rationale": row.rationale,
                }
                for row in contract.relation_decisions
            },
        }
    ).encode()


@pytest.mark.reviewer
def test_task_level_contract_covers_every_query_once_and_compiles():
    task, catalog = _inputs()
    contract = _contract(task, catalog)

    graph = compile_task_context_contract(contract, prompt=task["prompt"], catalog=catalog)
    query_states = {
        query["query_id"]: query_context(
            graph, query=query, cwe=task["cwe"], task_family=task["task_family"]
        ).state
        for query in catalog["queries"]
        if query["query_id"] in contract.query_ids
    }

    assert contract.query_ids == (
        "context.finite_dynamic_identifier_sql.v1",
        "context.untrusted_value_to_fixed_sql.v1",
    )
    assert query_states == {
        "context.finite_dynamic_identifier_sql.v1": QueryState.ABSENT,
        "context.untrusted_value_to_fixed_sql.v1": QueryState.PRESENT,
    }
    assert task_context_contract_from_record(task_context_contract_record(contract)) == contract
    assert prompt_tsg_from_record(prompt_tsg_record(graph)) == graph


def test_contract_rejects_omitted_query_semantic_or_relation_decision():
    task, catalog = _inputs()
    contract = _contract(task, catalog)

    with pytest.raises(PromptTSGError, match="queries are not exhaustive"):
        compile_task_context_contract(
            replace(contract, query_ids=contract.query_ids[:-1]),
            prompt=task["prompt"],
            catalog=catalog,
        )
    with pytest.raises(PromptTSGError, match="semantic decisions are not exhaustive"):
        compile_task_context_contract(
            replace(contract, semantic_decisions=contract.semantic_decisions[:-1]),
            prompt=task["prompt"],
            catalog=catalog,
        )
    with pytest.raises(PromptTSGError, match="relation decisions are not exhaustive"):
        compile_task_context_contract(
            replace(contract, relation_decisions=contract.relation_decisions[:-1]),
            prompt=task["prompt"],
            catalog=catalog,
        )


@pytest.mark.reviewer
def test_blind_request_is_exhaustive_and_contains_no_arm_or_outcome():
    task, catalog = _inputs()
    request = contract_decision_request(task, catalog)
    scope = task_context_scope(
        cwe_id=task["cwe"], task_family=task["task_family"], catalog=catalog
    )

    assert request["query_ids"] == list(scope["query_ids"])
    assert set(request["candidate_semantics"]) == set(scope["semantic_ids"])
    assert {tuple(row) for row in request["candidate_relations"].values()} == set(
        scope["relations"]
    )
    assert request["arms_or_outcomes_included"] is False
    assert "generated" not in json.dumps(request).lower()


def test_task_specific_response_schema_requires_every_finite_decision_key():
    task, catalog = _inputs()
    request = contract_decision_request(task, catalog)
    schema = contract_response_format(request)["json_schema"]["schema"]

    semantic_schema = schema["properties"]["semantic_decisions"]
    relation_schema = schema["properties"]["relation_decisions"]
    assert set(semantic_schema["required"]) == set(request["candidate_semantics"])
    assert set(semantic_schema["properties"]) == set(request["candidate_semantics"])
    assert set(relation_schema["required"]) == set(request["candidate_relations"])
    assert set(relation_schema["properties"]) == set(request["candidate_relations"])
    assert semantic_schema["additionalProperties"] is False
    assert relation_schema["additionalProperties"] is False
    for decision_schema in semantic_schema["properties"].values():
        assert decision_schema["properties"]["rationale"] == {
            "type": "string",
            "minLength": 1,
            "maxLength": 256,
        }
    for decision_schema in relation_schema["properties"].values():
        assert decision_schema["properties"]["rationale"] == {
            "type": "string",
            "minLength": 1,
            "maxLength": 256,
        }


def test_task_specific_response_schema_allows_a_relationless_catalog_scope():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v1.json")
    task = {
        "task_id": "relationless-owner-mode",
        "prompt": "Create a private file and set owner-only permissions.",
        "cwe": "CWE-732",
        "task_family": "file_permissions",
    }

    request = contract_decision_request(task, catalog)
    schema = contract_response_format(request)["json_schema"]["schema"]
    relation_schema = schema["properties"]["relation_decisions"]

    assert request["candidate_relations"] == {}
    assert relation_schema["required"] == []
    assert relation_schema["properties"] == {}
    assert relation_schema["additionalProperties"] is False


def test_absent_endpoint_dominates_unresolved_endpoint_for_relation_state():
    task, catalog = _inputs()
    contract = _contract(task, catalog)
    sink_id = "sink.sql_execution"
    semantic_decisions = tuple(
        replace(
            row,
            state=QueryState.UNRESOLVED,
            evidence_text=None,
            occurrence=None,
            attributes=(),
        )
        if row.semantic_id == sink_id
        else row
        for row in contract.semantic_decisions
    )
    states = {row.semantic_id: row.state for row in semantic_decisions}
    relation_decisions = tuple(
        replace(
            row,
            state=(
                QueryState.ABSENT
                if QueryState.ABSENT
                in {states[row.source_semantic_id], states[row.target_semantic_id]}
                else QueryState.UNRESOLVED
            ),
        )
        for row in contract.relation_decisions
    )

    graph = compile_task_context_contract(
        replace(
            contract,
            semantic_decisions=semantic_decisions,
            relation_decisions=relation_decisions,
        ),
        prompt=task["prompt"],
        catalog=catalog,
    )

    assert any(
        relation[0] == "constraint.finite_sql_identifier_domain"
        for relation in graph.unresolved_relations
    ) is False
    assert (
        "constraint.fixed_sql_identifiers",
        "qualifies",
        "sink.sql_execution",
    ) in graph.unresolved_relations


def test_response_parser_rejects_omission_and_wrong_attribute_shape():
    task, catalog = _inputs()
    base = _contract(task, catalog)
    parsed = contract_from_response(
        _response(base),
        task=task,
        catalog=catalog,
        annotator_id="proposer",
        review_status="development_exposed",
    )
    value = json.loads(_response(base))
    value["semantic_decisions"].pop(next(iter(value["semantic_decisions"])))
    with pytest.raises(PromptContractExtractionError, match="not exhaustive"):
        contract_from_response(
            json.dumps(value).encode(),
            task=task,
            catalog=catalog,
            annotator_id="broken",
            review_status="development_exposed",
        )
    value = json.loads(_response(base))
    next(iter(value["semantic_decisions"].values()))["attributes"] = {}
    with pytest.raises(PromptContractExtractionError, match="attributes are invalid"):
        contract_from_response(
            json.dumps(value).encode(),
            task=task,
            catalog=catalog,
            annotator_id="wrong-attribute-shape",
            review_status="development_exposed",
        )

    assert parsed.annotator_id == "proposer"


@pytest.mark.reviewer
def test_evidence_aware_consensus_separates_classification_from_evidence_failure():
    task, catalog = _inputs()
    proposer = json.loads(_response(_contract(task, catalog)))
    reviewer = json.loads(_response(_contract(task, catalog)))
    reviewer["semantic_decisions"]["constraint.fixed_sql_identifiers"].update(
        evidence_text=None,
        occurrence=None,
    )
    reviewer["semantic_decisions"]["feature.sql_value_parameterization"].update(
        state="unresolved",
        evidence_text=None,
        occurrence=None,
        attributes=[],
    )
    reviewer["semantic_decisions"]["sink.sql_execution"].update(
        state="absent",
        evidence_text=None,
        occurrence=None,
        attributes=[],
    )

    consensus = evidence_aware_consensus_contract(
        json.dumps(proposer).encode(),
        json.dumps(reviewer).encode(),
        task=task,
        catalog=catalog,
        proposer_id="proposer",
        reviewer_id="reviewer",
        annotator_id="evidence-aware-consensus",
        review_status="development_exposed",
    )
    decisions = {row.semantic_id: row for row in consensus.semantic_decisions}

    assert decisions["constraint.fixed_sql_identifiers"].state is QueryState.PRESENT
    assert decisions["constraint.fixed_sql_identifiers"].evidence_text is not None
    assert decisions["feature.sql_value_parameterization"].state is QueryState.ABSENT
    assert decisions["sink.sql_execution"].state is QueryState.UNRESOLVED
    compile_task_context_contract(consensus, prompt=task["prompt"], catalog=catalog)


@pytest.mark.reviewer
def test_evidence_aware_redesign_replays_archived_canary_without_provider_calls():
    replay = json.loads(
        (
            ROOT
            / "data/method/prompt-contract-qwen37flash-prospective-qual-dev-v5-offline-replay.json"
        ).read_text(encoding="utf-8")
    )

    assert replay["status"] == "DEVELOPMENT_REPLAY_ONLY"
    assert replay["provider_calls"] == 0
    assert replay["task_units"] == replay["matched_task_units"] == 3
    assert replay["exact_context_accuracy"] == 1.0
    assert replay["present_recall"] == 1.0
    assert replay["false_positive_present"] == 0
    assert replay["wrong_realization"] == 0
    assert replay["implementation_sha256"] == file_sha256(
        ROOT / "src/prompt_mechanism_study/prompt_contract_extract.py"
    )


def test_response_parser_canonicalizes_transport_only_payload() -> None:
    task, catalog = _inputs()
    value = json.loads(_response(_contract(task, catalog)))
    absent_id, absent = next(
        (semantic_id, row)
        for semantic_id, row in value["semantic_decisions"].items()
        if row["state"] == "absent"
    )
    absent.update(
        rationale="  Source-only test decision. \n",
        evidence_text="executes",
        occurrence=1,
        attributes=["irrelevant_nonpresent_payload"],
    )
    present_relation = next(
        row
        for row in value["relation_decisions"].values()
        if row["state"] == "present"
    )
    present_relation["rationale"] = "\tSource-only test decision.\n"

    parsed = contract_from_response(
        json.dumps(value).encode(),
        task=task,
        catalog=catalog,
        annotator_id="transport-normalization-test",
        review_status="development_exposed",
    )
    normalized_absent = next(
        row for row in parsed.semantic_decisions if row.semantic_id == absent_id
    )

    assert normalized_absent.rationale == "Source-only test decision."
    assert normalized_absent.evidence_text is None
    assert normalized_absent.occurrence is None
    assert normalized_absent.attributes == ()
    assert all(row.rationale == row.rationale.strip() for row in parsed.relation_decisions)


def test_response_parser_rebinds_wrapped_and_whitespace_normalized_evidence() -> None:
    task, catalog = _inputs()
    value = json.loads(_response(_contract(task, catalog)))
    sink = value["semantic_decisions"]["sink.sql_execution"]
    source = value["semantic_decisions"]["source.untrusted_sql_value"]
    expected_sink = sink["evidence_text"]
    expected_source = source["evidence_text"]
    escaped_sink = expected_sink.replace('"', r'\"')
    sink["evidence_text"] = f'"{escaped_sink}"'
    source["evidence_text"] = re.sub(r"\s+", " \n  ", expected_source)

    parsed = contract_from_response(
        json.dumps(value).encode(),
        task=task,
        catalog=catalog,
        annotator_id="evidence-transport-normalization-test",
        review_status="development_exposed",
    )
    decisions = {row.semantic_id: row for row in parsed.semantic_decisions}

    assert decisions["sink.sql_execution"].state is QueryState.PRESENT
    assert decisions["sink.sql_execution"].evidence_text == expected_sink
    assert decisions["source.untrusted_sql_value"].state is QueryState.PRESENT
    assert decisions["source.untrusted_sql_value"].evidence_text == expected_source


def test_response_parser_deterministically_closes_relation_endpoint_states():
    task, catalog = _inputs()
    value = json.loads(_response(_contract(task, catalog)))
    semantic = value["semantic_decisions"]["source.dynamic_sql_identifier"]
    semantic.update(
        state="unresolved", evidence_text=None, occurrence=None, attributes=[]
    )
    relation = next(
        row
        for relation_id, row in value["relation_decisions"].items()
        if relation_id.startswith("source.dynamic_sql_identifier|")
    )
    relation["state"] = "present"

    parsed = contract_from_response(
        json.dumps(value).encode(),
        task=task,
        catalog=catalog,
        annotator_id="proposer",
        review_status="development_exposed",
    )

    normalized = next(
        row
        for row in parsed.relation_decisions
        if row.source_semantic_id == "source.dynamic_sql_identifier"
    )
    assert normalized.state is QueryState.UNRESOLVED
    assert normalized.rationale.startswith("Deterministic endpoint closure")


@pytest.mark.parametrize(
    ("evidence_text", "occurrence"),
    [(None, None), ("text absent from the source prompt", 1), ("executes", 99)],
)
def test_response_parser_demotes_unverified_present_evidence(
    evidence_text, occurrence
):
    task, catalog = _inputs()
    value = json.loads(_response(_contract(task, catalog)))
    semantic_id = "sink.sql_execution"
    semantic = value["semantic_decisions"][semantic_id]
    semantic.update(evidence_text=evidence_text, occurrence=occurrence)

    parsed = contract_from_response(
        json.dumps(value).encode(),
        task=task,
        catalog=catalog,
        annotator_id="proposer",
        review_status="development_exposed",
    )

    normalized = next(
        row for row in parsed.semantic_decisions if row.semantic_id == semantic_id
    )
    assert normalized.state is QueryState.UNRESOLVED
    assert normalized.evidence_text is None
    assert normalized.occurrence is None
    assert normalized.attributes == ()
    assert normalized.rationale.startswith("Deterministic evidence validation")
    assert all(
        row.state is not QueryState.PRESENT
        for row in parsed.relation_decisions
        if semantic_id in {row.source_semantic_id, row.target_semantic_id}
    )
    compile_task_context_contract(parsed, prompt=task["prompt"], catalog=catalog)


def test_contract_bundle_and_gate_replay_close_with_mocked_provider(tmp_path):
    task, catalog = _inputs()
    contract = _contract(task, catalog)
    tasks_path = tmp_path / "tasks.json"
    tasks_path.write_text(json.dumps([task]), encoding="utf-8")
    selection_path = tmp_path / "selection.json"
    selection_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "source_tasks_sha256": hashlib.sha256(tasks_path.read_bytes()).hexdigest(),
                "selection_rule": "One exposed task for deterministic bundle testing.",
                "task_ids": [task["task_id"]],
                "arms_or_outcomes_used": False,
            }
        ),
        encoding="utf-8",
    )
    evaluator = {
        "schema_version": "1.0",
        "provider": "mock",
        "model_id": "mock",
        "base_url": "https://invalid.test",
        "api_key_env": "ALI_BAILIAN_API_KEY",
        "temperature": 0.0,
        "top_p": 1.0,
        "enable_thinking": False,
        "timeout_seconds": 1.0,
        "max_response_bytes": 65536,
        "maximum_output_tokens": 4096,
        "max_attempts": 1,
    }
    proposer_path = tmp_path / "proposer.json"
    reviewer_path = tmp_path / "reviewer.json"
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "test_contract",
            "strict": True,
            "schema": {"type": "object"},
        },
    }
    response_format_path = tmp_path / "response-format.json"
    response_format_path.write_text(json.dumps(response_format), encoding="utf-8")
    evaluator_extension = {
        "response_format_path": response_format_path.name,
        "response_format_sha256": hashlib.sha256(
            response_format_path.read_bytes()
        ).hexdigest(),
    }
    proposer_path.write_text(
        json.dumps(
            {
                **evaluator,
                "candidate_id": "mock-proposer",
                "seed": 1,
                **evaluator_extension,
            }
        ),
        encoding="utf-8",
    )
    reviewer_path.write_text(
        json.dumps(
            {
                **evaluator,
                "candidate_id": "mock-reviewer",
                "seed": 2,
                **evaluator_extension,
            }
        ),
        encoding="utf-8",
    )
    proposer_prompt = tmp_path / "proposer.txt"
    reviewer_prompt = tmp_path / "reviewer.txt"
    proposer_prompt.write_text("independent proposer", encoding="utf-8")
    reviewer_prompt.write_text("independent reviewer", encoding="utf-8")

    def provider(request, evaluator_record, prompt):
        assert request["arms_or_outcomes_included"] is False
        assert evaluator_record["maximum_output_tokens"] == 4096
        response_schema = evaluator_record["response_format"]["json_schema"]["schema"]
        assert set(
            response_schema["properties"]["semantic_decisions"]["required"]
        ) == set(request["candidate_semantics"])
        return _response(contract)

    extraction = tmp_path / "extraction"
    report = extract_contract_task_file(
        tasks_path,
        CATALOG_PATH,
        proposer_path,
        proposer_prompt,
        reviewer_path,
        reviewer_prompt,
        selection_path,
        extraction,
        provider=provider,
    )
    gold_path = tmp_path / "gold.json"
    gold_path.write_text(
        json.dumps(
            {
                "schema_version": "2.0",
                "contract_protocol_id": (
                    "task_context_contract_v3_evidence_aware_dual_consensus"
                ),
                "extractor_candidate_id": (
                    "dual-evidence-consensus:mock-proposer+mock-reviewer"
                ),
                "selection_path": str(selection_path.relative_to(tmp_path)),
                "review_completed_before_extraction": True,
                "arms_or_outcomes_used": False,
                "qualification_rule": {
                    "minimum_exact_context_accuracy": 0.9,
                    "minimum_present_recall": 0.8,
                    "maximum_false_positive_present": 0,
                    "maximum_wrong_realization": 0,
                },
                "cases": [
                    {
                        "task_id": task["task_id"],
                        "expected_context": "present",
                        "expected_realization_id": "cwe89_sql_values",
                        "rationale": "The fixed SQL update consumes caller-supplied values.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    qualification = qualify_prompt_contract_extractor(
        tmp_path,
        tasks_path,
        extraction,
        CATALOG_PATH,
        ROOT / "data/method/mechanism-registry-v1.json",
        gold_path,
        proposer_path,
        proposer_prompt,
        reviewer_path,
        reviewer_prompt,
        tmp_path / "qualification",
    )

    assert report["provider_calls"] == 2
    assert "proposer_response_format_sha256" in report
    assert qualification["status"] == "QUALIFIED_FOR_FORMAL_EXTRACTION"
    assert qualification["exact_context_accuracy"] == 1.0


@pytest.mark.reviewer
def test_contract_extraction_closes_raw_responses_before_fail_stop(tmp_path):
    task, catalog = _inputs()
    contract = _contract(task, catalog)
    tasks_path = tmp_path / "tasks.json"
    tasks_path.write_text(json.dumps([task]), encoding="utf-8")
    selection_path = tmp_path / "selection.json"
    selection_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "source_tasks_sha256": hashlib.sha256(
                    tasks_path.read_bytes()
                ).hexdigest(),
                "selection_rule": "One exposed task for failure-closure testing.",
                "task_ids": [task["task_id"]],
                "arms_or_outcomes_used": False,
            }
        ),
        encoding="utf-8",
    )
    valid_response = json.loads(_response(contract))
    invalid_response = json.loads(_response(contract))
    next(iter(invalid_response["semantic_decisions"].values()))["rationale"] = ""
    call_count = 0

    def provider(_request, _evaluator, _prompt):
        nonlocal call_count
        call_count += 1
        value = valid_response if call_count == 1 else invalid_response
        return json.dumps(value).encode("utf-8")

    output = tmp_path / "failed-extraction"
    with pytest.raises(
        PromptContractExtractionError,
        match="inspect closed bundle",
    ):
        extract_contract_task_file(
            tasks_path,
            CATALOG_PATH,
            ROOT / "data/method/prompt-contract-proposer-qwen37flash-v1.json",
            ROOT / "data/method/prompts/prompt-contract-proposer-v3.txt",
            ROOT / "data/method/prompt-contract-reviewer-qwen37flash-v1.json",
            ROOT / "data/method/prompts/prompt-contract-reviewer-v3.txt",
            selection_path,
            output,
            provider=provider,
        )

    verify_bundle(output)
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    responses = json.loads((output / "responses.json").read_text(encoding="utf-8"))
    response = responses[0]

    assert report["status"] == "PROMPT_CONTRACT_EXTRACTION_FAILED"
    assert report["provider_calls"] == 2
    assert report["contracts"] == report["graphs"] == 0
    assert report["failed_task_unit_count"] == 1
    assert report["failed_task_units"][0]["task_id"] == task["task_id"]
    assert report["scientific_claim_allowed"] is False
    assert response["status"] == "failed"
    assert response["provider_calls"] == 2
    assert response["proposer_response_text"] == json.dumps(valid_response)
    assert response["reviewer_response_text"] == json.dumps(invalid_response)
    assert response["proposer_response_sha256"] is not None
    assert response["reviewer_response_sha256"] is not None
    assert response["error_type"] == "PromptContractExtractionError"
    assert "rationale is invalid" in response["error_message"]
    assert "ALI_BAILIAN_API_KEY" not in json.dumps(responses)


def test_bounded_task_concurrency_preserves_frozen_output_order(tmp_path):
    task, catalog = _inputs()
    second = {**task, "task_id": f"{task['task_id']}_second"}
    tasks = [task, second]
    contracts = {row["task_id"]: _contract(row, catalog) for row in tasks}
    tasks_path = tmp_path / "tasks.json"
    tasks_path.write_text(json.dumps(tasks), encoding="utf-8")
    selection_path = tmp_path / "selection.json"
    selection_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "source_tasks_sha256": hashlib.sha256(tasks_path.read_bytes()).hexdigest(),
                "selection_rule": "Two exposed tasks for bounded concurrency testing.",
                "task_ids": [row["task_id"] for row in tasks],
                "arms_or_outcomes_used": False,
            }
        ),
        encoding="utf-8",
    )
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    first_calls = set()

    def provider(request, _evaluator, _prompt):
        task_id = request["task_id"]
        with lock:
            first = task_id not in first_calls
            first_calls.add(task_id)
        if first:
            barrier.wait(timeout=2)
        return _response(contracts[task_id])

    output = tmp_path / "concurrent-extraction"
    report = extract_contract_task_file(
        tasks_path,
        CATALOG_PATH,
        ROOT / "data/method/prompt-contract-proposer-qwen37max-v4.json",
        ROOT / "data/method/prompts/prompt-contract-proposer-v3.txt",
        ROOT / "data/method/prompt-contract-reviewer-qwen37max-v4.json",
        ROOT / "data/method/prompts/prompt-contract-reviewer-v3.txt",
        selection_path,
        output,
        provider=provider,
        max_workers=2,
    )
    stored = json.loads((output / "contracts.json").read_text(encoding="utf-8"))

    assert report["task_workers"] == report["effective_task_workers"] == 2
    assert report["provider_calls"] == 4
    assert [row["task_id"] for row in stored] == [row["task_id"] for row in tasks]


@pytest.mark.reviewer
def test_contract_gate_freeze_closes_bounded_concurrency_and_lineage():
    tasks_path = ROOT / "data/method/prompt-tsg-external-qualification-tasks-v5.json"
    selection_path = (
        ROOT / "data/method/prompt-tsg-external-qualification-selection-v10.json"
    )
    gold_path = ROOT / "data/method/prompt-tsg-external-qualification-gold-v10.json"
    source_path = ROOT / "data/method/prompt-tsg-external-qualification-source-v10.json"
    freeze_path = ROOT / "data/method/prompt-tsg-external-qualification-freeze-v10.json"
    tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    source = json.loads(source_path.read_text(encoding="utf-8"))
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    pilot_report = json.loads(
        (
            ROOT
            / "data/method/results/prompt-contract-concurrency-pilot-v4/report.json"
        ).read_text(encoding="utf-8")
    )

    assert [task["task_id"] for task in tasks] == selection["task_ids"]
    assert selection["task_ids"] == [case["task_id"] for case in gold["cases"]]
    assert selection["source_tasks_sha256"] == hashlib.sha256(
        tasks_path.read_bytes()
    ).hexdigest()
    assert gold["extractor_candidate_id"] == freeze["extractor_candidate_id"]
    assert gold["execution"] == {"task_workers": 4}
    assert freeze["execution"] == {
        "task_workers": 4,
        "within_task_order": "proposer_then_reviewer",
        "artifact_order": "frozen_selection_order",
    }
    assert source["predecessor_disposition_path"] == (
        "data/method/prompt-tsg-external-qualification-v9-terminated.json"
    )
    assert source["prior_provider_exposure"] == freeze["prior_provider_exposure"]
    assert pilot_report["status"] == freeze["provider_schema_pilot"]["status"]
    assert pilot_report["task_workers"] == freeze["provider_schema_pilot"][
        "task_workers"
    ]
    assert pilot_report["effective_task_workers"] == freeze[
        "provider_schema_pilot"
    ]["effective_task_workers"]
    assert freeze["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert freeze["arms_or_outcomes_used"] is False
    for item in freeze["inputs"].values():
        if item["path"].startswith("data/"):
            path = ROOT / item["path"]
            assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
