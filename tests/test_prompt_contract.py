import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

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
    consensus_contract,
    contract_decision_request,
    contract_from_response,
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


pytestmark = pytest.mark.reviewer

ROOT = Path(__file__).parents[1]
TASKS_PATH = ROOT / "data/method/prompt-tsg-external-qualification-tasks-v4.json"
CATALOG_PATH = ROOT / "data/method/prompt-tsg-catalog-v11.json"


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
            "semantic_decisions": [
                {
                    "semantic_id": row.semantic_id,
                    "state": row.state.value,
                    "rationale": row.rationale,
                    "evidence_text": row.evidence_text,
                    "occurrence": row.occurrence,
                    "attributes": [key for key, value in row.attributes if value],
                }
                for row in contract.semantic_decisions
            ],
            "relation_decisions": [
                {
                    "source_semantic_id": row.source_semantic_id,
                    "edge_type": row.edge_type,
                    "target_semantic_id": row.target_semantic_id,
                    "state": row.state.value,
                    "rationale": row.rationale,
                }
                for row in contract.relation_decisions
            ],
        }
    ).encode()


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


def test_blind_request_is_exhaustive_and_contains_no_arm_or_outcome():
    task, catalog = _inputs()
    request = contract_decision_request(task, catalog)
    scope = task_context_scope(
        cwe_id=task["cwe"], task_family=task["task_family"], catalog=catalog
    )

    assert request["query_ids"] == list(scope["query_ids"])
    assert set(request["candidate_semantics"]) == set(scope["semantic_ids"])
    assert {tuple(row) for row in request["candidate_relations"]} == set(
        scope["relations"]
    )
    assert request["arms_or_outcomes_included"] is False
    assert "generated" not in json.dumps(request).lower()


def test_response_parser_rejects_omission_and_consensus_makes_disagreement_unresolved():
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
    value["semantic_decisions"].pop()
    with pytest.raises(PromptContractExtractionError, match="not exhaustive"):
        contract_from_response(
            json.dumps(value).encode(),
            task=task,
            catalog=catalog,
            annotator_id="broken",
            review_status="development_exposed",
        )
    value = json.loads(_response(base))
    value["semantic_decisions"][0]["attributes"] = {}
    with pytest.raises(PromptContractExtractionError, match="attributes are invalid"):
        contract_from_response(
            json.dumps(value).encode(),
            task=task,
            catalog=catalog,
            annotator_id="wrong-attribute-shape",
            review_status="development_exposed",
        )

    reviewer = replace(
        parsed,
        annotator_id="reviewer",
        semantic_decisions=tuple(
            replace(row, state=QueryState.UNRESOLVED)
            if row.semantic_id == "feature.sql_value_parameterization"
            else row
            for row in parsed.semantic_decisions
        ),
    )
    consensus = consensus_contract(parsed, reviewer, annotator_id="consensus")

    assert next(
        row
        for row in consensus.semantic_decisions
        if row.semantic_id == "feature.sql_value_parameterization"
    ).state is QueryState.UNRESOLVED
    compile_task_context_contract(consensus, prompt=task["prompt"], catalog=catalog)


def test_graph_schema_two_preserves_frozen_schema_one_records():
    frozen = json.loads(
        (ROOT / "data/method/results/prompt-tsg-external-extraction-v4/graphs.json").read_text(
            encoding="utf-8"
        )
    )[0]

    graph = prompt_tsg_from_record(frozen)

    assert graph.schema_version == "1.0"
    assert graph.unresolved_relations == ()
    assert "unresolved_relations" not in prompt_tsg_record(graph)
    assert prompt_tsg_record(graph) == frozen


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
        "max_attempts": 1,
    }
    proposer_path = tmp_path / "proposer.json"
    reviewer_path = tmp_path / "reviewer.json"
    proposer_path.write_text(
        json.dumps({**evaluator, "candidate_id": "mock-proposer", "seed": 1}),
        encoding="utf-8",
    )
    reviewer_path.write_text(
        json.dumps({**evaluator, "candidate_id": "mock-reviewer", "seed": 2}),
        encoding="utf-8",
    )
    proposer_prompt = tmp_path / "proposer.txt"
    reviewer_prompt = tmp_path / "reviewer.txt"
    proposer_prompt.write_text("independent proposer", encoding="utf-8")
    reviewer_prompt.write_text("independent reviewer", encoding="utf-8")

    def provider(request, evaluator_record, prompt):
        assert request["arms_or_outcomes_included"] is False
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
                "contract_protocol_id": "task_context_contract_v2_dual_blind_consensus",
                "extractor_candidate_id": "dual-blind-consensus:mock-proposer+mock-reviewer",
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
    assert qualification["status"] == "QUALIFIED_FOR_FORMAL_EXTRACTION"
    assert qualification["exact_context_accuracy"] == 1.0


def test_prospective_v5_gate_freeze_is_source_only_and_self_consistent():
    tasks_path = ROOT / "data/method/prompt-tsg-external-qualification-tasks-v5.json"
    selection_path = (
        ROOT / "data/method/prompt-tsg-external-qualification-selection-v5.json"
    )
    gold_path = ROOT / "data/method/prompt-tsg-external-qualification-gold-v5.json"
    source_path = ROOT / "data/method/prompt-tsg-external-qualification-source-v5.json"
    freeze_path = ROOT / "data/method/prompt-tsg-external-qualification-freeze-v5.json"
    tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    source = json.loads(source_path.read_text(encoding="utf-8"))
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    catalog = load_catalog(CATALOG_PATH)

    task_ids = [task["task_id"] for task in tasks]
    assert len(tasks) == len(set(task_ids)) == 28
    assert task_ids == selection["task_ids"]
    assert task_ids == [case["task_id"] for case in gold["cases"]]
    assert selection["source_tasks_sha256"] == hashlib.sha256(
        tasks_path.read_bytes()
    ).hexdigest()
    assert all(
        task["prompt_sha256"]
        == hashlib.sha256(task["prompt"].encode("utf-8")).hexdigest()
        for task in tasks
    )
    assert all(
        task_context_scope(
            cwe_id=task["cwe"],
            task_family=task["task_family"],
            catalog=catalog,
        )["query_ids"]
        for task in tasks
    )
    assert sum(case["expected_context"] == "present" for case in gold["cases"]) == 10
    positive_realizations = sorted(
        {
            case["expected_realization_id"]
            for case in gold["cases"]
            if case["expected_context"] == "present"
        }
    )
    assert positive_realizations == sorted(
        source["support_scope"]["candidate_realization_ids_with_expected_present_gold"]
    )
    assert positive_realizations == sorted(freeze["candidate_support_realization_ids"])
    assert source["gold_annotation"]["independent_human_annotation"] is False
    assert source["review_completed_before_extraction"] is True
    assert gold["review_completed_before_extraction"] is True
    assert freeze["status"] == "FROZEN_BEFORE_PROVIDER_CALL"
    assert freeze["arms_or_outcomes_used"] is False
    for item in freeze["inputs"].values():
        path = ROOT / item["path"]
        if item["path"].startswith("data/"):
            assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
