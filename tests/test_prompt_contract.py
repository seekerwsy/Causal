import json
from dataclasses import replace
from pathlib import Path

import pytest

from prompt_mechanism_study.prompt_contract import (
    compile_task_context_contract,
    task_context_contract_from_record,
    task_context_contract_record,
)
from prompt_mechanism_study.prompt_tsg import (
    PromptTSGError,
    QueryState,
    feature_state,
    load_catalog,
    prompt_tsg_from_record,
    prompt_tsg_record,
    query_context,
)


pytestmark = pytest.mark.reviewer

ROOT = Path(__file__).parents[1]
CANARY_PATH = ROOT / "data/method/prompt-tsg-contract-first-canary-v1.json"
RESULT_PATH = ROOT / "data/method/prompt-tsg-contract-first-canary-v1-result.json"
TASKS_PATH = ROOT / "data/method/prompt-tsg-external-qualification-tasks-v4.json"
CATALOG_PATH = ROOT / "data/method/prompt-tsg-catalog-v11.json"


def _inputs():
    canary = json.loads(CANARY_PATH.read_text(encoding="utf-8"))
    tasks = {
        task["source"]["upstream_id"]: task
        for task in json.loads(TASKS_PATH.read_text(encoding="utf-8"))
    }
    return canary, tasks, load_catalog(CATALOG_PATH)


def test_exposed_four_case_contract_canary_compiles_expected_states():
    canary, tasks, catalog = _inputs()

    results = []
    artifact_rows = []
    for case in canary["cases"]:
        task = tasks[case["upstream_task_id"]]
        contract = task_context_contract_from_record(case["contract"])
        graph = compile_task_context_contract(contract, prompt=task["prompt"], catalog=catalog)
        query = next(
            item for item in catalog["queries"] if item["query_id"] == contract.query_id
        )
        state = query_context(
            graph,
            query=query,
            cwe=task["cwe"],
            task_family=task["task_family"],
        ).state
        target_state = feature_state(graph, query["actionable_feature_id"])

        assert graph.schema_version == "2.0"
        assert task_context_contract_from_record(
            task_context_contract_record(contract)
        ) == contract
        assert prompt_tsg_from_record(prompt_tsg_record(graph)) == graph
        assert state is QueryState(case["expected_query_state"])
        assert target_state is QueryState(case["expected_feature_state"])
        results.append((case["upstream_task_id"], state.value, target_state.value))
        artifact_rows.append(
            {
                "upstream_task_id": case["upstream_task_id"],
                "contract_id": contract.contract_id,
                "tsg_id": graph.tsg_id,
                "query_state": state.value,
                "feature_state": target_state.value,
            }
        )

    assert results == [
        ("sqlitedict.SqliteDict.update", "present", "absent"),
        ("diffprivlib.utils.check_random_state", "absent", "present"),
        ("kinto.plugins.openid.OpenIDConnectPolicy._verify_token", "present", "absent"),
        ("kinto.core.testing.get_user_headers", "absent", "absent"),
    ]
    result = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert result["cases"] == artifact_rows


def test_contract_rejects_an_omitted_semantic_or_relation_decision():
    canary, tasks, catalog = _inputs()
    case = canary["cases"][0]
    task = tasks[case["upstream_task_id"]]
    contract = task_context_contract_from_record(case["contract"])

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
    decisions = (
        replace(contract.semantic_decisions[0], rationale=""),
        *contract.semantic_decisions[1:],
    )
    with pytest.raises(PromptTSGError, match="semantic rationale is invalid"):
        compile_task_context_contract(
            replace(contract, semantic_decisions=decisions),
            prompt=task["prompt"],
            catalog=catalog,
        )


def test_unresolved_relation_remains_unresolved_instead_of_becoming_absent():
    canary, tasks, catalog = _inputs()
    case = canary["cases"][0]
    task = tasks[case["upstream_task_id"]]
    contract = task_context_contract_from_record(case["contract"])
    relation = replace(contract.relation_decisions[0], state=QueryState.UNRESOLVED)
    contract = replace(
        contract,
        relation_decisions=(relation, *contract.relation_decisions[1:]),
    )

    graph = compile_task_context_contract(contract, prompt=task["prompt"], catalog=catalog)
    query = next(item for item in catalog["queries"] if item["query_id"] == contract.query_id)

    assert graph.unresolved_relations == (relation.relation,)
    assert query_context(
        graph,
        query=query,
        cwe=task["cwe"],
        task_family=task["task_family"],
    ).state is QueryState.UNRESOLVED


def test_graph_schema_two_preserves_frozen_schema_one_records():
    frozen = json.loads(
        (
            ROOT / "data/method/results/prompt-tsg-external-extraction-v4/graphs.json"
        ).read_text(encoding="utf-8")
    )[0]

    graph = prompt_tsg_from_record(frozen)

    assert graph.schema_version == "1.0"
    assert graph.unresolved_relations == ()
    assert "unresolved_relations" not in prompt_tsg_record(graph)
    assert prompt_tsg_record(graph) == frozen
