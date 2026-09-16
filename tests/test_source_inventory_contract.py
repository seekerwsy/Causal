"""Source coverage, generation/runtime layers and operation-local role boundaries."""

from copy import deepcopy
from dataclasses import replace
import pytest
from prompt_mechanism_study.prompt_contract import (
    compile_open_task_contract, open_concept_catalog, open_contract_from_response,
    task_context_contract_from_record, task_context_contract_record,
)
from prompt_mechanism_study.prompt_tsg import PromptTSGError
from prompt_mechanism_study.records import canonical_value, content_id


SOURCE = "Implement Python code. Return JSON. Transform buffer in place. If remote, validate buffer."


def _inventory_contract():
    definitions = [
        ("g", "task_operation", "code.implementation", "Implement Python code"),
        ("j", "presentation_control", "answer.json", "Return JSON"),
        ("op", "task_operation", "buffer.transform", "Transform buffer in place"),
        ("x", "data_object", "buffer.value", "buffer"),
        ("c", "condition", "mode.remote", "If remote"),
        ("p", "safety_requirement", "buffer.validate", "validate buffer"),
    ]
    relations = [
        ("j", "constrains", "g", "Return JSON"),
        ("x", "used_by", "op", "Transform buffer in place"),
        ("op", "produces", "x", "Transform buffer in place"),
        ("c", "conditions", "p", "If remote, validate buffer"),
        ("p", "constrains", "op", "If remote, validate buffer"),
        ("p", "constrains", "x", "validate buffer"),
    ]
    catalog = open_concept_catalog()
    contract = open_contract_from_response(dict(
        concepts=[dict(concept_id=concept, node_type=kind, definition=quote)
                  for _, kind, concept, quote in definitions],
        nodes=[dict(local_id=key, concept_id=concept, evidence_text=quote, occurrence=1)
               for key, _, concept, quote in definitions],
        edges=[dict(source_node_local_id=source, target_node_local_id=target, edge_type=kind,
                    evidence_text=quote, occurrence=1) for source, kind, target, quote in relations],
        concept_states=[], feature_states=[], unresolved_notes=[]),
        task=dict(task_id="synthetic-source-inventory", prompt=SOURCE), catalog=catalog,
        annotator_id="authored-fixture", review_status="development_exposed")
    units = [
        ("Implement Python code.", ["g"]), ("Return JSON.", ["j"]),
        ("Transform buffer in place.", ["op", "x"]),
        ("If remote, validate buffer.", ["c", "p", "x"]),
    ]
    inventory = dict(
        source_units={f"u{i}": dict(evidence_text=quote, occurrence=1)
                      for i, (quote, _) in enumerate(units, 1)},
        coverage={f"u{i}": dict(facts=facts, status="represented", reason="Authored source facts.")
                  for i, (_, facts) in enumerate(units, 1)},
        layers={key: "generation" if key in {"g", "j"} else "runtime"
                for key, _, _, _ in definitions},
        operation_roles=[dict(operation="op", subject="x", role=role,
                              evidence_text="Transform buffer in place", occurrence=1)
                         for role in ("value_input", "result")])
    return catalog, replace(contract, source_inventory=inventory)


def test_local_input_and_result_can_be_the_same_source_object_and_metadata_roundtrips():
    catalog, contract = _inventory_contract()
    graph = compile_open_task_contract(contract, prompt=SOURCE, catalog=catalog)
    assert len(graph.nodes) == len(contract.facts) + 1
    record = task_context_contract_record(contract)
    assert record["source_inventory"] == contract.source_inventory
    assert task_context_contract_from_record(record) == contract
    authored = replace(contract, source_inventory=None)
    legacy = canonical_value(authored)
    legacy.pop("source_inventory")
    assert authored.contract_id == content_id("open_task_contract_", legacy)
    assert "source_inventory" not in task_context_contract_record(authored)
    assert task_context_contract_from_record(task_context_contract_record(authored)) == authored
    assert authored.contract_id != contract.contract_id


@pytest.mark.parametrize("section", ["source_units", "operation_roles"])
def test_units_and_role_evidence_must_quote_the_actual_source(section):
    catalog, contract = _inventory_contract()
    inventory = deepcopy(contract.source_inventory)
    row = inventory[section]["u1"] if section == "source_units" else inventory[section][0]
    row["evidence_text"] = "This evidence is not in the task."
    with pytest.raises(PromptTSGError):
        compile_open_task_contract(replace(contract, source_inventory=inventory), prompt=SOURCE, catalog=catalog)


@pytest.mark.parametrize('source,relation,target,match', [
    ('j', 'constrains', 'op', 'same resolved layer'),
    ('x', 'used_by', 'op', 'input role'),
    ('op', 'produces', 'x', 'result role'),
])
def test_edges_require_same_layer_and_the_exact_operation_subject_role(source, relation, target, match):
    catalog, contract = _inventory_contract()
    inventory = deepcopy(contract.source_inventory)
    if relation == "used_by":
        inventory["operation_roles"] = [row for row in inventory["operation_roles"] if row["role"] == "result"]
    if relation == "produces":
        inventory["operation_roles"] = [row for row in inventory["operation_roles"] if row["role"] != "result"]
    edge = dict(source=source, edge_type=relation, target=target, evidence_text=SOURCE, occurrence=1)
    with pytest.raises(PromptTSGError, match=match):
        compile_open_task_contract(replace(contract, source_inventory=inventory, relations=(edge,)),
                                   prompt=SOURCE, catalog=catalog)
