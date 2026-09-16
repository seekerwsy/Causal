"""Graph-derived hypotheses preserve semantic granularity and source-only boundaries."""

import json
import pytest
from prompt_mechanism_study.prompt_contract import (
    compile_task_context_contract,
    open_concept_catalog,
    open_contract_from_response,
    task_context_contract_record,
)
from prompt_mechanism_study.candidate_construction import (
    build_candidate_catalog,
    candidate_request,
    compile_candidate_proposal,
    prepare_candidate_request,
)
from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.prompt_tsg import prompt_tsg_record
from prompt_mechanism_study.prompt_contract_extract import contract_decision_request
from prompt_mechanism_study.task_input import generation_template_facts, prepare_task_input
from prompt_mechanism_study.records import content_hash


def _development_sources(*, include_template=False):
    """Artificial source facts exercise construction, never natural support or accuracy."""
    cases = [
        (
            "synthetic-two-atomic",
            "Run a SQL query using value x. Bind value x and reject values longer than ten characters.",
            [
                ("op", "task_operation", "sql_query", "Run a SQL query"),
                ("value", "data_object", "query_value", "value x"),
                ("binding", "safety_requirement", "parameter_binding", "Bind value x"),
                ("length", "safety_requirement", "input_length",
                 "reject values longer than ten characters"),
            ],
        ),
        (
            "synthetic-equivalent",
            "Run a SQL query using value y. Pass value y as a bound query parameter.",
            [
                ("op", "task_operation", "sql_query", "Run a SQL query"),
                ("value", "data_object", "query_value", "value y"),
                ("requirement", "safety_requirement", "parameter_binding",
                 "Pass value y as a bound query parameter"),
            ],
        ),
    ]
    tasks, contracts = [], []
    for task_id, prompt, facts in cases:
        task = dict(task_id=task_id, task_unit_id=task_id, near_duplicate_group_id=task_id,
                    prompt=prompt, language="python", api_family="database",
                    task_archetype="query", source_lineage_id="synthetic-source",
                    source_kind="synthetic_development", covariates=[])
        response = dict(
            concepts=[dict(concept_id=concept, node_type=kind, definition=concept)
                      for _, kind, concept, _ in facts],
            nodes=[dict(local_id=local, concept_id=concept, evidence_text=quote, occurrence=1)
                   for local, _, concept, quote in facts],
            edges=[dict(source_node_local_id=source, edge_type=relation,
                        target_node_local_id=target, evidence_text=prompt, occurrence=1)
                   for source, relation, target in [
                       ("value", "used_by", "op"),
                       *[(local, "constrains", target) for local, kind, _, _ in facts
                         if kind == "safety_requirement" for target in ("op", "value")],
                   ]],
            concept_states=[], feature_states=[], unresolved_notes=[],
        )
        if include_template:
            task = prepare_task_input(task)
            template = generation_template_facts(task)
            for key in ("concepts", "nodes", "edges"):
                response[key].extend(template[key])
        contracts.append(open_contract_from_response(
            response, task=task, catalog=open_concept_catalog(), annotator_id="synthetic-offline",
            review_status="development_exposed"))
        tasks.append(task)
    return tasks, contracts


def _design():
    return dict(
        outcome_id="oracle_evaluable_secure_code_yield",
        language_scope=["python"],
        api_scope=["database"],
        task_archetype_scope=["query"],
        operations=["add", "remove"],
        model_id="synthetic-offline",
        covariate_names=[],
        support_rule=dict(
            minimum_state_task_units=2,
            minimum_shared_lineages=1,
            maximum_unresolved_fraction=0.2,
            minimum_feature_reliability=0.8,
        ),
    )


def _proposal(request):
    occurrences, dispositions = {"parameter_binding": [], "input_length": []}, []
    for source in request["sources"]:
        nodes = {node["concept_id"]: node for node in source["nodes"]}
        for node in source["nodes"]:
            if node["concept_id"] in occurrences:
                occurrences[node["concept_id"]].append(dict(
                    task_id=source["task_id"], requirement_node_ids=[node["node_id"]],
                    scope=dict(operation_node_id=nodes["sql_query"]["node_id"],
                               subject_node_ids=[nodes["query_value"]["node_id"]], condition_node_ids=[])))
            if node["node_type"] in {"safety_requirement", "task_requirement", "constraint", "presentation_control"}:
                dispositions.append(dict(task_id=source["task_id"], requirement_node_id=node["node_id"],
                    status="included" if node["concept_id"] in occurrences else "not_actionable",
                    rationale="Synthetic source factor; fixed implementation and output requirements remain unchanged."))
    return dict(factors=[
        dict(label="Bound SQL value", definition="Require the specified SQL data value to be passed as a bound parameter.",
             atomicity_rationale="One requirement about SQL value parameter binding; length checking remains separate.",
             occurrences=occurrences["parameter_binding"]),
        dict(label="Ten-character limit", definition="Require rejecting the specified SQL data value when longer than ten characters.",
             atomicity_rationale="One requirement about input length; parameter binding remains separate.",
             occurrences=occurrences["input_length"]),
    ], dispositions=dispositions)


def _review(request, response, draft):
    return dict(request_sha256=content_hash(request), response_sha256=content_hash(response),
                reviewer_id="synthetic-authored-review", arms_or_outcomes_used=False,
                decisions=[dict(feature_id=factor["feature_id"], decision="accept",
                                rationale="Synthetic fixture verifies separate source-backed decisions only.",
                                source_supported=True, single_requirement=True, normalization_valid=True,
                                context_independent=True, scope_preserves_task=True)
                           for factor in draft["factors"]])


def _prepared_proposal():
    tasks, contracts = _development_sources()
    request = candidate_request(tasks, contracts)
    response, design = _proposal(request), _design()
    draft = compile_candidate_proposal(request, response, design)
    return request, response, design, draft


def test_atomic_source_nodes_stay_separate_and_equivalent_occurrences_pool_before_review():
    _, _, _, draft = _prepared_proposal()
    factors = {factor["label"]: factor for factor in draft["factors"]}
    assert len(factors) == 2
    binding = factors["Bound SQL value"]["source_occurrences"]
    length = factors["Ten-character limit"]["source_occurrences"]
    assert len(binding) == 2 and len(length) == 1
    first_binding = next(row for row in binding if row["task_id"] == "synthetic-two-atomic")
    assert first_binding["requirement_node_ids"] != length[0]["requirement_node_ids"]
    assert draft["status"] == "PENDING_SEMANTIC_REVIEW"
    assert all(factor["review_decision"] == "pending" for factor in factors.values())
    assert draft["policies"] == [] and draft["queries"] == []
    assert draft["scientific_claim_allowed"] is False
    assert draft["formal_execution_authorized"] is False


def _one_requirement_request(*, compound):
    """One source node may repeat its meaning across scopes, never change its meaning."""
    task = dict(task_id="synthetic-one-requirement", language="python")
    if compound:
        task["prompt"] = "Run a SQL query using value x. Bind value x and reject values longer than ten characters."
        operations = [("op", "task_operation", "sql_query", "Run a SQL query")]
        requirement = ("requirement", "safety_requirement", "binding_and_length",
                       "Bind value x and reject values longer than ten characters")
    else:
        task["prompt"] = "Read value x in query A and write value x in query B. Bind value x in both queries."
        operations = [("read", "task_operation", "sql_read", "Read value x in query A"),
                      ("write", "task_operation", "sql_write", "write value x in query B")]
        requirement = ("requirement", "safety_requirement", "parameter_binding", "Bind value x in both queries")
    facts = [*operations, ("value", "data_object", "query_value", "value x"), requirement]
    links = [("requirement", "constrains", "value")]
    for local, _, _, _ in operations:
        links.extend([("value", "used_by", local), ("requirement", "constrains", local)])
    response = dict(
        concepts=[dict(concept_id=concept, node_type=kind, definition=concept) for _, kind, concept, _ in facts],
        nodes=[dict(local_id=local, concept_id=concept, evidence_text=quote, occurrence=1)
               for local, _, concept, quote in facts],
        edges=[dict(source_node_local_id=source, edge_type=relation, target_node_local_id=target,
                    evidence_text=task["prompt"], occurrence=1) for source, relation, target in links],
        concept_states=[], feature_states=[], unresolved_notes=[])
    contract = open_contract_from_response(response, task=task, catalog=open_concept_catalog(),
                                           annotator_id="synthetic-offline", review_status="development_exposed")
    request = candidate_request([task], [contract])
    nodes = {node["concept_id"]: node for node in request["sources"][0]["nodes"]}
    requirement_id = nodes[requirement[2]]["node_id"]
    occurrences = [dict(task_id=task["task_id"], requirement_node_ids=[requirement_id],
        scope=dict(operation_node_id=nodes[concept]["node_id"],
                   subject_node_ids=[nodes["query_value"]["node_id"]], condition_node_ids=[]))
        for _, _, concept, _ in operations]
    disposition = dict(task_id=task["task_id"], requirement_node_id=requirement_id, status="included",
                       rationale="Synthetic source evidence for the candidate granularity boundary.")
    return request, occurrences, disposition


def test_compound_source_node_cannot_be_split_into_different_candidate_meanings():
    request, occurrences, disposition = _one_requirement_request(compound=True)
    response = dict(factors=[
        dict(label="Bound SQL value", definition="Require bound SQL parameters.",
             atomicity_rationale="Parameter binding is independent of length validation.", occurrences=occurrences),
        dict(label="Ten-character limit", definition="Require rejecting inputs longer than ten characters.",
             atomicity_rationale="Length validation is independent of parameter binding.", occurrences=occurrences),
    ], dispositions=[disposition])
    with pytest.raises(ValueError, match="source requirement node cannot be split into different candidate meanings"):
        compile_candidate_proposal(request, response, _design())
    response["factors"] = []
    disposition.update(status="unresolved", rationale="The compound requirement must first be split in the source TSG.")
    unresolved = compile_candidate_proposal(request, response, _design())
    assert unresolved["factors"] == unresolved["policies"] == []
    assert unresolved["dispositions"][0]["status"] == "unresolved"


def test_reviewed_factors_emit_both_atomic_edits_without_support_filtering():
    request, response, design, draft = _prepared_proposal()
    # Deliberately impossible natural-support counts cannot suppress proposal construction.
    design["support_rule"]["minimum_state_task_units"] = 10_000
    compiled = compile_candidate_proposal(
        request, response, design, _review(request, response, draft)
    )
    atomic = [policy for policy in compiled["policies"] if "factor" in policy]
    features = {factor["feature_id"] for factor in compiled["factors"]}
    assert len(atomic) == len(compiled["policies"]) == 4
    assert {
        (policy["factor"]["actionable_feature_id"], policy["factor"]["operation"])
        for policy in atomic
    } == {(feature, operation) for feature in features for operation in ("add", "remove")}
    for query in compiled["queries"]:
        context = set(query["required_semantics"]) | set(query["forbidden_semantics"])
        context.update(
            concept
            for source, _, target in query["required_relations"]
            for concept in (source, target)
        )
        assert not features & context
        assert any(
            compiled["source_types"][concept] == "task_operation"
            for concept in query["required_semantics"]
        )
    assert compiled["formal_execution_authorized"] is False


@pytest.mark.parametrize("change", ["missing_disposition", "invented_requirement", "narrowed_scope"])
def test_candidate_evidence_must_cover_real_requirements_and_their_exact_scope(change):
    request, response, design, _ = _prepared_proposal()
    occurrence = response["factors"][0]["occurrences"][0]
    if change == "missing_disposition":
        response["dispositions"].pop()
    elif change == "invented_requirement":
        occurrence["requirement_node_ids"] = [occurrence["scope"]["operation_node_id"]]
    else:
        occurrence["scope"]["subject_node_ids"] = []
    with pytest.raises(ValueError, match="dispositions|requirement evidence|subject set"):
        compile_candidate_proposal(request, response, design)


def test_rejected_or_unresolved_semantics_are_retained_without_policies():
    request, response, design, draft = _prepared_proposal()
    review = _review(request, response, draft)
    for decision, status in zip(review["decisions"], ("reject", "unresolved"), strict=True):
        decision["decision"] = status
        decision["single_requirement"] = False
    compiled = compile_candidate_proposal(request, response, design, review)
    assert {factor["review_decision"] for factor in compiled["factors"]} == {"reject", "unresolved"}
    assert len(compiled["factors"]) == 2 and compiled["policies"] == []


def _write_candidate_request(tmp_path, *, include_template=False):
    tasks, contracts = _development_sources(include_template=include_template)
    task_path = tmp_path / "source-tasks.json"
    task_path.write_text(json.dumps(tasks), encoding="utf-8")
    original_graphs = [compile_task_context_contract(contract, prompt=task["prompt"], catalog=open_concept_catalog())
                       for task, contract in zip(tasks, contracts, strict=True)]
    extraction = write_bundle(tmp_path / "extraction", {
        "report.json": dict(review_status="development_exposed", arms_or_outcomes_used=False),
        "tasks.json": tasks, "contracts.json": [task_context_contract_record(contract) for contract in contracts],
        "graphs.json": [prompt_tsg_record(graph) for graph in original_graphs],
    })
    request_bundle = tmp_path / "request"
    prepared = prepare_candidate_request(task_path, extraction, request_bundle)
    assert prepared["provider_calls"] == 0
    return tasks, contracts, task_path, extraction, request_bundle


def test_generated_catalog_preserves_fixed_template_and_enters_real_frozen_extractor(tmp_path):
    tasks, _, _, _, request_bundle = _write_candidate_request(tmp_path, include_template=True)
    request = read_json(request_bundle / "request.json")
    response, design = _proposal(request), _design()
    draft = compile_candidate_proposal(request, response, design)
    paths = [tmp_path / name for name in ("response.json", "design.json", "review.json")]
    for path, value in zip(paths, (response, design, _review(request, response, draft)), strict=True):
        path.write_text(json.dumps(value), encoding="utf-8")
    output = tmp_path / "candidate-catalog"
    report = build_candidate_catalog(request_bundle, paths[1], output, response_path=paths[0], review_path=paths[2])
    assert report["status"] == "REVIEWED" and report["accepted_factors"] == 2
    catalog = read_json(output / "catalog.json")
    prepared_task = prepare_task_input(tasks[0])
    extraction_request = contract_decision_request(prepared_task, catalog)
    assert extraction_request["request_kind"] == "source_only_fact_inventory"
    template = generation_template_facts(prepared_task)
    assert extraction_request["fixed_template"] == template
    for concept in template["concepts"]:
        identifier = concept["concept_id"]
        assert catalog["semantics"][identifier] == concept["node_type"]
        assert catalog["semantic_guidance"][identifier] == concept["definition"]
        assert catalog["normalization_map"][concept["node_type"] + "::" + identifier] == identifier
        assert identifier not in extraction_request["known_concepts"]
    assert len(extraction_request["fixed_template"]["nodes"]) == 5
    assert all(factor["feature_id"] not in {row["concept_id"] for row in template["concepts"]}
               for factor in read_json(output / "proposal.json")["factors"])
