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
    candidate_model_request,
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


def _compact_response(request, response):
    """Translate authored decisions only; expectations retain their original full scopes."""
    wire = candidate_model_request(request)
    refs = {}
    for source, short in zip(request["sources"], wire["sources"], strict=True):
        assert source["source_prompt"] == short["source_prompt"]
        for node, item in zip(sorted(source["nodes"], key=lambda n: n["node_id"]), short["nodes"], strict=True):
            refs[source["task_id"], node["node_id"]] = item["node_ref"]
            assert node["definition"] == item["definition"]
    decisions = {}
    for factor in response["factors"]:
        for row in factor["occurrences"]:
            for requirement in row["requirement_node_ids"]:
                ref = refs[row["task_id"], requirement]
                decision = dict(status="include", label=factor["label"], definition=factor["definition"],
                                rationale=factor["atomicity_rationale"])
                assert ref not in decisions or decisions[ref] == decision
                decisions[ref] = decision
    decisions.update({refs[row["task_id"], row["requirement_node_id"]]: dict(
        status=row["status"], label="", definition="", rationale=row["rationale"])
        for row in response["dispositions"] if row["status"] != "included"})
    return dict(decisions=decisions)


def _prepared_proposal():
    tasks, contracts = _development_sources()
    request = candidate_request(tasks, contracts)
    response, design = _proposal(request), _design()
    draft = compile_candidate_proposal(request, response, design)
    return request, response, design, draft


def test_atomic_source_nodes_stay_separate_and_equivalent_occurrences_pool_before_review():
    request, response, design, draft = _prepared_proposal()
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
    compact = _compact_response(request, response)
    selected = compile_candidate_proposal(request, compact, design)
    assert selected["factors"] == draft["factors"]
    assert selected["response_sha256"] == content_hash(compact)
    assert len(json.dumps(compact)) < len(json.dumps(response))
    assert all(source["task_id"] not in json.dumps(candidate_model_request(request)) for source in request["sources"])
    # A model cannot revise targets/conditions, invent keys, skip units or bundle nodes.
    for change in ("invented", "scope", "omission"):
        altered = json.loads(json.dumps(compact))
        first = next(iter(altered["decisions"]))
        if change == "invented":
            altered["decisions"]["T999.N999"] = altered["decisions"].pop(first)
        elif change == "scope":
            altered["decisions"][first]["scope"] = {}
        else:
            altered["decisions"].pop(first)
        with pytest.raises(ValueError, match="requirement decision.*fields"):
            compile_candidate_proposal(request, altered, design)


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
    # One unit can retain several source-bound operations; the model does not choose a subset.
    request, occurrences, disposition = _one_requirement_request(compound=False)
    response = dict(factors=[dict(label="Binding", definition="Bind the data value in both queries.",
        atomicity_rationale="One shared requirement at both stated operations.", occurrences=occurrences)],
        dispositions=[disposition])
    legacy = compile_candidate_proposal(request, response, _design())
    compact = _compact_response(request, response)
    assert len(compact["decisions"]) == 1
    assert compile_candidate_proposal(request, compact, _design())["factors"] == legacy["factors"]


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


def test_generated_catalog_preserves_fixed_template_and_enters_real_frozen_extractor(tmp_path, monkeypatch):
    tasks, _, _, _, request_bundle = _write_candidate_request(tmp_path, include_template=True)
    request = read_json(request_bundle / "request.json")
    response, design = _compact_response(request, _proposal(request)), _design()
    assert read_json(request_bundle / "model-request.json") == candidate_model_request(request)
    draft = compile_candidate_proposal(request, response, design)
    paths = [tmp_path / name for name in ("response.json", "design.json", "review.json")]
    for path, value in zip(paths, (response, design, _review(request, response, draft)), strict=True):
        path.write_text(json.dumps(value), encoding="utf-8")
    output = tmp_path / "candidate-catalog"
    report = build_candidate_catalog(request_bundle, paths[1], output, response_path=paths[0], review_path=paths[2])
    assert report["status"] == "REVIEWED" and report["accepted_factors"] == 2
    sent = []
    def fake_complete(model_request, evaluator, prompt):
        sent.append(model_request)
        schema = evaluator["response_format"]["json_schema"]["schema"]
        assert schema["required"] == ["decisions"]
        assert set(schema["properties"]["decisions"]["required"]) == set(response["decisions"])
        return json.dumps(response).encode()
    monkeypatch.setattr("prompt_mechanism_study.functional_judge.bailian_complete", fake_complete)
    monkeypatch.setattr("prompt_mechanism_study.candidate_construction._proposal_evaluator", lambda path: {})
    proposed = build_candidate_catalog(request_bundle, paths[1], tmp_path / "mock-provider-proposal", evaluator_path=paths[1])
    assert sent == [candidate_model_request(request)]
    assert proposed["status"] == "PENDING_SEMANTIC_REVIEW" and proposed["accepted_factors"] == 0
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


def _whole_policy_source(kind, text, *, present=True, guard=False, choice=False,
                         catalog=None, feature=None, prompt=None, object_uses=0,
                         object_subjects=("buffer",), owned_order=False):
    """Authored structures isolate projection/editing, not automatic extraction quality."""
    from dataclasses import replace
    invariant = "The entire task must preserve the status format."
    if owned_order:
        invariant = "Processing must finalize the status format before returning status."
    base = "Process the request and write the diagnostic log. Return status. " + invariant
    if owned_order:
        base += " Processing precedes returning."
    if kind == "objects":
        base += " The input buffer and saved path are available."
    task = dict(task_id="synthetic-complete-policy", language="python",
                prompt=prompt if prompt is not None else base + (" " + text if present else ""))
    rows = [("op", "task_operation", "processing", "Process the request and write the diagnostic log"),
            ("return", "task_operation", "returning", "Return status"),
            ("invariant", "task_requirement", "status_format", invariant)]
    if kind == "objects":
        rows.extend((("buffer", "data_object", "buffer", "input buffer"),
                     ("path", "data_object", "path", "saved path")))
    if present:
        rows.append(("r", "safety_requirement", "policy", text))
        if guard:
            rows.append(("g", "condition", "failure", "If processing fails"))
        if choice:
            rows.extend((key, "safety_requirement", key, quote) for key, quote in
                        (("redact", "redaction"), ("omit", "omission")))
            if choice == "not":
                rows.append(("both", "safety_requirement", "both", "redaction and omission"))
    selected = "op" if kind in {"targets", "each_function"} else "task.root"
    structures = ({"r": dict(kind="or" if choice else "atom", members=["redact", "omit"] if choice else [])}
                  if present else {})
    structures["invariant"] = dict(kind="atom", members=[])
    if choice and present:
        structures.update({key: dict(kind="atom", members=[]) for key in ("redact", "omit")})
        if choice == "not":
            structures.update(r=dict(kind="not", members=["both"]), both=dict(kind="and", members=["redact", "omit"]))
    targets = ["redact", "omit"] if choice else ["r"]
    links = ([(key, "constrains", "op") for key in targets] if present and kind == "targets" else [])
    if kind == "objects":
        links += [(key, "constrains", obj) for key in targets for obj in object_subjects] if present else []
        links += [(obj, "used_by", op) for obj in object_subjects for op in ("op", "return")[:object_uses]]
    if present and guard:
        links.append(("g", "conditions", "r"))
    concepts = [dict(concept_id=concept, node_type=node_type, definition=quote)
                for _, node_type, concept, quote in rows]
    identities = {concept: concept for _, _, concept, _ in rows}
    if catalog is not None:
        identities = {concept: (feature if key == "r" else catalog["normalization_map"][node_type + "::" + concept])
                      for key, node_type, concept, _ in rows}
    supplied = dict(concepts=concepts if catalog is None else [],
        nodes=[dict(local_id=key, concept_id=identities[concept], evidence_text=quote, occurrence=1)
               for key, _, concept, quote in rows],
        edges=[dict(source_node_local_id=a, edge_type=relation, target_node_local_id=b,
                    evidence_text=task["prompt"], occurrence=1) for a, relation, b in links],
        concept_states=[], feature_states=[], unresolved_notes=[])
    supplied_catalog = catalog or open_concept_catalog()
    contract = open_contract_from_response(supplied, task=task, catalog=supplied_catalog,
        annotator_id="authored-projection-reference", review_status="development_exposed")
    retained = {"invariant": dict(kind="task", boundaries=[], target_class=None)}
    if present and kind not in {"targets", "objects"}:
        retained["r"] = dict(kind="task" if kind == "task" else "each",
                             boundaries=["op"] if kind == "each_function" else [],
                             target_class=None if kind == "task" else "diagnostic log entries")
    inventory = dict(source_units={"u": dict(evidence_text=task["prompt"], occurrence=1)},
        coverage={"u": dict(status="represented", facts=[key for key, _, _, _ in rows], reason="Authored semantic contrast.")},
        layers={key: "runtime" for key, _, _, _ in rows},
        operation_roles=[dict(operation=b, subject=a, role="value_input",
                              evidence_text=task["prompt"], occurrence=1)
                         for a, relation, b in links if relation == "used_by"],
        requirement_structures=structures, requirement_scopes=retained)
    contract = replace(contract, source_inventory=inventory)
    if owned_order:
        def order(evidence):
            return dict(source="op", edge_type="precedes", target="return", evidence_text=evidence, occurrence=1)
        inventory["requirement_relations"] = {"invariant": [order(invariant)]}
        if present:
            inventory["requirement_relations"]["r"] = [order(text)]
        # This separately sourced order is deliberately also shared by two
        # distinct policies; deleting one owner must not delete either support.
        contract = replace(contract, relations=contract.relations + (order("Processing precedes returning."),))
    graph = compile_task_context_contract(contract, prompt=task["prompt"], catalog=supplied_catalog)
    return task, contract, graph, selected


def test_complete_policy_projection_and_both_edits_preserve_scope_and_internal_conditions(record_property):
    from dataclasses import replace
    from prompt_mechanism_study.candidate_construction import _candidate_catalog, choose_candidate_scope
    from prompt_mechanism_study.prompt_contract_extract import fixed_scope_request, apply_fixed_scope_response
    from prompt_mechanism_study.prompt_tsg import requirement_owned_nodes, PromptTSGError, catalog_sha256
    from prompt_mechanism_study.prompt_contract_qualification import open_graph_assertions, evaluate_open_semantic_case
    from prompt_mechanism_study.mechanisms import bind_task_hypothesis, render_task_hypothesis, MechanismRegistryError
    cases = [
        ("conditional", "targets", "If processing fails, do not include access tokens in the diagnostic log.", True, False),
        ("whole", "task", "The entire task must allocate at most 1 MB in total.", False, False),
        ("universal", "each", "Every diagnostic log entry must redact access tokens.", False, False),
        ("bounded_universal", "each_function", "Every diagnostic log entry in request processing must redact access tokens.", False, False),
        ("choice", "targets", "Use redaction or omission for access tokens in the diagnostic log.", False, True),
        ("compound_prohibition", "targets", "Do not combine redaction and omission for access tokens in the diagnostic log.", False, "not"),
        ("before", "targets", "Redact access tokens before writing the diagnostic log.", False, False),
        ("after", "targets", "Redact access tokens after writing the diagnostic log.", False, False),
        ("owned_order", "targets", "Sanitize access tokens during request processing before returning status.", False, False),
        ("object_unused", "objects", "The input buffer must contain at most 256 KB.", False, False),
        ("object_used", "objects", "The input buffer must contain at most 256 KB.", False, False),
        ("object_shared", "objects", "The input buffer must contain at most 256 KB.", False, False),
        ("object_guard", "objects", "If processing fails, the input buffer must contain no credentials.", True, False),
        ("object_set", "objects", "Do not disclose the values of the input buffer or saved path.", False, False),
        ("object_choice", "objects", "Use redaction or omission for credentials in the input buffer.", False, True),
    ]
    results, factors = [], {}
    for name, kind, text, guard, choice in cases:
        options = dict(object_uses={"object_used": 1, "object_shared": 2}.get(name, 0),
                       object_subjects=("buffer", "path") if name == "object_set" else ("buffer",),
                       owned_order=name == "owned_order")
        task, contract, graph, selected = _whole_policy_source(kind, text, guard=guard, choice=choice, **options)
        before_projection = prompt_tsg_record(graph)
        request = candidate_request([task], [contract])
        by_meaning = {n["concept_id"]: n for n in request["sources"][0]["nodes"]}
        scope = dict(operation_node_id=by_meaning["processing" if selected == "op" else "task.root"]["node_id"],
                     subject_node_ids=sorted(by_meaning[key]["node_id"] for key in options["object_subjects"]) if kind == "objects" else [],
                     condition_node_ids=[by_meaning["failure"]["node_id"]] if guard else [])
        response = dict(factors=[dict(label=name, definition=text,
            atomicity_rationale="One complete policy; conditions, boundary and alternatives are internal to this policy.",
            occurrences=[dict(task_id=task["task_id"], requirement_node_ids=[by_meaning["policy"]["node_id"]], scope=scope)])],
            dispositions=[dict(task_id=task["task_id"], requirement_node_id=node["node_id"],
                status="included" if node["concept_id"] == "policy" else "not_actionable",
                rationale="Whole policy only; choice members are not independently asserted.")
                for node in request["sources"][0]["nodes"] if node["node_type"] in {"safety_requirement", "task_requirement"}])
        draft = compile_candidate_proposal(request, response, _design())
        compact = _compact_response(request, response)
        assert compile_candidate_proposal(request, compact, _design())["factors"] == draft["factors"]
        if choice:
            child = next(n for n in candidate_model_request(request)["sources"][0]["nodes"]
                         if n["node_type"] == "safety_requirement" and n["complete_bindings"] == [])
            invalid = json.loads(json.dumps(compact))
            invalid["decisions"][child["node_ref"]] = dict(status="include", label="Member",
                definition=child["definition"], rationale="A member is not an independently asserted requirement.")
            with pytest.raises(ValueError, match="no complete source binding"):
                compile_candidate_proposal(request, invalid, _design())
        response = compact
        reviewed = compile_candidate_proposal(request, response, _design(), _review(request, response, draft))
        assert prompt_tsg_record(graph) == before_projection
        factor = reviewed["factors"][0]
        feature, selector = factor["feature_id"], factor["scope_selector"]
        factors[name] = feature
        assert selector["policy_condition_semantic_ids"] or not guard
        assert selector["condition_semantic_ids"] == []
        assert len(reviewed["policies"]) == 2
        catalog = _candidate_catalog([contract], reviewed, _design(), reviewed["review"])

        def assessed(present, prompt=None):
            fresh_task, fresh, fresh_graph, _ = _whole_policy_source(kind, text, present=present,
                guard=guard, choice=choice, catalog=catalog, feature=feature, prompt=prompt, **options)
            req = fixed_scope_request(fresh, prompt=fresh_task["prompt"], catalog=catalog)
            assert len(req["scopes"]) == 1 and not req["withheld_scopes"]
            key, row = next(iter(req["scopes"].items()))
            assert row["admissible_positive_requirements"] == (["r"] if present else [])
            answer = dict(states={key: dict(applicability="applicable",
                applicability_rationale="Authored reference: the unchanged task processes requests and writes logs; the whole-task resource comparison preserves both operations.",
                expression="explicitly_required" if present else "not_expressed", requirements=["r"] if present else [])},
                unresolved_notes=[])
            applied = apply_fixed_scope_response(json.dumps(answer).encode(), request=req, contract=fresh, prompt=fresh_task["prompt"], catalog=catalog)
            final = compile_task_context_contract(applied, prompt=fresh_task["prompt"], catalog=catalog)
            state = final.scoped_feature_assessments[0]
            assert state.state == ("present" if present else "absent")
            assert not state.scope.condition_node_ids
            return fresh_task, applied, final, state.scope

        absent_task, absent, absent_graph, absent_scope = assessed(False)
        present_task, present, present_graph, present_scope = assessed(True)
        assert sum(a["kind"] == "requirement_scope" for a in open_graph_assertions(prompt_tsg_record(present_graph)).values()) == len(present_graph.requirement_scopes)
        # Policy-only guard/choice nodes disappear without altering task selection.
        assert choose_candidate_scope(absent_graph, selector) == absent_scope
        assert choose_candidate_scope(present_graph, selector) == present_scope
        if kind == "objects":
            assert selector["scope_kind"] == "objects" and factor["query"]["required_relations"] == []
            assert next(n for n in present_graph.nodes if n.node_id == present_scope.operation_node_id).semantic_id == "task.root"
            assert len(present_scope.subject_node_ids) == len(options["object_subjects"])
            # Object incidence never multiplies/narrows the policy, including shared objects.
            assert not any(e.source_id in present_graph.scoped_feature_assessments[0].requirement_node_ids
                           and e.edge_type == "constrains" and e.target_id == present_scope.operation_node_id
                           for e in present_graph.edges)
        if name == "object_unused":
            # Selection uses object identity only: a second matching object is
            # ambiguous even though the original has the positive requirement.
            subject = next(n for n in present_graph.nodes if n.node_id in present_scope.subject_node_ids)
            other = next(n for n in present_graph.nodes if n.node_type == "data_object" and n != subject)
            ambiguous = replace(present_graph, nodes=tuple(replace(n, semantic_id=subject.semantic_id)
                                if n == other else n for n in present_graph.nodes))
            assert choose_candidate_scope(ambiguous, selector) is None
            impostor = replace(present, relations=present.relations + (dict(source="r", edge_type="constrains",
                target="op", evidence_text=present_task["prompt"], occurrence=1),))
            with pytest.raises(PromptTSGError, match="complete policy binding"):
                compile_task_context_contract(impostor, prompt=present_task["prompt"], catalog=catalog)
            for state in ("absent", "not_applicable"):
                negative = replace(impostor, feature_states=tuple(dict(r, state=state, requirements=[])
                                                                 for r in impostor.feature_states))
                with pytest.raises(PromptTSGError, match="negative policy state"):
                    compile_task_context_contract(negative, prompt=present_task["prompt"], catalog=catalog)
            legacy = json.loads(json.dumps(catalog))
            legacy["feature_scope_selectors"][feature].update(scope_kind="targets",
                operation_semantic_id=catalog["normalization_map"]["task_operation::processing"])
            legacy_contract = replace(present, catalog=legacy, input_catalog_sha256=catalog_sha256(legacy))
            with pytest.raises(PromptTSGError, match="explicit object policy selector"):
                compile_task_context_contract(legacy_contract, prompt=present_task["prompt"], catalog=legacy)
            # Operation-local impact declarations cannot certify object-wide
            # irrelevance. Explicit generation-only influence can still be ignored.
            inventory = json.loads(json.dumps(present.source_inventory))
            inventory["coverage"]["u"]["status"] = "unresolved"
            inventory["unit_impacts"] = {"u": dict(effect="local", operations=["return"], complete=False,
                reason="Authored unresolved source-impact contrast.")}
            incomplete = replace(present, source_inventory=inventory)
            withheld = fixed_scope_request(incomplete, prompt=present_task["prompt"], catalog=catalog)
            assert not withheld["scopes"] and withheld["withheld_scopes"]
            inventory["unit_impacts"]["u"].update(effect="no_runtime_effect", operations=[])
            assert fixed_scope_request(incomplete, prompt=present_task["prompt"], catalog=catalog)["scopes"]
            # Root anchoring does not bring an unrelated operation into this
            # candidate's review; exact object/global requirements remain needed.
            raw_graph, raw_contract = prompt_tsg_record(present_graph), task_context_contract_record(present)
            ids = {n.semantic_id: n for n in present_graph.nodes}
            selected_nodes = {"root": ids["task.root"], "object": subject}
            state_key = "root/" + feature + "/subjects=object/conditions="
            expected = dict(task_id=present.task_id, source_prompt_sha256=content_hash(present_task["prompt"]),
                nodes=[dict(key=key, node_types=[n.node_type], semantic_ids=[n.semantic_id],
                            evidence_text=present_task["prompt"][n.evidence_start:n.evidence_end], occurrence=1)
                       for key, n in selected_nodes.items()],
                feature_checks=[dict(target="root", subjects=["object"], conditions=[], feature_id=feature, state="present")],
                critical_checks=[["feature_state", state_key]], non_target_checks=[],
                scope_dependencies={state_key: [["feature_state", state_key]]})
            assertions = open_graph_assertions(raw_graph, contract=raw_contract)
            evidence = [dict(evidence_text=present_task["prompt"], occurrence=1)]
            audit = dict(graph_sha256=content_hash(raw_graph), contract_sha256=content_hash(raw_contract),
                source_prompt_sha256=content_hash(present_task["prompt"]), assertions={key: dict(status="SUPPORTED",
                    rationale="Authored projection fixture.", source_evidence=evidence) for key in assertions})
            for local, blocked in (("return", False), ("r", True), ("invariant", True)):
                fact = next(f for f in present.facts if f["local_id"] == local)
                key = next(k for k, a in assertions.items() if a["kind"] == "node"
                           and a["statement"]["semantic_id"] == fact["semantic_id"])
                audit["assertions"][key].update(status="UNSUPPORTED", impact=dict(effect="irrelevant", scopes=[],
                    rationale="Attempted source-local waiver; structural dependencies override it.", source_evidence=evidence))
                scored = evaluate_open_semantic_case(raw_graph, prompt=present_task["prompt"], expected=expected,
                    assertion_review=audit, extraction_failed=False, contract=raw_contract)
                assert scored["scope_quality"][0]["usable"] is not blocked
                audit["assertions"][key]["status"] = "SUPPORTED"
        if kind in {"task", "each"}:
            assert next(n for n in present_graph.nodes if n.node_id == present_scope.operation_node_id).semantic_id == "task.root"
            assert not any(e.source_id in present_graph.scoped_feature_assessments[0].requirement_node_ids
                           and e.edge_type == "constrains" for e in present_graph.edges)
        if guard:
            broken = replace(present, relations=tuple(r for r in present.relations if r["edge_type"] != "conditions"))
            with pytest.raises(PromptTSGError, match="complete policy binding"):
                compile_task_context_contract(broken, prompt=present_task["prompt"], catalog=catalog)
            for lost_state in ("absent", "not_applicable"):
                contradicted = replace(broken, feature_states=tuple(dict(r, state=lost_state, requirements=[]) for r in broken.feature_states))
                with pytest.raises(PromptTSGError, match="negative policy state"):
                    compile_task_context_contract(contradicted, prompt=present_task["prompt"], catalog=catalog)
        for source_present, operation in ((False, "add"), (True, "remove")):
            source_task, source_graph, source_scope = ((present_task, present_graph, present_scope) if source_present else
                                                       (absent_task, absent_graph, absent_scope))
            binding = bind_task_hypothesis(policy_id="authored-policy", graph=source_graph, query=factor["query"],
                factor_feature_ids=(feature,), factor_operations=(operation,), factor_scopes=(source_scope,))
            rendered = render_task_hypothesis(binding, source_graph, prompt=source_task["prompt"], catalog=catalog,
                enabled=(True,), additions={feature: text})
            assert (text in rendered["prompt"]) is (operation == "add")
            if kind == "objects" and operation == "add":
                assert "For the named source objects:" in rendered["prompt"]
                assert "For the runtime task as a whole:" not in rendered["prompt"]
            assert "Process the request and write the diagnostic log. Return status." in rendered["prompt"]
            _, _, target_graph, _ = assessed(not source_present, rendered["prompt"])
            targets = source_graph.scoped_feature_assessments[0].requirement_node_ids
            preserved = {n.node_id for n in source_graph.nodes if n.node_type != "task"} - requirement_owned_nodes(source_graph, targets)
            mapped = {n.node_id: next(m.node_id for m in target_graph.nodes if m.semantic_id == n.semantic_id
                      and rendered["prompt"][m.evidence_start:m.evidence_end] == source_task["prompt"][n.evidence_start:n.evidence_end])
                      for n in source_graph.nodes if n.node_id in preserved}
            variant = dict(binding_id=binding.binding_id, source_prompt_sha256=content_hash(source_task["prompt"]),
                enabled=[True], prompt=rendered["prompt"], graph=prompt_tsg_record(target_graph), source_to_variant_nodes=mapped,
                source_review=dict(outcomes_used=False, reviewer_id="authored-reference", rationale="Whole fixed policy changed; both original operations preserved."))
            checked = render_task_hypothesis(binding, source_graph, prompt=source_task["prompt"], catalog=catalog,
                enabled=(True,), additions={}, reviewed_variant=variant)
            assert checked["prompt"] == rendered["prompt"]
            if name == "owned_order" and operation == "remove":
                assert len(source_graph.requirement_relations) == 2
                assert len(target_graph.requirement_relations) == 1
                assert all(edge[1] != "precedes" for edge in factor["query"]["required_relations"])
                # Each mutation still compiles as a graph with the assigned
                # target policy absent; preservation, not state labels, rejects it.
                for corrupted, error in (
                    (replace(target_graph, edges=tuple(e for e in target_graph.edges if e.edge_type != "precedes")),
                     "non-target relation structure"),
                    (replace(target_graph, requirement_relations=()), "another requirement's owned relation"),
                ):
                    with pytest.raises(MechanismRegistryError, match=error):
                        render_task_hypothesis(binding, source_graph, prompt=source_task["prompt"], catalog=catalog,
                            enabled=(True,), additions={}, reviewed_variant=dict(variant, graph=prompt_tsg_record(corrupted)))
            if name == "whole":
                invariant_id = next(n.node_id for n in target_graph.nodes if n.node_type == "task_requirement")
                corrupted = replace(target_graph, requirement_scopes=tuple(
                    (key, "each", boundaries, "diagnostic log entries") if key == invariant_id else (key, k, boundaries, cls)
                    for key, k, boundaries, cls in target_graph.requirement_scopes))
                with pytest.raises(MechanismRegistryError, match="non-target composition or scope"):
                    render_task_hypothesis(binding, source_graph, prompt=source_task["prompt"], catalog=catalog,
                        enabled=(True,), additions={}, reviewed_variant=dict(variant, graph=prompt_tsg_record(corrupted)))
        results.append(dict(case=name, projection=True, add=True, remove=True))
    assert factors["before"] != factors["after"]
    assert factors["object_unused"] == factors["object_used"] == factors["object_shared"]
    assert len(set(factors.values())) == len(cases) - 2
    record_property("authored_policy_checks", json.dumps(results))
