"""Scientific boundaries of source-only open concepts and operation-bound hypotheses."""

import json
from copy import deepcopy
from dataclasses import replace
import pytest
from annotation_fixture import (
    authored_source_inventory,
    indexed_annotation,
    scope_answer,
)
from prompt_mechanism_study.prompt_contract import (
    compile_task_context_contract,
    open_concept_catalog,
    open_contract_from_response,
    task_context_contract_from_record,
    task_context_contract_record,
)
from prompt_mechanism_study.prompt_contract_extract import (
    PromptContractExtractionError,
    apply_fixed_scope_response,
    contract_decision_request,
    extract_contract_task_file,
    fixed_scope_request,
    fixed_scope_response_format,
    contract_from_response,
    open_contract_response_format,
    fixed_binding_request,
    fixed_binding_response_format,
    apply_fixed_binding_response,
)
from prompt_mechanism_study.artifact_io import (
    file_sha256,
    read_json,
)
from prompt_mechanism_study.functional_judge import bailian_complete
from prompt_mechanism_study.prompt_tsg import (
    PromptTSGError,
    prompt_tsg_record,
    catalog_sha256,
    FeatureScope,
    build_prompt_tsg,
)
from prompt_mechanism_study.prompt_contract_qualification import (
    evaluate_open_graph_expectations,
    evaluate_open_semantic_case,
    open_graph_assertions,
    qualify_prompt_contract_extractor,
    representation_implementation_identity,
    PromptContractQualificationError,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.task_input import generation_template_facts

PROMPT = "Read external x in query A. Read external y in query B. Parameterize query B."


def _add_fixed_generation_concepts(catalog, task):
    """Include the declared fixed template in a synthetic frozen vocabulary."""
    for concept in generation_template_facts(task)["concepts"]:
        catalog["semantics"][concept["concept_id"]] = concept["node_type"]
        catalog["semantic_guidance"][concept["concept_id"]] = concept["definition"]


def _synthetic_qualification_rule():
    # Permissive values test mechanics only; they are not scientific thresholds.
    return dict(minimum_task_units=1, minimum_profile_task_units=1,
        minimum_complete_task_fraction=1, maximum_unsupported_task_fraction=0,
        maximum_wrong_decisive_state_task_fraction=0, confidence_level=0.95,
        maximum_incomplete_error_upper_bound=0.99, maximum_unsupported_error_upper_bound=0.99,
        maximum_wrong_decisive_error_upper_bound=0.99, minimum_profile_reliability_lower_bound=0.01)


def _semantic_qualification_fixture(tmp_path, failure=None):
    """Explicit synthetic reference and reviews; no natural accuracy or real reviewer identities."""
    from prompt_mechanism_study.task_input import prepare_task_input
    _, source = _contract()
    catalog = deepcopy(source.catalog)
    catalog.update(concept_policy="FROZEN", queries=[dict(query_id="sql", required_semantics=["sql_query"],
        actionable_feature_id="parameter_binding", forbidden_semantics=[], required_relations=[],
        realization_id="bind", cwe_id="source_semantics", task_family="source_semantics")])
    def write(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path
    task = dict(task_id="synthetic-source-review", prompt=PROMPT, language="python")
    _add_fixed_generation_concepts(catalog, task)
    paths = dict(tasks=write("tasks.json", [task]), catalog=write("catalog.json", catalog),
        evaluator=write("evaluator.json", dict(schema_version="1.0", candidate_id="offline",
            provider="ali_bailian_pay_as_you_go", model_id="offline", base_url="https://unused.invalid",
            api_key_env="ALI_BAILIAN_API_KEY", temperature=0, top_p=1, seed=1, enable_thinking=False,
            max_attempts=1, timeout_seconds=1, max_response_bytes=65536)))
    paths["selection"] = write("selection.json", dict(schema_version="1.0", source_tasks_sha256=file_sha256(paths["tasks"]),
        selection_rule="Synthetic scientific-boundary fixture.", task_ids=[task["task_id"]], arms_or_outcomes_used=False))
    paths["prompt"] = tmp_path / "prompt.txt"
    paths["prompt"].write_text("Offline fixture.", encoding="utf-8")
    prepared = prepare_task_input(task)
    case = dict(task_id=task["task_id"], source_prompt_sha256=content_hash(prepared["prompt"]),
        nodes=[dict(key=f["local_id"], node_types=[catalog["semantics"][f["semantic_id"]]],
                    semantic_ids=[f["semantic_id"]], evidence_text=f["evidence_text"], occurrence=f["occurrence"])
               for f in source.facts],
        edges=[[r["source"], r["edge_type"], r["target"]] for r in source.relations],
        distinct=[["a", "b"]], non_target_checks=[["node", "x"]],
        feature_checks=[dict(target="b", subjects=[], conditions=[], feature_id="parameter_binding", state="present")],
        critical_checks=[["feature_state", "b/parameter_binding/subjects=/conditions="], ["distinct", "a/b"]])
    reference = dict(protocol_id="open_tsg_source_semantics", reference_kind="SYNTHETIC_TEST",
        reference_author_id="synthetic-source-fixture-author", independence_attested=True,
        review_completed_before_extraction=True, extractor_outputs_used=False, arms_or_outcomes_used=False,
        bindings=dict(task_file_sha256=file_sha256(paths["tasks"]), task_selection_sha256=file_sha256(paths["selection"]),
            task_selection_record_sha256=content_hash(read_json(paths["selection"])), catalog_sha256=catalog_sha256(catalog),
            evaluator_sha256=file_sha256(paths["evaluator"]), annotator_prompt_sha256=file_sha256(paths["prompt"]),
            representation_implementation_sha256=representation_implementation_identity(), candidate_id="single-evidence:offline"),
        qualification_rule=_synthetic_qualification_rule(), cases=[case],
        required_profiles=[dict(language="python", operation_semantic_id="sql_query",
                                feature_id="parameter_binding", expected_state="present")])
    paths["reference"] = write("reference.json", reference)
    calls = []
    def provider(request, _config, _prompt):
        calls.append(request)
        assert "synthetic-source-fixture-author" not in json.dumps(request)
        assert "minimum_complete_task_fraction" not in json.dumps(request)
        if request["request_kind"] in {"source_only_atomic_records", "source_only_record_review"}:
            if failure == "graph" and request["request_kind"] == "source_only_atomic_records":
                return b'{"nodes": "invalid"}'
            if failure == "binding" and request["request_kind"] == "source_only_record_review":
                raise RuntimeError("Deliberate offline binding failure")
            return json.dumps(indexed_annotation(request, dict(concepts=[], concept_states=[], feature_states=[], unresolved_notes=[],
                nodes=[dict(local_id=f["local_id"], concept_id=f["semantic_id"], evidence_text=f["evidence_text"],
                            occurrence=f["occurrence"]) for f in source.facts],
                edges=[dict(source_node_local_id=e["source"], target_node_local_id=e["target"],
                            edge_type=e["edge_type"], evidence_text=e["evidence_text"], occurrence=e["occurrence"])
                       for e in source.relations]))).encode()
        if failure == "scope":
            raise RuntimeError("Deliberate offline measurement-stage failure")
        return json.dumps(dict(states={key: scope_answer(row, expression="explicitly_required" if row["target"] == "fact.3" else "not_expressed",
            requirements=["fact.4"] if row["target"] == "fact.3" else [])
            for key, row in request["scopes"].items()}, unresolved_notes=[])).encode()
    return paths, case, provider, calls, write


def _extract_semantic_fixture(paths, provider, output):
    return extract_contract_task_file(paths["tasks"], paths["catalog"], paths["evaluator"], paths["prompt"],
        paths["selection"], output, provider=provider, review_status="development_exposed",
        qualification_reference_path=paths["reference"])


def _source_review_fixture(output, paths, case, write):
    from prompt_mechanism_study.artifact_io import bundle_digest
    rows = read_json(output / "graphs.json")
    graph = rows[0] if rows else None
    contracts = read_json(output / "contracts.json")
    contract = contracts[0] if contracts else None
    audit = dict(extraction_bundle_sha256=bundle_digest(output), source_reference_sha256=file_sha256(paths["reference"]),
        reviewer_id="synthetic-review-fixture-author", independence_attested=True, arms_or_outcomes_used=False,
        cases=[dict(task_id=case["task_id"], graph_sha256=content_hash(graph), source_prompt_sha256=case["source_prompt_sha256"],
                    contract_sha256=content_hash(contract),
                    assertions={key: dict(status="SUPPORTED", rationale="Authored synthetic fixture assertion.",
                        source_evidence=[dict(evidence_text=PROMPT, occurrence=1)]) for key in open_graph_assertions(graph, contract=contract)})])
    return write("audit.json", audit), graph


@pytest.mark.parametrize("failure", [None, "graph", "binding", "scope"])
def test_independent_source_qualification_replays_three_steps_and_keeps_failed_tasks(tmp_path, failure):
    paths, case, provider, calls, write = _semantic_qualification_fixture(tmp_path, failure)
    output = tmp_path / "extract"
    if failure:
        with pytest.raises(PromptContractExtractionError, match="closed bundle"):
            _extract_semantic_fixture(paths, provider, output)
    else:
        _extract_semantic_fixture(paths, provider, output)
    audit, _ = _source_review_fixture(output, paths, case, write)
    result = qualify_prompt_contract_extractor(tmp_path, paths["tasks"], output, paths["catalog"],
        tmp_path / "unused-legacy-registry", paths["reference"], paths["evaluator"], paths["prompt"],
        tmp_path / "qualification", assertion_review_path=audit)
    assert result["task_units"] == 1
    assert result["failed_extraction_task_units"] == int(failure is not None)
    assert result["complete_task_units"] == int(failure is None)
    assert result["status"] == ("QUALIFICATION_FAILED" if failure else "SYNTHETIC_REFERENCE_CHECK_PASSED")
    assert result["scientific_claim_allowed"] is False
    profile = result["uncertainty"]["profiles"][0]
    assert profile["task_units"] == 1
    assert profile["reliability_lower_bound"] == pytest.approx(0.0125 if failure is None else 0)
    assert len(calls) == (2 if failure in {"graph", "binding"} else 3)


def test_qualification_error_bounds_have_exact_tails_and_do_not_duplicate_task_support(tmp_path):
    from scipy.stats import beta
    from prompt_mechanism_study.prompt_contract_qualification import binomial_error_upper_bound, open_qualification_statistics
    for n, errors, alpha in ((1, 0, 0.0125), (20, 4, 0.01), (1000, 600, 0.001), (10, 10, 0.01)):
        expected = 1 if errors == n else beta.ppf(1 - alpha, errors + 1, n - errors)
        assert binomial_error_upper_bound(errors, n, alpha) == pytest.approx(expected, abs=2e-12)
    assert binomial_error_upper_bound(0, 0, 0.01) is None
    paths, case, provider, calls, write = _semantic_qualification_fixture(tmp_path)
    output = tmp_path / "extract"
    _extract_semantic_fixture(paths, provider, output)
    audit, graph = _source_review_fixture(output, paths, case, write)
    tasks = read_json(output / "tasks.json")
    scored = evaluate_open_semantic_case(graph, prompt=tasks[0]["prompt"], expected=case,
        assertion_review=read_json(audit)["cases"][0], extraction_failed=False,
        contract=read_json(output / "contracts.json")[0])
    reference = read_json(paths["reference"])
    reference["cases"][0]["feature_checks"] *= 2
    stats = open_qualification_statistics(reference, tasks, [scored])
    assert stats["uncertainty"]["profiles"][0]["task_units"] == 1
    reference["required_profiles"].append({**reference["required_profiles"][0], "expected_state": "absent"})
    stats = open_qualification_statistics(reference, tasks, [scored])
    empty = next(p for p in stats["uncertainty"]["profiles"] if p["expected_state"] == "absent")
    assert empty["reliability_lower_bound"] is None and empty["task_units"] == 0
    assert not stats["acceptance_rule_passed"]
    assert stats["uncertainty"]["family_size"] == 5
    reference["required_profiles"].pop()
    reference["qualification_rule"]["minimum_profile_reliability_lower_bound"] = 0.8
    assert not open_qualification_statistics(reference, tasks, [scored])["acceptance_rule_passed"]


def test_source_reference_is_frozen_before_provider_calls_and_cannot_be_retrofitted(tmp_path):
    paths, case, provider, calls, write = _semantic_qualification_fixture(tmp_path)
    reference = read_json(paths["reference"])
    reference["bindings"]["evaluator_sha256"] = "0" * 64
    write("reference.json", reference)
    with pytest.raises(PromptContractQualificationError, match="identity"):
        _extract_semantic_fixture(paths, provider, tmp_path / "rejected")
    assert calls == []
    reference["bindings"]["evaluator_sha256"] = file_sha256(paths["evaluator"])
    reference["cases"][0]["feature_checks"][0]["state"] = None
    write("reference.json", reference)
    with pytest.raises(PromptContractQualificationError, match="exact scopes"):
        _extract_semantic_fixture(paths, provider, tmp_path / "missing-state")
    assert calls == []
    reference["cases"][0]["feature_checks"][0]["state"] = "present"
    write("reference.json", reference)
    output = tmp_path / "extract"
    _extract_semantic_fixture(paths, provider, output)
    reference["qualification_rule"]["minimum_complete_task_fraction"] = 0.5
    write("reference.json", reference)
    result = qualify_prompt_contract_extractor(tmp_path, paths["tasks"], output, paths["catalog"],
        tmp_path / "unused", paths["reference"], paths["evaluator"], paths["prompt"], tmp_path / "blocked")
    assert result["status"] == "QUALIFICATION_BLOCKED"
    assert "SOURCE_REFERENCE_NOT_CAPTURED_BEFORE_EXTRACTION" in result["blockers"]


def test_source_semantic_audit_checks_extra_assertions_concepts_and_exact_scope_states(tmp_path):
    paths, case, provider, calls, write = _semantic_qualification_fixture(tmp_path)
    output = tmp_path / "extract"
    _extract_semantic_fixture(paths, provider, output)
    audit_path, graph = _source_review_fixture(output, paths, case, write)
    review = read_json(audit_path)["cases"][0]
    prompt = read_json(output / "tasks.json")[0]["prompt"]
    def score(expected=case, audit=review):
        return evaluate_open_semantic_case(graph, prompt=prompt, expected=expected,
                                          assertion_review=audit, extraction_failed=False,
                                          contract=read_json(output / "contracts.json")[0])
    assert score()["complete_task"] is True
    missing = deepcopy(review)
    key = next(iter(missing["assertions"]))
    missing["assertions"].pop(key)
    assert score(audit=missing)["unresolved_review_assertions"] == [key]
    unsupported = deepcopy(review)
    unsupported["assertions"][key]["status"] = "UNSUPPORTED"
    assert score(audit=unsupported)["unsupported_assertions"] == [key]
    assert score(audit=unsupported)["complete_task"] is False
    wrong = deepcopy(case)
    wrong["nodes"][0]["semantic_ids"] = ["some_other_concept"]
    assert score(expected=wrong)["coverage"]["passed"] < score()["coverage"]["passed"]
    wrong["feature_checks"][0]["state"] = "absent"
    assert score(expected=wrong)["wrong_decisive_states"]
    stale = deepcopy(review)
    stale["graph_sha256"] = "0" * 64
    with pytest.raises(PromptContractQualificationError, match="stale"):
        score(audit=stale)
    # Explicit source-local review can isolate an unrelated extra assertion;
    # default/unlocated uncertainty still blocks, and endpoint dependencies win.
    local_case=deepcopy(case)
    state_key=score()['scope_quality'][0]['key']
    local_case['scope_dependencies']={state_key:[['feature_state',state_key],['node','b']]}
    contract=read_json(output/'contracts.json')[0]
    assertions=open_graph_assertions(graph,contract=contract)
    evidence=[dict(evidence_text=prompt,occurrence=1)]
    unrelated=next(k for k,a in assertions.items() if a['kind']=='node'
        and a['statement']['semantic_id']=='external_value')
    audit=deepcopy(review)
    audit['assertions'][unrelated].update(status='UNSUPPORTED',impact=dict(effect='irrelevant',scopes=[],
        rationale='Synthetic error of A input does not affect the declared B requirement.',source_evidence=evidence))
    localized=score(expected=local_case,audit=audit)
    assert not localized['complete_task'] and localized['scope_quality'][0]['usable']
    assert localized['candidate_metrics']['certified_correct']==1
    assert localized['candidate_metrics']['extra_accepted']>0
    assert localized['candidate_metrics']['acceptance_precision'] is None
    audit['assertions'][unrelated]['impact']['effect']='unresolved'
    assert not score(expected=local_case,audit=audit)['scope_quality'][0]['usable']
    audit['assertions'][unrelated]['impact']['effect']='irrelevant'
    # An extra requirement connected to B cannot be waived merely because the
    # fixed reference dependency table does not name that requirement's node.
    requirement=next(k for k,a in assertions.items() if a['kind']=='node'
        and a['statement']['semantic_id']=='parameter_binding')
    audit['assertions'][requirement].update(status='UNSUPPORTED',impact=deepcopy(audit['assertions'][unrelated]['impact']))
    assert not score(expected=local_case,audit=audit)['scope_quality'][0]['usable']
    audit['assertions'][requirement]['status']='SUPPORTED'
    op_id=next(n['node_id'] for n in graph['nodes'] if prompt[n['evidence_start']:n['evidence_end']]=='query B')
    related=next(k for k,a in assertions.items() if a['kind']=='node' and a['statement']['node_id']==op_id)
    audit['assertions'][related].update(status='UNSUPPORTED',impact=deepcopy(audit['assertions'][unrelated]['impact']))
    assert not score(expected=local_case,audit=audit)['scope_quality'][0]['usable']
    # Missing review stays uncertain, with no fabricated precision estimate.
    audit['assertions'].pop(related)
    assert score(expected=local_case,audit=audit)['candidate_metrics']['acceptance_precision'] is None
    from prompt_mechanism_study.prompt_contract_qualification import summarize_review_changes
    changes=summarize_review_changes(['a','b','c','d'],dict(a='incorrect',b='correct',c='incorrect',d='unknown'),
        dict(a='correct',b='incorrect',c='unknown',d='correct'))
    assert changes['net_corrections']==0 and changes['transitions']['incorrect->unknown']==1


def test_typed_role_error_cannot_hide_behind_identical_graph_assertions(tmp_path):
    paths, case, provider, _, write = _semantic_qualification_fixture(tmp_path)
    output = tmp_path / "extract"
    _extract_semantic_fixture(paths, provider, output)
    audit, graph = _source_review_fixture(output, paths, case, write)
    contract = read_json(output / "contracts.json")[0]
    prompt = read_json(output / "tasks.json")[0]["prompt"]
    changed = deepcopy(contract)
    role = next(r for r in changed["source_inventory"]["operation_roles"] if r["role"] == "input_unspecified")
    role["role"] = "resource"
    # Both roles generate used_by, so the graph itself cannot reveal the error.
    changed.pop("contract_id")
    changed_contract = task_context_contract_from_record(changed)
    changed = task_context_contract_record(changed_contract)
    rebuilt = compile_task_context_contract(changed_contract,
                                            prompt=prompt, catalog=read_json(paths["catalog"]))
    changed_graph = prompt_tsg_record(rebuilt)
    assert open_graph_assertions(changed_graph) == open_graph_assertions(graph)
    graph = changed_graph
    original_review = read_json(audit)["cases"][0]
    original_review["graph_sha256"] = content_hash(graph)
    with pytest.raises(PromptContractQualificationError, match="stale"):
        evaluate_open_semantic_case(graph, prompt=prompt, expected=case, contract=changed,
            assertion_review=original_review, extraction_failed=False)
    assertions = open_graph_assertions(graph, contract=changed)
    reviewed = deepcopy(next(iter(original_review["assertions"].values())))
    review = {**original_review, "contract_sha256": content_hash(changed),
              "assertions": {key: deepcopy(reviewed) for key in assertions}}
    role_key = next(key for key, a in assertions.items() if a["kind"] == "operation_role" and a["statement"] == role)
    review["assertions"][role_key].update(status="UNSUPPORTED", rationale="The synthetic source names an external input, not a resource facility.")
    result = evaluate_open_semantic_case(graph, prompt=prompt, expected=case, contract=changed,
                                         assertion_review=review, extraction_failed=False)
    assert result["coverage"]["passed"] == result["coverage"]["total"]
    assert result["unsupported_assertions"] == [role_key]
    assert result["complete_task"] is False


def _contract():
    def node(local, kind, concept, text):
        return dict(local_id=local, node_type=kind, concept_id=concept,
                    definition=concept, evidence_text=text, occurrence=1)
    value = dict(nodes=[node("x", "data_object", "external_value", "external x"),
                       node("a", "task_operation", "sql_query", "query A"),
                       node("b", "task_operation", "sql_query", "query B"),
                       node("p", "safety_requirement", "parameter_binding", "Parameterize query B")],
                 edges=[dict(source="x", target="a", edge_type="used_by",
                             evidence_text="Read external x in query A", occurrence=1),
                        dict(source="p", target="b", edge_type="constrains",
                             evidence_text="Parameterize query B", occurrence=1)],
                 concept_states=[], feature_states=[
                     dict(target="a", concept_id="parameter_binding", state="absent", rationale="Only B is constrained."),
                     dict(target="b", concept_id="parameter_binding", state="present", rationale="The explicit B requirement.")],
                 unresolved_notes=[])
    value['concepts'] = list({n['concept_id']: {k:n[k] for k in ('concept_id','node_type','definition')} for n in value['nodes']}.values())
    value['nodes'] = [{k:v for k,v in n.items() if k not in {'node_type','definition'}} for n in value['nodes']]
    value['edges'] = [{('source_node_local_id' if k=='source' else 'target_node_local_id' if k=='target' else k):v for k,v in e.items()} for e in value['edges']]
    catalog = open_concept_catalog()
    contract = open_contract_from_response(value, task={"task_id": "synthetic-multi-operation", "prompt": PROMPT},
                                          catalog=catalog, annotator_id="test", review_status="development_exposed")
    return catalog, contract


def _scoped_graph(*, bound_inputs=("x",), source_prefix="", source_query=False,
                  shell_required=True, task_id="synthetic-scoped-boundaries"):
    """Exposed synthetic boundary fixture; never a natural support or accuracy sample."""
    source = ("Run query A using input x and input y. Run query B using input z. "
              "If remote, bind x in A. Reject shell syntax for z. Preserve response order.")
    facts = [
        ("a", "task_operation", "sql_query", "query A"),
        ("b", "task_operation", "sql_query", "query B"),
        ("x", "data_object", "external_value", "input x"),
        ("y", "data_object", "external_value", "input y"),
        ("z", "data_object", "external_value", "input z"),
        ("c", "condition", "remote_condition", "If remote"),
        ("p", "safety_requirement", "parameter_binding", "bind x in A."),
        ("s", "safety_requirement", "shell_syntax_rejection", "Reject shell syntax for z."),
        ("o", "task_requirement", "response_order", "Preserve response order."),
    ]
    clause = "bind both x and y in A." if len(bound_inputs) == 2 else f"bind {bound_inputs[0]} in A."
    source = source.replace("bind x in A.", clause)
    source = source_prefix + source
    facts[6] = ("p", "safety_requirement", "parameter_binding", clause)
    relations = [("x", "used_by", "a"), ("y", "used_by", "a"), ("z", "used_by", "b"),
                 ("p", "constrains", "a"), ("c", "conditions", "p"),
                 ("s", "constrains", "b"), ("s", "constrains", "z"), ("o", "constrains", "b")]
    relations += [("p", "constrains", key) for key in bound_inputs]
    catalog = open_concept_catalog()
    catalog["semantics"].update({concept: kind for _, kind, concept, _ in facts})
    if source_query:
        catalog.update(concept_policy="FROZEN", queries=[dict(query_id="sql",
            required_semantics=["sql_query"], actionable_feature_id="parameter_binding",
            forbidden_semantics=[], required_relations=[], realization_id="bind",
            cwe_id="source_semantics", task_family="source_semantics")])
    if not shell_required:
        source = source.replace("Reject shell syntax for z. ", "")
        facts = [fact for fact in facts if fact[0] != "s"]
        relations = [edge for edge in relations if edge[0] != "s"]
    assessments = [dict(target="a", subjects=["x"], conditions=["c"], concept_id="parameter_binding",
                        state="present" if "x" in bound_inputs else "absent", requirements=["p"] if "x" in bound_inputs else []),
                   dict(target="a", subjects=["y"], conditions=["c"], concept_id="parameter_binding",
                        state="present" if "y" in bound_inputs else "absent", requirements=["p"] if "y" in bound_inputs else []),
                   dict(target="b", subjects=["z"], conditions=[], concept_id="shell_syntax_rejection",
                        state="present" if shell_required else "absent", requirements=["s"] if shell_required else [])]
    graph = build_prompt_tsg(task_id=task_id, prompt=source, extractor_id="source-fixture",
        catalog=catalog, schema_version="3.0",
        facts=[dict(local_id=key, node_type=kind, semantic_id=concept, evidence_text=quote, occurrence=1, attributes={})
               for key, kind, concept, quote in facts],
        relations=[dict(source=a, edge_type=rel, target=b) for a, rel, b in relations],
        scoped_feature_assessments=assessments)
    ids = {key: next(node.node_id for node in graph.nodes
                    if node.semantic_id == concept and source[node.evidence_start:node.evidence_end] == quote)
           for key, _, concept, quote in facts}
    return source, catalog, graph, ids


def test_atomic_source_gates_use_exact_scopes_without_requiring_control_text():
    from prompt_mechanism_study.representation import (
        AnalysisScope,
        AtomicPolicyKey,
        Operation,
        PolicyFactor,
        freeze_source_eligibility,
    )

    prompt, catalog, graph, ids = _scoped_graph(source_query=True)
    scope = AnalysisScope("sql-inputs", "sql", ("python",), ("database",), ("query",))
    common = dict(
        task_id=graph.task_id,
        task_unit_id="unit",
        prompt=prompt,
        graph=graph,
        catalog=catalog,
        eligibility_policy_sha256=content_hash("prospective scoped-source rule"),
    )
    x = FeatureScope(ids["a"], (ids["x"],), (ids["c"],))
    y = FeatureScope(ids["a"], (ids["y"],), (ids["c"],))
    add = AtomicPolicyKey(scope, PolicyFactor("parameter_binding", Operation.ADD), "secure_yield")
    remove = replace(add, factor=PolicyFactor("parameter_binding", Operation.REMOVE))
    assert freeze_source_eligibility(add, factor_scope=y, **common).eligible
    assert (
        freeze_source_eligibility(add, factor_scope=x, **common).exclusion_reason
        == "add_source_present"
    )
    removed = freeze_source_eligibility(remove, factor_scope=x, **common)
    assert removed.eligible and removed.target_evidence_node_ids == (ids["p"],)
    assert (
        freeze_source_eligibility(
            add, factor_scope=FeatureScope(ids["a"]), **common
        ).exclusion_reason
        == "add_source_unresolved"
    )
    assert (
        freeze_source_eligibility(add, factor_scope=None, **common).exclusion_reason
        == "factor_scope_unresolved"
    )
    assert (
        freeze_source_eligibility(
            add, factor_scope=None, **{**common, "graph": None}
        ).exclusion_reason
        == "source_graph_unavailable"
    )
    with pytest.raises(ValueError, match="different task"):
        freeze_source_eligibility(add, factor_scope=y, **{**common, "task_id": "another-task"})


def _scoped_support_fixture(tmp_path, *, missing_graph=False):
    """Eight artificial cells verify accounting only, never natural discovery support."""
    from prompt_mechanism_study.artifact_io import write_bundle, bundle_digest
    from prompt_mechanism_study.records import canonical_value
    from prompt_mechanism_study.representation import (
        AnalysisScope,
        AtomicPolicyKey,
        Operation,
        PolicyFactor,
    )

    scope = AnalysisScope("sql-inputs", "sql", ("python",), ("database",), ("query",))
    add = AtomicPolicyKey(scope, PolicyFactor("parameter_binding", Operation.ADD), "secure_yield")
    remove = replace(add, factor=replace(add.factor, operation=Operation.REMOVE))
    tasks, graphs, bindings = ([], [], [])
    for first in (False, True):
        for second in (False, True):
            for replicate in range(2):
                task_id = f"synthetic-{int(first)}{int(second)}-{replicate}"
                prompt, catalog, graph, ids = _scoped_graph(
                    bound_inputs=("x",) if first else ("y",),
                    shell_required=second,
                    task_id=task_id,
                    source_query=True,
                )
                tasks.append(
                    dict(
                        task_id=task_id,
                        task_unit_id=task_id,
                        near_duplicate_group_id=task_id,
                        prompt=prompt,
                        language="python",
                        api_family="database",
                        task_archetype="query",
                        source_lineage_id=f"synthetic-lineage-{replicate}",
                        source_kind="synthetic_development",
                        covariates=[["size", 1.0]],
                    )
                )
                graphs.append(prompt_tsg_record(graph))
                bindings.append(
                    dict(
                        task_id=task_id,
                        prompt_tsg_id=graph.tsg_id,
                        factor_scopes=canonical_value(
                            {"parameter_binding": FeatureScope(ids["a"], (ids["x"],), (ids["c"],))}
                        ),
                    )
                )
    if missing_graph:
        tasks.append(
            {
                **tasks[0],
                "task_id": "synthetic-failed",
                "task_unit_id": "synthetic-failed",
                "near_duplicate_group_id": "synthetic-failed",
            }
        )
        bindings.append(
            dict(
                task_id="synthetic-failed",
                prompt_tsg_id=None,
                factor_scopes={"parameter_binding": None},
            )
        )

    def write(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(canonical_value(value)), encoding="utf-8")
        return path

    task_path, catalog_path = (write("tasks.json", tasks), write("catalog.json", catalog))
    graph_bundle = write_bundle(tmp_path / "graphs", {"graphs.json": graphs})
    config = dict(
        source_tasks_sha256=file_sha256(task_path),
        catalog_sha256=catalog_sha256(catalog),
        graph_bundle_sha256=[bundle_digest(graph_bundle)],
        model_id="offline-model",
        covariate_names=["size"],
        policies=canonical_value([add, remove]),
        task_bindings=bindings,
        arms_or_outcomes_used=False,
        scope_choice_used_feature_states=False,
        factor_definitions={
            feature: dict(
                definition=f"Synthetic single requirement: {feature}",
                scope_rule="Fixed named operation/input/condition; never select by feature state.",
                atomicity_review="SOURCE_REVIEWED_SINGLE_REQUIREMENT",
            )
            for feature in ("parameter_binding",)
        },
        support_rule=dict(
            minimum_state_task_units=2,
            minimum_shared_lineages=1,
            maximum_unresolved_fraction=0.0,
            minimum_feature_reliability=0.8,
        ),
        representation_qualification=_synthetic_support_qualification(
            tmp_path, tasks[:8], graphs, catalog
        ),
    )
    return (
        task_path,
        graph_bundle,
        catalog_path,
        write("scopes.json", config),
        (add, remove),
        config,
        write,
    )


def _synthetic_support_qualification(tmp_path, source_tasks, graphs, catalog):
    """Artificial trials exercise interval arithmetic/transport, never empirical accuracy.

    The repeated templates below are explicitly synthetic and cannot be used as
    independent natural task support. Only the production qualifier can establish
    source-review/extractor replay closure on an actual independent selection.
    """
    from prompt_mechanism_study.prompt_contract_qualification import open_qualification_statistics
    from prompt_mechanism_study.artifact_io import write_bundle, bundle_digest
    tasks, cases, results = [], [], []
    for index in range(64):
        source, graph = source_tasks[index % 8], graphs[index % 8]
        task = {**source, **{k: f"synthetic-qualification-{index}" for k in
                            ("task_id", "task_unit_id", "near_duplicate_group_id")}}
        nodes = [dict(key=n["node_id"], node_types=[n["node_type"]], semantic_ids=[n["semantic_id"]],
            evidence_text=task["prompt"][n["evidence_start"]:n["evidence_end"]], occurrence=1)
            for n in graph["nodes"] if n["node_type"] != "task"]
        checks = [dict(target=a["scope"]["operation_node_id"], subjects=a["scope"]["subject_node_ids"],
            conditions=a["scope"]["condition_node_ids"], feature_id=a["feature_id"], state=a["state"])
            for a in graph["scoped_feature_assessments"]]
        case = dict(task_id=task["task_id"], source_prompt_sha256=content_hash(task["prompt"]),
            nodes=nodes, feature_checks=checks, non_target_checks=[["node", nodes[0]["key"]]])
        coverage = evaluate_open_graph_expectations(graph, prompt=task["prompt"], expected=case)
        case["critical_checks"] = [[r["kind"], r["key"]] for r in coverage["checks"] if r["kind"] == "feature_state"]
        review = dict(graph_sha256=content_hash(graph), source_prompt_sha256=content_hash(task["prompt"]),
            assertions={key: dict(status="SUPPORTED", rationale="Synthetic authored assertion only.",
                source_evidence=[dict(evidence_text=task["prompt"], occurrence=1)]) for key in open_graph_assertions(graph)})
        tasks.append(task)
        cases.append(case)
        results.append(evaluate_open_semantic_case(graph, prompt=task["prompt"], expected=case,
            assertion_review=review, extraction_failed=False))
    reference = dict(protocol_id="open_tsg_source_semantics", reference_kind="SYNTHETIC_TEST",
        reference_author_id="synthetic-fixture", review_completed_before_extraction=True,
        extractor_outputs_used=False, arms_or_outcomes_used=False, independence_attested=True,
        bindings=dict(candidate_id="offline", catalog_sha256=catalog_sha256(catalog),
            representation_implementation_sha256=representation_implementation_identity()),
        qualification_rule=_synthetic_qualification_rule(), cases=cases,
        required_profiles=[dict(language="python", operation_semantic_id="sql_query", feature_id=feature,
            expected_state=state) for feature in ("parameter_binding", "shell_syntax_rejection") for state in ("present", "absent")])
    report = dict(status="SYNTHETIC_REFERENCE_CHECK_PASSED", blockers=[], reference_kind="SYNTHETIC_TEST",
        bindings=reference["bindings"], source_reference_record_sha256=content_hash(reference),
        **open_qualification_statistics(reference, tasks, results))
    bundle = write_bundle(tmp_path / "synthetic-qualification", {"qualification.json": report,
        "source-reference.json": reference, "source-tasks.json": tasks, "case-results.json": results})
    return dict(bundle=bundle.name, bundle_sha256=bundle_digest(bundle))


def _source_support_folds(output, policies, atomic):
    """Feed the actual producer rows into the existing shared candidate/fold Gates."""
    from prompt_mechanism_study.prioritization import (
        CandidateCoverageSummary,
        AtomicShadowPlan,
        atomic_preoutcome_data_sha256,
        freeze_atomic_candidate_universe,
        freeze_atomic_candidate_folds,
    )
    from prompt_mechanism_study.representation import ModelBoundCandidateRecord
    from prompt_mechanism_study.artifact_io import bundle_digest
    from prompt_mechanism_study.verification.integrity import _decode_target_value

    cover = {
        _decode_target_value(
            row, CandidateCoverageSummary, "coverage"
        ).candidate_id: _decode_target_value(row, CandidateCoverageSummary, "coverage")
        for row in read_json(output / "coverage-summaries.json")
    }

    def record(policy):
        return ModelBoundCandidateRecord(
            policy.policy_key, "offline-model", "phase-context-policy-v3", "3.0"
        )

    atomic_policies = policies
    universe = freeze_atomic_candidate_universe(
        atomic_policies,
        tuple(map(record, atomic_policies)),
        supported_policy_keys=tuple((p.policy_key for p in atomic_policies)),
        coverage_summaries={p.policy_key: cover[p.policy_key] for p in atomic_policies},
        realization_policy_ids={p.policy_key: "synthetic-rewrite" for p in atomic_policies},
        candidate_family_ids={
            p.policy_key: p.analysis_scope.analysis_scope_id for p in atomic_policies
        },
        preoutcome_data_sha256=atomic_preoutcome_data_sha256(atomic),
        discovery_population_sha256=content_hash("synthetic population"),
        positivity_audit_sha256=bundle_digest(output),
        information_budget_sha256=content_hash("synthetic fixed information budget"),
        top_k=1,
        representation_adapter_id="scoped-source-fixture",
    )
    atomic_folds = freeze_atomic_candidate_folds(
        universe, atomic, AtomicShadowPlan("offline-model", ("size",), 2, 1.0, 13, 0.8, 0.5)
    )
    return (atomic_folds, cover)


@pytest.mark.parametrize("missing_graph", [False, True])
def test_scoped_source_support_keeps_units_unknowns_operation_recoding_and_provenance(
    tmp_path, missing_graph
):
    from prompt_mechanism_study.discovery_population import audit_discovery_positivity
    from prompt_mechanism_study.prioritization import AtomicPreOutcomeObservation
    from prompt_mechanism_study.verification.integrity import _decode_target_value

    tasks, graphs, catalog, scopes, policies, config, write = _scoped_support_fixture(
        tmp_path, missing_graph=missing_graph
    )
    result = audit_discovery_positivity(
        tasks, (graphs,), catalog, tmp_path / "support", scope_bindings_path=scopes
    )
    source = read_json(tmp_path / "support" / "positivity-rows.json")
    summaries = {row["policy_key"]: row for row in read_json(tmp_path / "support" / "support.json")}
    assert result["task_units"] == 8 + int(missing_graph)
    assert len(source) == 2 * result["task_units"]
    assert result["atomic_preoutcome_rows"] == 8
    for policy in policies:
        summary = summaries[policy.policy_key]
        assert summary["unknown_task_units"] == int(missing_graph)
        assert summary["support_gate_passed"] is (not missing_graph)
    records = {row["policy_key"]: row for row in source if row["task_id"] == "synthetic-00-0"}
    assert records[policies[0].policy_key]["target_state_cell"] == "0"
    assert records[policies[1].policy_key]["target_state_cell"] == "1"
    assert (
        records[policies[0].policy_key]["source_assessments"][0]["factor_scope"]
        == records[policies[1].policy_key]["source_assessments"][0]["factor_scope"]
    )
    atomic = tuple(
        (
            _decode_target_value(row, AtomicPreOutcomeObservation, "atomic")
            for row in read_json(tmp_path / "support" / "atomic-preoutcome-observations.json")
        )
    )
    assert all((row.source_binding_sha256 for row in atomic))
    assert all(
        (
            all((bool(reasons) == missing_graph for _, reasons in row.source_gate_failures))
            for row in atomic
        )
    )
    assert all(
        "outcome" not in row
        for row in read_json(tmp_path / "support" / "atomic-preoutcome-observations.json")
    )
    atomic_folds, cover = _source_support_folds(tmp_path / "support", policies, atomic)
    assert len(atomic_folds.manifests) == (0 if missing_graph else 2)
    assert all((row.total_task_units == 8 + int(missing_graph) for row in cover.values()))
    assert all(
        (row.representation_resolved_rate == 8 / (8 + int(missing_graph)) for row in cover.values())
    )
    if missing_graph:
        from prompt_mechanism_study.prioritization import DiscoverabilityReason

        assert all(
            (
                DiscoverabilityReason.SOURCE_SCOPE_SUPPORT_FAILED in decision.reasons
                for decision in atomic_folds.discoverability
            )
        )
    from prompt_mechanism_study.prioritization import (
        atomic_preoutcome_observations,
        atomic_preoutcome_data_sha256,
    )

    for value in (0, 1):
        assert atomic_preoutcome_data_sha256(
            atomic_preoutcome_observations([row.with_outcome(value) for row in atomic])
        ) == atomic_preoutcome_data_sha256(atomic)


def test_fixed_scope_assessment_cannot_create_coordinates_or_default_missing_states():
    _, contract = _contract()
    catalog = deepcopy(contract.catalog)
    catalog.update(concept_policy="FROZEN", queries=[dict(query_id="sql",
        required_semantics=["sql_query"], actionable_feature_id="parameter_binding",
        forbidden_semantics=[], required_relations=[], realization_id="bind",
        cwe_id="source_semantics", task_family="source_semantics")])
    contract = replace(contract, catalog=catalog, input_catalog_sha256=catalog_sha256(catalog),
                       feature_states=())
    request = fixed_scope_request(contract, prompt=PROMPT, catalog=catalog)
    assert len(request["scopes"]) == 3
    assert all(row['definition'] == catalog['semantic_guidance'].get(row['concept_id'], '') for row in request['facts'])
    assert not {"arm", "outcome", "seed", "cwe", "task_family"} & set(request)
    schema = fixed_scope_response_format(request)["json_schema"]["schema"]
    assert set(schema["properties"]["states"]["required"]) == set(request["scopes"])
    fields = next(iter(schema["properties"]["states"]["properties"].values()))["properties"]
    assert fields["expression"]["enum"] == ["not_expressed", "unresolved"]
    assert fields["applicability"]["enum"] == ["applicable", "not_applicable", "unresolved"]
    assert "state" not in fields
    for key, scope in request['scopes'].items():
        assert ('explicitly_required' in schema['properties']['states']['properties'][key]['properties']['expression']['enum']) == bool(scope['admissible_positive_requirements'])
        assert 'applicability_evidence' not in schema['properties']['states']['properties'][key]['properties']
        assert scope['target'] in schema['properties']['states']['properties'][key]['description']
        assert set(scope['bound_subject_roles']) == set(scope['subjects'])
    states = {key: scope_answer(scope, expression="explicitly_required" if scope["target"] == "b" else "not_expressed",
                        requirements=["p"] if scope["target"] == "b" else [])
              for key, scope in request["scopes"].items()}
    def apply(values, frozen_request=request):
        return apply_fixed_scope_response(json.dumps(dict(states=values, unresolved_notes=[])).encode(),
            request=frozen_request, contract=contract, prompt=PROMPT, catalog=catalog)
    result = apply(states)
    assert {row["state"] for row in result.feature_states} == {"present", "absent"}
    assert result.facts == contract.facts and result.relations == contract.relations
    input_key = next(key for key, scope in request["scopes"].items() if scope["subjects"])
    # Old ambiguous annotation labels are not an alternate active response path.
    old_wire = apply({**states, input_key: dict(state="absent", requirements=[], rationale="Legacy label.")})
    assert next(row for row in old_wire.feature_states if row["subjects"])["state"] == "unresolved"
    missing = apply({key: row for key, row in states.items() if key != input_key})
    assert next(row for row in missing.feature_states if row["subjects"])["state"] == "unresolved"
    # Unmentioned security wording cannot settle an ambiguous input role.
    ambiguous = apply({**states, input_key: scope_answer(request["scopes"][input_key], applicability="unresolved")})
    assert next(row for row in ambiguous.feature_states if row["subjects"])["state"] == "unresolved"
    inapplicable = apply({**states, input_key: scope_answer(request["scopes"][input_key], applicability="not_applicable")})
    assert next(row for row in inapplicable.feature_states if row["subjects"])["state"] == "not_applicable"
    unsupported = apply({**states, input_key: {**states[input_key], "applicability_evidence": []}})
    assert next(row for row in unsupported.feature_states if row["subjects"])["state"] == "unresolved"
    b_key = next(key for key, scope in request["scopes"].items() if scope["target"] == "b")
    contradictory = apply({**states, b_key: scope_answer(request["scopes"][b_key])})
    assert next(row for row in contradictory.feature_states if row["target"] == "b")["state"] == "unresolved"
    assert any("negative contradicts" in note for note in contradictory.unresolved_notes)
    contradiction = apply({**states, b_key: {**states[b_key], "applicability": "not_applicable"}})
    assert next(row for row in contradiction.feature_states if row["target"] == "b")["state"] == "unresolved"
    with pytest.raises(PromptContractExtractionError, match="fields"):
        apply({**states, "invented_scope": states[b_key]})
    changed = deepcopy(request)
    changed["scopes"][input_key]["target"] = "b"
    with pytest.raises(PromptContractExtractionError, match="exact source"):
        apply(states, changed)


def test_only_condition_predicates_can_change_scopes_and_rejected_conditions_do_not_disappear():
    source = "Use Python. Query A uses input x. If remote, parameterize x in A."
    catalog = open_concept_catalog()
    catalog.update(concept_policy="FROZEN", queries=[dict(query_id="sql", required_semantics=["query"],
        actionable_feature_id="binding", forbidden_semantics=[], required_relations=[], realization_id="bind",
        cwe_id="source_semantics", task_family="source_semantics")])
    catalog["semantics"].update(query="task_operation", arg="data_object", language="constraint",
                                remote="condition", binding="safety_requirement")
    def n(key, concept, quote):
        return dict(local_id=key, concept_id=concept, evidence_text=quote, occurrence=1)
    def e(a, kind, b, quote):
        return dict(source_node_local_id=a, edge_type=kind, target_node_local_id=b,
                    evidence_text=quote, occurrence=1)
    raw = dict(concepts=[], concept_states=[], feature_states=[], unresolved_notes=[],
        nodes=[n("a", "query", "Query A"), n("x", "arg", "input x"), n("lang", "language", "Use Python"),
               n("c", "remote", "If remote"), n("p", "binding", "parameterize x in A")],
        edges=[e("x", "used_by", "a", "Query A uses input x"), e("lang", "constrains", "a", "Use Python"),
               e("c", "conditions", "p", "If remote, parameterize x in A"),
               e("p", "constrains", "a", "parameterize x in A"), e("p", "constrains", "x", "parameterize x in A")])
    def compile_raw(value):
        return open_contract_from_response(value, task=dict(task_id="synthetic-condition-role", prompt=source),
            catalog=catalog, annotator_id="source-fixture", review_status="development_exposed")
    contract = compile_raw(raw)
    scopes = fixed_scope_request(contract, prompt=source, catalog=catalog)["scopes"]
    assert {tuple(s["conditions"]) for s in scopes.values()} == {(), ("c",)}
    assert all("lang" not in s["conditions"] for s in scopes.values())
    inventory = replace(contract, relations=(), source_inventory=authored_source_inventory(source, raw))
    binding_request = fixed_binding_request(inventory, prompt=source, catalog=catalog)
    assert set(binding_request["binding_rows"]["lang"]) == {"operations", "subjects"}
    assert set(binding_request["binding_rows"]["c"]) == {"operations", "requirements"}
    assert "x" not in binding_request["binding_rows"]  # Objects cannot emit requirements or conditions.
    wire = indexed_annotation(binding_request, raw)
    bound = apply_fixed_binding_response(json.dumps(wire).encode(), request=binding_request,
        contract=inventory, prompt=source, catalog=catalog)
    assert {(r["source"], r["edge_type"], r["target"]) for r in bound.relations} == {
        (r["source"], r["edge_type"], r["target"]) for r in contract.relations}
    broken_wire = deepcopy(wire)
    broken_wire["bindings"]["c"]["requirements"][0]["evidence_end_token"] = 0
    with pytest.raises(PromptContractExtractionError, match="source-token"):
        apply_fixed_binding_response(json.dumps(broken_wire).encode(), request=binding_request,
            contract=inventory, prompt=source, catalog=catalog)
    invalid = deepcopy(raw)
    invalid["edges"][1]["edge_type"] = "conditions"
    with pytest.raises(PromptTSGError, match="condition binding"):
        compile_raw(invalid)
    unresolved = deepcopy(raw)
    unresolved["nodes"][3]["evidence_text"] = "Unstated predicate"
    with pytest.raises(PromptTSGError, match="condition binding"):
        compile_raw(unresolved)


def test_indexed_operation_incidence_preserves_shared_intermediates_and_exact_repeated_spans():
    from prompt_mechanism_study.task_input import prepare_task_input
    task = prepare_task_input(dict(task_id="synthetic-indexed-incidence", language="python",
        generation_system_prompt="Follow the supplied source task.", prompt=(
        "Use f(x,y). Extract x and y from the request. "
        "Use x in query A. Use y in query B. Return the value. Return the value.")))
    catalog = open_concept_catalog()
    catalog.update(concept_policy="FROZEN")
    catalog["semantics"].update(extract="task_operation", query="task_operation", argument="data_object", result="data_object")
    catalog["semantic_guidance"].update(extract="Extract supplied request fields.", query="Query the data.",
                                       argument="A separately named supplied field.", result="A stated returned value.")
    request = contract_decision_request(task, catalog)
    def node(key, concept, quote, occurrence=1):
        return dict(local_id=key, concept_id=concept, evidence_text=quote, occurrence=occurrence)
    def edge(source, kind, target, quote):
        return dict(source_node_local_id=source, target_node_local_id=target, edge_type=kind,
                    evidence_text=quote, occurrence=1)
    raw_graph = dict(concepts=[], concept_states=[], feature_states=[], unresolved_notes=[], nodes=[
        node("extract", "extract", "Extract x and y from the request"),
        node("a", "query", "query A"), node("b", "query", "query B"),
        node("x", "argument", "x", task["prompt"][:task["prompt"].index("f(x,y)") + 2].count("x") + 1),
        node("y", "argument", "y", task["prompt"][:task["prompt"].index("f(x,y)") + 4].count("y") + 1),
        node("later_value", "result", "the value", 2)], edges=[
        edge("extract", "produces", "x", "Extract x and y from the request"),
        edge("extract", "produces", "y", "Extract x and y from the request"),
        edge("x", "used_by", "a", "Use x in query A"),
        edge("y", "used_by", "b", "Use y in query B")])
    wire = indexed_annotation(request, raw_graph)
    schema = open_contract_response_format(request)["json_schema"]["schema"]["properties"]
    assert set(schema) == {"nodes", "coverage", "unresolved_notes"}
    assert set(schema["nodes"]["items"]["properties"]["concept_id"]["enum"]) == {"extract", "query", "argument", "result"}
    def compile_wire(value):
        return contract_from_response(json.dumps(value).encode(), task=task, catalog=catalog,
                                      annotator_id="synthetic-offline", review_status="development_exposed")
    facts = compile_wire(wire)
    assert facts.relations == ()
    binding = fixed_binding_request(facts, prompt=task["prompt"], catalog=catalog)
    binding_wire = indexed_annotation(binding, raw_graph)
    contract = apply_fixed_binding_response(json.dumps(binding_wire).encode(), request=binding,
        contract=facts, prompt=task["prompt"], catalog=catalog)
    assert contract.facts == facts.facts
    assert {(r["source"], r["edge_type"], r["target"]) for r in contract.relations} == {
        ("fact.1", "produces", "fact.4"), ("fact.1", "produces", "fact.5"),
        ("fact.4", "used_by", "fact.2"), ("fact.5", "used_by", "fact.3")}
    later = next(f for f in contract.facts if f["local_id"] == "fact.6")
    assert later["evidence_text"] == "the value" and later["occurrence"] == 2
    graph = compile_task_context_contract(contract, prompt=task["prompt"], catalog=catalog)
    assert next(n for n in graph.nodes if n.semantic_id == "result").evidence_start == task["prompt"].rindex("the value")
    damaged = deepcopy(wire)
    damaged["nodes"][3]["evidence_end_token"] = len(request["source_tokens"]) + 1
    broken = compile_wire(damaged)
    assert "fact.4" not in {f["local_id"] for f in broken.facts}
    next_binding = fixed_binding_request(broken, prompt=task["prompt"], catalog=catalog)
    assert "fact.4" not in fixed_binding_response_format(next_binding)["json_schema"]["schema"]["properties"]["operation_roles"]["items"]["properties"]["subject"].get("enum", [])
    assert any("unbound_source_token_span: fact.4" in note for note in broken.unresolved_notes)
    with pytest.raises(PromptContractExtractionError, match="fields"):
        compile_wire(raw_graph)  # Frozen historical responses use their captured implementation.
    for bad_target in ["fact.2", "undefined"]:
        bad = deepcopy(binding_wire)
        bad["operation_roles"][0]["subject"] = bad_target
        with pytest.raises(PromptTSGError, match="endpoint"):
            apply_fixed_binding_response(json.dumps(bad).encode(), request=binding,
                contract=facts, prompt=task["prompt"], catalog=catalog)
    missing = deepcopy(binding_wire)
    del missing["bindings"]["fact.3"]
    with pytest.raises(PromptContractExtractionError, match="incomplete"):
        apply_fixed_binding_response(json.dumps(missing).encode(), request=binding,
            contract=facts, prompt=task["prompt"], catalog=catalog)
    changed = deepcopy(binding)
    changed["facts"][0]["evidence_text"] = "invented"
    with pytest.raises(PromptContractExtractionError, match="exact fact inventory"):
        apply_fixed_binding_response(json.dumps(binding_wire).encode(), request=changed,
            contract=facts, prompt=task["prompt"], catalog=catalog)


@pytest.mark.parametrize('source_first', [
    True,
])
def test_operation_inventory_schema_order_survives_the_actual_provider_request(monkeypatch, source_first):
    """The intended annotation sequence must reach the provider, not just exist in Python."""
    from prompt_mechanism_study.records import canonical_json
    request = contract_decision_request(dict(task_id="synthetic-wire-order", prompt=PROMPT, language="python"),
                                        open_concept_catalog())
    response_format = open_contract_response_format(request)
    seen = []
    class Reply:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def read(self, _maximum):
            return b'{"choices":[{"finish_reason":"stop","message":{"content":"{}"}}]}'
    def respond(http_request, *, timeout):
        seen.append(json.loads(http_request.data))
        return Reply()
    monkeypatch.setenv("ALI_BAILIAN_API_KEY", "offline-test-only")
    monkeypatch.setattr("prompt_mechanism_study.functional_judge.urlopen", respond)
    bailian_complete(request, dict(api_key_env="ALI_BAILIAN_API_KEY", base_url="https://unused.invalid",
        model_id="offline", temperature=0, top_p=1, seed=1, enable_thinking=False,
        maximum_output_tokens=8192, timeout_seconds=1, max_response_bytes=65536,
        response_format=response_format), "JSON source annotation fixture.", source_first_delivery=source_first)
    body = seen[0]
    properties = body["response_format"]["json_schema"]["schema"]["properties"]
    assert list(properties) == ["nodes", "coverage", "unresolved_notes"]
    assert list(properties["nodes"]["items"]["properties"]) == [
        "concept", "source_units", "evidence_start_token", "evidence_end_token", "layer"]
    # JSON meaning and artifact hashes remain fixed under both deliveries.
    assert content_hash(body["response_format"]) == content_hash(response_format)
    payload = json.loads(body["messages"][1]["content"])
    assert payload == request and content_hash(payload) == content_hash(request)
    if source_first:
        assert list(payload).index("source_prompt") < list(payload).index("known_concepts")
        assert list(payload["source_tokens"]) == sorted(payload["source_tokens"], key=int)
        assert body["messages"][1]["content"] != canonical_json(request)
    else:
        assert body["messages"][1]["content"] == canonical_json(request)
        assert list(payload["source_tokens"]) == sorted(payload["source_tokens"])
    assert body["max_tokens"] == 8192 and body["seed"] == 1
