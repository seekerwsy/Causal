import hashlib
import json
from pathlib import Path

import pytest

from prompt_mechanism_study.eligibility import qualify_prompt_tsg_extractor
from prompt_mechanism_study.prompt_tsg import (
    PromptTSGError,
    QueryState,
    apply_feature_patch,
    build_prompt_tsg,
    feature_state,
    load_catalog,
    prompt_tsg_from_record,
    prompt_tsg_record,
    query_context,
    query_for_realization,
    validate_prompt_tsg,
)
from prompt_mechanism_study.prompt_tsg_extract import (
    extract_prompt_tsg,
    extract_task_file,
    extraction_request,
)
from prompt_mechanism_study.records import content_hash


pytestmark = pytest.mark.extended

ROOT = Path(__file__).parents[1]
CATALOG_PATH = ROOT / "data/method/prompt-tsg-catalog-v1.json"
PROMPT = "Run the fixed git executable with a user-provided branch name and return its output."


def _fact(local_id, node_type, semantic_id, evidence_text, **attributes):
    return {
        "local_id": local_id,
        "node_type": node_type,
        "semantic_id": semantic_id,
        "evidence_text": evidence_text,
        "occurrence": 1,
        "attributes": attributes,
    }


def _path_authority(task, state, evidence_text, occurrence=1):
    return {
        "annotation_protocol_id": "explicit_path_base_authority_v1",
        "task_id": task["task_id"],
        "prompt_sha256": content_hash(task["prompt"]),
        "authority_state": state,
        "evidence_text": evidence_text,
        "occurrence": occurrence,
        "rationale": f"test fixture for {state}",
    }


def _command_graph(*, unresolved=()):
    catalog = load_catalog(CATALOG_PATH)
    facts = [
        _fact(
            "source",
            "source",
            "source.untrusted_command_argument",
            "user-provided branch name",
            caller_controlled=True,
        ),
        _fact("sink", "sink", "sink.process_execution", "Run"),
        _fact(
            "fixed",
            "constraint",
            "constraint.fixed_executable",
            "fixed git executable",
            fixed=True,
        ),
        _fact("operation", "task_operation", "task.operation", "return its output"),
    ]
    return catalog, build_prompt_tsg(
        task_id="task-1",
        prompt=PROMPT,
        extractor_id="llm-facts-v1",
        catalog=catalog,
        facts=facts,
        relations=[{"edge_type": "flows_to", "source": "source", "target": "sink"}],
        unresolved_semantics=unresolved,
    )


def test_catalog_and_graph_are_canonical_and_round_trip():
    catalog, graph = _command_graph()
    reordered = build_prompt_tsg(
        task_id="task-1",
        prompt=PROMPT,
        extractor_id="llm-facts-v1",
        catalog=catalog,
        facts=[
            _fact("operation", "task_operation", "task.operation", "return its output"),
            _fact(
                "fixed",
                "constraint",
                "constraint.fixed_executable",
                "fixed git executable",
                fixed=True,
            ),
            _fact("sink", "sink", "sink.process_execution", "Run"),
            _fact(
                "source",
                "source",
                "source.untrusted_command_argument",
                "user-provided branch name",
                caller_controlled=True,
            ),
        ],
        relations=[{"target": "sink", "source": "source", "edge_type": "flows_to"}],
    )

    assert graph == reordered
    assert graph == prompt_tsg_from_record(prompt_tsg_record(graph))
    validate_prompt_tsg(graph, prompt=PROMPT, catalog=catalog)


@pytest.mark.reviewer
def test_active_catalog_guides_every_query_bound_semantic():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v5.json")
    query_semantics = set()
    for query in catalog["queries"]:
        query_semantics.update(query["required_semantics"])
        query_semantics.update(query["forbidden_semantics"])
        query_semantics.add(query["actionable_feature_id"])

    assert query_semantics <= set(catalog["semantic_guidance"])


@pytest.mark.reviewer
def test_prospective_catalog_freezes_xml_and_sql_semantic_boundaries():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v8.json")
    guidance = catalog["semantic_guidance"]

    assert "DTD validation or internal-DTD support alone does not entail" in guidance[
        "constraint.external_entities_required"
    ]
    assert "Separately named function or request parameters" in guidance[
        "source.dynamic_sql_identifier"
    ]
    assert "optional separately named parameters" in guidance[
        "constraint.fixed_sql_identifiers"
    ]


@pytest.mark.reviewer
def test_successor_catalog_freezes_pipeline_and_format_boundaries():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v9.json")
    guidance = catalog["semantic_guidance"]

    assert "predetermined pipeline of named tools" in guidance[
        "constraint.fixed_executable"
    ]
    assert "framework checkpoints" in guidance["source.untrusted_python_literal"]
    assert "framework checkpoint" in guidance["sink.python_literal_deserialization"]


@pytest.mark.reviewer
def test_bigcodebench_external_qualification_freeze_is_self_consistent():
    tasks_path = ROOT / "data/method/prompt-tsg-external-qualification-tasks-v3.json"
    tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
    selection = json.loads(
        (
            ROOT
            / "data/method/prompt-tsg-external-qualification-selection-v3.json"
        ).read_text(encoding="utf-8")
    )
    gold = json.loads(
        (ROOT / "data/method/prompt-tsg-external-qualification-gold-v3.json").read_text(
            encoding="utf-8"
        )
    )
    source = json.loads(
        (
            ROOT / "data/method/prompt-tsg-external-qualification-source-v3.json"
        ).read_text(encoding="utf-8")
    )

    task_ids = [row["task_id"] for row in tasks]
    assert set(selection) == {
        "schema_version",
        "source_tasks_sha256",
        "selection_rule",
        "task_ids",
        "arms_or_outcomes_used",
    }
    assert len(tasks) == len(set(task_ids)) == 31
    assert task_ids == selection["task_ids"]
    assert task_ids == [row["task_id"] for row in gold["cases"]]
    assert selection["source_tasks_sha256"] == hashlib.sha256(
        tasks_path.read_bytes()
    ).hexdigest()
    assert all(
        row["prompt_sha256"]
        == hashlib.sha256(row["prompt"].encode("utf-8")).hexdigest()
        for row in tasks
    )
    assert sum(row["expected_context"] == "present" for row in gold["cases"]) == 19
    assert source["method_revision_commit"] == "c49956a"
    assert source["source"]["commit"] == (
        "a3b89850db670d7302571142b881e4f85eef18e3"
    )
    assert source["source"]["source_sha256"] == (
        "58142744edaf6036387f8761701f1b353432b0ed33f2edec1de8a59e7431ef7a"
    )
    assert source["population_rule"]["frozen_task_units"] == 31
    assert source["overlap_audit"]["against_seven_source"][
        "normalized_exact_matches"
    ] == 0
    assert source["overlap_audit"]["against_prior_external"][
        "normalized_exact_matches"
    ] == 0

    exposed_prompt_hashes = {
        row["prompt_sha256"]
        for version in ("v1", "v2")
        for row in json.loads(
            (
                ROOT
                / f"data/method/prompt-tsg-external-qualification-tasks-{version}.json"
            ).read_text(encoding="utf-8")
        )
    }
    assert exposed_prompt_hashes.isdisjoint(
        {row["prompt_sha256"] for row in tasks}
    )


@pytest.mark.reviewer
def test_caller_supplied_path_base_cannot_satisfy_trusted_base_context():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v5.json")
    prompt = (
        "Read a user-provided filename from the directory supplied in the "
        "dir_path function argument."
    )
    graph = build_prompt_tsg(
        task_id="caller-base-task",
        prompt=prompt,
        extractor_id="bounded-facts-v1",
        catalog=catalog,
        facts=[
            _fact(
                "path",
                "source",
                "source.untrusted_relative_path",
                "user-provided filename",
                caller_controlled=True,
            ),
            _fact("sink", "sink", "sink.file_access", "Read"),
            _fact(
                "base",
                "constraint",
                "constraint.caller_supplied_path_base",
                "directory supplied in the dir_path function argument",
                caller_controlled=True,
            ),
        ],
        relations=[
            {"edge_type": "flows_to", "source": "path", "target": "sink"},
            {"edge_type": "qualifies", "source": "base", "target": "sink"},
        ],
    )
    query = query_for_realization(catalog, "cwe22_path_confinement")

    assert query_context(
        graph,
        query=query,
        cwe="CWE-22",
        task_family="path_access",
    ).state is QueryState.ABSENT


@pytest.mark.reviewer
def test_independently_configured_path_base_remains_applicable():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v5.json")
    prompt = "Read a user filename beneath the application's configured upload directory."
    graph = build_prompt_tsg(
        task_id="configured-base-task",
        prompt=prompt,
        extractor_id="bounded-facts-v1",
        catalog=catalog,
        facts=[
            _fact(
                "path",
                "source",
                "source.untrusted_relative_path",
                "user filename",
                caller_controlled=True,
            ),
            _fact("sink", "sink", "sink.file_access", "Read"),
            _fact(
                "base",
                "constraint",
                "constraint.trusted_path_base",
                "application's configured upload directory",
                fixed=True,
            ),
        ],
        relations=[
            {"edge_type": "flows_to", "source": "path", "target": "sink"},
            {"edge_type": "qualifies", "source": "base", "target": "sink"},
        ],
    )
    query = query_for_realization(catalog, "cwe22_path_confinement")

    assert query_context(
        graph,
        query=query,
        cwe="CWE-22",
        task_family="path_access",
    ).state is QueryState.PRESENT


@pytest.mark.reviewer
def test_unspecified_path_base_authority_remains_unresolved():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v5.json")
    prompt = "Read a user filename beneath base_dir. Context: base_dir is the directory used for reads."
    graph = build_prompt_tsg(
        task_id="ambiguous-base-task",
        prompt=prompt,
        extractor_id="explicit-authority-v1",
        catalog=catalog,
        facts=[
            _fact(
                "path",
                "source",
                "source.untrusted_relative_path",
                "user filename",
                caller_controlled=True,
            ),
            _fact("sink", "sink", "sink.file_access", "Read"),
        ],
        relations=[
            {"edge_type": "flows_to", "source": "path", "target": "sink"}
        ],
        unresolved_semantics=[
            "constraint.caller_supplied_path_base",
            "constraint.trusted_path_base",
        ],
    )
    query = query_for_realization(catalog, "cwe22_path_confinement")

    assert query_context(
        graph,
        query=query,
        cwe="CWE-22",
        task_family="path_access",
    ).state is QueryState.UNRESOLVED


@pytest.mark.reviewer
def test_structured_authority_overrides_proposer_and_bypasses_semantic_reviewer():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v5.json")
    prompt = "Read a user filename beneath base_dir. Context: base_dir is the directory used for reads."
    task = {
        "task_id": "ambiguous-base-extraction-task",
        "task_unit_id": "ambiguous-base-extraction-task",
        "prompt": prompt,
        "cwe": "CWE-22",
        "task_family": "path_access",
    }
    response = {
        "facts": [
            _fact(
                "path",
                "source",
                "source.untrusted_relative_path",
                "user filename",
                caller_controlled=True,
            ),
            _fact("sink", "sink", "sink.file_access", "Read"),
            _fact(
                "wrong-base",
                "constraint",
                "constraint.trusted_path_base",
                "base_dir",
                fixed=True,
            ),
        ],
        "relations": [
            {"edge_type": "flows_to", "source": "path", "target": "sink"},
            {"edge_type": "qualifies", "source": "wrong-base", "target": "sink"},
        ],
        "unresolved_semantics": [],
    }
    review = {
        "facts": [
            _fact(
                "review-path",
                "source",
                "source.untrusted_relative_path",
                "user filename",
                caller_controlled=True,
            ),
            _fact("review-sink", "sink", "sink.file_access", "Read"),
        ],
        "relations": [
            {
                "edge_type": "flows_to",
                "source": "review-path",
                "target": "review-sink",
            }
        ],
        "unresolved_semantics": [],
    }

    def provider(request, _evaluator, system_prompt):
        import json

        if request.get("request_kind") == "prompt_tsg_bounded_ambiguity_adjudication":
            assert not set(request["candidate_semantics"]) & {
                "constraint.caller_supplied_path_base",
                "constraint.trusted_path_base",
            }
            assert request["allowed_relations"] == [
                [
                    "source.untrusted_relative_path",
                    "flows_to",
                    "sink.file_access",
                ]
            ]
            assert request["evidence_binding_policy"]["asserted_candidate"].startswith(
                "reuse validated proposer evidence"
            )
            return json.dumps(review).encode()
        return json.dumps(response).encode()

    graph, _, _, projection = extract_prompt_tsg(
        task,
        catalog=catalog,
        evaluator={"candidate_id": "explicit-authority-proposer-v1"},
        system_prompt="propose facts",
        reviewer_evaluator={"candidate_id": "explicit-authority-reviewer-v1"},
        reviewer_prompt="review facts",
        path_authority_annotation=_path_authority(
            task,
            "unspecified",
            "base_dir",
        ),
        provider=provider,
    )
    query = query_for_realization(catalog, "cwe22_path_confinement")

    assert query_context(
        graph,
        query=query,
        cwe="CWE-22",
        task_family="path_access",
    ).state is QueryState.UNRESOLVED
    assert projection["semantic_review"]["unresolved_semantics"] == []
    assert projection["path_authority"]["authority_state"] == "unspecified"
    assert projection["path_authority"]["model_facts_removed"] == [
        {
            "local_id": "wrong-base",
            "semantic_id": "constraint.trusted_path_base",
        }
    ]


@pytest.mark.reviewer
@pytest.mark.parametrize(
    ("state", "prompt", "base_evidence", "source_evidence", "expected"),
    [
        (
            "application_configured",
            "Read a user filename beneath the application-configured base_dir, "
            "which is not caller-controlled.",
            "application-configured base_dir, which is not caller-controlled",
            "user filename",
            QueryState.PRESENT,
        ),
        (
            "caller_supplied",
            "Read a user filename beneath base_dir supplied as a function argument.",
            "base_dir supplied as a function argument",
            "user filename",
            QueryState.ABSENT,
        ),
        (
            "unspecified",
            "Read a user filename beneath base_dir.",
            "base_dir",
            "user filename",
            QueryState.UNRESOLVED,
        ),
        (
            "no_bounding_base",
            "Read a user-provided file path.",
            None,
            "user-provided file path",
            QueryState.ABSENT,
        ),
    ],
)
def test_structured_path_authority_has_total_four_state_projection(
    state, prompt, base_evidence, source_evidence, expected
):
    import json

    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v5.json")
    task = {
        "task_id": f"path-authority-{state}",
        "task_unit_id": f"path-authority-{state}",
        "prompt": prompt,
        "cwe": "CWE-22",
        "task_family": "path_access",
    }
    response = {
        "facts": [
            _fact(
                "path",
                "source",
                "source.untrusted_relative_path",
                source_evidence,
                caller_controlled=True,
            ),
            _fact("sink", "sink", "sink.file_access", "Read"),
        ],
        "relations": [
            {"edge_type": "flows_to", "source": "path", "target": "sink"}
        ],
        "unresolved_semantics": [],
    }

    graph, _, _, projection = extract_prompt_tsg(
        task,
        catalog=catalog,
        evaluator={"candidate_id": "path-authority-test"},
        system_prompt="extract facts",
        path_authority_annotation=_path_authority(
            task,
            state,
            base_evidence,
            None if state == "no_bounding_base" else 1,
        ),
        provider=lambda *_: json.dumps(response).encode(),
    )
    query = query_for_realization(catalog, "cwe22_path_confinement")

    assert query_context(
        graph,
        query=query,
        cwe="CWE-22",
        task_family="path_access",
    ).state is expected
    assert projection["path_authority"]["projection_status"] == "applied"


@pytest.mark.reviewer
def test_path_authority_bundle_is_bound_to_source_population(tmp_path):
    import hashlib
    import json

    prompt = "Read a user filename beneath the application-configured base_dir."
    task = {
        "task_id": "path-authority-bundle-task",
        "task_unit_id": "path-authority-bundle-task",
        "prompt": prompt,
        "prompt_sha256": content_hash(prompt),
        "cwe": "CWE-22",
        "task_family": "path_access",
    }
    tasks_path = tmp_path / "tasks.json"
    tasks_path.write_text(json.dumps([task]), encoding="utf-8")
    annotation_path = tmp_path / "path-authority.json"
    annotation_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "annotation_protocol_id": "explicit_path_base_authority_v1",
                "source_tasks_sha256": hashlib.sha256(
                    tasks_path.read_bytes()
                ).hexdigest(),
                "review_completed_before_extraction": True,
                "arms_or_outcomes_used": False,
                "annotations": [
                    {
                        key: value
                        for key, value in _path_authority(
                            task,
                            "application_configured",
                            "application-configured base_dir",
                        ).items()
                        if key != "annotation_protocol_id"
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    response = {
        "facts": [
            _fact(
                "path",
                "source",
                "source.untrusted_relative_path",
                "user filename",
                caller_controlled=True,
            ),
            _fact("sink", "sink", "sink.file_access", "Read"),
        ],
        "relations": [
            {"edge_type": "flows_to", "source": "path", "target": "sink"}
        ],
        "unresolved_semantics": [],
    }

    report = extract_task_file(
        tasks_path,
        ROOT / "data/method/prompt-tsg-catalog-v5.json",
        ROOT / "data/method/prompt-tsg-extractor-qwen35flash-v1.json",
        ROOT / "data/method/prompts/prompt-tsg-facts-v1.txt",
        tmp_path / "bundle",
        path_authority_annotations_path=annotation_path,
        provider=lambda *_: json.dumps(response).encode(),
    )

    assert report["status"] == "PROMPT_TSG_EXTRACTION_COMPLETE"
    assert report["path_authority_protocol_id"] == "explicit_path_base_authority_v1"
    assert report["path_authority_annotated_tasks"] == 1
    assert report["path_authority_state_counts"] == {"application_configured": 1}
    stored_request = json.loads(
        (tmp_path / "bundle/requests.json").read_text(encoding="utf-8")
    )[0]
    assert stored_request["deterministic_projection"]["path_authority"][
        "authority_state"
    ] == "application_configured"


@pytest.mark.reviewer
def test_semantic_reviewer_drops_relations_outside_query_scope():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v5.json")
    prompt = "Read a user filename from the directory supplied as dir_path."
    task = {
        "task_id": "caller-base-review-task",
        "task_unit_id": "caller-base-review-task",
        "prompt": prompt,
        "cwe": "CWE-22",
        "task_family": "path_access",
    }
    facts = [
        _fact(
            "path",
            "source",
            "source.untrusted_relative_path",
            "user filename",
            caller_controlled=True,
        ),
        _fact("sink", "sink", "sink.file_access", "Read"),
        _fact(
            "base",
            "constraint",
            "constraint.caller_supplied_path_base",
            "directory supplied as dir_path",
            caller_controlled=True,
        ),
    ]
    response = {
        "facts": facts,
        "relations": [
            {"edge_type": "flows_to", "source": "path", "target": "sink"},
            {"edge_type": "qualifies", "source": "base", "target": "sink"},
        ],
        "unresolved_semantics": [],
    }

    def provider(_request, _evaluator, _prompt):
        import json

        return json.dumps(response).encode()

    graph, _, _, projection = extract_prompt_tsg(
        task,
        catalog=catalog,
        evaluator={"candidate_id": "proposer-v1"},
        system_prompt="propose facts",
        reviewer_evaluator={"candidate_id": "reviewer-v1"},
        reviewer_prompt="review facts",
        provider=provider,
    )
    query = query_for_realization(catalog, "cwe22_path_confinement")

    assert query_context(
        graph,
        query=query,
        cwe="CWE-22",
        task_family="path_access",
    ).state is QueryState.ABSENT
    assert any(
        relation["reason"] == "non_query_relation"
        for relation in projection["semantic_review"]["rejected_relations"]
    )


@pytest.mark.reviewer
def test_evidence_must_be_an_exact_prompt_span():
    catalog = load_catalog(CATALOG_PATH)
    with pytest.raises(PromptTSGError, match="evidence"):
        build_prompt_tsg(
            task_id="task-1",
            prompt=PROMPT,
            extractor_id="llm-facts-v1",
            catalog=catalog,
            facts=[
                _fact(
                    "source",
                    "source",
                    "source.untrusted_command_argument",
                    "not in the prompt",
                )
            ],
            relations=[],
        )


def test_evidence_allows_only_deterministic_whitespace_normalization():
    catalog = load_catalog(CATALOG_PATH)
    prompt = 'Remove "username" from the  "users" table.'
    graph = build_prompt_tsg(
        task_id="task-space",
        prompt=prompt,
        extractor_id="llm-facts-v1",
        catalog=catalog,
        facts=[
            _fact(
                "constraint",
                "constraint",
                "constraint.fixed_sql_identifiers",
                'the "users" table',
            )
        ],
        relations=[],
    )
    node = next(node for node in graph.nodes if node.semantic_id.endswith("fixed_sql_identifiers"))
    assert prompt[node.evidence_start : node.evidence_end] == 'the  "users" table'


@pytest.mark.reviewer
def test_context_query_has_total_four_valued_semantics():
    catalog, graph = _command_graph()
    query = query_for_realization(catalog, "cwe78_fixed_executable_argv")

    present = query_context(graph, query=query, cwe="CWE-78", task_family="command_execution")
    not_applicable = query_context(
        graph, query=query, cwe="CWE-89", task_family="command_execution"
    )
    assert present.state == QueryState.PRESENT
    assert not_applicable.state == QueryState.NOT_APPLICABLE

    _, unresolved = _command_graph(unresolved=("constraint.fixed_executable",))
    result = query_context(
        unresolved, query=query, cwe="CWE-78", task_family="command_execution"
    )
    assert result.state == QueryState.UNRESOLVED

    absent = build_prompt_tsg(
        task_id="task-2",
        prompt="Return a constant.",
        extractor_id="llm-facts-v1",
        catalog=catalog,
        facts=[],
        relations=[],
    )
    result = query_context(
        absent, query=query, cwe="CWE-78", task_family="command_execution"
    )
    assert result.state == QueryState.ABSENT


@pytest.mark.reviewer
def test_typed_patch_adds_only_the_catalog_feature():
    catalog, graph = _command_graph()
    suffix = "Pass command arguments as an argv list and do not invoke a shell."
    patched = apply_feature_patch(
        graph,
        prompt=PROMPT,
        appended_text=suffix,
        semantic_id="feature.argv_without_shell",
        catalog=catalog,
    )

    assert feature_state(graph, "feature.argv_without_shell") == QueryState.ABSENT
    assert feature_state(patched, "feature.argv_without_shell") == QueryState.PRESENT
    assert len(patched.nodes) == len(graph.nodes) + 1
    assert len(patched.edges) == len(graph.edges) + 1
    original = {
        (node.node_type, node.semantic_id, node.evidence_start, node.evidence_end)
        for node in graph.nodes
        if node.semantic_id != "task.root"
    }
    patched_projection = {
        (node.node_type, node.semantic_id, node.evidence_start, node.evidence_end)
        for node in patched.nodes
    }
    assert original <= patched_projection


@pytest.mark.reviewer
def test_task_local_text_stays_evidence_bound_not_a_global_feature():
    catalog, graph = _command_graph()
    operation = next(node for node in graph.nodes if node.semantic_id == "task.operation")

    assert operation.evidence_start == PROMPT.index("return its output")
    assert operation.attributes == ()
    assert "return its output" not in catalog["semantics"]


def test_llm_facts_extractor_is_task_sliced_and_deterministically_validated(tmp_path):
    catalog = load_catalog(CATALOG_PATH)
    task = {
        "task_id": "task-1",
        "task_unit_id": "task-1",
        "prompt": PROMPT,
        "source_prompt_sha256": content_hash(PROMPT),
        "oracle_profile_id": "python.cwe78.function_parameter_subprocess.v2",
        "cwe": "CWE-78",
        "task_family": "command_execution",
    }
    response = {
        "facts": [
            _fact(
                "source",
                "source",
                "source.untrusted_command_argument",
                "user-provided branch name",
                caller_controlled=True,
            ),
            _fact("sink", "sink", "sink.process_execution", "Run"),
            _fact(
                "fixed",
                "constraint",
                "constraint.fixed_executable",
                "fixed git executable",
                fixed=True,
            ),
        ],
        "relations": [{"edge_type": "flows_to", "source": "source", "target": "sink"}],
        "unresolved_semantics": ["feature.argv_without_shell"],
    }

    request = extraction_request(task, catalog)
    assert "source.untrusted_sql_value" not in request["candidate_semantics"]
    assert request["arms_or_outcomes_included"] is False

    def provider(actual_request, _evaluator, _prompt):
        assert actual_request == request
        import json

        return json.dumps(response).encode()

    evaluator = {"candidate_id": "llm-facts-v1"}
    graph, _, _, projection = extract_prompt_tsg(
        task,
        catalog=catalog,
        evaluator=evaluator,
        system_prompt="extract facts",
        provider=provider,
    )
    assert graph.task_id == "task-1"
    assert projection == {
        "rejected_facts": [],
        "rejected_relations": [],
        "ignored_unresolved_features": ["feature.argv_without_shell"],
    }

    tasks_path = tmp_path / "tasks.jsonl"
    tasks_path.write_text(__import__("json").dumps(task) + "\n", encoding="utf-8")
    evaluator_path = tmp_path / "evaluator.json"
    evaluator_path.write_text(
        (ROOT / "data/method/prompt-tsg-extractor-qwen35flash-v1.json").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    prompt_path = ROOT / "data/method/prompts/prompt-tsg-facts-v1.txt"
    report = extract_task_file(
        tasks_path,
        CATALOG_PATH,
        evaluator_path,
        prompt_path,
        tmp_path / "bundle",
        provider=provider,
    )
    assert report["graphs"] == 1
    assert len(report["extractor_implementation_sha256"]) == 64
    assert len(report["provider_adapter_sha256"]) == 64
    assert report["arms_or_outcomes_used"] is False


def test_extractor_drops_only_nonverbatim_descriptive_facts():
    catalog = load_catalog(CATALOG_PATH)
    task = {
        "task_id": "task-1",
        "task_unit_id": "task-1",
        "prompt": PROMPT,
        "cwe": "CWE-78",
        "task_family": "command_execution",
    }
    response = {
        "facts": [
            _fact(
                "source",
                "source",
                "source.untrusted_command_argument",
                "user-provided branch name",
                caller_controlled=True,
            ),
            _fact("sink", "sink", "sink.process_execution", "Run"),
            _fact(
                "summary",
                "task_operation",
                "task.operation",
                "Run ... and return its output",
            ),
        ],
        "relations": [
            {"edge_type": "flows_to", "source": "source", "target": "sink"},
            {"edge_type": "qualifies", "source": "summary", "target": "sink"},
        ],
        "unresolved_semantics": [],
    }

    def provider(_request, _evaluator, _prompt):
        import json

        return json.dumps(response).encode()

    graph, _, _, projection = extract_prompt_tsg(
        task,
        catalog=catalog,
        evaluator={"candidate_id": "llm-facts-v1"},
        system_prompt="extract facts",
        provider=provider,
    )

    assert {node.semantic_id for node in graph.nodes} == {
        "task.root",
        "source.untrusted_command_argument",
        "sink.process_execution",
    }
    assert projection["rejected_facts"] == [
        {
            "local_id": "summary",
            "semantic_id": "task.operation",
            "reason": "noncontiguous_or_nonverbatim_descriptive_evidence",
        }
    ]
    assert projection["rejected_relations"] == [
        {
            "edge_type": "qualifies",
            "source": "summary",
            "target": "sink",
            "reason": "edge_type_matrix_violation",
        }
    ]


def test_extractor_never_drops_nonverbatim_catalog_bound_facts():
    catalog = load_catalog(CATALOG_PATH)
    task = {
        "task_id": "task-1",
        "task_unit_id": "task-1",
        "prompt": PROMPT,
        "cwe": "CWE-78",
        "task_family": "command_execution",
    }
    response = {
        "facts": [
            _fact(
                "source",
                "source",
                "source.untrusted_command_argument",
                "user-provided ... branch name",
                caller_controlled=True,
            )
        ],
        "relations": [],
        "unresolved_semantics": [],
    }

    def provider(_request, _evaluator, _prompt):
        import json

        return json.dumps(response).encode()

    with pytest.raises(ValueError, match="catalog-bound"):
        extract_prompt_tsg(
            task,
            catalog=catalog,
            evaluator={"candidate_id": "llm-facts-v1"},
            system_prompt="extract facts",
            provider=provider,
        )


@pytest.mark.reviewer
def test_extractor_normalizes_only_a_unique_exact_evidence_occurrence():
    catalog = load_catalog(CATALOG_PATH)
    task = {
        "task_id": "task-unique-occurrence",
        "task_unit_id": "task-unique-occurrence",
        "prompt": PROMPT,
        "cwe": "CWE-78",
        "task_family": "command_execution",
    }
    response = {
        "facts": [
            _fact(
                "source",
                "source",
                "source.untrusted_command_argument",
                "user-provided branch name",
                caller_controlled=True,
            )
            | {"occurrence": 9},
            _fact("sink", "sink", "sink.process_execution", "Run"),
            _fact(
                "fixed",
                "constraint",
                "constraint.fixed_executable",
                "fixed git executable",
                fixed=True,
            ),
        ],
        "relations": [
            {"edge_type": "flows_to", "source": "source", "target": "sink"}
        ],
        "unresolved_semantics": [],
    }

    def provider(_request, _evaluator, _prompt):
        import json

        return json.dumps(response).encode()

    graph, _, _, projection = extract_prompt_tsg(
        task,
        catalog=catalog,
        evaluator={"candidate_id": "llm-facts-v1"},
        system_prompt="extract facts",
        provider=provider,
    )
    source = next(
        node
        for node in graph.nodes
        if node.semantic_id == "source.untrusted_command_argument"
    )

    assert source.evidence_start == PROMPT.index("user-provided branch name")
    assert projection["normalized_evidence_occurrences"] == [
        {
            "local_id": "source",
            "semantic_id": "source.untrusted_command_argument",
            "provided_occurrence": 9,
            "normalized_occurrence": 1,
            "reason": "unique_exact_evidence_span",
        }
    ]


@pytest.mark.reviewer
def test_semantic_reviewer_reuses_validated_proposer_evidence_binding():
    import json

    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v5.json")
    prompt = "Read theme_path beneath the configured root. theme_path selects a theme."
    task = {
        "task_id": "repeated-path-evidence-task",
        "task_unit_id": "repeated-path-evidence-task",
        "prompt": prompt,
        "cwe": "CWE-22",
        "task_family": "path_access",
    }
    proposal = {
        "facts": [
            _fact(
                "source",
                "source",
                "source.untrusted_relative_path",
                "theme_path",
                caller_controlled=True,
            ),
            _fact("sink", "sink", "sink.file_access", "Read"),
        ],
        "relations": [
            {"edge_type": "flows_to", "source": "source", "target": "sink"}
        ],
        "unresolved_semantics": [],
    }
    review = {
        "facts": [
            _fact(
                "review-source",
                "source",
                "source.untrusted_relative_path",
                "theme_path",
            )
            | {"occurrence": 38},
            _fact("review-sink", "sink", "sink.file_access", "Read"),
        ],
        "relations": [
            {
                "edge_type": "flows_to",
                "source": "review-source",
                "target": "review-sink",
            }
        ],
        "unresolved_semantics": [],
    }

    def provider(request, _evaluator, _prompt):
        value = (
            review
            if request.get("request_kind")
            == "prompt_tsg_bounded_ambiguity_adjudication"
            else proposal
        )
        return json.dumps(value).encode()

    graph, _, _, projection = extract_prompt_tsg(
        task,
        catalog=catalog,
        evaluator={"candidate_id": "proposer-v1"},
        system_prompt="propose facts",
        reviewer_evaluator={"candidate_id": "reviewer-v1"},
        reviewer_prompt="review semantics",
        provider=provider,
    )
    source = next(
        node
        for node in graph.nodes
        if node.semantic_id == "source.untrusted_relative_path"
    )

    assert source.evidence_start == prompt.index("theme_path")
    assert projection["semantic_review"]["reused_proposer_evidence"] == [
        {
            "local_id": "review-source",
            "semantic_id": "source.untrusted_relative_path",
            "reviewed_evidence_text": "theme_path",
            "reviewed_occurrence": 38,
            "proposer_evidence_text": "theme_path",
            "proposer_occurrence": 1,
        }
    ]


@pytest.mark.reviewer
def test_blind_semantic_reviewer_rejects_unsupported_proposed_facts():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v2.json")
    prompt = "Load a YAML configuration file."
    task = {
        "task_id": "yaml-task",
        "task_unit_id": "yaml-task",
        "prompt": prompt,
        "cwe": "CWE-502",
        "task_family": "deserialization",
    }
    proposal = {
        "facts": [
            _fact("source", "source", "source.untrusted_yaml", prompt),
            _fact("sink", "sink", "sink.yaml_deserialization", prompt),
            _fact(
                "format",
                "constraint",
                "constraint.yaml_format_required",
                "YAML configuration file",
            ),
        ],
        "relations": [
            {"edge_type": "flows_to", "source": "source", "target": "sink"}
        ],
        "unresolved_semantics": [],
    }
    review = {
        "facts": [
            _fact("review-sink", "sink", "sink.yaml_deserialization", prompt),
            _fact(
                "review-format",
                "constraint",
                "constraint.yaml_format_required",
                "YAML configuration file",
            ),
        ],
        "relations": [],
        "unresolved_semantics": [],
    }

    def provider(request, evaluator, _prompt):
        import json

        if request.get("request_kind") == "prompt_tsg_bounded_ambiguity_adjudication":
            assert evaluator["candidate_id"] == "reviewer-v1"
            assert request["arms_or_outcomes_included"] is False
            return json.dumps(review).encode()
        assert evaluator["candidate_id"] == "proposer-v1"
        return json.dumps(proposal).encode()

    graph, _, _, projection = extract_prompt_tsg(
        task,
        catalog=catalog,
        evaluator={"candidate_id": "proposer-v1"},
        system_prompt="propose facts",
        reviewer_evaluator={"candidate_id": "reviewer-v1"},
        reviewer_prompt="review facts",
        provider=provider,
    )

    query = query_for_realization(catalog, "cwe502_yaml_deserialization")
    assert graph.extractor_id == "proposer-v1+reviewer-v1"
    assert query_context(
        graph,
        query=query,
        cwe="CWE-502",
        task_family="deserialization",
    ).state is QueryState.ABSENT
    assert projection["semantic_review"]["rejected_facts"] == [
        {
            "local_id": "source",
            "semantic_id": "source.untrusted_yaml",
            "reason": "semantic_reviewer_rejected",
        }
    ]
    assert projection["semantic_review"]["rejected_relations"] == [
        {
            "edge_type": "flows_to",
            "source": "source",
            "target": "sink",
            "reason": "semantic_reviewer_rejected",
        }
    ]


@pytest.mark.reviewer
def test_blind_semantic_reviewer_can_resolve_only_proposer_declared_ambiguity():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v3.json")
    prompt = (
        "Write a Python function that takes a job ID as input. "
        "Use subprocess to execute one command that retrieves the job exit code. "
        "The command must include the job ID as a parameter."
    )
    task = {
        "task_id": "job-task",
        "task_unit_id": "job-task",
        "prompt": prompt,
        "cwe": "CWE-78",
        "task_family": "command_execution",
    }
    proposal = {
        "facts": [
            _fact(
                "source",
                "source",
                "source.untrusted_command_argument",
                "The command must include the job ID as a parameter",
                caller_controlled=True,
            ),
            _fact(
                "sink",
                "sink",
                "sink.process_execution",
                "Use subprocess to execute one command",
            ),
        ],
        "relations": [
            {"edge_type": "flows_to", "source": "source", "target": "sink"}
        ],
        "unresolved_semantics": ["constraint.fixed_executable"],
    }

    def provider(request, evaluator, _prompt):
        import json

        if request.get("request_kind") != "prompt_tsg_bounded_ambiguity_adjudication":
            assert evaluator["candidate_id"] == "proposer-v1"
            return json.dumps(proposal).encode()
        assert evaluator["candidate_id"] == "reviewer-v2"
        assert request["candidate_semantics"]["constraint.fixed_executable"][
            "proposer_status"
        ] == "unresolved"
        assert [
            "source.untrusted_command_argument",
            "flows_to",
            "sink.process_execution",
        ] in request["allowed_relations"]
        return json.dumps(
            {
                "facts": [
                    _fact(
                        "review-source",
                        "source",
                        "source.untrusted_command_argument",
                        "The command must include the job ID as a parameter",
                    ),
                    _fact(
                        "review-sink",
                        "sink",
                        "sink.process_execution",
                        "Use subprocess to execute one command",
                    ),
                    _fact(
                        "review-fixed",
                        "constraint",
                        "constraint.fixed_executable",
                        "one command that retrieves the job exit code",
                    ),
                ],
                "relations": [
                    {
                        "edge_type": "flows_to",
                        "source": "review-source",
                        "target": "review-sink",
                    }
                ],
                "unresolved_semantics": [],
            }
        ).encode()

    graph, _, _, projection = extract_prompt_tsg(
        task,
        catalog=catalog,
        evaluator={"candidate_id": "proposer-v1"},
        system_prompt="propose facts",
        reviewer_evaluator={"candidate_id": "reviewer-v2"},
        reviewer_prompt="adjudicate ambiguity",
        provider=provider,
    )

    query = query_for_realization(catalog, "cwe78_fixed_executable_argv")
    assert query_context(
        graph,
        query=query,
        cwe="CWE-78",
        task_family="command_execution",
    ).state is QueryState.PRESENT
    assert "constraint.fixed_executable" in projection["semantic_review"][
        "accepted_semantics"
    ]
    assert projection["semantic_review"]["unsupported_proposer_ambiguities"] == []


@pytest.mark.reviewer
def test_empty_catalog_candidate_scope_skips_semantic_provider():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v3.json")
    prompt = "Return deserialized pickled data from the request."
    task = {
        "task_id": "pickle-task",
        "task_unit_id": "pickle-task",
        "prompt": prompt,
        "cwe": "CWE-502",
        "task_family": "deserialization",
    }
    proposal = {
        "facts": [
            _fact(
                "requirement",
                "task_requirement",
                "task.requirement",
                prompt,
            )
        ],
        "relations": [],
        "unresolved_semantics": [],
    }
    calls = []

    def provider(_request, evaluator, _prompt):
        import json

        calls.append(evaluator["candidate_id"])
        if evaluator["candidate_id"] != "proposer-v1":
            raise AssertionError("empty candidate scope must not call semantic reviewer")
        return json.dumps(proposal).encode()

    graph, _, _, projection = extract_prompt_tsg(
        task,
        catalog=catalog,
        evaluator={"candidate_id": "proposer-v1"},
        system_prompt="propose facts",
        reviewer_evaluator={"candidate_id": "reviewer-v2"},
        reviewer_prompt="adjudicate ambiguity",
        provider=provider,
    )

    assert calls == ["proposer-v1"]
    assert {node.semantic_id for node in graph.nodes} == {
        "task.root",
        "task.requirement",
    }
    assert projection["semantic_review"]["provider_called"] is False


@pytest.mark.reviewer
def test_external_qualification_replays_structured_authority_identity(tmp_path: Path):
    report = qualify_prompt_tsg_extractor(
        ROOT,
        ROOT / "data/method/prompt-tsg-external-qualification-tasks-v1.json",
        ROOT / "data/method/results/prompt-tsg-external-extraction-v1",
        ROOT / "data/method/prompt-tsg-catalog-v5.json",
        ROOT / "data/method/mechanism-registry-v1.json",
        ROOT / "data/method/prompt-tsg-external-qualification-gold-v1.json",
        tmp_path / "qualification",
        path_authority_annotations_path=(
            ROOT / "data/method/prompt-tsg-external-path-authority-v1.json"
        ),
    )

    assert report["status"] == "QUALIFICATION_FAILED"
    assert report["exact_context_accuracy"] == 0.875
    assert report["present_recall"] == 0.6
    assert report["false_positive_present"] == 0
    assert report["wrong_realization"] == 1
    assert report["path_authority_annotated_tasks"] == 3
