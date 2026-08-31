import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import bundle_digest, verify_bundle
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


def _model_response(value):
    return json.dumps(
        {
            **value,
            "facts": [
                {key: item for key, item in fact.items() if key != "node_type"}
                for fact in value["facts"]
            ],
        }
    ).encode()


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
def test_prospective_catalog_excludes_fixed_security_values_from_randomness():
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v11.json")

    assert "fixed literal security token" in catalog["semantic_guidance"][
        "constraint.reproducible_pseudorandom_required"
    ]
    random_query = next(
        query
        for query in catalog["queries"]
        if query["realization_id"] == "cwe338_security_sensitive_randomness"
    )
    assert "constraint.reproducible_pseudorandom_required" in random_query[
        "forbidden_semantics"
    ]


def test_compiled_extractor_candidate_files_share_the_model_fact_contract():
    proposer = json.loads(
        (ROOT / "data/method/prompt-tsg-extractor-qwen37max-v17.json").read_text()
    )
    reviewer = json.loads(
        (
            ROOT
            / "data/method/prompt-tsg-ambiguity-adjudication-qwen37max-v7.json"
        ).read_text()
    )
    proposer_prompt = (
        ROOT / "data/method/prompts/prompt-tsg-facts-v15.txt"
    ).read_text()
    reviewer_prompt = (
        ROOT / "data/method/prompts/prompt-tsg-ambiguity-adjudication-v3.txt"
    ).read_text()

    assert proposer["candidate_id"].endswith("-v17")
    assert reviewer["candidate_id"].endswith("-v7")
    for prompt in (proposer_prompt, reviewer_prompt):
        assert "exactly local_id, semantic_id, evidence_text, occurrence, attributes" in prompt
        assert "never copy node_type into a fact" in prompt
    assert "asserted, unresolved, or omitted" in reviewer_prompt



def test_legacy_deveval_v4_freeze_verifies_against_its_original_commit():
    tasks_path = ROOT / "data/method/prompt-tsg-external-qualification-tasks-v4.json"
    tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
    selection = json.loads(
        (
            ROOT
            / "data/method/prompt-tsg-external-qualification-selection-v4.json"
        ).read_text(encoding="utf-8")
    )
    gold = json.loads(
        (ROOT / "data/method/prompt-tsg-external-qualification-gold-v4.json").read_text(
            encoding="utf-8"
        )
    )
    source = json.loads(
        (
            ROOT / "data/method/prompt-tsg-external-qualification-source-v4.json"
        ).read_text(encoding="utf-8")
    )
    freeze = json.loads(
        (
            ROOT / "data/method/prompt-tsg-external-qualification-freeze-v4.json"
        ).read_text(encoding="utf-8")
    )
    catalog = load_catalog(ROOT / "data/method/prompt-tsg-catalog-v11.json")

    task_ids = [row["task_id"] for row in tasks]
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
    assert source["source"]["commit"] == (
        "c1653455e0a18480a29aa07ba51636070f113316"
    )
    assert source["source"]["source_sha256"] == (
        "1798383d278e7dc907f4568cd9369bd424884298e4cf88af8c9ec55a08c5dbab"
    )
    assert source["population_rule"]["frozen_task_units"] == 31
    assert sum(source["population_rule"]["family_quotas"].values()) == 31
    for family, upstream_ids in source["population_rule"][
        "selected_upstream_ids_by_family"
    ].items():
        assert upstream_ids == [
            row["source"]["upstream_id"]
            for row in tasks
            if row["task_family"] == family
        ]
    assert sum(row["expected_context"] == "present" for row in gold["cases"]) == 16

    positive_realizations = sorted(
        {
            row["expected_realization_id"]
            for row in gold["cases"]
            if row["expected_context"] == "present"
        }
    )
    assert positive_realizations == freeze["candidate_support_realization_ids"]
    assert positive_realizations == source["support_scope"][
        "candidate_realization_ids_with_expected_present_gold"
    ]
    catalog_realizations = sorted(
        {query["realization_id"] for query in catalog["queries"]}
    )
    assert sorted(set(catalog_realizations) - set(positive_realizations)) == source[
        "support_scope"
    ]["catalog_realization_ids_without_expected_present_gold"]

    for item in freeze["inputs"].values():
        if item["path"].startswith("src/"):
            payload = subprocess.check_output(
                [
                    "git",
                    "show",
                    f'{freeze["method_revision_commit"]}:{item["path"]}',
                ],
                cwd=ROOT,
            )
        else:
            payload = (ROOT / item["path"]).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
    assert freeze["model_requests_observed_before_freeze"] is False
    assert freeze["arms_or_outcomes_used"] is False

    exposed_prompt_hashes = {
        row["prompt_sha256"]
        for version in ("v1", "v2", "v3")
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

    failure = json.loads(
        (
            ROOT / "data/method/prompt-tsg-external-qualification-v4-failure.json"
        ).read_text(encoding="utf-8")
    )
    extraction = ROOT / failure["extractor_bundle_path"]
    qualification = ROOT / failure["qualification_bundle_path"]
    verify_bundle(extraction)
    verify_bundle(qualification)
    assert bundle_digest(extraction) == failure["extractor_bundle_sha256"]
    assert bundle_digest(qualification) == failure["qualification_bundle_sha256"]
    for key in ("catalog", "freeze", "source_manifest"):
        assert failure[f"{key}_sha256"] == hashlib.sha256(
            (ROOT / failure[f"{key}_path"]).read_bytes()
        ).hexdigest()
    assert failure["tasks_sha256"] == hashlib.sha256(tasks_path.read_bytes()).hexdigest()
    assert failure["selection_sha256"] == hashlib.sha256(
        (
            ROOT
            / "data/method/prompt-tsg-external-qualification-selection-v4.json"
        ).read_bytes()
    ).hexdigest()
    assert failure["gold_sha256"] == hashlib.sha256(
        (
            ROOT / "data/method/prompt-tsg-external-qualification-gold-v4.json"
        ).read_bytes()
    ).hexdigest()

    extraction_report = json.loads(
        (extraction / "report.json").read_text(encoding="utf-8")
    )
    qualification_report = json.loads(
        (qualification / "qualification.json").read_text(encoding="utf-8")
    )
    assert extraction_report["status"] == "PROMPT_TSG_EXTRACTION_COMPLETE"
    assert extraction_report["graphs"] == failure["execution"]["completed_graphs"] == 31
    assert '"node_type"' not in (extraction / "responses.json").read_text(
        encoding="utf-8"
    )
    assert qualification_report["status"] == failure["status"] == "QUALIFICATION_FAILED"
    for metric in (
        "matched_task_units",
        "mismatched_task_units",
        "exact_context_accuracy",
        "present_recall",
        "false_positive_present",
        "wrong_realization",
    ):
        assert qualification_report[metric] == failure["qualification"][metric]
    assert len(failure["mismatches"]) == 4
    assert failure["scientific_claim_allowed"] is False



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
            return _model_response(review)
        return _model_response(response)

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
        provider=lambda *_: _model_response(response),
    )
    query = query_for_realization(catalog, "cwe22_path_confinement")

    assert query_context(
        graph,
        query=query,
        cwe="CWE-22",
        task_family="path_access",
    ).state is expected
    assert projection["path_authority"]["projection_status"] == "applied"


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
        provider=lambda *_: _model_response(response),
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

        return _model_response(response)

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
    assert request["schema_version"] == "2.0"
    assert "node_type" not in request["output_contract"]["fact_keys"]
    assert "source.untrusted_sql_value" not in request["candidate_semantics"]
    assert request["arms_or_outcomes_included"] is False

    def provider(actual_request, _evaluator, _prompt):
        assert actual_request == request
        import json

        return _model_response(response)

    evaluator = {"candidate_id": "llm-facts-v1"}
    graph, _, _, projection = extract_prompt_tsg(
        task,
        catalog=catalog,
        evaluator=evaluator,
        system_prompt="extract facts",
        provider=provider,
    )
    assert graph.task_id == "task-1"
    assert next(
        node for node in graph.nodes if node.semantic_id == "sink.process_execution"
    ).node_type == "sink"
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

        return _model_response(response)

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

        return _model_response(response)

    with pytest.raises(ValueError, match="catalog-bound"):
        extract_prompt_tsg(
            task,
            catalog=catalog,
            evaluator={"candidate_id": "llm-facts-v1"},
            system_prompt="extract facts",
            provider=provider,
        )


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

        return _model_response(response)

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
        return _model_response(value)

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
            return _model_response(review)
        assert evaluator["candidate_id"] == "proposer-v1"
        return _model_response(proposal)

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


def test_blind_semantic_reviewer_can_recover_an_omitted_task_slice_fact():
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
        "unresolved_semantics": [],
    }

    def provider(request, evaluator, _prompt):
        import json

        if request.get("request_kind") != "prompt_tsg_bounded_ambiguity_adjudication":
            assert evaluator["candidate_id"] == "proposer-v1"
            return _model_response(proposal)
        assert evaluator["candidate_id"] == "reviewer-v2"
        assert request["candidate_semantics"]["constraint.fixed_executable"][
            "proposer_status"
        ] == "omitted"
        assert [
            "source.untrusted_command_argument",
            "flows_to",
            "sink.process_execution",
        ] in request["allowed_relations"]
        return _model_response(
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
        )

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
    assert projection["semantic_review"]["reviewer_recovered_semantics"] == [
        "constraint.fixed_executable"
    ]
    assert projection["semantic_review"]["unsupported_proposer_ambiguities"] == []


def test_full_task_slice_review_does_not_force_an_unsupported_format():
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
    review = {"facts": [], "relations": [], "unresolved_semantics": []}
    calls = []

    def provider(request, evaluator, _prompt):
        import json

        calls.append(evaluator["candidate_id"])
        if evaluator["candidate_id"] == "proposer-v1":
            return _model_response(proposal)
        assert evaluator["candidate_id"] == "reviewer-v2"
        assert all(
            value["proposer_status"] == "omitted"
            for value in request["candidate_semantics"].values()
        )
        return _model_response(review)

    graph, _, _, projection = extract_prompt_tsg(
        task,
        catalog=catalog,
        evaluator={"candidate_id": "proposer-v1"},
        system_prompt="propose facts",
        reviewer_evaluator={"candidate_id": "reviewer-v2"},
        reviewer_prompt="adjudicate ambiguity",
        provider=provider,
    )

    assert calls == ["proposer-v1", "reviewer-v2"]
    assert {node.semantic_id for node in graph.nodes} == {
        "task.root",
        "task.requirement",
    }
    assert projection["semantic_review"]["provider_called"] is True
    assert projection["semantic_review"]["reviewer_recovered_semantics"] == []


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
    assert report["positive_gold_realization_ids"] == sorted(
        {
            case["expected_realization_id"]
            for case in json.loads(
                (
                    ROOT
                    / "data/method/prompt-tsg-external-qualification-gold-v1.json"
                ).read_text(encoding="utf-8")
            )["cases"]
            if case["expected_context"] == "present"
        }
    )
