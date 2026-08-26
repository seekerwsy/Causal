import hashlib
import json
from pathlib import Path

import pytest

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
from prompt_mechanism_study.four_arm import _intervention_unit, apply_tsg_exclusion_ledger
from prompt_mechanism_study.mechanisms import (
    load_mechanism_registry,
    tsg_mechanism_binding,
)
from prompt_mechanism_study.records import content_hash


pytestmark = pytest.mark.reviewer

ROOT = Path(__file__).parents[1]
CATALOG_PATH = ROOT / "data/method/prompt-tsg-catalog-v1.json"
PROMPT = "Run the fixed git executable with a user-provided branch name and return its output."


def test_contract_review_applies_only_frozen_exclusions(tmp_path: Path) -> None:
    source = tmp_path / "source.jsonl"
    source.write_text('{"task_id":"a"}\n{"task_id":"b"}\n', encoding="utf-8")
    review = tmp_path / "review.json"
    review.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "review_name": "test",
                "source_tasks_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "outcome_values_used": False,
                "exclusions": [
                    {
                        "task_id": "b",
                        "reason_code": "contract_mismatch",
                        "explanation": "The task does not share the frozen contract.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "retained.jsonl"
    report = apply_tsg_exclusion_ledger(source, review, output, tmp_path / "report")
    assert report["retained_tasks"] == 1
    assert json.loads(output.read_text(encoding="utf-8"))["task_id"] == "a"


def _fact(local_id, node_type, semantic_id, evidence_text, **attributes):
    return {
        "local_id": local_id,
        "node_type": node_type,
        "semantic_id": semantic_id,
        "evidence_text": evidence_text,
        "occurrence": 1,
        "attributes": attributes,
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
        "semantic_cluster_id": "task-1",
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
    assert report["arms_or_outcomes_used"] is False


def test_tsg_binding_drives_llm_intervention_and_deterministic_arm_patches():
    catalog, graph = _command_graph()
    registry = load_mechanism_registry(ROOT / "data/formal/four-arm-mechanisms-v3.json")
    task = {
        "task_id": "task-1",
        "semantic_cluster_id": "task-1",
        "cwe": "CWE-78",
        "task_family": "command_execution",
        "prompt": PROMPT,
        "source_prompt_sha256": content_hash(PROMPT),
        "oracle_profile_id": "python.cwe78.function_parameter_subprocess.v2",
        "functional_contract": {
            "requirements": [{"requirement_id": "req_1", "criterion": "return output"}]
        },
    }
    binding = tsg_mechanism_binding(task, graph, catalog, registry)
    assert binding["decision"] == "applicable"
    task.update(
        {
            "realization_id": binding["realization_id"],
            "prompt_tsg": prompt_tsg_record(graph),
            "prompt_tsg_binding": binding,
        }
    )
    calls = 0

    def provider(request, _evaluator, _prompt):
        nonlocal calls
        calls += 1
        assert "task_context" not in request
        assert request["prompt_tsg_context"]["prompt_tsg_id"] == graph.tsg_id
        if calls == 1:
            return json.dumps(
                {
                    "specific_text": (
                        "Pass command arguments as a sequence and keep shell execution disabled."
                    )
                }
            ).encode()
        return json.dumps(
            {
                "specific": {
                    "required_delta_satisfied": True,
                    "forbidden_delta_absent": True,
                    "functional_contract_preserved": True,
                    "input_format_preserved": True,
                    "interface_preserved": True,
                    "extra_security_mechanism_absent": True,
                },
                "generic": {
                    "target_mechanism_absent": True,
                    "generic_security_present": True,
                    "functional_contract_preserved": True,
                },
                "placebo": {
                    "target_mechanism_absent": True,
                    "generic_security_absent": True,
                    "functional_contract_preserved": True,
                    "style_only": True,
                },
                "reason": "The suffixes match their frozen roles.",
            }
        ).encode()

    inputs = {
        "registry": registry,
        "executor": {},
        "validator": {},
        "executor_prompt": "executor",
        "validator_prompt": "validator",
        "prompt_tsg_catalog": catalog,
        "config": {
            "intervention": {
                "generic_text": "Apply appropriate security safeguards while preserving behavior.",
                "placebo_text": "Use descriptive local variable names and consistent formatting.",
                "placebo_forbidden_terms": ["security", "secure", "validate", "query"],
                "maximum_suffix_characters": 360,
            }
        },
    }
    artifacts, passed = _intervention_unit(inputs, task, provider)

    assert passed is True
    variants = artifacts["prompt-tsg-variants.json"]["arm_prompt_tsgs"]
    assert set(variants) == {"absent", "specific", "generic", "placebo"}
    assert variants["absent"]["tsg_id"] == graph.tsg_id
    assert variants["specific"]["tsg_id"] != variants["generic"]["tsg_id"]
