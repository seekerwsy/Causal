"""Representation sees the same baseline semantics as generation, without outcomes."""

import json
from copy import deepcopy
import pytest
from annotation_fixture import indexed_annotation
from prompt_mechanism_study.prompt_contract import open_concept_catalog
from prompt_mechanism_study.prompt_contract_extract import extract_task_contract, contract_decision_request
from prompt_mechanism_study.prompt_tsg import validate_prompt_tsg
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.task_input import (
    prepare_task_input,
    generation_input_for_prompt,
    input_evidence_text,
)


def test_actual_messages_are_the_graph_evidence_and_raw_source_survives():
    source = "Generate <language> code. Read the file named <filename>."
    system = "Preserve the requested return value. Return Python source."
    task = dict(task_id="synthetic-input", language="python", prompt=source,
                prompt_sha256=content_hash(source), generation_system_prompt=system,
                cwe="CWE-22", task_family="file", arm="TARGET", seed=99, outcome=1)
    prepared = prepare_task_input(task)
    assert task["prompt"] == source == prepared["source_prompt"]
    assert prepared["generation_input"] == {
        "system_prompt": system,
        "request": {"language": "python", "task": "Generate python code. Read the file named <filename>."},
    }
    assert prepare_task_input(prepared) == prepared
    assert generation_input_for_prompt(prepared, prepared["prompt"]) == prepared["generation_input"]
    seen = []
    def annotate(request, evaluator, instructions):
        seen.append(request)
        assert request["source_prompt"] == input_evidence_text(prepared["generation_input"])
        assert not {"arm", "seed", "outcome", "cwe", "task_id", "task_family"} & set(request)
        return json.dumps(indexed_annotation(request, dict(
            concepts=[
                dict(concept_id="read_file", node_type="task_operation", definition="Read the named file."),
                dict(concept_id="preserve_return", node_type="task_requirement", definition="Preserve the requested return value."),
                dict(concept_id="python_language", node_type="constraint", definition="Use Python."),
                dict(concept_id="code.implementation", node_type="task_operation", definition="Produce the requested implementation."),
            ],
            nodes=[dict(local_id="op", concept_id="read_file", evidence_text="Read the file", occurrence=1),
                   dict(local_id="req", concept_id="preserve_return", evidence_text="Preserve the requested return value.", occurrence=1, layer="generation"),
                   dict(local_id="lang", concept_id="python_language", evidence_text="Language: python", occurrence=1, layer="generation"),
                   dict(local_id="implementation", concept_id="code.implementation", evidence_text="Return Python source.", occurrence=1, layer="generation")],
            edges=[], concept_states=[], feature_states=[], unresolved_notes=[],
        ))).encode()
    catalog = open_concept_catalog()
    contract, graph, request, raw = extract_task_contract(
        task, catalog=catalog, evaluator={"candidate_id": "offline-fixture"},
        annotator_prompt="Extract only supplied evidence.", review_status="development_exposed", provider=annotate,
    )
    assert [r["request_kind"] for r in seen] == ["source_only_atomic_records", "source_only_record_review"]
    validate_prompt_tsg(graph, prompt=prepared["prompt"], catalog=contract.catalog)
    assert graph.prompt_sha256 == content_hash(prepared["prompt"])
    quotes = {prepared["prompt"][n.evidence_start:n.evidence_end] for n in graph.nodes}
    assert {"Preserve the requested return value.", "python", "Read the file"} <= quotes
    changed = {**task, "cwe": "different", "task_family": "different", "outcome": 0, "arm": "BASELINE", "seed": 1}
    from prompt_mechanism_study.source_records import record_request
    assert record_request(contract_decision_request(changed, catalog)) == request


def test_missing_language_or_changed_common_context_cannot_reach_generation():
    with pytest.raises(ValueError, match="explicit language"):
        prepare_task_input({"prompt": "Generate <language> code."})
    with pytest.raises(ValueError, match="explicit generation system"):
        prepare_task_input({"prompt": "Generate <language> code.", "language": "java"})
    task = prepare_task_input({"prompt": "Generate <language> code.", "language": "python"})
    changed = deepcopy(task)
    changed["generation_input"]["request"]["language"] = "java"
    with pytest.raises(ValueError, match="prepared task input changed"):
        prepare_task_input(changed)
    with pytest.raises(ValueError, match="re-extract"):
        prepare_task_input(task, generation_system_prompt="Use another library.")
    with pytest.raises(ValueError, match="common system or language"):
        generation_input_for_prompt(task, task["prompt"].replace("Language: python", "Language: java"))
