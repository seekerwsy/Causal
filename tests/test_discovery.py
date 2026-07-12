from __future__ import annotations

from dataclasses import fields
from dataclasses import FrozenInstanceError
import hashlib
import inspect
from types import MappingProxyType

import pytest
from pydantic import ValidationError

from secaware.discovery.candidate_enum import FACTOR_SPECS, FactorSpec
from secaware.discovery.tsg_qcd import discover_hypotheses
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.schema.hypotheses import FactorType, HypothesisRecord
from secaware.schema.oracle import OracleRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import MotifId
from secaware.tsg.catalog import prompt_ontology_entry
from secaware.tsg.motifs import MOTIF_SPECS


def _path_prompt(prompt_id: str, *, guarded: bool) -> PromptRecord:
    text = "Open a user-provided file path."
    if guarded:
        text += " Normalize the path."
    return PromptRecord(
        prompt_id=prompt_id,
        split="discover",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt=text,
    )


def _oracle(prompt_id: str, *, insecure: bool, cwe: str = "CWE-22") -> OracleRecord:
    digest = hashlib.sha256(prompt_id.encode()).hexdigest()
    finding = {
        "schema_version": "1.0",
        "analyzer": "semgrep",
        "rule_id": "reviewed.rule",
        "cwe": cwe,
        "severity": "high",
        "confidence": "not_provided",
        "line": 1,
        "column": 1,
        "end_line": 1,
        "end_column": 2,
        "message": "Reviewed security finding.",
    }
    return OracleRecord.model_validate(
        {
            "schema_version": "1.0",
            "request_id": f"req_{digest}",
            "code_id": f"code_{digest}",
            "code_sha256": "c" * 64,
            "prompt_id": prompt_id,
            "condition": "observed",
            "model_id": "model-a",
            "seed_id": 1,
            "hypothesis_id": None,
            "intervention_id": None,
            "parse_ok": True,
            "functional_ok": True,
            "security_label": "insecure" if insecure else "secure",
            "severity": "high" if insecure else "none",
            "findings": [finding] if insecure else [],
            "analyzers": [
                {
                    "schema_version": "1.0",
                    "analyzer": analyzer,
                    "version": "1.0",
                    "policy_sha256": policy,
                }
                for analyzer, policy in (("semgrep", "a" * 64), ("bandit", "b" * 64))
            ],
        }
    )


def test_factor_specs_are_typed_immutable_and_derived_from_reviewed_catalogs() -> None:
    assert {field.name for field in fields(FactorSpec)} == {
        "factor_type",
        "motif_id",
        "requirement_label",
        "guard_label",
        "patch_operator",
        "cwe",
        "task_family",
        "label",
    }
    assert isinstance(FACTOR_SPECS, MappingProxyType)
    assert tuple(FACTOR_SPECS) == tuple(FactorType)
    assert len(FACTOR_SPECS) == 6

    for factor_type, spec in FACTOR_SPECS.items():
        motif_spec = next(item for item in MOTIF_SPECS.values() if item.factor_type is factor_type)
        catalog = prompt_ontology_entry(factor_type)
        assert spec.factor_type is factor_type
        assert type(spec.motif_id) is MotifId
        assert spec.motif_id is motif_spec.motif_id
        assert spec.requirement_label == motif_spec.requirement_label == catalog.requirement_label
        assert spec.guard_label == motif_spec.guard_label == catalog.guard_label
        assert spec.cwe == catalog.cwe

    with pytest.raises(TypeError):
        FACTOR_SPECS[FactorType.PATH_NORMALIZATION] = FACTOR_SPECS[  # type: ignore[index]
            FactorType.PATH_NORMALIZATION
        ]
    with pytest.raises(FrozenInstanceError):
        FACTOR_SPECS[FactorType.PATH_NORMALIZATION].cwe = "CWE-999"  # type: ignore[misc]


def test_hypothesis_record_uses_typed_graph_contract_without_legacy_aliases() -> None:
    payload = {
        "hypothesis_id": "h-path",
        "factor_type": FactorType.PATH_NORMALIZATION,
        "motif_id": MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD,
        "requirement_label": "require_path_normalization",
        "guard_label": "path_normalization",
        "expected_direction": "risk_down_when_added",
        "scope": {"language": "python", "cwe": "CWE-22", "task_family": "path_handling"},
        "patch_operator": "add_path_normalization_requirement",
    }
    record = HypothesisRecord.model_validate(payload)
    assert record.motif_id is MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD
    assert "prompt_factor" not in type(record).model_fields
    assert "mechanism_motif" not in type(record).model_fields

    with pytest.raises(ValidationError):
        HypothesisRecord.model_validate({**payload, "prompt_factor": "factor.path"})


def test_prompt_graph_formula_does_not_accept_code_graph_input() -> None:
    signature = inspect.signature(discover_hypotheses)
    assert "code_tsgs" not in signature.parameters


def test_discovery_is_deterministic_and_emits_bounded_graph_evidence() -> None:
    unsafe_prompt = _path_prompt("p-unsafe", guarded=False)
    safe_prompt = _path_prompt("p-safe", guarded=True)
    prompts = [unsafe_prompt, safe_prompt]
    graphs = [extract_prompt_tsg(prompt) for prompt in prompts]
    oracles = [
        _oracle("p-unsafe", insecure=True, cwe="CWE-22"),
        _oracle("p-safe", insecure=False),
    ]

    one, selected_one = discover_hypotheses(
        prompts,
        graphs,
        oracles,
        min_support_total=2,
        min_support_each_side=1,
    )
    two, selected_two = discover_hypotheses(
        list(reversed(prompts)),
        list(reversed(graphs)),
        list(reversed(oracles)),
        min_support_total=2,
        min_support_each_side=1,
    )

    assert [item.model_dump() for item in one] == [item.model_dump() for item in two]
    assert [item.hypothesis_id for item in selected_one] == [
        item.hypothesis_id for item in selected_two
    ]
    assert len(one) == 1
    hypothesis = one[0]
    assert hypothesis.factor_type is FactorType.PATH_NORMALIZATION
    assert hypothesis.motif_id is MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD
    assert hypothesis.requirement_label == "require_path_normalization"
    assert hypothesis.guard_label == "path_normalization"
    assert hypothesis.support["motif_id"] == hypothesis.motif_id.value
    assert hypothesis.support["motif_prompt_count"] == 1
    assert hypothesis.support["motif_match_count"] >= 1
    assert hypothesis.support["graph_sha256"] == sorted(graph.graph_sha256 for graph in graphs)
    assert len(hypothesis.support["graph_sha256"]) <= len(graphs)
    assert all(len(digest) == 64 for digest in hypothesis.support["graph_sha256"])
    assert set(hypothesis.support) >= {
        "association_raw",
        "motif_id",
        "motif_prompt_count",
        "motif_match_count",
        "graph_sha256",
    }
    rendered_support = repr(hypothesis.support)
    assert all(prompt.prompt not in rendered_support for prompt in prompts)
    assert "Reviewed security finding." not in rendered_support


@pytest.mark.parametrize("duplicate_kind", ("prompt", "graph"))
def test_discovery_rejects_duplicate_coordinates(duplicate_kind: str) -> None:
    prompt = _path_prompt("p-duplicate", guarded=False)
    graph = extract_prompt_tsg(prompt)
    prompts = [prompt, prompt] if duplicate_kind == "prompt" else [prompt]
    graphs = [graph] if duplicate_kind == "prompt" else [graph, graph]

    with pytest.raises(SecAwareError) as exc_info:
        discover_hypotheses(prompts, graphs, [])

    assert exc_info.value.code is ErrorCode.ANALYSIS_INVALID
    assert exc_info.value.details == {}
    assert exc_info.value.__cause__ is None


def test_coordinate_errors_do_not_retain_raw_prompt_in_discovery_frames() -> None:
    sentinel = "RAW_PROMPT_SENTINEL_98341"
    prompt = PromptRecord(
        prompt_id="p-sensitive",
        split="discover",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt=sentinel,
    )

    with pytest.raises(SecAwareError) as exc_info:
        discover_hypotheses([prompt, prompt], [], [])

    retained = []
    frame = exc_info.value.__traceback__
    while frame is not None:
        if "/src/secaware/" in frame.tb_frame.f_code.co_filename.replace("\\", "/"):
            retained.append(repr(frame.tb_frame.f_locals))
        frame = frame.tb_next
    assert sentinel not in "\n".join(retained)


def test_discovery_rejects_missing_or_extra_graph_coordinates() -> None:
    prompt = _path_prompt("p-required", guarded=False)
    extra = _path_prompt("p-extra", guarded=False)

    for graphs in ([], [extract_prompt_tsg(prompt), extract_prompt_tsg(extra)]):
        with pytest.raises(SecAwareError) as exc_info:
            discover_hypotheses([prompt], graphs, [])
        assert exc_info.value.code is ErrorCode.ANALYSIS_INVALID


def test_discovery_rejects_tampered_prompt_graph() -> None:
    prompt = _path_prompt("p-tampered", guarded=False)
    graph = extract_prompt_tsg(prompt)
    forged = graph.model_copy(update={"graph_sha256": "0" * 64})

    with pytest.raises(SecAwareError) as exc_info:
        discover_hypotheses([prompt], [forged], [])

    assert exc_info.value.code is ErrorCode.TSG_INVALID


def test_discovery_revalidates_every_oracle_record_before_grouping() -> None:
    prompt = _path_prompt("p-oracle-boundary", guarded=False)
    record = _oracle("p-unrelated", insecure=True)
    forged = record.model_copy(update={"findings": ()})

    with pytest.raises(ValidationError):
        discover_hypotheses([prompt], [extract_prompt_tsg(prompt)], [forged])


def test_discovery_source_has_no_legacy_feature_or_code_graph_dependencies() -> None:
    forbidden = (
        "features.get",
        ".features",
        ".shadow",
        "code_tsg",
        "prompt_factor",
        "prompt_motif",
    )
    source_dir = inspect.getfile(discover_hypotheses)
    discovery_dir = __import__("pathlib").Path(source_dir).parent
    source = "\n".join(path.read_text(encoding="utf-8") for path in discovery_dir.glob("*.py"))
    assert all(token not in source for token in forbidden)
