from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest
from pydantic import ValidationError

from secaware.errors import SecAwareError
from secaware.schema.features import FeatureState, PromptExtractorBackend
from secaware.schema.prompt_extraction import (
    EvidenceSpan,
    PromptExtractionProposalRecord,
    proposal_id_for_payload,
)
from secaware.schema.records import PromptRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
)
from secaware.tsg.proposal_validator import validate_proposal


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _prompt(text: str = "Read a user-provided file path and normalize the path.") -> PromptRecord:
    return PromptRecord(
        prompt_id="p-contract",
        task_id="task-contract",
        split="discover",
        language="python",
        task_family="file_access",
        cwe="CWE-22",
        prompt=text,
    )


def _applicable(feature_id: str) -> bool:
    spec = next(item for item in PROMPT_FEATURE_CATALOG if item.feature_id == feature_id)
    cwe_ok = not spec.applicable_cwes or "CWE-22" in spec.applicable_cwes
    family_ok = not spec.applicable_task_families or "file_access" in spec.applicable_task_families
    return cwe_ok and family_ok


def _facts_payload(*, reverse: bool = False) -> dict[str, object]:
    prompt = _prompt()
    facts: list[dict[str, object]] = []
    present = {
        "task.file_read": "user-provided file path",
        "safety.path_normalization": "normalize the path",
    }
    for spec in PROMPT_FEATURE_CATALOG:
        state = (
            FeatureState.PRESENT
            if spec.feature_id in present
            else FeatureState.ABSENT
            if _applicable(spec.feature_id)
            else FeatureState.NOT_APPLICABLE
        )
        evidence: list[dict[str, object]] = []
        if state is FeatureState.PRESENT:
            text = present[spec.feature_id]
            start = prompt.prompt.index(text)
            evidence.append(
                {
                    "start": start,
                    "end": start + len(text),
                    "text": text,
                    "text_sha256": _sha(text),
                }
            )
        facts.append(
            {
                "feature_id": spec.feature_id,
                "state": state,
                "semantic_role": "feature_state",
                "evidence": evidence,
                "relation_feature_ids": [],
            }
        )
    if reverse:
        facts.reverse()
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "prompt_id": prompt.prompt_id,
        "task_id": prompt.task_id,
        "prompt_sha256": _sha(prompt.prompt),
        "backend": PromptExtractorBackend.LLM_FACTS_V1,
        "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        "policy_sha256": "8" * 64,
        "response_sha256": _sha("facts-response"),
        "raw_response": "facts-response",
        "facts": facts,
        "direct_nodes": [],
        "direct_edges": [],
    }
    payload["proposal_id"] = proposal_id_for_payload(payload)
    return payload


def test_strict_records_are_immutable_and_forbid_unknown_fields() -> None:
    span = EvidenceSpan.model_validate(
        {"start": 0, "end": 1, "text": "x", "text_sha256": _sha("x")}
    )
    with pytest.raises((TypeError, ValidationError)):
        span.start = 1
    with pytest.raises(ValidationError):
        EvidenceSpan.model_validate(
            {
                "start": 0,
                "end": 1,
                "text": "x",
                "text_sha256": _sha("x"),
                "outcome": "secure",
            }
        )


def test_fact_payload_is_canonicalized_independent_of_input_order() -> None:
    one = PromptExtractionProposalRecord.model_validate(_facts_payload())
    two = PromptExtractionProposalRecord.model_validate(_facts_payload(reverse=True))

    assert one.facts == two.facts
    assert one.model_dump_json() == two.model_dump_json()


def test_validate_proposal_checks_unicode_character_offsets_and_exact_hashes() -> None:
    prompt = _prompt("界Read a user-provided file path and normalize the path.")
    payload = _facts_payload()
    payload["prompt_sha256"] = _sha(prompt.prompt)
    facts = payload["facts"]
    assert isinstance(facts, list)
    for fact in facts:
        assert isinstance(fact, dict)
        evidence = fact["evidence"]
        assert isinstance(evidence, list)
        for span in evidence:
            assert isinstance(span, dict)
            span["start"] += 1
            span["end"] += 1
    payload["proposal_id"] = proposal_id_for_payload(payload)
    proposal = PromptExtractionProposalRecord.model_validate(payload)

    assert validate_proposal(proposal, prompt) == proposal

    bad = proposal.model_dump(mode="python", round_trip=True)
    fact_with_evidence = next(fact for fact in bad["facts"] if fact["evidence"])
    fact_with_evidence["evidence"][0]["text_sha256"] = "0" * 64
    bad["proposal_id"] = proposal_id_for_payload(bad)
    with pytest.raises((ValidationError, SecAwareError)):
        validate_proposal(PromptExtractionProposalRecord.model_validate(bad), prompt)


def test_proposal_id_and_model_canonicalize_nested_evidence_order() -> None:
    payload = _facts_payload()
    prompt = _prompt()
    fact = next(item for item in payload["facts"] if item["feature_id"] == "task.file_read")
    second_text = "file path"
    second_start = prompt.prompt.index(second_text)
    fact["evidence"].append(
        {
            "start": second_start,
            "end": second_start + len(second_text),
            "text": second_text,
            "text_sha256": _sha(second_text),
        }
    )
    forward_id = proposal_id_for_payload(payload)
    fact["evidence"].reverse()
    reverse_id = proposal_id_for_payload(payload)
    payload["proposal_id"] = forward_id

    assert forward_id == reverse_id
    assert PromptExtractionProposalRecord.model_validate(payload).proposal_id == forward_id


def test_direct_contract_rejects_duplicate_edge_slot_with_different_evidence() -> None:
    prompt = _prompt()

    def span(text: str) -> dict[str, object]:
        start = prompt.prompt.index(text)
        return {
            "start": start,
            "end": start + len(text),
            "text": text,
            "text_sha256": _sha(text),
        }

    early = span("Read")
    middle = span("file path")
    late = span("normalize")
    node_evidence = [late]
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "prompt_id": prompt.prompt_id,
        "task_id": prompt.task_id,
        "prompt_sha256": _sha(prompt.prompt),
        "backend": PromptExtractorBackend.LLM_DIRECT_GRAPH_V1,
        "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        "policy_sha256": "9" * 64,
        "response_sha256": _sha("parallel-direct"),
        "raw_response": "parallel-direct",
        "facts": [],
        "direct_nodes": [
            {
                "local_id": "v1",
                "node_type": "prompt_requirement",
                "label": "safety.path_normalization:prompt_requirement",
                "feature_id": "safety.path_normalization",
                "evidence": node_evidence,
            },
            {
                "local_id": "v2",
                "node_type": "guard",
                "label": "safety.path_normalization:guard",
                "feature_id": "safety.path_normalization",
                "evidence": node_evidence,
            },
        ],
        "direct_edges": [
            {
                "src_local_id": "v1",
                "dst_local_id": "v2",
                "edge_type": "requires",
                "evidence": [late, early],
            },
            {
                "src_local_id": "v1",
                "dst_local_id": "v2",
                "edge_type": "requires",
                "evidence": [middle],
            },
        ],
    }
    payload["proposal_id"] = proposal_id_for_payload(payload)

    with pytest.raises(ValidationError):
        PromptExtractionProposalRecord.model_validate(payload)


def test_one_direct_edge_slot_accepts_multiple_order_invariant_evidence_spans() -> None:
    prompt = _prompt()

    def span(text: str) -> dict[str, object]:
        start = prompt.prompt.index(text)
        return {
            "start": start,
            "end": start + len(text),
            "text": text,
            "text_sha256": _sha(text),
        }

    evidence = [span("normalize"), span("Read")]
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "prompt_id": prompt.prompt_id,
        "task_id": prompt.task_id,
        "prompt_sha256": _sha(prompt.prompt),
        "backend": PromptExtractorBackend.LLM_DIRECT_GRAPH_V1,
        "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        "policy_sha256": "9" * 64,
        "response_sha256": _sha("single-direct-edge"),
        "raw_response": "single-direct-edge",
        "facts": [],
        "direct_nodes": [
            {
                "local_id": "v1",
                "node_type": "prompt_requirement",
                "label": "safety.path_normalization:prompt_requirement",
                "feature_id": "safety.path_normalization",
                "evidence": [span("normalize")],
            },
            {
                "local_id": "v2",
                "node_type": "guard",
                "label": "safety.path_normalization:guard",
                "feature_id": "safety.path_normalization",
                "evidence": [span("normalize")],
            },
        ],
        "direct_edges": [
            {
                "src_local_id": "v1",
                "dst_local_id": "v2",
                "edge_type": "requires",
                "evidence": evidence,
            }
        ],
    }
    payload["proposal_id"] = proposal_id_for_payload(payload)
    reverse = deepcopy(payload)
    reverse["direct_edges"][0]["evidence"].reverse()
    reverse["proposal_id"] = proposal_id_for_payload(reverse)

    one = PromptExtractionProposalRecord.model_validate(payload)
    two = PromptExtractionProposalRecord.model_validate(reverse)
    assert one.proposal_id == two.proposal_id
    assert one.direct_edges == two.direct_edges
    assert len(one.direct_edges[0].evidence) == 2

    one_record = build_prompt_tsg(one, prompt)
    two_record = build_prompt_tsg(two, prompt)
    assert one_record.graph_sha256 == two_record.graph_sha256
    assert one_record.nodes == two_record.nodes
    assert one_record.edges == two_record.edges


def test_validate_proposal_rejects_prompt_binding_and_fabricated_evidence() -> None:
    proposal = PromptExtractionProposalRecord.model_validate(_facts_payload())
    with pytest.raises(SecAwareError):
        validate_proposal(proposal, _prompt("Different prompt text."))

    payload = _facts_payload()
    payload["facts"][1]["evidence"][0]["text"] = "fabricated"
    payload["facts"][1]["evidence"][0]["text_sha256"] = _sha("fabricated")
    payload["proposal_id"] = proposal_id_for_payload(payload)
    with pytest.raises(SecAwareError):
        validate_proposal(PromptExtractionProposalRecord.model_validate(payload), _prompt())


def test_validate_proposal_normalizes_non_utf8_prompt_failure() -> None:
    proposal = PromptExtractionProposalRecord.model_validate(_facts_payload())
    prompt = _prompt()
    prompt.prompt = "\ud800"

    with pytest.raises(SecAwareError):
        validate_proposal(proposal, prompt)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(expected_outcome="secure"),
        lambda value: value.update(candidates=[{}, {}]),
        lambda value: value.update(response_sha256="0" * 64),
        lambda value: value.update(catalog_sha256="0" * 64),
        lambda value: value["facts"][0].update(feature_id="safety.unknown"),
        lambda value: value["facts"][0].update(semantic_role="not valid"),
        lambda value: value["facts"].append(dict(value["facts"][0])),
        lambda value: value["facts"][0].update(
            state=FeatureState.PRESENT,
            evidence=[],
        ),
        lambda value: value.update(raw_response="x" * 262_145),
    ],
)
def test_fact_contract_rejects_forbidden_digest_catalog_duplicate_and_bounds(mutation) -> None:
    payload = _facts_payload()
    mutation(payload)
    if set(payload) <= set(PromptExtractionProposalRecord.model_fields):
        payload["proposal_id"] = proposal_id_for_payload(payload)
    with pytest.raises(ValidationError):
        PromptExtractionProposalRecord.model_validate(payload)


def test_fact_contract_rejects_conflicting_state_and_mixed_backend_payload() -> None:
    payload = _facts_payload()
    conflict = dict(payload["facts"][0])
    conflict["semantic_role"] = "secondary"
    conflict["state"] = FeatureState.UNRESOLVED
    payload["facts"].append(conflict)
    payload["proposal_id"] = proposal_id_for_payload(payload)
    with pytest.raises(ValidationError):
        PromptExtractionProposalRecord.model_validate(payload)


def test_contract_rejects_duplicate_evidence_and_duplicate_direct_edges() -> None:
    payload = _facts_payload()
    fact = next(item for item in payload["facts"] if item["evidence"])
    fact["evidence"].append(dict(fact["evidence"][0]))
    payload["proposal_id"] = proposal_id_for_payload(payload)
    with pytest.raises(ValidationError):
        PromptExtractionProposalRecord.model_validate(payload)

    prompt = _prompt()
    text = "normalize the path"
    start = prompt.prompt.index(text)
    evidence = [
        {
            "start": start,
            "end": start + len(text),
            "text": text,
            "text_sha256": _sha(text),
        }
    ]
    direct: dict[str, object] = {
        "schema_version": "1.0",
        "prompt_id": prompt.prompt_id,
        "task_id": prompt.task_id,
        "prompt_sha256": _sha(prompt.prompt),
        "backend": PromptExtractorBackend.LLM_DIRECT_GRAPH_V1,
        "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        "policy_sha256": "9" * 64,
        "response_sha256": _sha("direct-response"),
        "raw_response": "direct-response",
        "facts": [],
        "direct_nodes": [
            {
                "local_id": "v1",
                "node_type": "prompt_requirement",
                "label": "path normalization requirement",
                "feature_id": "safety.path_normalization",
                "evidence": evidence,
            },
            {
                "local_id": "v2",
                "node_type": "guard",
                "label": "path normalization guard",
                "feature_id": "safety.path_normalization",
                "evidence": evidence,
            },
        ],
        "direct_edges": [
            {
                "src_local_id": "v1",
                "dst_local_id": "v2",
                "edge_type": "requires",
                "evidence": evidence,
            },
            {
                "src_local_id": "v1",
                "dst_local_id": "v2",
                "edge_type": "requires",
                "evidence": evidence,
            },
        ],
    }
    direct["proposal_id"] = proposal_id_for_payload(direct)
    with pytest.raises(ValidationError):
        PromptExtractionProposalRecord.model_validate(direct)


def test_raw_response_bound_is_in_characters_and_still_requires_valid_utf8() -> None:
    payload = _facts_payload()
    payload["raw_response"] = "界" * 100_000
    payload["response_sha256"] = _sha(payload["raw_response"])
    payload["proposal_id"] = proposal_id_for_payload(payload)

    assert (
        PromptExtractionProposalRecord.model_validate(payload).raw_response
        == payload["raw_response"]
    )

    payload = _facts_payload()
    payload["direct_nodes"] = [
        {
            "local_id": "v1",
            "node_type": "prompt_requirement",
            "label": "path normalization requirement",
            "feature_id": "safety.path_normalization",
            "evidence": payload["facts"][1]["evidence"],
        }
    ]
    payload["proposal_id"] = proposal_id_for_payload(payload)
    with pytest.raises(ValidationError):
        PromptExtractionProposalRecord.model_validate(payload)


def test_direct_contract_rejects_dangling_alias_and_illegal_feature_type() -> None:
    prompt = _prompt()
    text = "normalize the path"
    start = prompt.prompt.index(text)
    evidence = [
        {
            "start": start,
            "end": start + len(text),
            "text": text,
            "text_sha256": _sha(text),
        }
    ]
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "prompt_id": prompt.prompt_id,
        "task_id": prompt.task_id,
        "prompt_sha256": _sha(prompt.prompt),
        "backend": PromptExtractorBackend.LLM_DIRECT_GRAPH_V1,
        "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        "policy_sha256": "9" * 64,
        "response_sha256": _sha("direct-response"),
        "raw_response": "direct-response",
        "facts": [],
        "direct_nodes": [
            {
                "local_id": "v1",
                "node_type": "prompt_requirement",
                "label": "path normalization requirement",
                "feature_id": "safety.path_normalization",
                "evidence": evidence,
            },
            {
                "local_id": "v2",
                "node_type": "guard",
                "label": "path normalization guard",
                "feature_id": "safety.path_normalization",
                "evidence": evidence,
            },
        ],
        "direct_edges": [
            {
                "src_local_id": "v1",
                "dst_local_id": "v3",
                "edge_type": "requires",
                "evidence": evidence,
            }
        ],
    }
    payload["proposal_id"] = proposal_id_for_payload(payload)
    with pytest.raises(ValidationError):
        PromptExtractionProposalRecord.model_validate(payload)

    payload["direct_nodes"][0]["node_type"] = "prompt_requirement"
    payload["direct_edges"][0]["src_local_id"] = "v2"
    payload["direct_edges"][0]["dst_local_id"] = "v1"
    payload["proposal_id"] = proposal_id_for_payload(payload)
    with pytest.raises(ValidationError):
        PromptExtractionProposalRecord.model_validate(payload)

    payload["direct_edges"][0]["dst_local_id"] = "v2"
    payload["direct_nodes"][0]["node_type"] = "sink"
    payload["proposal_id"] = proposal_id_for_payload(payload)
    with pytest.raises(ValidationError):
        PromptExtractionProposalRecord.model_validate(payload)
