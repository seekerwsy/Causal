import json

import pytest

from prompt_mechanism_study.contract_cleaning import (
    ContractCleaningError,
    _parse_content_reviews,
    _parse_evidence_backfill,
    _parse_semantic_repairs,
    _terminal_quality,
)
from prompt_mechanism_study.records import content_hash


def _batch():
    prompt = "实现函数 solve。输入值应原样返回。"
    return [
        {
            "task_unit_id": "task-a",
            "language": "python",
            "source_prompt": prompt,
            "source_prompt_sha256": content_hash(prompt),
            "old_contract": {
                "resolution_status": "resolved",
                "entrypoint": "solve",
                "requirements": ["Return the input value unchanged."],
                "inputs": ["value"],
                "outputs": ["the unchanged input value"],
                "side_effects": [],
                "environment_dependencies": [],
            },
            "old_review": {
                "issue_codes": ["none"],
                "remaining_deterministic_issue_codes": [],
            },
        }
    ]


def _evidence():
    return {
        "entrypoint": [{"evidence_text": "solve", "evidence_occurrence": 1}],
        "requirements": [
            [
                {"evidence_text": "输入值", "evidence_occurrence": 1},
                {"evidence_text": "原样返回", "evidence_occurrence": 1},
            ]
        ],
        "inputs": [[{"evidence_text": "输入值", "evidence_occurrence": 1}]],
        "outputs": [[{"evidence_text": "原样返回", "evidence_occurrence": 1}]],
        "side_effects": [],
        "environment_dependencies": [],
    }


def test_evidence_backfill_uses_utf8_byte_offsets_and_multiple_spans() -> None:
    raw = json.dumps(
        {
            "items": [
                {
                    "item_index": 1,
                    "binding_status": "bound",
                    "content_evidence": _evidence(),
                    "reason": "All values are directly supported.",
                }
            ]
        },
        ensure_ascii=False,
    ).encode()

    result = _parse_evidence_backfill(raw, _batch())[0]

    spans = result["content_evidence"]["requirements"][0]
    prompt_bytes = _batch()[0]["source_prompt"].encode("utf-8")
    assert len(spans) == 2
    assert prompt_bytes[spans[0]["start_byte"] : spans[0]["end_byte"]].decode() == "输入值"
    assert prompt_bytes[spans[1]["start_byte"] : spans[1]["end_byte"]].decode() == "原样返回"


def test_unbound_evidence_cannot_carry_partial_spans() -> None:
    raw = json.dumps(
        {
            "items": [
                {
                    "item_index": 1,
                    "binding_status": "needs_repair",
                    "content_evidence": _evidence(),
                    "reason": "The contract adds behavior.",
                }
            ]
        },
        ensure_ascii=False,
    ).encode()

    with pytest.raises(ContractCleaningError):
        _parse_evidence_backfill(raw, _batch())


def test_semantic_repair_requires_evidence_for_every_contract_value() -> None:
    response = {
        "item_index": 1,
        "resolution_status": "resolved",
        "entrypoint": "solve",
        "requirements": ["Return the input value unchanged."],
        "inputs": ["value"],
        "outputs": ["the unchanged input value"],
        "side_effects": [],
        "environment_dependencies": [],
        "content_evidence": _evidence(),
        "source_specification_assessment": "sufficient",
        "repair_category": "CONTRACT_EXTRACTION_ERROR",
        "reason": "The prior wording was not source faithful.",
    }
    result = _parse_semantic_repairs(
        json.dumps({"items": [response]}, ensure_ascii=False).encode(), _batch()
    )[0]
    assert result["source_specification_assessment"] == "sufficient"

    response["content_evidence"]["outputs"] = []
    with pytest.raises(ContractCleaningError):
        _parse_semantic_repairs(
            json.dumps({"items": [response]}, ensure_ascii=False).encode(), _batch()
        )


def test_review_keeps_producer_failure_nonterminal() -> None:
    raw = json.dumps(
        {
            "reviews": [
                {
                    "item_index": 1,
                    "contract_status": "faulty",
                    "evidence_status": "unsupported",
                    "source_specification_disposition": "sufficient",
                    "issue_codes": ["missing_explicit_requirement"],
                    "repair_category": "OMITTED_EXPLICIT_REQUIREMENT",
                    "reason": "The source is sufficient; the producer omitted a condition.",
                }
            ]
        }
    ).encode()
    row = _parse_content_reviews(raw, _batch())[0]
    assert _terminal_quality(row) is None


def test_review_maps_only_faithful_supported_contracts_to_final_quality() -> None:
    row = {
        "contract_status": "faithful",
        "evidence_status": "supported",
        "source_specification_disposition": "insufficient",
    }
    assert _terminal_quality(row) == "QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION"
