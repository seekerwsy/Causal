import json

import pytest

from prompt_mechanism_study.contract_cleaning import (
    ContractCleaningError,
    _parse_contract_repairs,
    _parse_content_reviews,
    _parse_evidence_backfill,
    _parse_semantic_repairs,
    _terminal_quality,
    _transport_retry,
)
from prompt_mechanism_study.functional_judge import JudgeGateError
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
    return [
        {
            "target_id": "entrypoint",
            "spans": [{"evidence_text": "solve", "evidence_occurrence": 1}],
        },
        {
            "target_id": "requirements:1",
            "spans": [
                {"evidence_text": "输入值", "evidence_occurrence": 1},
                {"evidence_text": "原样返回", "evidence_occurrence": 1},
            ],
        },
        {
            "target_id": "inputs:1",
            "spans": [{"evidence_text": "输入值", "evidence_occurrence": 1}],
        },
        {
            "target_id": "outputs:1",
            "spans": [{"evidence_text": "原样返回", "evidence_occurrence": 1}],
        },
    ]


def test_evidence_backfill_uses_utf8_byte_offsets_and_multiple_spans() -> None:
    raw = json.dumps(
        {
            "items": [
                {
                    "item_index": 1,
                    "binding_status": "bound",
                    "evidence_bindings": _evidence(),
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
                    "evidence_bindings": _evidence(),
                    "reason": "The contract adds behavior.",
                }
            ]
        },
        ensure_ascii=False,
    ).encode()

    with pytest.raises(ContractCleaningError):
        _parse_evidence_backfill(raw, _batch())


def test_incomplete_bound_evidence_is_deterministically_escalated() -> None:
    evidence = _evidence()[:-1]
    raw = json.dumps(
        {
            "items": [
                {
                    "item_index": 1,
                    "binding_status": "bound",
                    "evidence_bindings": evidence,
                    "reason": "Bound by the model.",
                }
            ]
        },
        ensure_ascii=False,
    ).encode()

    row = _parse_evidence_backfill(raw, _batch())[0]

    assert row["model_binding_status"] == "bound"
    assert row["binding_status"] == "needs_repair"
    assert row["content_evidence"] is None


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
        "evidence_bindings": _evidence(),
        "source_specification_assessment": "sufficient",
        "repair_category": "CONTRACT_EXTRACTION_ERROR",
        "reason": "The prior wording was not source faithful.",
    }
    result = _parse_semantic_repairs(
        json.dumps({"items": [response]}, ensure_ascii=False).encode(), _batch()
    )[0]
    assert result["source_specification_assessment"] == "sufficient"

    response["evidence_bindings"] = response["evidence_bindings"][:-1]
    with pytest.raises(ContractCleaningError):
        _parse_semantic_repairs(
            json.dumps({"items": [response]}, ensure_ascii=False).encode(), _batch()
        )


def test_semantic_contract_repair_does_not_mix_evidence_bookkeeping() -> None:
    response = {
        "item_index": 1,
        "resolution_status": "resolved",
        "entrypoint": "solve",
        "requirements": ["Return the input value unchanged."],
        "inputs": ["value"],
        "outputs": ["the unchanged input value"],
        "side_effects": [],
        "environment_dependencies": [],
        "source_specification_assessment": "sufficient",
        "repair_category": "CONTRACT_EXTRACTION_ERROR",
        "reason": "The source directly specifies the behavior.",
    }
    row = _parse_contract_repairs(
        json.dumps({"items": [response]}).encode(), _batch()
    )[0]
    assert row["requirements"] == ["Return the input value unchanged."]
    assert "content_evidence" not in row
    assert row["discarded_out_of_scope_evidence"] is False

    response["evidence_bindings"] = []
    projected = _parse_contract_repairs(
        json.dumps({"items": [response]}).encode(), _batch()
    )[0]
    assert projected["discarded_out_of_scope_evidence"] is True
    assert "evidence_bindings" not in projected


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


def test_transport_retry_does_not_retry_semantic_or_credential_failures(monkeypatch) -> None:
    monkeypatch.setattr("prompt_mechanism_study.contract_cleaning.time.sleep", lambda _: None)
    attempts = []

    def transient(*_):
        attempts.append(1)
        if len(attempts) < 3:
            raise JudgeGateError("provider request failed")
        return b"ok"

    assert _transport_retry(transient)({}, {}, "prompt") == b"ok"
    assert len(attempts) == 3

    def credential(*_):
        raise JudgeGateError("provider credential is unavailable")

    with pytest.raises(JudgeGateError):
        _transport_retry(credential)({}, {}, "prompt")


def test_response_binding_uses_last_duplicate_only_when_index_set_is_complete() -> None:
    batch = _batch()
    needs_repair = {
        "item_index": 1,
        "binding_status": "needs_repair",
        "evidence_bindings": None,
        "reason": "First diagnostic.",
    }
    bound = {
        "item_index": 1,
        "binding_status": "bound",
        "evidence_bindings": _evidence(),
        "reason": "Corrected complete response.",
    }
    row = _parse_evidence_backfill(
        json.dumps({"items": [needs_repair, bound]}, ensure_ascii=False).encode(), batch
    )[0]
    assert row["model_binding_status"] == "bound"

    with pytest.raises(ContractCleaningError):
        _parse_evidence_backfill(
            json.dumps({"items": [{**needs_repair, "item_index": 2}]}).encode(), batch
        )
