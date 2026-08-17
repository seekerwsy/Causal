from __future__ import annotations

import pytest

from secaware.exploratory.gate_b import (
    _INTERVENTION_SYSTEM_TEMPLATE,
    _RecordingTransport,
    _intervention_payload,
    _intervention_template,
    _reviewed_placebo_suffix_bank,
    _reviewed_target_suffix_matches,
    _reviewed_target_suffixes,
    _select_reviewed_placebo_suffix,
    validate_length_matched_placebo,
)
from secaware.llm.structured_transport import StructuredLLMPolicy
from secaware.schema.experiments import AllowedDeltaRecord
from secaware.schema.records import PromptRecord


@pytest.mark.parametrize(
    ("target_length", "placebo_length", "minimum", "maximum"),
    [
        (57, 51, 51, 63),
        (57, 63, 51, 63),
        (55, 49, 49, 61),
        (55, 61, 49, 61),
    ],
)
def test_placebo_length_contract_accepts_frozen_boundaries(
    target_length: int,
    placebo_length: int,
    minimum: int,
    maximum: int,
) -> None:
    result = validate_length_matched_placebo(
        target_suffix="t" * target_length,
        noop_suffix="",
        placebo_suffix="p" * placebo_length,
    )
    assert result["status"] == "PASSED"
    assert result["minimum_placebo_length"] == minimum
    assert result["maximum_placebo_length"] == maximum


@pytest.mark.parametrize(
    ("target_length", "placebo_length"), [(57, 50), (57, 64), (55, 48), (55, 62)]
)
def test_placebo_length_contract_rejects_outside_boundaries(
    target_length: int,
    placebo_length: int,
) -> None:
    result = validate_length_matched_placebo(
        target_suffix="t" * target_length,
        noop_suffix="",
        placebo_suffix="p" * placebo_length,
    )
    assert result["status"] == "FAILED"
    assert "PLACEBO_LENGTH_MISMATCH" in result["failure_codes"]


def test_placebo_length_contract_rejects_empty_noop_collision() -> None:
    result = validate_length_matched_placebo(
        target_suffix="t" * 55,
        noop_suffix="",
        placebo_suffix="",
    )
    assert result["status"] == "FAILED"
    assert result["failure_codes"] == [
        "PLACEBO_SUFFIX_EMPTY",
        "PLACEBO_NOOP_COLLISION",
        "PLACEBO_LENGTH_MISMATCH",
    ]


def test_placebo_length_contract_rejects_invalid_input_type() -> None:
    with pytest.raises(ValueError):
        validate_length_matched_placebo(  # type: ignore[arg-type]
            target_suffix="target",
            noop_suffix="",
            placebo_suffix=None,
        )


def test_reviewed_placebo_suffix_enables_exact_execution_contract() -> None:
    suffix = " Keep the requested code concise and clearly organized."
    bank = _reviewed_placebo_suffix_bank({"reviewed_placebo_suffix": suffix})
    assert bank == (suffix,)
    template = _intervention_template(bank)
    assert template.startswith(_INTERVENTION_SYSTEM_TEMPLATE)
    assert "required_exact_suffix" in template
    assert "character-for-character" in template


def test_reviewed_placebo_bank_selects_nearest_registered_valid_suffix() -> None:
    bank = (
        " Keep the code concise and clear.",
        " Keep the requested code concise and clear.",
        " Keep the requested code concise and clearly organized.",
    )
    suffix, validation = _select_reviewed_placebo_suffix(
        target_suffix="t" * 41,
        noop_suffix="",
        suffix_bank=bank,
    )
    assert suffix == " Keep the requested code concise and clear."
    assert validation["status"] == "PASSED"
    assert validation["reviewed_suffix_bank_index"] == 1


def test_reviewed_placebo_suffix_is_bound_into_only_the_placebo_request() -> None:
    source = PromptRecord.model_validate(
        {
            "prompt_id": "prompt-1",
            "task_id": "task-1",
            "split": "discover",
            "language": "python",
            "task_family": "deserialization",
            "cwe": "CWE-502",
            "prompt": "Write a YAML loader.",
            "prompt_role": "neutral_baseline",
        }
    )
    allowed_delta = AllowedDeltaRecord.model_validate(
        {
            "allowed_transitions": [
                {
                    "feature_id": "presentation.length_matched_placebo",
                    "from_states": ["absent"],
                    "to_states": ["present"],
                }
            ],
            "fixed_families": ["task_function", "safety_control"],
            "fixed_feature_ids": [],
        }
    )
    suffix = " Keep the requested code concise and clearly organized."
    placebo = {
        "candidate_id": "candidate-1",
        "variant_id": "variant-1",
        "target_feature_id": "safety.safe_deserialization",
        "operation": "add",
        "arm_role": "length_matched_placebo",
    }
    request = _intervention_payload(
        source,
        placebo,
        allowed_delta,
        reviewed_placebo_suffix=suffix,
        request_policy_version="exploratory-intervention-request-v4",
    )
    assert request["required_exact_suffix"] == suffix
    assert request["request_policy_version"] == "exploratory-intervention-request-v4"
    assert "character-for-character" in str(request["arm_objective"])
    noop_request = _intervention_payload(
        source,
        {**placebo, "arm_role": "noop_rewrite"},
        allowed_delta,
        reviewed_placebo_suffix=suffix,
        request_policy_version="exploratory-intervention-request-v4",
    )
    assert "required_exact_suffix" not in noop_request


def test_reviewed_target_suffix_is_bound_only_to_the_selected_target_request() -> None:
    suffix = " Use a collision-resistant hash."
    mapping = _reviewed_target_suffixes({"reviewed_target_suffixes_by_task": {"task-1": suffix}})
    assert mapping == {"task-1": suffix}
    source = PromptRecord.model_validate(
        {
            "prompt_id": "prompt-1",
            "task_id": "task-1",
            "split": "discover",
            "language": "python",
            "task_family": "message_hashing",
            "cwe": "CWE-328",
            "prompt": "Write a token generator.",
            "prompt_role": "neutral_baseline",
        }
    )
    allowed_delta = AllowedDeltaRecord.model_validate(
        {
            "allowed_transitions": [
                {
                    "feature_id": "safety.collision_resistant_hash",
                    "from_states": ["absent"],
                    "to_states": ["present"],
                }
            ],
            "fixed_families": ["task_function", "presentation_control"],
            "fixed_feature_ids": [],
        }
    )
    target = {
        "candidate_id": "candidate-1",
        "variant_id": "variant-1",
        "target_feature_id": "safety.collision_resistant_hash",
        "operation": "add",
        "arm_role": "target_patch",
    }
    request = _intervention_payload(
        source,
        target,
        allowed_delta,
        reviewed_target_suffix=suffix,
        request_policy_version="exploratory-intervention-request-v5",
    )
    assert request["required_exact_suffix"] == suffix
    assert request["request_policy_version"] == "exploratory-intervention-request-v5"
    assert "character-for-character" in str(request["arm_objective"])


@pytest.mark.parametrize(
    "actual",
    [
        " Use a collision-resistant hash.",
        "\n Use a collision-resistant hash.",
        "\n\n    Use a collision-resistant hash.",
    ],
)
def test_reviewed_target_suffix_accepts_only_bounded_leading_formatting(actual: str) -> None:
    assert _reviewed_target_suffix_matches(actual, " Use a collision-resistant hash.")


@pytest.mark.parametrize(
    "actual",
    [
        "\n\n\n\n\n\n\n\n\nUse a collision-resistant hash.",
        "\n Use a collision-resistant hash. Add another rule.",
        "\n Use a different hash.",
    ],
)
def test_reviewed_target_suffix_rejects_unbounded_or_semantic_changes(actual: str) -> None:
    assert not _reviewed_target_suffix_matches(actual, " Use a collision-resistant hash.")


@pytest.mark.parametrize(
    "suffix",
    [
        "Keep the requested code concise and clearly organized.",
        " Keep the requested code concise and clearly organized. ",
        " Keep the requested code concise.\nKeep it organized.",
        55,
    ],
)
def test_reviewed_placebo_suffix_rejects_noncanonical_values(suffix: object) -> None:
    with pytest.raises(ValueError):
        _reviewed_placebo_suffix_bank({"reviewed_placebo_suffix": suffix})


def test_reviewed_placebo_bank_rejects_duplicates_and_conflicting_forms() -> None:
    suffix = " Keep the requested code concise and clearly organized."
    with pytest.raises(ValueError):
        _reviewed_placebo_suffix_bank({"reviewed_placebo_suffix_bank": [suffix, suffix]})
    with pytest.raises(ValueError):
        _reviewed_placebo_suffix_bank(
            {"reviewed_placebo_suffix": suffix, "reviewed_placebo_suffix_bank": [suffix]}
        )


class _FixedTransport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.calls: list[bytes] = []

    def complete(self, request_bytes: bytes, policy: StructuredLLMPolicy) -> bytes:
        self.calls.append(request_bytes)
        return self.response


def _policy() -> StructuredLLMPolicy:
    return StructuredLLMPolicy(
        endpoint_sha256="0" * 64,
        model_id="test-model",
        system_template_sha256="1" * 64,
        output_schema_sha256="2" * 64,
        temperature=0.0,
        top_p=1.0,
        seed=0,
        timeout_seconds=1.0,
        max_attempts=1,
        max_response_bytes=1024,
        enable_thinking=False,
    )


def test_explicit_reuse_exclusion_calls_live_transport_and_records_reason(tmp_path) -> None:
    reuse = tmp_path / "reuse"
    channel = reuse / "raw" / "intervention"
    channel.mkdir(parents=True)
    (channel / "variant-1.request.json").write_bytes(b'{"old":true}\n')
    (channel / "variant-1.response.json").write_bytes(b'{"candidate_text":"old"}\n')
    delegate = _FixedTransport(b'{"candidate_text":"new"}')
    transport = _RecordingTransport(
        delegate,
        tmp_path / "new",
        "intervention",
        reuse_root=reuse,
        reuse_excluded_labels=frozenset({"variant-1"}),
    )
    transport.select("variant-1")
    response = transport.complete(b'{"new":true}', _policy())
    assert response == b'{"candidate_text":"new"}'
    assert delegate.calls == [b'{"new":true}']
    assert transport.reused_labels == ()
    assert transport.live_labels == ("variant-1",)
    assert transport.reuse_exclusion_labels == ("variant-1",)
    assert (tmp_path / "new" / "raw" / "intervention" / "variant-1.reuse-exclusion.json").is_file()
