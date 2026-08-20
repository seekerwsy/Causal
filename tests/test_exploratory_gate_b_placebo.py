from __future__ import annotations

import pytest

from secaware.exploratory.gate_b import (
    _APPEND_SUFFIX_OUTPUT_MODE,
    _INTERVENTION_SYSTEM_TEMPLATE,
    _append_boundary_policy,
    _intervention_payload,
    _intervention_template,
    _materialize_intervention_text,
    _parse_append_suffix_response,
    _RecordingTransport,
    _reuse_transport_roots,
    _reviewed_placebo_suffix_bank,
    _reviewed_target_suffix_matches,
    _reviewed_target_suffixes,
    _select_reviewed_placebo_suffix,
    _selected_gate_b_task_ids,
    _validated_gate_b_cwe_counts,
    _validated_provider_call_budget,
    _variant_extractor_reuse_exclusions,
    validate_length_matched_placebo,
)
from secaware.intervention.append_boundary import (
    LEGACY_DIRECT_CONCAT_POLICY,
    PYTHON_COMMENT_BOUNDARY_POLICY,
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


def test_append_suffix_mode_uses_a_nonconflicting_single_field_contract() -> None:
    template = _intervention_template((), _APPEND_SUFFIX_OUTPUT_MODE)
    assert 'single top-level key "append_suffix"' in template
    assert "candidate_text" not in template
    assert "Do not return the complete candidate prompt" in template


def test_append_suffix_response_is_strict_and_materializes_exact_prefix() -> None:
    raw = b'{"append_suffix":" Use parameterized queries."}'
    assert _parse_append_suffix_response(raw, 1024) == " Use parameterized queries."
    text, suffix = _materialize_intervention_text(
        source_prompt="Write a query function.",
        raw_response=raw,
        output_mode=_APPEND_SUFFIX_OUTPUT_MODE,
        maximum=1024,
    )
    assert text == "Write a query function. Use parameterized queries."
    assert suffix == " Use parameterized queries."


def test_append_suffix_python_comment_policy_materializes_a_safe_boundary() -> None:
    source = "def remove_user(username):\n    '''Remove the named user.'''"
    text, suffix = _materialize_intervention_text(
        source_prompt=source,
        raw_response=b'{"append_suffix":" Use parameterized queries."}',
        output_mode=_APPEND_SUFFIX_OUTPUT_MODE,
        maximum=1024,
        append_boundary_policy=PYTHON_COMMENT_BOUNDARY_POLICY,
    )

    assert suffix == " Use parameterized queries."
    assert text == source + "\n\n# Use parameterized queries."


def test_append_boundary_policy_is_explicit_and_legacy_by_default() -> None:
    assert (
        _append_boundary_policy({}, intervention_output_mode=_APPEND_SUFFIX_OUTPUT_MODE)
        == LEGACY_DIRECT_CONCAT_POLICY
    )
    assert (
        _append_boundary_policy(
            {"append_boundary_policy": PYTHON_COMMENT_BOUNDARY_POLICY},
            intervention_output_mode=_APPEND_SUFFIX_OUTPUT_MODE,
        )
        == PYTHON_COMMENT_BOUNDARY_POLICY
    )
    with pytest.raises(ValueError, match="append-boundary policy"):
        _append_boundary_policy(
            {"append_boundary_policy": PYTHON_COMMENT_BOUNDARY_POLICY},
            intervention_output_mode="full_candidate_text_v1",
        )


@pytest.mark.parametrize(
    "raw",
    [
        b'{"candidate_text":"wrong key"}',
        b'{"append_suffix":""}',
        b'{"append_suffix":"   "}',
        b'{"append_suffix":"one","append_suffix":"two"}',
        b'{"append_suffix":"ok","extra":true}',
        b"not-json",
    ],
)
def test_append_suffix_response_rejects_noncanonical_payloads(raw: bytes) -> None:
    with pytest.raises(ValueError):
        _parse_append_suffix_response(raw, 1024)


def test_append_suffix_mode_rejects_accidental_full_prompt_repetition() -> None:
    with pytest.raises(ValueError, match="repeated the source prompt"):
        _materialize_intervention_text(
            source_prompt="Write a query function.",
            raw_response=b'{"append_suffix":"Write a query function. Use parameters."}',
            output_mode=_APPEND_SUFFIX_OUTPUT_MODE,
            maximum=1024,
        )


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


def test_append_suffix_control_request_withholds_target_semantics() -> None:
    source = PromptRecord.model_validate(
        {
            "prompt_id": "prompt-1",
            "task_id": "task-1",
            "split": "discover",
            "language": "python",
            "task_family": "deserialization",
            "cwe": "CWE-502",
            "prompt": "Write a JSON loader.",
            "prompt_role": "neutral_baseline",
        }
    )
    allowed_delta = AllowedDeltaRecord.model_validate(
        {
            "allowed_transitions": [],
            "fixed_families": [
                "task_function",
                "safety_control",
                "presentation_control",
            ],
            "fixed_feature_ids": [],
        }
    )
    variant = {
        "candidate_id": "candidate-1",
        "variant_id": "variant-1",
        "target_feature_id": "safety.safe_deserialization",
        "operation": "add",
        "arm_role": "noop_rewrite",
    }
    request = _intervention_payload(
        source,
        variant,
        allowed_delta,
        output_mode=_APPEND_SUFFIX_OUTPUT_MODE,
        request_policy_version="exploratory-intervention-request-v7",
    )
    assert "target" not in request
    assert "operation" not in request
    assert request["control_target_visibility"] == "withheld"
    assert "Do not mention security" in str(request["arm_objective"])

    target_request = _intervention_payload(
        source,
        {**variant, "arm_role": "target_patch"},
        allowed_delta,
        output_mode=_APPEND_SUFFIX_OUTPUT_MODE,
        request_policy_version="exploratory-intervention-request-v6",
    )
    assert target_request["target"] == {
        "feature_id": "safety.safe_deserialization",
        "feature_family": "safety_control",
    }
    assert target_request["operation"] == "add"


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


def test_reuse_channel_policy_can_reuse_only_intervention_and_refresh_extractor(
    tmp_path,
) -> None:
    reuse = tmp_path / "reuse"
    assert _reuse_transport_roots(reuse)[:2] == (reuse, reuse)
    intervention_root, extractor_root, mode = _reuse_transport_roots(
        reuse,
        intervention_responses_only=True,
    )
    assert intervention_root == reuse
    assert extractor_root == reuse
    assert mode == "intervention_and_source_extractor_reuse_variant_fresh_v1"
    with pytest.raises(ValueError, match="reuse channel policy"):
        _reuse_transport_roots(None, intervention_responses_only=True)


def test_variant_refresh_excludes_only_variant_extractions_from_reuse() -> None:
    labels = _variant_extractor_reuse_exclusions(
        frozenset({"gate-a-1", "gate-a-2"}),
        refresh_variants=True,
    )

    assert labels == frozenset({"variant-gate-a-1", "variant-gate-a-2"})
    assert "source-prompt-1" not in labels


def test_extractor_reuse_keeps_source_and_refreshes_changed_variant(tmp_path) -> None:
    reuse = tmp_path / "reuse"
    channel = reuse / "raw" / "extractor"
    channel.mkdir(parents=True)
    (channel / "source-prompt-1.request.json").write_bytes(b'{"source":true}\n')
    (channel / "source-prompt-1.response.json").write_bytes(b'{"facts":[]}\n')
    (channel / "variant-gate-a-1.request.json").write_bytes(b'{"old":true}\n')
    (channel / "variant-gate-a-1.response.json").write_bytes(b'{"facts":["old"]}\n')
    delegate = _FixedTransport(b'{"facts":["fresh"]}')
    transport = _RecordingTransport(
        delegate,
        tmp_path / "new",
        "extractor",
        reuse_root=reuse,
        reuse_excluded_labels=frozenset({"variant-gate-a-1"}),
    )

    transport.select("source-prompt-1")
    assert transport.complete(b'{"source":true}', _policy()) == b'{"facts":[]}'
    transport.select("variant-gate-a-1")
    assert transport.complete(b'{"new":true}', _policy()) == b'{"facts":["fresh"]}'
    assert transport.reused_labels == ("source-prompt-1",)
    assert transport.live_labels == ("variant-gate-a-1",)
    assert transport.reuse_exclusion_labels == ("variant-gate-a-1",)


def _source_prompt(task_id: str, cwe: str) -> PromptRecord:
    return PromptRecord.model_validate(
        {
            "prompt_id": f"prompt-{task_id}",
            "task_id": task_id,
            "split": "discover",
            "language": "python",
            "task_family": "test",
            "cwe": cwe,
            "prompt": "value = 1",
            "prompt_role": "neutral_baseline",
        }
    )


def test_multi_per_cwe_selection_accepts_unique_gate_a_tasks_and_exact_budget() -> None:
    sources = {
        "task-78-a": _source_prompt("task-78-a", "CWE-78"),
        "task-78-b": _source_prompt("task-78-b", "CWE-78"),
        "task-89-a": _source_prompt("task-89-a", "CWE-89"),
        "task-89-b": _source_prompt("task-89-b", "CWE-89"),
    }
    config = {
        "task_selection_policy": "explicit_task_ids_multi_per_cwe_v1",
        "selected_task_ids": list(sources),
        "provider_call_budget": {
            "intervention_calls": 16,
            "extractor_calls": 20,
            "total_provider_calls": 36,
        },
    }
    selected = _selected_gate_b_task_ids(config, sources)

    assert selected == tuple(sources)
    assert _validated_gate_b_cwe_counts(
        task_selection_policy=config["task_selection_policy"],
        selected_sources=tuple(sources[item] for item in selected),
        gate_a_candidate_count=2,
    ) == {"CWE-78": 2, "CWE-89": 2}
    assert (
        _validated_provider_call_budget(
            config,
            independent_tasks=4,
            require_explicit=True,
        )
        == config["provider_call_budget"]
    )


def test_multi_per_cwe_selection_rejects_duplicate_unknown_and_single_cwe_tasks() -> None:
    sources = {
        "task-a": _source_prompt("task-a", "CWE-78"),
        "task-b": _source_prompt("task-b", "CWE-78"),
    }
    for selected in (["task-a", "task-a"], ["task-a", "missing"]):
        with pytest.raises(ValueError, match="task selection"):
            _selected_gate_b_task_ids(
                {
                    "task_selection_policy": "explicit_task_ids_multi_per_cwe_v1",
                    "selected_task_ids": selected,
                },
                sources,
            )
    with pytest.raises(ValueError, match="CWE coverage"):
        _validated_gate_b_cwe_counts(
            task_selection_policy="explicit_task_ids_multi_per_cwe_v1",
            selected_sources=tuple(sources.values()),
            gate_a_candidate_count=1,
        )
    with pytest.raises(ValueError, match="provider budget"):
        _validated_provider_call_budget(
            {},
            independent_tasks=2,
            require_explicit=True,
        )


def test_legacy_explicit_selection_keeps_one_task_per_cwe_contract() -> None:
    sources = (
        _source_prompt("task-78", "CWE-78"),
        _source_prompt("task-89", "CWE-89"),
    )

    assert _validated_gate_b_cwe_counts(
        task_selection_policy="explicit_task_ids",
        selected_sources=sources,
        gate_a_candidate_count=2,
    ) == {"CWE-78": 1, "CWE-89": 1}
    with pytest.raises(ValueError, match="CWE coverage"):
        _validated_gate_b_cwe_counts(
            task_selection_policy="explicit_task_ids",
            selected_sources=(sources[0], _source_prompt("task-78-b", "CWE-78")),
            gate_a_candidate_count=2,
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
