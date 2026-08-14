from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from m5_executor_fixtures import hypothesis, prompt_pair
from m5_executor_fixtures import request
from secaware.config import AppConfig, InterventionConfig, TSGConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.base import ExtractionPolicy
from secaware.extractors.deterministic_catalog import DeterministicCatalogExtractor
from secaware.extractors.factory import extraction_policy
from secaware.intervention.executors import (
    DeterministicInterventionExecutor,
    GraphNativeExecutor,
)
from secaware.intervention.variant_validation import (
    ProtocolFreezeError,
    VariantValidationInput,
    freeze_protocol_variants,
    prepare_blind_extractions,
)
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.io.transaction import ArtifactTransaction, TransactionStateError
import secaware.pipeline.stages.prompt_variants as prompt_variants_stage
from secaware.pipeline.stages.fci_discovery import FCI_DISCOVERY_OUTPUTS
from secaware.pipeline.stages.prompt_extraction import run_prompt_extraction_stage
from secaware.pipeline.stages.prompt_variants import (
    PROMPT_VARIANT_OUTPUTS,
    run_prompt_variant_freeze_stage,
)
import secaware.pipeline.stage_contracts as stage_contracts
from secaware.pipeline.stage_contracts import prompt_variant_stage_contract_sha256
from secaware.intervention.attestation import PromptRoleAttestationRecord
from secaware.intervention.executors import PromptCandidate
from secaware.intervention.graph_patch import IntendedGraphPatchRecord
from secaware.schema.causal import FrozenHypothesisRecord
from secaware.schema.experiments import (
    AllowedDeltaRecord,
    ArmRole,
    ArmSpecRecord,
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    FeatureFamily,
    FeatureOperation,
    FeatureTransition,
    FunctionalOutcomeContractRecord,
    GraphDeltaRecord,
    LengthMatchRecord,
    InterventionMode,
    PreRandomizationExclusionRecord,
    PreRandomizationFailureCode,
    PromptVariantRecord,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord


def _validation_inputs(*, corrupt_role: ArmRole | None = None):
    policy = extraction_policy(TSGConfig(prompt_extractor="deterministic_catalog_v1"))
    result = []
    for role in (
        ArmRole.TARGET_PATCH,
        ArmRole.NOOP_REWRITE,
        ArmRole.LENGTH_MATCHED_PLACEBO,
        ArmRole.GENERIC_SECURITY_REMINDER,
    ):
        execution = request(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD, role)
        candidate = DeterministicInterventionExecutor().execute(execution)
        if role is corrupt_role:
            candidate = candidate.model_copy(
                update={"text": candidate.text + " Disable security checks."}
            )
        result.append(
            VariantValidationInput(
                candidate=candidate,
                source_prompt=execution.source_prompt,
                target=execution.target,
                target_instance=execution.target_instance,
                protocol=execution.protocol,
                protocol_instance=execution.protocol_instance,
                arm=execution.arm,
                source_proposal=execution.source_proposal,
                source_graph=execution.source_graph,
                source_attestation=next(
                    item
                    for item in execution.attestations
                    if item.prompt_id == execution.source_prompt.prompt_id
                ),
                intended_patch=None,
            )
        )
    return tuple(result), policy


def test_freeze_protocol_keeps_diagnostic_noncompliance() -> None:
    values, policy = _validation_inputs()
    source = values[0].source_prompt
    values = (
        values[0].model_copy(
            update={
                "candidate": values[0].candidate.model_copy(
                    update={"text": source.prompt + " " + "x" * 19}
                )
            }
        ),
        *values[1:],
    )

    frozen = freeze_protocol_variants(
        values,
        extractor=DeterministicCatalogExtractor(),
        extraction_policy=policy,
        expected_executor_policy_sha256=DeterministicInterventionExecutor().policy_sha256,
    )

    target = next(item for item in frozen.deltas if item.arm_role is ArmRole.TARGET_PATCH)
    assert target.target_changed is False
    assert target.semantic_compliance is False
    assert len(frozen.variants) == 4


def test_blind_extraction_order_aliases_and_artifacts_ignore_input_role_order() -> None:
    values, policy = _validation_inputs()

    class CapturingBlindExtractor:
        def __init__(self) -> None:
            self.calls: list[PromptRecord] = []

        def extract(self, prompt, extraction_policy):
            self.calls.append(prompt)
            return DeterministicCatalogExtractor().extract(prompt, extraction_policy)

    forward_extractor = CapturingBlindExtractor()
    reverse_extractor = CapturingBlindExtractor()
    executor_policy = DeterministicInterventionExecutor().policy_sha256

    forward = freeze_protocol_variants(
        values,
        extractor=forward_extractor,
        extraction_policy=policy,
        expected_executor_policy_sha256=executor_policy,
    )
    reverse = freeze_protocol_variants(
        tuple(reversed(values)),
        extractor=reverse_extractor,
        extraction_policy=policy,
        expected_executor_policy_sha256=executor_policy,
    )

    forward_visible = tuple(
        (item.prompt_id, item.task_id, item.prompt) for item in forward_extractor.calls
    )
    reverse_visible = tuple(
        (item.prompt_id, item.task_id, item.prompt) for item in reverse_extractor.calls
    )
    assert forward_visible == reverse_visible
    assert forward == reverse
    forbidden = {value.arm.role.value for value in values} | {
        values[0].target.target_spec_id,
        values[0].target_instance.target_instance_id,
        values[0].protocol.arm_protocol_id,
        values[0].protocol_instance.protocol_instance_id,
    }
    for prompt in forward_extractor.calls:
        assert prompt.prompt_id.startswith("variant_prompt_")
        assert len(prompt.prompt_id) == len("variant_prompt_") + 64
        assert prompt.task_id.startswith("blind_task_")
        assert all(token not in prompt.prompt_id for token in forbidden)
        assert all(token not in prompt.task_id for token in forbidden)


def test_equal_blind_keys_are_extracted_once_without_occurrence_aliases() -> None:
    values, policy = _validation_inputs()
    source_text = values[0].source_prompt.prompt
    tied = tuple(
        item.model_copy(
            update={"candidate": item.candidate.model_copy(update={"text": source_text})}
        )
        for item in values
    )

    class CapturingExtractor:
        def __init__(self) -> None:
            self.aliases: list[str] = []

        def extract(self, prompt, extraction_policy):
            self.aliases.append(prompt.prompt_id)
            return DeterministicCatalogExtractor().extract(prompt, extraction_policy)

    left_extractor = CapturingExtractor()
    right_extractor = CapturingExtractor()
    executor_policy = DeterministicInterventionExecutor().policy_sha256

    left = freeze_protocol_variants(
        tied,
        extractor=left_extractor,
        extraction_policy=policy,
        expected_executor_policy_sha256=executor_policy,
    )
    right = freeze_protocol_variants(
        tuple(reversed(tied)),
        extractor=right_extractor,
        extraction_policy=policy,
        expected_executor_policy_sha256=executor_policy,
    )

    assert left_extractor.aliases == right_extractor.aliases
    assert len(left_extractor.aliases) == 1
    assert left == right


class _CountingExtractor:
    def __init__(self) -> None:
        self.calls: list[PromptRecord] = []

    def extract(self, prompt, extraction_policy):
        self.calls.append(prompt)
        return DeterministicCatalogExtractor().extract(prompt, extraction_policy)


def _assert_zero_call_source_preflight_failure(
    values: tuple[VariantValidationInput, ...],
    policy: ExtractionPolicy,
    expected_role: ArmRole,
) -> None:
    extractor = _CountingExtractor()
    with pytest.raises(ProtocolFreezeError) as exc_info:
        freeze_protocol_variants(
            values,
            extractor=extractor,
            extraction_policy=policy,
            expected_executor_policy_sha256=DeterministicInterventionExecutor().policy_sha256,
        )

    assert extractor.calls == []
    assert exc_info.value.failed_arm_roles == (expected_role,)
    assert exc_info.value.failure_codes == (PreRandomizationFailureCode.SOURCE_PROVENANCE_MISMATCH,)


def test_candidate_target_binding_fails_before_any_blind_extraction() -> None:
    values, policy = _validation_inputs()
    victim = values[0]
    forged = victim.model_copy(
        update={
            "candidate": victim.candidate.model_copy(
                update={"target_spec_id": "target_" + "f" * 64}
            )
        }
    )

    _assert_zero_call_source_preflight_failure((forged, *values[1:]), policy, victim.arm.role)


def test_blind_cache_api_rejects_unpreflighted_input_without_extractor_calls() -> None:
    values, policy = _validation_inputs()
    victim = values[0]
    forged = victim.model_copy(
        update={
            "candidate": victim.candidate.model_copy(
                update={"target_spec_id": "target_" + "f" * 64}
            )
        }
    )
    extractor = _CountingExtractor()

    with pytest.raises(ProtocolFreezeError):
        prepare_blind_extractions(
            (forged, *values[1:]),
            extractor=extractor,
            extraction_policy=policy,
            expected_executor_policy_sha256=DeterministicInterventionExecutor().policy_sha256,
        )

    assert extractor.calls == []


def test_attestation_binding_fails_before_any_blind_extraction() -> None:
    values, policy = _validation_inputs()
    victim = values[0]
    payload = victim.source_attestation.model_dump(
        mode="python",
        exclude={"schema_version", "attestation_id"},
    )
    payload["task_id"] = "foreign-task"
    forged_attestation = PromptRoleAttestationRecord.from_content(**payload)
    forged = victim.model_copy(update={"source_attestation": forged_attestation})

    _assert_zero_call_source_preflight_failure((forged, *values[1:]), policy, victim.arm.role)


def test_graph_patch_binding_fails_before_any_blind_extraction() -> None:
    policy = extraction_policy(TSGConfig(prompt_extractor="deterministic_catalog_v1"))
    values: list[VariantValidationInput] = []
    roles = (
        ArmRole.TARGET_PATCH,
        ArmRole.NOOP_REWRITE,
        ArmRole.LENGTH_MATCHED_PLACEBO,
        ArmRole.GENERIC_SECURITY_REMINDER,
    )
    for role in roles:
        execution = request(
            FeatureFamily.SAFETY_CONTROL,
            FeatureOperation.ADD,
            role,
            mode=InterventionMode.GRAPH_NATIVE,
        )
        patch, candidate = GraphNativeExecutor(DeterministicInterventionExecutor()).execute(
            execution
        )
        values.append(
            VariantValidationInput(
                candidate=candidate,
                source_prompt=execution.source_prompt,
                target=execution.target,
                target_instance=execution.target_instance,
                protocol=execution.protocol,
                protocol_instance=execution.protocol_instance,
                arm=execution.arm,
                source_proposal=execution.source_proposal,
                source_graph=execution.source_graph,
                source_attestation=next(
                    item
                    for item in execution.attestations
                    if item.prompt_id == execution.source_prompt.prompt_id
                ),
                intended_patch=patch,
            )
        )
    victim = values[0]
    original_patch = victim.intended_patch
    assert original_patch is not None
    forged_patch = IntendedGraphPatchRecord.from_content(
        target_spec_id="target_" + "e" * 64,
        target_instance_id=original_patch.target_instance_id,
        arm_protocol_id=original_patch.arm_protocol_id,
        protocol_instance_id=original_patch.protocol_instance_id,
        arm_role=original_patch.arm_role,
        before_graph_sha256=original_patch.before_graph_sha256,
        allowed_delta_sha256=original_patch.allowed_delta_sha256,
        intended_transitions=original_patch.intended_transitions,
    )
    forged = victim.model_copy(
        update={
            "candidate": victim.candidate.model_copy(
                update={"intended_patch_id": forged_patch.patch_id}
            ),
            "intended_patch": forged_patch,
        }
    )

    _assert_zero_call_source_preflight_failure(
        (forged, *values[1:]),
        policy,
        victim.arm.role,
    )


def test_executor_policy_binding_fails_before_any_blind_extraction() -> None:
    values, policy = _validation_inputs()
    extractor = _CountingExtractor()

    with pytest.raises(ProtocolFreezeError) as exc_info:
        freeze_protocol_variants(
            values,
            extractor=extractor,
            extraction_policy=policy,
            expected_executor_policy_sha256="f" * 64,
        )

    assert extractor.calls == []
    assert exc_info.value.failed_arm_roles == values[0].protocol.arm_roles
    assert exc_info.value.failure_codes == tuple(
        PreRandomizationFailureCode.EXECUTOR_POLICY_MISMATCH
        for _role in values[0].protocol.arm_roles
    )


def test_stateful_extractor_sees_only_global_blind_key_order() -> None:
    values, policy = _validation_inputs()

    class OrderSensitiveExtractor:
        def __init__(self) -> None:
            self.visible: list[tuple[str, str, str]] = []

        def extract(self, prompt, extraction_policy):
            self.visible.append((prompt.prompt_id, prompt.task_id, prompt.prompt))
            return DeterministicCatalogExtractor().extract(prompt, extraction_policy)

    forward = OrderSensitiveExtractor()
    reverse = OrderSensitiveExtractor()
    prepare_blind_extractions(
        values,
        extractor=forward,
        extraction_policy=policy,
        expected_executor_policy_sha256=DeterministicInterventionExecutor().policy_sha256,
    )
    prepare_blind_extractions(
        tuple(reversed(values)),
        extractor=reverse,
        extraction_policy=policy,
        expected_executor_policy_sha256=DeterministicInterventionExecutor().policy_sha256,
    )

    assert forward.visible == reverse.visible
    assert len(forward.visible) == len({item[0] for item in forward.visible})


_PROMPT_VARIANT_SCHEMA_BINDINGS = (
    ("app_config_schema", AppConfig),
    ("prompt_schema", PromptRecord),
    ("attestation_schema", PromptRoleAttestationRecord),
    ("functional_contract_schema", FunctionalOutcomeContractRecord),
    ("frozen_hypothesis_schema", FrozenHypothesisRecord),
    ("proposal_schema", PromptExtractionProposalRecord),
    ("prompt_tsg_schema", PromptTSGRecord),
    ("candidate_schema", PromptCandidate),
    ("feature_transition_schema", FeatureTransition),
    ("allowed_delta_schema", AllowedDeltaRecord),
    ("arm_schema", ArmSpecRecord),
    ("target_schema", TargetSpecRecord),
    ("target_instance_schema", TargetInstanceRecord),
    ("protocol_schema", ConfirmationProtocolRecord),
    ("protocol_instance_schema", ConfirmationProtocolInstanceRecord),
    ("patch_schema", IntendedGraphPatchRecord),
    ("delta_schema", GraphDeltaRecord),
    ("variant_schema", PromptVariantRecord),
    ("length_match_schema", LengthMatchRecord),
    ("exclusion_schema", PreRandomizationExclusionRecord),
)


def test_stage_contract_directly_binds_every_parsed_and_semantic_schema() -> None:
    payload = stage_contracts.prompt_variant_stage_contract_payload()

    assert {key for key, _model in _PROMPT_VARIANT_SCHEMA_BINDINGS} <= set(payload)


@pytest.mark.parametrize(
    "payload",
    (
        {"max_protocol_instances": 0},
        {"max_arm_executions": 0},
        {"max_protocol_instances": True},
        {"max_arm_executions": 1.5},
    ),
)
def test_intervention_execution_limits_are_strict_positive_integers(payload: dict) -> None:
    with pytest.raises(ValidationError):
        InterventionConfig.model_validate(
            {
                "mode": "text_native",
                "executor": "deterministic",
                "llm": None,
                "operations": ["add", "remove"],
                "max_protocols": 8,
                **payload,
            }
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("max_protocol_instances", 255),
        ("max_arm_executions", 2047),
    ),
)
def test_stage_policy_binds_every_execution_limit(field: str, value: int) -> None:
    config = AppConfig.model_validate(
        {
            "run": {"name": "limits", "random_seed": 7, "output_dir": "runs/limits"},
            "data": {
                "prompts_path": "data/prompts.jsonl",
                "prompt_attestations_path": "data/attestations.jsonl",
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1", "llm": None},
            "intervention": {
                "mode": "text_native",
                "executor": "deterministic",
                "llm": None,
                "operations": ["add", "remove"],
                "max_protocols": 8,
                "max_protocol_instances": 256,
                "max_arm_executions": 2048,
            },
        }
    )
    changed = config.model_copy(
        update={
            "intervention": config.intervention.model_copy(update={field: value}),
        }
    )

    assert prompt_variants_stage.prompt_variant_stage_policy_sha256(
        changed
    ) != prompt_variants_stage.prompt_variant_stage_policy_sha256(config)


@pytest.mark.parametrize(("schema_key", "model"), _PROMPT_VARIANT_SCHEMA_BINDINGS)
def test_each_prompt_variant_schema_drift_changes_stage_contract(
    schema_key: str,
    model: type,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = prompt_variant_stage_contract_sha256("build-confirmation-variants")
    original = model.model_json_schema

    def drifted(_cls, *args, **kwargs):
        return {**original(*args, **kwargs), "x-secaware-drift": schema_key}

    monkeypatch.setattr(model, "model_json_schema", classmethod(drifted))

    assert prompt_variant_stage_contract_sha256("build-confirmation-variants") != before


def test_one_hard_invalid_arm_excludes_the_whole_protocol_without_replacement() -> None:
    values, policy = _validation_inputs(corrupt_role=ArmRole.GENERIC_SECURITY_REMINDER)

    try:
        freeze_protocol_variants(
            values,
            extractor=DeterministicCatalogExtractor(),
            extraction_policy=policy,
            expected_executor_policy_sha256=DeterministicInterventionExecutor().policy_sha256,
        )
    except ProtocolFreezeError as error:
        assert error.protocol_instance_id == values[0].protocol_instance.protocol_instance_id
        assert error.failed_arm_roles == (ArmRole.GENERIC_SECURITY_REMINDER,)
    else:  # pragma: no cover - explicit assertion message
        raise AssertionError("hard-invalid protocol unexpectedly froze")


def test_prompt_variant_stage_has_exact_atomic_eleven_output_contract() -> None:
    assert tuple(name for name, _model in PROMPT_VARIANT_OUTPUTS) == (
        "target_specs.jsonl",
        "target_instances.jsonl",
        "confirmation_protocols.jsonl",
        "confirmation_protocol_instances.jsonl",
        "intended_patches.jsonl",
        "variant_extraction_proposals.jsonl",
        "variant_prompt_tsg.jsonl",
        "graph_deltas.jsonl",
        "prompt_variants.jsonl",
        "length_matches.jsonl",
        "pre_randomization_exclusions.jsonl",
    )


def test_semantic_definitions_are_reused_across_task_instances() -> None:
    left, policy = _validation_inputs()
    right = tuple(
        item.model_copy(
            update={
                "target_instance": item.target_instance.model_copy(update={"task_id": "other-task"})
            }
        )
        for item in left
    )

    # A forged instance cannot create a second semantic definition or partial block.
    try:
        freeze_protocol_variants(
            (*left, *right),
            extractor=DeterministicCatalogExtractor(),
            extraction_policy=policy,
            expected_executor_policy_sha256=DeterministicInterventionExecutor().policy_sha256,
        )
    except ProtocolFreezeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("forged cross-task instance unexpectedly froze")


def _stage_store(
    tmp_path: Path,
    *,
    llm_executor: bool = False,
    graph_native: bool = False,
    task_count: int = 1,
    confirmation_feature_ids: tuple[str, ...] | None = None,
    hypothesis_records: tuple[FrozenHypothesisRecord, ...] | None = None,
    max_protocols: int = 8,
    max_protocol_instances: int = 256,
    max_arm_executions: int = 2048,
    rfci_enabled: bool = False,
    discovery_min_independent_tasks: int = 20,
    randomization_min_independent_tasks: int = 20,
    task_functional_contracts_path: Path | None = None,
    functional_judge: dict[str, object] | None = None,
) -> tuple[AppConfig, RunStore]:
    if task_count < 1 or (confirmation_feature_ids is not None and task_count != 1):
        raise ValueError("unsupported task count")
    feature_ids = confirmation_feature_ids or ("safety.path_normalization",) * task_count
    if not feature_ids:
        raise ValueError("unsupported confirmation features")
    prompts: list[PromptRecord] = []
    attestation_records: list[PromptRoleAttestationRecord] = []
    for task_index, feature_id in enumerate(feature_ids):
        baseline, variant, attestations = prompt_pair(
            FeatureFamily.SAFETY_CONTROL,
            FeatureOperation.ADD,
            feature_id=feature_id,
        )
        task_suffix = chr(ord("a") + task_index)
        task_id = f"task-{task_suffix}"
        scoped_baseline = PromptRecord.model_validate(
            {
                **baseline.model_dump(mode="python"),
                "prompt_id": f"{task_id}-baseline",
                "task_id": task_id,
            }
        )
        scoped_variant = PromptRecord.model_validate(
            {
                **variant.model_dump(mode="python"),
                "prompt_id": f"{task_id}-variant",
                "task_id": task_id,
                "counterpart_prompt_id": scoped_baseline.prompt_id,
            }
        )
        scoped_attestations: list[PromptRoleAttestationRecord] = []
        for attestation, prompt in zip(
            attestations,
            (scoped_baseline, scoped_variant),
            strict=True,
        ):
            payload = attestation.model_dump(
                mode="python",
                exclude={"attestation_id", "schema_version"},
            )
            payload.update(
                {
                    "prompt_id": prompt.prompt_id,
                    "task_id": prompt.task_id,
                    "prompt_sha256": prompt.prompt_sha256,
                    "counterpart_prompt_id": prompt.counterpart_prompt_id,
                    "counterpart_prompt_sha256": (
                        scoped_baseline.prompt_sha256
                        if prompt.counterpart_prompt_id is not None
                        else None
                    ),
                }
            )
            scoped_attestations.append(PromptRoleAttestationRecord.from_content(**payload))
        prompts.extend((scoped_baseline, scoped_variant))
        attestation_records.extend(scoped_attestations)
    prompts_path = tmp_path / "prompts.jsonl"
    attestations_path = tmp_path / "attestations.jsonl"
    write_jsonl(prompts_path, prompts)
    write_jsonl(attestations_path, attestation_records)
    intervention: dict[str, object] = {
        "mode": "graph_native" if graph_native else "text_native",
        "executor": "llm" if llm_executor else "deterministic",
        "llm": (
            {
                "model_id": "intervention-model",
                "base_url": "https://provider.invalid/v1",
                "api_key_env": "INTERVENTION_API_KEY",
                "timeout_seconds": 30.0,
                "max_attempts": 1,
                "max_response_bytes": 262144,
                "temperature": 0.0,
                "top_p": 1.0,
                "seed": 0,
            }
            if llm_executor
            else None
        ),
        "operations": ["add", "remove"],
        "max_protocols": max_protocols,
        "max_protocol_instances": max_protocol_instances,
        "max_arm_executions": max_arm_executions,
    }
    config = AppConfig.model_validate(
        {
            "run": {"name": "variant-stage", "random_seed": 7, "output_dir": str(tmp_path / "run")},
            "data": {
                "prompts_path": str(prompts_path),
                "prompt_attestations_path": str(attestations_path),
                "functional_outcome_contracts_path": None,
                "task_functional_contracts_path": (
                    str(task_functional_contracts_path)
                    if task_functional_contracts_path is not None
                    else None
                ),
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1", "llm": None},
            "discovery": {
                "min_independent_tasks": discovery_min_independent_tasks,
            },
            "rfci": {"enabled": rfci_enabled},
            "randomization": {
                "min_independent_tasks_per_semantic_protocol": (
                    randomization_min_independent_tasks
                ),
            },
            "intervention": intervention,
            "functional_judge": functional_judge or {"enabled": False, "llm": None},
        }
    )
    store = RunStore(config)
    store.prepare()
    run_prompt_extraction_stage(config, store, force=False)
    outputs = tuple(store.path("discovery", name) for name, _model in FCI_DISCOVERY_OUTPUTS)
    assert not store.should_skip_stage("fci-discovery", (), outputs, False)
    frozen_hypotheses = hypothesis_records if hypothesis_records is not None else (hypothesis(),)
    for (name, _model), path in zip(FCI_DISCOVERY_OUTPUTS, outputs, strict=True):
        write_jsonl(
            path,
            frozen_hypotheses if name == "hypotheses_frozen.jsonl" else (),
        )
    store.seal_stage_outputs("fci-discovery", outputs)
    store.record_stage("fci-discovery", (), outputs)
    return config, store


def test_stage_executes_then_independently_extracts_and_atomically_publishes(
    tmp_path: Path,
) -> None:
    config, store = _stage_store(tmp_path)

    run_prompt_variant_freeze_stage(config, store, force=False)

    output_paths = tuple(
        store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
    )
    assert all(path.exists() for path in output_paths)
    variants = read_jsonl(
        store.path("interventions", "prompt_variants.jsonl"),
        PromptVariantRecord,
        required=True,
        allow_empty=False,
    )
    assert {item.arm_role for item in variants} == {
        ArmRole.TARGET_PATCH,
        ArmRole.NOOP_REWRITE,
        ArmRole.LENGTH_MATCHED_PLACEBO,
        ArmRole.GENERIC_SECURITY_REMINDER,
    }
    assert all(
        item.target_changed is not None
        for item in read_jsonl(
            store.path("interventions", "graph_deltas.jsonl"),
            GraphDeltaRecord,
            required=True,
            allow_empty=False,
        )
    )
    assert store.path(".stages", "build-confirmation-variants.json").exists()


@pytest.mark.parametrize(
    "limits",
    (
        {"task_count": 2, "max_protocol_instances": 1},
        {"task_count": 1, "max_arm_executions": 3},
    ),
)
def test_execution_limits_fail_typed_before_executor_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limits: dict[str, int],
) -> None:
    config, store = _stage_store(tmp_path, **limits)
    constructor_calls = 0

    def forbidden_executor(*_args, **_kwargs):
        nonlocal constructor_calls
        constructor_calls += 1
        raise AssertionError("executor constructed after resource limit")

    monkeypatch.setattr(prompt_variants_stage, "_executor_for_config", forbidden_executor)

    with pytest.raises(SecAwareError) as exc_info:
        run_prompt_variant_freeze_stage(config, store, force=False)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert exc_info.value.message == "prompt protocol resource limit exceeded"
    assert constructor_calls == 0
    assert not store.path(".stages", "build-confirmation-variants.json").exists()
    assert all(
        not store.path("interventions", name).exists() for name, _model in PROMPT_VARIANT_OUTPUTS
    )


@pytest.mark.parametrize(
    "hypothesis_feature_order",
    (
        (
            "safety.input_validation",
            "safety.safe_deserialization",
            "safety.path_normalization",
            "safety.sql_parameterization",
        ),
        (
            "safety.sql_parameterization",
            "safety.input_validation",
            "safety.path_normalization",
            "safety.safe_deserialization",
        ),
    ),
)
def test_ineligible_hypotheses_do_not_consume_semantic_protocol_limit(
    tmp_path: Path,
    hypothesis_feature_order: tuple[str, ...],
) -> None:
    eligible_features = (
        "safety.path_normalization",
        "safety.sql_parameterization",
    )
    config, store = _stage_store(
        tmp_path,
        confirmation_feature_ids=eligible_features,
        hypothesis_records=tuple(
            hypothesis(feature_id=feature_id) for feature_id in hypothesis_feature_order
        ),
        max_protocols=len(eligible_features),
    )

    result = run_prompt_variant_freeze_stage(config, store, force=False)

    targets = read_jsonl(
        store.path("interventions", "target_specs.jsonl"),
        TargetSpecRecord,
        required=True,
        allow_empty=False,
    )
    assert result.protocol_instance_count == len(eligible_features)
    assert {item.feature_id for item in targets} == set(eligible_features)


def test_first_eligible_target_beyond_protocol_limit_fails_before_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    eligible_features = (
        "safety.path_normalization",
        "safety.sql_parameterization",
        "safety.safe_subprocess",
    )
    hypotheses = (
        hypothesis(feature_id="safety.input_validation"),
        hypothesis(feature_id="safety.safe_deserialization"),
        *(hypothesis(feature_id=feature_id) for feature_id in eligible_features),
    )
    config, store = _stage_store(
        tmp_path,
        confirmation_feature_ids=eligible_features,
        hypothesis_records=hypotheses,
        max_protocols=2,
    )
    original_batch = prompt_variants_stage.materialize_target_instances
    materialized_features: list[str] = []
    executor_calls = 0

    def spy_batch(target, hypothesis_record, prompts, index):
        materialized_features.append(target.feature_id)
        return original_batch(target, hypothesis_record, prompts, index)

    def forbidden_executor(*_args, **_kwargs):
        nonlocal executor_calls
        executor_calls += 1
        raise AssertionError("executor constructed after semantic protocol limit")

    monkeypatch.setattr(prompt_variants_stage, "materialize_target_instances", spy_batch)
    monkeypatch.setattr(prompt_variants_stage, "_executor_for_config", forbidden_executor)

    with pytest.raises(SecAwareError) as exc_info:
        run_prompt_variant_freeze_stage(config, store, force=False)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert exc_info.value.message == "prompt protocol resource limit exceeded"
    assert materialized_features == list(eligible_features[:2])
    assert executor_calls == 0
    assert not store.path(".stages", "build-confirmation-variants.json").exists()
    assert all(
        not store.path("interventions", name).exists() for name, _model in PROMPT_VARIANT_OUTPUTS
    )


def test_large_prompt_bundle_is_indexed_and_materialized_once_linearly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_count = 12
    config, store = _stage_store(tmp_path, task_count=task_count, max_protocols=1)
    original_index = prompt_variants_stage.build_target_materialization_index
    original_batch = prompt_variants_stage.materialize_target_instances
    index_calls = 0
    batch_source_counts: list[int] = []

    def spy_index(*args, **kwargs):
        nonlocal index_calls
        index_calls += 1
        return original_index(*args, **kwargs)

    def spy_batch(target, hypothesis_record, prompts, index):
        batch_source_counts.append(len(prompts))
        return original_batch(target, hypothesis_record, prompts, index)

    monkeypatch.setattr(
        prompt_variants_stage,
        "build_target_materialization_index",
        spy_index,
    )
    monkeypatch.setattr(
        prompt_variants_stage,
        "materialize_target_instances",
        spy_batch,
    )

    result = run_prompt_variant_freeze_stage(config, store, force=False)

    assert result.protocol_instance_count == task_count
    assert index_calls == 1
    assert batch_source_counts == [task_count]


def test_real_stage_blind_sorts_extractor_calls_without_fixed_arm_positions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path, task_count=2)

    class CapturingStageExtractor:
        def __init__(self) -> None:
            self.calls: list[PromptRecord] = []

        def extract(self, prompt, policy):
            self.calls.append(prompt)
            return DeterministicCatalogExtractor().extract(prompt, policy)

    extractor = CapturingStageExtractor()
    monkeypatch.setattr(
        prompt_variants_stage,
        "extractor_for_config",
        lambda *_args, **_kwargs: extractor,
    )

    run_prompt_variant_freeze_stage(config, store, force=False)

    calls_by_blind_task: dict[str, list[PromptRecord]] = {}
    for call in extractor.calls:
        calls_by_blind_task.setdefault(call.task_id, []).append(call)
    # The two task records have identical source/candidate content.  They must
    # share one blind task alias and one semantic extraction per content key.
    assert len(calls_by_blind_task) == 1
    for calls in calls_by_blind_task.values():
        text_digests = [hashlib.sha256(item.prompt.encode("utf-8")).hexdigest() for item in calls]
        assert text_digests == sorted(text_digests)
    assert len(extractor.calls) == 4
    assert len({item.prompt_id for item in extractor.calls}) == len(extractor.calls)
    assert all(item.task_id.startswith("blind_task_") for item in extractor.calls)


def test_stage_preflights_every_protocol_before_global_blind_scheduling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path, task_count=2)
    base_executor = DeterministicInterventionExecutor()
    invalid_marker = " invalid-preflight-only"

    class OneTaskForgingExecutor:
        def execute(self, execution_request):
            candidate = base_executor.execute(execution_request)
            if (
                execution_request.source_prompt.task_id == "task-a"
                and execution_request.arm.role is ArmRole.TARGET_PATCH
            ):
                return candidate.model_copy(
                    update={
                        "target_spec_id": "target_" + "f" * 64,
                        "text": candidate.text + invalid_marker,
                    }
                )
            return candidate

    extractor = _CountingExtractor()
    monkeypatch.setattr(
        prompt_variants_stage,
        "_executor_for_config",
        lambda *_args, **_kwargs: OneTaskForgingExecutor(),
    )
    monkeypatch.setattr(
        prompt_variants_stage,
        "extractor_for_config",
        lambda *_args, **_kwargs: extractor,
    )

    result = run_prompt_variant_freeze_stage(config, store, force=False)

    assert result.frozen_protocol_instance_count == 1
    assert result.exclusion_count == 1
    assert all(invalid_marker not in call.prompt for call in extractor.calls)
    variants = read_jsonl(
        store.path("interventions", "prompt_variants.jsonl"),
        PromptVariantRecord,
        required=True,
        allow_empty=False,
    )
    exclusions = read_jsonl(
        store.path("interventions", "pre_randomization_exclusions.jsonl"),
        PreRandomizationExclusionRecord,
        required=True,
        allow_empty=False,
    )
    assert {item.task_id for item in variants} == {"task-b"}
    assert len(variants) == 4
    assert len(exclusions) == 1
    assert exclusions[0].task_id == "task-a"
    assert exclusions[0].failed_arm_roles == (ArmRole.TARGET_PATCH,)
    assert exclusions[0].failure_codes == (PreRandomizationFailureCode.SOURCE_PROVENANCE_MISMATCH,)


def test_forward_reverse_contrast_views_emit_only_the_attested_owner_operation(
    tmp_path: Path,
) -> None:
    config, store = _stage_store(tmp_path)

    run_prompt_variant_freeze_stage(config, store, force=False)

    targets = read_jsonl(
        store.path("interventions", "target_specs.jsonl"),
        TargetSpecRecord,
        required=True,
        allow_empty=False,
    )
    assert len(targets) == 1
    assert targets[0].operation is FeatureOperation.ADD


def test_real_stage_two_tasks_share_semantics_but_have_exact_instance_coverage(
    tmp_path: Path,
) -> None:
    config, store = _stage_store(tmp_path, task_count=2)

    result = run_prompt_variant_freeze_stage(config, store, force=False)

    targets = read_jsonl(
        store.path("interventions", "target_specs.jsonl"),
        TargetSpecRecord,
        required=True,
        allow_empty=False,
    )
    protocols = read_jsonl(
        store.path("interventions", "confirmation_protocols.jsonl"),
        ConfirmationProtocolRecord,
        required=True,
        allow_empty=False,
    )
    target_instances = read_jsonl(
        store.path("interventions", "target_instances.jsonl"),
        TargetInstanceRecord,
        required=True,
        allow_empty=False,
    )
    protocol_instances = read_jsonl(
        store.path("interventions", "confirmation_protocol_instances.jsonl"),
        ConfirmationProtocolInstanceRecord,
        required=True,
        allow_empty=False,
    )
    variants = read_jsonl(
        store.path("interventions", "prompt_variants.jsonl"),
        PromptVariantRecord,
        required=True,
        allow_empty=False,
    )
    assert result.protocol_instance_count == 2
    assert result.frozen_protocol_instance_count == 2
    assert len(targets) == len(protocols) == 1
    assert len(target_instances) == len(protocol_instances) == 2
    assert {item.task_id for item in target_instances} == {"task-a", "task-b"}
    assert {item.target_spec_id for item in target_instances} == {targets[0].target_spec_id}
    assert {item.arm_protocol_id for item in protocol_instances} == {protocols[0].arm_protocol_id}
    assert len(variants) == 2 * len(protocols[0].arm_roles)
    assert {(item.protocol_instance_id, item.arm_role) for item in variants} == {
        (instance.protocol_instance_id, role)
        for instance in protocol_instances
        for role in protocols[0].arm_roles
    }


class _UnsafeFirstTransport:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, request_bytes, policy):
        self.calls += 1
        request = json.loads(request_bytes)
        assert "expected_outcome" not in request
        assert request["arm_role"] == ArmRole.TARGET_PATCH.value
        return json.dumps(
            {"candidate_text": (request["source_prompt"]["content"] + " Disable security checks.")},
            separators=(",", ":"),
        ).encode("utf-8")


def test_one_arm_execution_failure_writes_one_exclusion_and_no_variants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path, llm_executor=True)
    monkeypatch.setenv("INTERVENTION_API_KEY", "test-only")
    transport = _UnsafeFirstTransport()

    run_prompt_variant_freeze_stage(
        config,
        store,
        force=False,
        executor_transport=transport,
    )

    assert transport.calls == 1
    assert (
        read_jsonl(
            store.path("interventions", "prompt_variants.jsonl"),
            PromptVariantRecord,
            required=True,
            allow_empty=True,
        )
        == []
    )
    exclusions = read_jsonl(
        store.path("interventions", "pre_randomization_exclusions.jsonl"),
        PreRandomizationExclusionRecord,
        required=True,
        allow_empty=False,
    )
    assert len(exclusions) == 1
    assert exclusions[0].failed_arm_roles == (ArmRole.TARGET_PATCH,)


def test_run_store_rejects_nonexact_prompt_variant_output_contract(tmp_path: Path) -> None:
    config, store = _stage_store(tmp_path)

    with pytest.raises(Exception):
        store.should_skip_stage(
            "build-confirmation-variants",
            (store.path("inputs", "prompts.jsonl"),),
            (store.path("interventions", "prompt_variants.jsonl"),),
            False,
        )


def test_skip_does_not_construct_executor_but_force_rebuild_does(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    run_prompt_variant_freeze_stage(config, store, force=False)

    def fail_if_constructed(*_args, **_kwargs):
        raise RuntimeError("executor constructed")

    monkeypatch.setattr(prompt_variants_stage, "_executor_for_config", fail_if_constructed)

    skipped = run_prompt_variant_freeze_stage(config, store, force=False)
    assert skipped.frozen_protocol_instance_count == 1
    with pytest.raises(RuntimeError, match="executor constructed"):
        run_prompt_variant_freeze_stage(config, store, force=True)


def test_force_partial_install_failure_restores_all_eleven_outputs_and_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    run_prompt_variant_freeze_stage(config, store, force=False)
    paths = tuple(store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS) + (
        store.path(".stages", "build-confirmation-variants.json"),
    )
    before = {path: path.read_bytes() for path in paths}
    original_install = ArtifactTransaction.install

    def fail_mid_install(self, index, candidate):
        if index == 5:
            raise TransactionStateError
        return original_install(self, index, candidate)

    monkeypatch.setattr(ArtifactTransaction, "install", fail_mid_install)

    with pytest.raises(SecAwareError):
        run_prompt_variant_freeze_stage(config, store, force=True)

    assert {path: path.read_bytes() for path in paths} == before


def test_combined_snapshot_drift_rolls_back_before_first_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    original_freeze = prompt_variants_stage.freeze_protocol_variants
    changed = False

    def mutate_input_after_freeze(*args, **kwargs):
        nonlocal changed
        result = original_freeze(*args, **kwargs)
        if not changed:
            attestation_path = Path(config.data.prompt_attestations_path)
            attestation_path.write_bytes(attestation_path.read_bytes() + b"\n")
            changed = True
        return result

    monkeypatch.setattr(
        prompt_variants_stage,
        "freeze_protocol_variants",
        mutate_input_after_freeze,
    )

    with pytest.raises(SecAwareError, match="inputs changed"):
        run_prompt_variant_freeze_stage(config, store, force=False)

    assert not store.path(".stages", "build-confirmation-variants.json").exists()
    assert all(
        not store.path("interventions", name).exists() for name, _model in PROMPT_VARIANT_OUTPUTS
    )


def test_future_assignment_artifact_is_rejected_before_variant_execution(
    tmp_path: Path,
) -> None:
    config, store = _stage_store(tmp_path)
    store.path("interventions", "assignments.jsonl").write_text("{}\n", encoding="utf-8")

    with pytest.raises(SecAwareError, match="future"):
        run_prompt_variant_freeze_stage(config, store, force=False)

    assert not store.path(".stages", "build-confirmation-variants.json").exists()


@pytest.mark.parametrize(
    "control",
    (MemoryError("future-guard"), KeyboardInterrupt("future-guard"), SystemExit("future-guard")),
)
def test_future_artifact_guard_rethrows_process_control_by_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control: BaseException,
) -> None:
    config, store = _stage_store(tmp_path)
    manifest_root = store.path(".stages")
    original_iterdir = Path.iterdir

    def fail_manifest_iterdir(path: Path):
        if path == manifest_root:
            raise control
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", fail_manifest_iterdir)

    with pytest.raises(type(control)) as exc_info:
        prompt_variants_stage._guard_no_randomization_or_future_artifacts(store)

    assert exc_info.value is control


@pytest.mark.parametrize(
    "control",
    (MemoryError("variant-hash"), KeyboardInterrupt("variant-hash"), SystemExit("variant-hash")),
)
def test_prompt_variant_hash_validator_rethrows_process_control_by_identity(
    monkeypatch: pytest.MonkeyPatch,
    control: BaseException,
) -> None:
    import secaware.schema.experiments as experiment_schema

    record = PromptVariantRecord.model_construct(
        arm_role=ArmRole.TARGET_PATCH,
        prompt_text="candidate",
    )

    def fail_sha256(*_args, **_kwargs):
        raise control

    monkeypatch.setattr(experiment_schema.hashlib, "sha256", fail_sha256)

    with pytest.raises(type(control)) as exc_info:
        record.validate_semantics_and_digest()

    assert exc_info.value is control


@pytest.mark.parametrize(
    "future_stage",
    ("randomize-confirmation", "confirm", "intervene", "jci", "rfci", "reporting"),
)
def test_future_stage_manifest_is_rejected_before_variant_execution(
    tmp_path: Path,
    future_stage: str,
) -> None:
    config, store = _stage_store(tmp_path)
    store.path(".stages", f"{future_stage}.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(SecAwareError, match="future"):
        run_prompt_variant_freeze_stage(config, store, force=False)

    assert not store.path(".stages", "build-confirmation-variants.json").exists()


def test_graph_native_readback_rejects_duplicate_patch_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path, graph_native=True)
    original_freeze = prompt_variants_stage.freeze_protocol_variants

    def duplicate_first_patch(*args, **kwargs):
        frozen = original_freeze(*args, **kwargs)
        assert len(frozen.intended_patches) == len(frozen.variants)
        return replace(
            frozen,
            intended_patches=(frozen.intended_patches[0],) * len(frozen.variants),
        )

    monkeypatch.setattr(
        prompt_variants_stage,
        "freeze_protocol_variants",
        duplicate_first_patch,
    )

    with pytest.raises(SecAwareError, match="bundle"):
        run_prompt_variant_freeze_stage(config, store, force=False)

    assert not store.path(".stages", "build-confirmation-variants.json").exists()


def test_stage_policy_drift_invalidates_skip_and_attempts_rebuild(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    run_prompt_variant_freeze_stage(config, store, force=False)

    monkeypatch.setattr(
        prompt_variants_stage,
        "prompt_variant_stage_policy_sha256",
        lambda _config: "f" * 64,
    )

    def prove_rebuild(*_args, **_kwargs):
        raise RuntimeError("policy drift rebuilt")

    monkeypatch.setattr(prompt_variants_stage, "_executor_for_config", prove_rebuild)

    with pytest.raises(RuntimeError, match="policy drift rebuilt"):
        run_prompt_variant_freeze_stage(config, store, force=False)


def test_catalog_contract_drift_invalidates_real_stage_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    run_prompt_variant_freeze_stage(config, store, force=False)
    monkeypatch.setattr(stage_contracts, "PROMPT_FEATURE_CATALOG_SHA256", "1" * 64)
    monkeypatch.setattr(
        store,
        "require_committed_output",
        lambda *_args, **_kwargs: {},
    )

    def prove_rebuild(*_args, **_kwargs):
        raise RuntimeError("catalog drift rebuilt")

    monkeypatch.setattr(prompt_variants_stage, "_executor_for_config", prove_rebuild)

    with pytest.raises(RuntimeError, match="catalog drift rebuilt"):
        run_prompt_variant_freeze_stage(config, store, force=False)


def test_executor_policy_drift_invalidates_real_stage_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    run_prompt_variant_freeze_stage(config, store, force=False)
    monkeypatch.setattr(
        prompt_variants_stage,
        "_expected_executor_policy_sha256",
        lambda _config: "2" * 64,
    )

    def prove_rebuild(*_args, **_kwargs):
        raise RuntimeError("executor drift rebuilt")

    monkeypatch.setattr(prompt_variants_stage, "_executor_for_config", prove_rebuild)

    with pytest.raises(RuntimeError, match="executor drift rebuilt"):
        run_prompt_variant_freeze_stage(config, store, force=False)


def test_extractor_policy_drift_invalidates_real_stage_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    run_prompt_variant_freeze_stage(config, store, force=False)
    original = prompt_variants_stage.extraction_policy
    calls = 0

    def drift_only_stage_policy(tsg_config):
        nonlocal calls
        calls += 1
        policy = original(tsg_config)
        if calls == 1:
            return policy
        return ExtractionPolicy(
            backend=policy.backend,
            policy_sha256="3" * 64,
            catalog_sha256=policy.catalog_sha256,
            max_response_chars=policy.max_response_chars,
        )

    monkeypatch.setattr(
        prompt_variants_stage,
        "extraction_policy",
        drift_only_stage_policy,
    )

    def prove_rebuild(*_args, **_kwargs):
        raise RuntimeError("extractor drift rebuilt")

    monkeypatch.setattr(prompt_variants_stage, "_executor_for_config", prove_rebuild)

    with pytest.raises(RuntimeError, match="extractor drift rebuilt"):
        run_prompt_variant_freeze_stage(config, store, force=False)


def test_config_drift_invalidates_real_stage_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    run_prompt_variant_freeze_stage(config, store, force=False)
    changed = config.model_copy(
        update={
            "intervention": config.intervention.model_copy(
                update={"max_protocols": config.intervention.max_protocols + 1}
            )
        }
    )
    changed_store = RunStore(changed)
    monkeypatch.setattr(
        changed_store,
        "require_committed_output",
        lambda *_args, **_kwargs: {},
    )

    def prove_rebuild(*_args, **_kwargs):
        raise RuntimeError("config drift rebuilt")

    monkeypatch.setattr(prompt_variants_stage, "_executor_for_config", prove_rebuild)

    with pytest.raises(RuntimeError, match="config drift rebuilt"):
        run_prompt_variant_freeze_stage(changed, changed_store, force=False)


def test_direct_schema_drift_invalidates_real_stage_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    run_prompt_variant_freeze_stage(config, store, force=False)
    original = PromptRecord.model_json_schema

    def drifted(_cls, *args, **kwargs):
        return {**original(*args, **kwargs), "x-secaware-drift": "prompt-schema"}

    monkeypatch.setattr(PromptRecord, "model_json_schema", classmethod(drifted))

    def prove_rebuild(*_args, **_kwargs):
        raise RuntimeError("schema drift rebuilt")

    monkeypatch.setattr(prompt_variants_stage, "_executor_for_config", prove_rebuild)

    with pytest.raises(RuntimeError, match="schema drift rebuilt"):
        run_prompt_variant_freeze_stage(config, store, force=False)


def test_app_config_schema_drift_invalidates_real_stage_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    run_prompt_variant_freeze_stage(config, store, force=False)
    original = AppConfig.model_json_schema

    def drifted(_cls, *args, **kwargs):
        return {**original(*args, **kwargs), "x-secaware-drift": "app-config-schema"}

    monkeypatch.setattr(AppConfig, "model_json_schema", classmethod(drifted))

    def prove_rebuild(*_args, **_kwargs):
        raise RuntimeError("app config schema drift rebuilt")

    monkeypatch.setattr(prompt_variants_stage, "_executor_for_config", prove_rebuild)

    with pytest.raises(RuntimeError, match="app config schema drift rebuilt"):
        run_prompt_variant_freeze_stage(config, store, force=False)


def test_producer_replacement_is_blocked_while_consumer_holds_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    original_freeze = prompt_variants_stage.freeze_protocol_variants
    conflicts: list[ErrorCode] = []

    def attempt_producer_replacement(*args, **kwargs):
        contender = RunStore(config)
        try:
            run_prompt_extraction_stage(config, contender, force=True)
        except SecAwareError as error:
            conflicts.append(error.code)
        else:  # pragma: no cover - the lease must be process-wide
            raise AssertionError("producer replacement unexpectedly acquired its lease")
        return original_freeze(*args, **kwargs)

    monkeypatch.setattr(
        prompt_variants_stage,
        "freeze_protocol_variants",
        attempt_producer_replacement,
    )

    run_prompt_variant_freeze_stage(config, store, force=False)

    assert conflicts == [ErrorCode.MANIFEST_CONFLICT]


def test_fci_producer_replacement_is_blocked_while_consumer_holds_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    original_freeze = prompt_variants_stage.freeze_protocol_variants
    conflicts: list[ErrorCode] = []

    def attempt_fci_replacement(*args, **kwargs):
        contender = RunStore(config)
        fci_outputs = tuple(
            contender.path("discovery", name) for name, _model in FCI_DISCOVERY_OUTPUTS
        )
        try:
            contender.should_skip_stage(
                "fci-discovery",
                (),
                fci_outputs,
                True,
            )
        except SecAwareError as error:
            conflicts.append(error.code)
        else:  # pragma: no cover - the producer lease must remain held
            raise AssertionError("FCI replacement unexpectedly acquired its lease")
        return original_freeze(*args, **kwargs)

    monkeypatch.setattr(
        prompt_variants_stage,
        "freeze_protocol_variants",
        attempt_fci_replacement,
    )

    run_prompt_variant_freeze_stage(config, store, force=False)

    assert conflicts == [ErrorCode.MANIFEST_CONFLICT]


def test_readback_rejects_content_address_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    original_freeze = prompt_variants_stage.freeze_protocol_variants

    def mutate_delta_without_readdressing(*args, **kwargs):
        frozen = original_freeze(*args, **kwargs)
        mutated = frozen.deltas[0].model_copy(
            update={"target_changed": not frozen.deltas[0].target_changed}
        )
        return replace(frozen, deltas=(mutated, *frozen.deltas[1:]))

    monkeypatch.setattr(
        prompt_variants_stage,
        "freeze_protocol_variants",
        mutate_delta_without_readdressing,
    )

    with pytest.raises(SecAwareError, match="bundle"):
        run_prompt_variant_freeze_stage(config, store, force=False)


def test_readback_rejects_duplicate_prompt_variant_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    original_read_jsonl = prompt_variants_stage.read_jsonl

    def duplicate_variant(path, model, **kwargs):
        values = tuple(original_read_jsonl(path, model, **kwargs))
        if model is PromptVariantRecord:
            assert values
            return (*values, values[0])
        return values

    monkeypatch.setattr(prompt_variants_stage, "read_jsonl", duplicate_variant)

    with pytest.raises(SecAwareError, match="bundle"):
        run_prompt_variant_freeze_stage(config, store, force=False)


def test_relation_validation_failure_before_commit_publishes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    failure = SecAwareError(
        code=ErrorCode.CONTRACT,
        stage="build-confirmation-variants",
        message="staged relation closure rejected",
    )
    relation_calls = 0

    def reject_staged_relations(*_args, **_kwargs):
        nonlocal relation_calls
        relation_calls += 1
        staged = tuple(store.path("interventions").glob(".*.stage.candidate"))
        assert len(staged) == len(PROMPT_VARIANT_OUTPUTS)
        raise failure

    monkeypatch.setattr(
        prompt_variants_stage,
        "_validate_bundle_relations",
        reject_staged_relations,
    )

    with pytest.raises(SecAwareError) as exc_info:
        run_prompt_variant_freeze_stage(config, store, force=False)

    assert exc_info.value is failure
    assert relation_calls == 1
    assert not store.path(".stages", "build-confirmation-variants.json").exists()
    assert all(
        not store.path("interventions", name).exists() for name, _model in PROMPT_VARIANT_OUTPUTS
    )


@pytest.mark.parametrize("field", ("prompt_text", "prompt_sha256"))
def test_readback_rejects_prompt_text_hash_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    config, store = _stage_store(tmp_path)
    original_read_jsonl = prompt_variants_stage.read_jsonl

    def corrupt_variant(path, model, **kwargs):
        values = tuple(original_read_jsonl(path, model, **kwargs))
        if model is not PromptVariantRecord:
            return values
        assert values
        payload = values[0].model_dump(mode="python")
        payload[field] = "corrupt text" if field == "prompt_text" else "f" * 64
        corrupted = PromptVariantRecord.model_construct(**payload)
        return (corrupted, *values[1:])

    monkeypatch.setattr(prompt_variants_stage, "read_jsonl", corrupt_variant)

    with pytest.raises(SecAwareError, match="bundle"):
        run_prompt_variant_freeze_stage(config, store, force=False)


def test_readback_rejects_self_valid_cross_record_coordinate_forgery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    original_freeze = prompt_variants_stage.freeze_protocol_variants

    def forge_coordinates(*args, **kwargs):
        frozen = original_freeze(*args, **kwargs)
        old_delta = frozen.deltas[0]
        delta_payload = old_delta.model_dump(mode="python", exclude={"delta_id"})
        delta_payload.update(
            {
                "target_spec_id": "target_" + "d" * 64,
                "target_instance_id": "target_instance_" + "d" * 64,
                "arm_protocol_id": "arm_protocol_" + "d" * 64,
            }
        )
        forged_delta = GraphDeltaRecord.from_content(**delta_payload)
        old_variant = next(item for item in frozen.variants if item.delta_id == old_delta.delta_id)
        variant_payload = old_variant.model_dump(mode="python", exclude={"variant_id"})
        variant_payload.update(
            {
                "task_id": "foreign-task",
                "source_prompt_id": "foreign-prompt",
                "hypothesis_id": "hypothesis_" + "d" * 64,
                "target_spec_id": forged_delta.target_spec_id,
                "target_instance_id": forged_delta.target_instance_id,
                "arm_protocol_id": forged_delta.arm_protocol_id,
                "delta_id": forged_delta.delta_id,
            }
        )
        forged_variant = PromptVariantRecord.from_content(**variant_payload)
        return replace(
            frozen,
            deltas=tuple(
                forged_delta if item.delta_id == old_delta.delta_id else item
                for item in frozen.deltas
            ),
            variants=tuple(
                forged_variant if item.variant_id == old_variant.variant_id else item
                for item in frozen.variants
            ),
        )

    monkeypatch.setattr(
        prompt_variants_stage,
        "freeze_protocol_variants",
        forge_coordinates,
    )

    with pytest.raises(SecAwareError, match="bundle"):
        run_prompt_variant_freeze_stage(config, store, force=False)


def test_readback_rejects_foreign_length_match_coordinate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    original_freeze = prompt_variants_stage.freeze_protocol_variants

    def forge_length_coordinate(*args, **kwargs):
        frozen = original_freeze(*args, **kwargs)
        old_length = frozen.length_matches[0]
        length_payload = old_length.model_dump(mode="python", exclude={"length_match_id"})
        length_payload["protocol_instance_id"] = "protocol_instance_" + "e" * 64
        forged_length = LengthMatchRecord.from_content(**length_payload)
        old_delta = next(
            item for item in frozen.deltas if item.length_match_id == old_length.length_match_id
        )
        delta_payload = old_delta.model_dump(mode="python", exclude={"delta_id"})
        delta_payload["length_match_id"] = forged_length.length_match_id
        forged_delta = GraphDeltaRecord.from_content(**delta_payload)
        old_variant = next(item for item in frozen.variants if item.delta_id == old_delta.delta_id)
        variant_payload = old_variant.model_dump(mode="python", exclude={"variant_id"})
        variant_payload.update(
            {
                "delta_id": forged_delta.delta_id,
                "length_match_id": forged_length.length_match_id,
            }
        )
        forged_variant = PromptVariantRecord.from_content(**variant_payload)
        return replace(
            frozen,
            length_matches=(forged_length,),
            deltas=tuple(
                forged_delta if item.delta_id == old_delta.delta_id else item
                for item in frozen.deltas
            ),
            variants=tuple(
                forged_variant if item.variant_id == old_variant.variant_id else item
                for item in frozen.variants
            ),
        )

    monkeypatch.setattr(
        prompt_variants_stage,
        "freeze_protocol_variants",
        forge_length_coordinate,
    )

    with pytest.raises(SecAwareError, match="bundle"):
        run_prompt_variant_freeze_stage(config, store, force=False)


def test_readback_rejects_self_valid_foreign_exclusion_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path, llm_executor=True)
    monkeypatch.setenv("INTERVENTION_API_KEY", "test-only")
    original_exclusion = prompt_variants_stage._exclusion

    def forge_exclusion(*args, **kwargs):
        exclusion = original_exclusion(*args, **kwargs)
        payload = exclusion.model_dump(mode="python", exclude={"exclusion_id"})
        payload["task_id"] = "foreign-task"
        return PreRandomizationExclusionRecord.from_content(**payload)

    monkeypatch.setattr(prompt_variants_stage, "_exclusion", forge_exclusion)

    with pytest.raises(SecAwareError, match="bundle"):
        run_prompt_variant_freeze_stage(
            config,
            store,
            force=False,
            executor_transport=_UnsafeFirstTransport(),
        )


def test_readback_rejects_unknown_orphan_proposal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _stage_store(tmp_path)
    original_freeze = prompt_variants_stage.freeze_protocol_variants

    def inject_orphan(values, **kwargs):
        frozen = original_freeze(values, **kwargs)
        return replace(
            frozen,
            proposals=(*frozen.proposals, values[0].source_proposal),
        )

    monkeypatch.setattr(
        prompt_variants_stage,
        "freeze_protocol_variants",
        inject_orphan,
    )

    with pytest.raises(SecAwareError, match="bundle"):
        run_prompt_variant_freeze_stage(config, store, force=False)


def test_all_eleven_outputs_are_canonically_sorted_with_unique_primary_ids(
    tmp_path: Path,
) -> None:
    config, store = _stage_store(tmp_path)
    run_prompt_variant_freeze_stage(config, store, force=False)
    id_fields = (
        "target_spec_id",
        "target_instance_id",
        "arm_protocol_id",
        "protocol_instance_id",
        "patch_id",
        "proposal_id",
        "graph_id",
        "delta_id",
        "variant_id",
        "length_match_id",
        "exclusion_id",
    )
    all_ids: list[str] = []
    for (name, model), id_field in zip(PROMPT_VARIANT_OUTPUTS, id_fields, strict=True):
        records = read_jsonl(
            store.path("interventions", name),
            model,
            required=True,
            allow_empty=True,
        )
        identities = [getattr(item, id_field) for item in records]
        assert identities == sorted(identities)
        assert len(identities) == len(set(identities))
        all_ids.extend(identities)
    assert len(all_ids) == len(set(all_ids))
