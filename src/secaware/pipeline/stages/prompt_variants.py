"""Atomic construction and independent validation of confirmation prompt arms."""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

from secaware.causal.freeze import revalidate_frozen_hypothesis
from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.base import ExtractionPolicy
from secaware.extractors.factory import extraction_policy, extractor_for_config
from secaware.intervention.arm_catalog import materialize_arm_protocol
from secaware.intervention.attestation import (
    PromptRoleAttestationRecord,
    validate_prompt_role_attestations,
)
from secaware.intervention.executors import (
    DETERMINISTIC_INTERVENTION_POLICY_SHA256,
    INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE,
    DeterministicInterventionExecutor,
    GraphNativeExecutor,
    InterventionExecutionRequest,
    LLMInterventionExecutor,
    intervention_executor_policy_sha256,
    structured_policy_from_config,
)
from secaware.intervention.targeting import (
    materialize_protocol_instance,
    materialize_target_instance,
    materialize_target_spec,
)
from secaware.intervention.graph_patch import (
    IntendedGraphPatchRecord,
    allowed_delta_sha256,
)
from secaware.intervention.variant_validation import (
    BLIND_EXTRACTION_ORDER_VERSION,
    ProtocolFreezeError,
    VariantValidationInput,
    blind_extractor_task_id,
    blind_occurrence_ranks,
    freeze_protocol_variants,
    validate_graph_delta_record,
    validate_length_match_record,
)
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.llm.structured_transport import (
    OpenAICompatibleStructuredTransport,
    StructuredJSONTransport,
)
from secaware.pipeline.artifact import canonical_sha256
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.pipeline.stages.fci_discovery import FCI_DISCOVERY_OUTPUTS
from secaware.pipeline.stages.prompt_extraction import validate_exact_extraction_coverage
from secaware.schema.causal import FrozenHypothesisRecord
from secaware.schema.experiments import (
    ArmRole,
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    FeatureFamily,
    FeatureOperation,
    FunctionalOutcomeContractRecord,
    GraphDeltaRecord,
    InterventionExecutorKind,
    InterventionMode,
    LengthMatchRecord,
    PreRandomizationExclusionRecord,
    PreRandomizationFailureCode,
    PromptRole,
    PromptVariantRecord,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256, prompt_feature_spec
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.proposal_validator import validate_proposal


_STAGE = "build-confirmation-variants"
_MAX_INPUT_FILE_BYTES = 256_000_000
_MAX_COMBINED_INPUT_BYTES = 768_000_000
_MAX_JSONL_RECORDS = 100_000
_MAX_JSONL_LINE_BYTES = 4_000_000
_FUTURE_STAGE_NAMES = frozenset(
    {
        "intervene",
        "confirm",
        "randomize-confirmation",
        "generate-confirmation",
        "run-oracle-confirmation",
        "import-functional-outcomes",
        "analyze-jci",
        "analyze-rfci",
        "report",
        "effects",
        "jci",
        "rfci",
        "reporting",
    }
)
_FUTURE_STAGE_PREFIXES = (
    "intervene-",
    "confirm-",
    "randomize-confirmation-",
    "generate-confirmation-",
    "run-oracle-confirmation-",
    "import-functional-outcomes-",
    "analyze-jci-",
    "analyze-rfci-",
    "report-",
    "effects-",
    "jci-",
    "rfci-",
    "reporting-",
)
_FUTURE_ARTIFACT_PREFIXES = {
    "interventions": ("assignment", "randomization"),
    "generation": ("confirmation", "assignment"),
    "oracle": ("confirmation",),
}


PROMPT_VARIANT_OUTPUTS = (
    ("target_specs.jsonl", TargetSpecRecord),
    ("target_instances.jsonl", TargetInstanceRecord),
    ("confirmation_protocols.jsonl", ConfirmationProtocolRecord),
    ("confirmation_protocol_instances.jsonl", ConfirmationProtocolInstanceRecord),
    ("intended_patches.jsonl", IntendedGraphPatchRecord),
    ("variant_extraction_proposals.jsonl", PromptExtractionProposalRecord),
    ("variant_prompt_tsg.jsonl", PromptTSGRecord),
    ("graph_deltas.jsonl", GraphDeltaRecord),
    ("prompt_variants.jsonl", PromptVariantRecord),
    ("length_matches.jsonl", LengthMatchRecord),
    ("pre_randomization_exclusions.jsonl", PreRandomizationExclusionRecord),
)


def _stage_error(message: str) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage=_STAGE,
        message=message,
        details={},
        retryable=False,
    )


def _guard_no_randomization_or_future_artifacts(store: RunStore) -> None:
    """Keep this stage strictly pre-randomization, including during force rebuilds."""

    try:
        manifest_root = store.path(".stages")
        for candidate in manifest_root.iterdir():
            if not candidate.is_file() or candidate.suffix != ".json":
                continue
            stage_name = candidate.stem
            if stage_name in _FUTURE_STAGE_NAMES or any(
                stage_name.startswith(prefix) for prefix in _FUTURE_STAGE_PREFIXES
            ):
                raise ValueError
        for directory in ("analysis", "reports"):
            root = store.path(directory)
            if any(candidate.is_file() for candidate in root.rglob("*")):
                raise ValueError
        for directory, prefixes in _FUTURE_ARTIFACT_PREFIXES.items():
            root = store.path(directory)
            for candidate in root.rglob("*"):
                if candidate.is_file() and candidate.name.casefold().startswith(prefixes):
                    raise ValueError
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("future randomization or analysis artifact already exists") from None


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )


@dataclass(frozen=True, slots=True, repr=False)
class _FileSnapshot:
    payload: bytes
    sha256: str
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True, slots=True, repr=False)
class _StageInputSnapshot:
    files: tuple[_FileSnapshot, ...]
    prompts: tuple[PromptRecord, ...]
    attestations: tuple[PromptRoleAttestationRecord, ...]
    contracts: tuple[FunctionalOutcomeContractRecord, ...]
    source_proposals: tuple[PromptExtractionProposalRecord, ...]
    source_graphs: tuple[PromptTSGRecord, ...]
    hypotheses: tuple[FrozenHypothesisRecord, ...]
    extractor_policy: ExtractionPolicy


@dataclass(frozen=True, slots=True, repr=False)
class _ProtocolInstanceBuild:
    hypothesis: FrozenHypothesisRecord
    target: TargetSpecRecord
    target_instance: TargetInstanceRecord
    protocol: ConfirmationProtocolRecord
    protocol_instance: ConfirmationProtocolInstanceRecord
    source_prompt: PromptRecord
    functional_contract: FunctionalOutcomeContractRecord | None


@dataclass(frozen=True, slots=True)
class PromptVariantStageResult:
    protocol_instance_count: int
    frozen_protocol_instance_count: int
    exclusion_count: int


def _read_file_snapshot(path: Path, *, allow_empty: bool) -> _FileSnapshot:
    descriptor = -1
    buffer = bytearray()
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_INPUT_FILE_BYTES
            or (not allow_empty and before.st_size < 1)
        ):
            raise ValueError
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise ValueError
        remaining = opened.st_size
        digest = hashlib.sha256()
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError
            buffer.extend(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        after_path = path.lstat()
        if (
            _file_identity(after) != _file_identity(opened)
            or _file_identity(after_path) != _file_identity(opened)
            or len(buffer) != opened.st_size
        ):
            raise ValueError
        return _FileSnapshot(bytes(buffer), digest.hexdigest(), _file_identity(after_path))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("prompt variant input snapshot failed validation") from None
    finally:
        buffer.clear()
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _parse_jsonl_bytes(
    payload: bytes,
    model: type,
    *,
    allow_empty: bool,
) -> tuple:
    try:
        text = payload.decode("utf-8", errors="strict")
        records: list[object] = []
        for raw in text.splitlines():
            if not raw.strip():
                continue
            if len(raw.encode("utf-8")) > _MAX_JSONL_LINE_BYTES:
                raise ValueError
            value = json.loads(
                raw,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
            records.append(model.model_validate(value))
            if len(records) > _MAX_JSONL_RECORDS:
                raise ValueError
        if not records and not allow_empty:
            raise ValueError
        return tuple(records)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("prompt variant input artifact failed validation") from None


def _expected_executor_policy_sha256(config: AppConfig) -> str:
    if config.intervention.executor is InterventionExecutorKind.DETERMINISTIC:
        return DETERMINISTIC_INTERVENTION_POLICY_SHA256
    llm = config.intervention.llm
    if llm is None:
        raise _stage_error("intervention executor policy failed validation")
    return intervention_executor_policy_sha256(structured_policy_from_config(llm))


def prompt_variant_stage_policy_sha256(config: AppConfig) -> str:
    """Bind separate executor and extractor policies into one stage fingerprint."""

    try:
        extractor = extraction_policy(config.tsg)
        executor_sha256 = _expected_executor_policy_sha256(config)
        return canonical_sha256(
            {
                "schema_version": "1.0",
                "policy_version": "prompt-variant-stage-policy-v1",
                "extractor_policy_sha256": extractor.policy_sha256,
                "executor_policy_sha256": executor_sha256,
                "intervention_mode": config.intervention.mode.value,
                "intervention_executor": config.intervention.executor.value,
                "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
                "blind_extraction_order_version": BLIND_EXTRACTION_ORDER_VERSION,
            }
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _stage_error("prompt variant stage policy failed validation") from None


def _executor_for_config(
    config: AppConfig,
    transport: StructuredJSONTransport | None,
):
    if config.intervention.executor is InterventionExecutorKind.DETERMINISTIC:
        if transport is not None:
            raise _stage_error("intervention executor dependency failed validation")
        renderer = DeterministicInterventionExecutor()
    else:
        llm = config.intervention.llm
        if llm is None:
            raise _stage_error("intervention executor dependency failed validation")
        selected_transport = transport
        if selected_transport is None:
            selected_transport = OpenAICompatibleStructuredTransport(
                base_url=llm.base_url,
                api_key_env=llm.api_key_env,
                system_template=INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE,
            )
        renderer = LLMInterventionExecutor(
            selected_transport,
            structured_policy_from_config(llm),
        )
    if config.intervention.mode is InterventionMode.GRAPH_NATIVE:
        return GraphNativeExecutor(renderer)
    return renderer


_SOURCE_ROLE = {
    (FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD): PromptRole.NEUTRAL_BASELINE,
    (FeatureFamily.SAFETY_CONTROL, FeatureOperation.REMOVE): PromptRole.POSITIVE_SAFETY_CONTROL,
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.ADD): PromptRole.TASK_FUNCTION_BASELINE,
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.REMOVE): PromptRole.TASK_FUNCTION_VARIANT,
    (FeatureFamily.PRESENTATION_CONTROL, FeatureOperation.ADD): PromptRole.PRESENTATION_BASELINE,
    (FeatureFamily.PRESENTATION_CONTROL, FeatureOperation.REMOVE): PromptRole.PRESENTATION_VARIANT,
}


def _materialize_definitions(
    snapshot: _StageInputSnapshot,
    config: AppConfig,
) -> tuple[
    tuple[TargetSpecRecord, ...],
    tuple[TargetInstanceRecord, ...],
    tuple[ConfirmationProtocolRecord, ...],
    tuple[ConfirmationProtocolInstanceRecord, ...],
    tuple[_ProtocolInstanceBuild, ...],
]:
    target_by_id: dict[str, TargetSpecRecord] = {}
    target_instance_by_id: dict[str, TargetInstanceRecord] = {}
    protocol_by_id: dict[str, ConfirmationProtocolRecord] = {}
    protocol_instance_by_id: dict[str, ConfirmationProtocolInstanceRecord] = {}
    builds: list[_ProtocolInstanceBuild] = []
    attestation_by_prompt_id = {item.prompt_id: item for item in snapshot.attestations}
    contract_by_feature = {item.task_feature_id: item for item in snapshot.contracts}
    try:
        for hypothesis in snapshot.hypotheses:
            if (
                hypothesis.catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
                or hypothesis.extractor_policy_sha256 != snapshot.extractor_policy.policy_sha256
            ):
                raise ValueError
            for operation in config.intervention.operations:
                if operation not in hypothesis.permitted_operations:
                    continue
                target = materialize_target_spec(hypothesis, operation)
                contract = (
                    contract_by_feature.get(target.feature_id)
                    if target.feature_family is FeatureFamily.TASK_FUNCTION
                    else None
                )
                protocol = materialize_arm_protocol(
                    hypothesis,
                    target,
                    functional_contract=contract,
                )
                role = _SOURCE_ROLE[(target.feature_family, operation)]
                eligible: list[PromptRecord] = []
                spec = prompt_feature_spec(target.feature_id)
                for prompt in snapshot.prompts:
                    attestation = attestation_by_prompt_id.get(prompt.prompt_id)
                    if (
                        prompt.split != "confirm"
                        or prompt.prompt_role is not role
                        or prompt.cwe != hypothesis.cwe
                        or attestation is None
                        or attestation.contrast_owner_operation is not operation
                        or (spec.applicable_cwes and prompt.cwe not in spec.applicable_cwes)
                        or (
                            spec.applicable_task_families
                            and prompt.task_family not in spec.applicable_task_families
                        )
                    ):
                        continue
                    eligible.append(prompt)
                if not eligible:
                    continue
                existing_target = target_by_id.setdefault(target.target_spec_id, target)
                existing_protocol = protocol_by_id.setdefault(protocol.arm_protocol_id, protocol)
                if existing_target != target or existing_protocol != protocol:
                    raise ValueError
                for prompt in sorted(eligible, key=lambda item: (item.task_id, item.prompt_id)):
                    target_instance = materialize_target_instance(
                        target,
                        hypothesis,
                        prompt,
                        snapshot.prompts,
                        snapshot.attestations,
                    )
                    protocol_instance = materialize_protocol_instance(protocol, target_instance)
                    if (
                        target_instance.target_instance_id in target_instance_by_id
                        or protocol_instance.protocol_instance_id in protocol_instance_by_id
                    ):
                        raise ValueError
                    target_instance_by_id[target_instance.target_instance_id] = target_instance
                    protocol_instance_by_id[protocol_instance.protocol_instance_id] = (
                        protocol_instance
                    )
                    builds.append(
                        _ProtocolInstanceBuild(
                            hypothesis=hypothesis,
                            target=target,
                            target_instance=target_instance,
                            protocol=protocol,
                            protocol_instance=protocol_instance,
                            source_prompt=prompt,
                            functional_contract=contract,
                        )
                    )
        if (
            not builds
            or len(target_by_id) > config.intervention.max_protocols
            or len(protocol_by_id) != len(target_by_id)
        ):
            raise ValueError
        builds.sort(
            key=lambda item: (
                item.protocol.arm_protocol_id,
                item.target_instance.task_id,
                item.protocol_instance.protocol_instance_id,
            )
        )
        return (
            tuple(sorted(target_by_id.values(), key=lambda item: item.target_spec_id)),
            tuple(
                sorted(
                    target_instance_by_id.values(),
                    key=lambda item: item.target_instance_id,
                )
            ),
            tuple(sorted(protocol_by_id.values(), key=lambda item: item.arm_protocol_id)),
            tuple(
                sorted(
                    protocol_instance_by_id.values(),
                    key=lambda item: item.protocol_instance_id,
                )
            ),
            tuple(builds),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("prompt protocol materialization failed validation") from None


def _exclusion(
    build: _ProtocolInstanceBuild,
    roles: tuple[ArmRole, ...],
    codes: tuple[PreRandomizationFailureCode, ...],
) -> PreRandomizationExclusionRecord:
    detail_sha256 = canonical_sha256(
        {
            "schema_version": "1.0",
            "protocol_instance_id": build.protocol_instance.protocol_instance_id,
            "failed_arm_roles": [item.value for item in roles],
            "failure_codes": [item.value for item in codes],
        }
    )
    return PreRandomizationExclusionRecord.from_content(
        hypothesis_id=build.hypothesis.hypothesis_id,
        target_spec_id=build.target.target_spec_id,
        target_instance_id=build.target_instance.target_instance_id,
        arm_protocol_id=build.protocol.arm_protocol_id,
        protocol_instance_id=build.protocol_instance.protocol_instance_id,
        task_id=build.source_prompt.task_id,
        failed_arm_roles=roles,
        failure_codes=codes,
        detail_sha256=detail_sha256,
    )


def _validate_bundle_relations(
    *,
    snapshot: _StageInputSnapshot,
    config: AppConfig,
    groups: Sequence[Sequence],
) -> PromptVariantStageResult:
    try:
        if len(groups) != len(PROMPT_VARIANT_OUTPUTS):
            raise ValueError
        checked_groups: list[tuple] = []
        for group, (_name, model) in zip(groups, PROMPT_VARIANT_OUTPUTS, strict=True):
            checked: list[object] = []
            for item in group:
                if type(item) is not model:
                    raise ValueError
                checked.append(
                    model.model_validate(
                        item.model_dump(mode="python", round_trip=True, warnings=False)
                    )
                )
            checked_groups.append(tuple(checked))
        (
            target_specs,
            target_instances,
            protocols,
            protocol_instances,
            patches,
            proposals,
            graphs,
            deltas,
            variants,
            length_matches,
            exclusions,
        ) = checked_groups
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
        all_primary_ids: list[str] = []
        for values, id_field in zip(checked_groups, id_fields, strict=True):
            identities = tuple(getattr(item, id_field) for item in values)
            if identities != tuple(sorted(identities)) or len(identities) != len(set(identities)):
                raise ValueError
            all_primary_ids.extend(identities)
        if len(all_primary_ids) != len(set(all_primary_ids)):
            raise ValueError
        expected = _materialize_definitions(snapshot, config)
        if (
            target_specs != expected[0]
            or target_instances != expected[1]
            or protocols != expected[2]
            or protocol_instances != expected[3]
        ):
            raise ValueError
        build_by_instance = {
            item.protocol_instance.protocol_instance_id: item for item in expected[4]
        }
        if set(build_by_instance) != {item.protocol_instance_id for item in protocol_instances}:
            raise ValueError
        protocol_by_id = {item.arm_protocol_id: item for item in protocols}
        instance_by_id = {item.protocol_instance_id: item for item in protocol_instances}
        target_by_id = {item.target_spec_id: item for item in target_specs}
        target_instance_by_id = {item.target_instance_id: item for item in target_instances}
        source_by_id = {item.prompt_id: item for item in snapshot.prompts}
        source_graph_by_prompt = {item.prompt_id: item for item in snapshot.source_graphs}
        proposal_by_id = {item.proposal_id: item for item in proposals}
        graph_by_id = {item.graph_id: item for item in graphs}
        delta_by_id = {item.delta_id: item for item in deltas}
        variant_by_coordinate = {
            (item.protocol_instance_id, item.arm_role): item for item in variants
        }
        delta_by_coordinate = {(item.protocol_instance_id, item.arm_role): item for item in deltas}
        exclusion_by_instance = {item.protocol_instance_id: item for item in exclusions}
        length_by_id = {item.length_match_id: item for item in length_matches}
        length_by_coordinate = {
            (item.protocol_instance_id, item.matched_arm_role): item for item in length_matches
        }
        patch_by_coordinate = {(item.protocol_instance_id, item.arm_role): item for item in patches}
        if any(
            len(mapping) != len(values)
            for mapping, values in (
                (protocol_by_id, protocols),
                (instance_by_id, protocol_instances),
                (proposal_by_id, proposals),
                (graph_by_id, graphs),
                (delta_by_id, deltas),
                (delta_by_coordinate, deltas),
                (variant_by_coordinate, variants),
                (exclusion_by_instance, exclusions),
                (length_by_id, length_matches),
                (length_by_coordinate, length_matches),
                (patch_by_coordinate, patches),
            )
        ):
            raise ValueError
        expected_executor_policy = _expected_executor_policy_sha256(config)
        used_patch_ids: set[str] = set()
        used_proposal_ids: set[str] = set()
        used_graph_ids: set[str] = set()
        used_delta_ids: set[str] = set()
        used_variant_ids: set[str] = set()
        used_length_ids: set[str] = set()
        used_exclusion_ids: set[str] = set()
        valid_instance_count = 0
        for protocol_instance_id in sorted(build_by_instance):
            build = build_by_instance[protocol_instance_id]
            instance = instance_by_id[protocol_instance_id]
            protocol = protocol_by_id[instance.arm_protocol_id]
            target_instance = target_instance_by_id[instance.target_instance_id]
            target = target_by_id[target_instance.target_spec_id]
            if (
                build.protocol_instance != instance
                or build.protocol != protocol
                or build.target_instance != target_instance
                or build.target != target
            ):
                raise ValueError
            roles = protocol.arm_roles
            role_set = set(roles)
            local_variants = {
                role: variant_by_coordinate[(protocol_instance_id, role)]
                for role in roles
                if (protocol_instance_id, role) in variant_by_coordinate
            }
            local_deltas = {
                role: delta_by_coordinate[(protocol_instance_id, role)]
                for role in roles
                if (protocol_instance_id, role) in delta_by_coordinate
            }
            local_patches = {
                role: patch_by_coordinate[(protocol_instance_id, role)]
                for role in roles
                if (protocol_instance_id, role) in patch_by_coordinate
            }
            local_lengths = {
                role: length_by_coordinate[(protocol_instance_id, role)]
                for role in roles
                if (protocol_instance_id, role) in length_by_coordinate
            }
            exclusion = exclusion_by_instance.get(protocol_instance_id)
            if exclusion is not None:
                role_order = {role: index for index, role in enumerate(roles)}
                expected_detail_sha256 = canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "protocol_instance_id": instance.protocol_instance_id,
                        "failed_arm_roles": [item.value for item in exclusion.failed_arm_roles],
                        "failure_codes": [item.value for item in exclusion.failure_codes],
                    }
                )
                if (
                    local_variants
                    or local_deltas
                    or local_patches
                    or local_lengths
                    or not set(exclusion.failed_arm_roles) <= role_set
                    or exclusion.failed_arm_roles
                    != tuple(
                        sorted(
                            exclusion.failed_arm_roles,
                            key=lambda role: role_order[role],
                        )
                    )
                    or exclusion.hypothesis_id != build.hypothesis.hypothesis_id
                    or exclusion.target_spec_id != target.target_spec_id
                    or exclusion.target_instance_id != target_instance.target_instance_id
                    or exclusion.arm_protocol_id != protocol.arm_protocol_id
                    or exclusion.protocol_instance_id != instance.protocol_instance_id
                    or exclusion.task_id != source_by_id[instance.source_prompt_id].task_id
                    or exclusion.detail_sha256 != expected_detail_sha256
                ):
                    raise ValueError
                used_exclusion_ids.add(exclusion.exclusion_id)
                continue
            valid_instance_count += 1
            if (
                set(local_variants) != role_set
                or set(local_deltas) != role_set
                or (
                    config.intervention.mode is InterventionMode.GRAPH_NATIVE
                    and set(local_patches) != role_set
                )
                or (config.intervention.mode is InterventionMode.TEXT_NATIVE and local_patches)
            ):
                raise ValueError
            source = source_by_id[instance.source_prompt_id]
            source_graph = source_graph_by_prompt[source.prompt_id]
            for arm in protocol.arms:
                variant = local_variants[arm.role]
                proposal = proposal_by_id[variant.proposal_id]
                graph = graph_by_id[variant.graph_id]
                delta = local_deltas[arm.role]
                expected_length = local_lengths.get(arm.role)
                expected_length_id = (
                    expected_length.length_match_id if expected_length is not None else None
                )
                variant_prompt = PromptRecord.model_validate(
                    {
                        **source.model_dump(mode="python"),
                        "prompt_id": variant.variant_prompt_id,
                        "task_id": blind_extractor_task_id(
                            source,
                            snapshot.extractor_policy,
                        ),
                        "prompt": variant.prompt_text,
                    }
                )
                validate_proposal(proposal, variant_prompt)
                if (
                    variant.task_id != source.task_id
                    or variant.source_prompt_id != source.prompt_id
                    or variant.hypothesis_id != build.hypothesis.hypothesis_id
                    or variant.target_spec_id != target.target_spec_id
                    or variant.target_instance_id != target_instance.target_instance_id
                    or variant.arm_protocol_id != protocol.arm_protocol_id
                    or variant.protocol_instance_id != instance.protocol_instance_id
                    or variant.arm_role is not arm.role
                    or variant.prompt_sha256 != variant_prompt.prompt_sha256
                    or variant.executor_policy_sha256 != expected_executor_policy
                    or variant.extractor_policy_sha256 != snapshot.extractor_policy.policy_sha256
                    or variant.length_match_id != expected_length_id
                    or proposal.proposal_id != variant.proposal_id
                    or proposal.prompt_id != variant.variant_prompt_id
                    or proposal.task_id != variant_prompt.task_id
                    or proposal.prompt_sha256 != variant.prompt_sha256
                    or proposal.backend is not snapshot.extractor_policy.backend
                    or proposal.catalog_sha256 != snapshot.extractor_policy.catalog_sha256
                    or proposal.policy_sha256 != snapshot.extractor_policy.policy_sha256
                    or build_prompt_tsg(proposal, variant_prompt) != graph
                    or graph.graph_id != variant.graph_id
                    or graph.proposal_id != proposal.proposal_id
                    or graph.prompt_id != variant.variant_prompt_id
                    or graph.task_id != variant_prompt.task_id
                    or graph.task_family != source.task_family
                    or graph.cwe != source.cwe
                    or graph.extractor_backend is not snapshot.extractor_policy.backend
                    or graph.extractor_policy_sha256 != snapshot.extractor_policy.policy_sha256
                    or delta.delta_id != variant.delta_id
                    or delta.target_spec_id != target.target_spec_id
                    or delta.target_instance_id != target_instance.target_instance_id
                    or delta.arm_protocol_id != protocol.arm_protocol_id
                    or delta.protocol_instance_id != instance.protocol_instance_id
                    or delta.arm_role is not arm.role
                    or graph.graph_sha256 != delta.after_graph_sha256
                    or source_graph.graph_sha256 != delta.before_graph_sha256
                    or delta.length_match_id != expected_length_id
                ):
                    raise ValueError
                record_to_multidigraph(graph)
                validate_graph_delta_record(
                    delta,
                    before_graph=source_graph,
                    after_graph=graph,
                    target=target,
                    arm=arm,
                    expected_length_match_id=expected_length_id,
                )
                if expected_length is not None:
                    reference = local_variants.get(expected_length.reference_arm_role)
                    if (
                        reference is None
                        or expected_length.arm_protocol_id != protocol.arm_protocol_id
                        or expected_length.protocol_instance_id != instance.protocol_instance_id
                        or expected_length.matched_arm_role is not arm.role
                    ):
                        raise ValueError
                    validate_length_match_record(
                        expected_length,
                        source_text=source.prompt,
                        reference_text=reference.prompt_text,
                        matched_text=variant.prompt_text,
                    )
                    used_length_ids.add(expected_length.length_match_id)
                patch = local_patches.get(arm.role)
                if config.intervention.mode is InterventionMode.GRAPH_NATIVE:
                    if (
                        patch is None
                        or patch.target_spec_id != target.target_spec_id
                        or patch.target_instance_id != target_instance.target_instance_id
                        or patch.arm_protocol_id != protocol.arm_protocol_id
                        or patch.protocol_instance_id != instance.protocol_instance_id
                        or patch.arm_role is not arm.role
                        or patch.before_graph_sha256 != source_graph.graph_sha256
                        or patch.allowed_delta_sha256 != allowed_delta_sha256(arm.allowed_delta)
                        or patch.intended_transitions != arm.allowed_delta.allowed_transitions
                    ):
                        raise ValueError
                    used_patch_ids.add(patch.patch_id)
                elif patch is not None:
                    raise ValueError
                used_proposal_ids.add(proposal.proposal_id)
                used_graph_ids.add(graph.graph_id)
                used_delta_ids.add(delta.delta_id)
                used_variant_ids.add(variant.variant_id)
        if (
            used_patch_ids != set(item.patch_id for item in patches)
            or used_proposal_ids != set(proposal_by_id)
            or used_graph_ids != set(graph_by_id)
            or used_delta_ids != set(delta_by_id)
            or used_variant_ids != set(item.variant_id for item in variants)
            or used_length_ids != set(length_by_id)
            or used_exclusion_ids != set(item.exclusion_id for item in exclusions)
            or valid_instance_count + len(exclusions) != len(protocol_instances)
        ):
            raise ValueError
        return PromptVariantStageResult(
            protocol_instance_count=len(protocol_instances),
            frozen_protocol_instance_count=valid_instance_count,
            exclusion_count=len(exclusions),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("prompt variant bundle failed readback validation") from None


def run_prompt_variant_freeze_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
    executor_transport: StructuredJSONTransport | None = None,
    extractor_transport: StructuredJSONTransport | None = None,
) -> PromptVariantStageResult:
    """Execute, independently extract, validate, and atomically freeze all arms."""

    if type(config) is not AppConfig or type(store) is not RunStore or store.config != config:
        raise _stage_error("prompt variant stage configuration failed validation")
    policy = extraction_policy(config.tsg)
    stage_policy_sha256 = prompt_variant_stage_policy_sha256(config)
    expected_executor_policy = _expected_executor_policy_sha256(config)
    prompt_path = store.path("inputs", "prompts.jsonl")
    attestation_path = Path(config.data.prompt_attestations_path)
    contract_path = (
        Path(config.data.functional_outcome_contracts_path)
        if config.data.functional_outcome_contracts_path is not None
        else None
    )
    extraction_paths = (
        store.path("tsg", "prompt_extraction_proposals.jsonl"),
        store.path("tsg", "prompt_tsg.jsonl"),
    )
    fci_paths = tuple(store.path("discovery", name) for name, _model in FCI_DISCOVERY_OUTPUTS)
    extraction_manifest = store.path(".stages", "extract-prompt-tsg.json")
    fci_manifest = store.path(".stages", "fci-discovery.json")
    inputs = (
        prompt_path,
        attestation_path,
        *((contract_path,) if contract_path is not None else ()),
        *extraction_paths,
        *fci_paths,
        extraction_manifest,
        fci_manifest,
    )
    allow_empty = tuple(
        path in set(fci_paths) and path.name != "hypotheses_frozen.jsonl" for path in inputs
    )
    output_specs = tuple(
        JsonlOutputSpec(
            store.path("interventions", name),
            model,
            require_nonempty=index < 4,
        )
        for index, (name, model) in enumerate(PROMPT_VARIANT_OUTPUTS)
    )
    snapshot: _StageInputSnapshot | None = None

    def capture_input_snapshot() -> tuple[str, ...]:
        nonlocal snapshot
        if snapshot is not None:
            raise _stage_error("prompt variant input snapshot failed validation")
        _guard_no_randomization_or_future_artifacts(store)
        captured_files: list[_FileSnapshot] = []
        combined_bytes = 0
        for path, empty in zip(inputs, allow_empty, strict=True):
            captured = _read_file_snapshot(path, allow_empty=empty)
            combined_bytes += len(captured.payload)
            if combined_bytes > _MAX_COMBINED_INPUT_BYTES:
                captured_files.clear()
                raise _stage_error("prompt variant input snapshot exceeded bounds")
            captured_files.append(captured)
        files = tuple(captured_files)
        payload_by_path = {path: file.payload for path, file in zip(inputs, files, strict=True)}
        prompts = _parse_jsonl_bytes(payload_by_path[prompt_path], PromptRecord, allow_empty=False)
        attestations = _parse_jsonl_bytes(
            payload_by_path[attestation_path],
            PromptRoleAttestationRecord,
            allow_empty=False,
        )
        contracts = (
            _parse_jsonl_bytes(
                payload_by_path[contract_path],
                FunctionalOutcomeContractRecord,
                allow_empty=False,
            )
            if contract_path is not None
            else ()
        )
        proposals = _parse_jsonl_bytes(
            payload_by_path[extraction_paths[0]],
            PromptExtractionProposalRecord,
            allow_empty=False,
        )
        graphs = _parse_jsonl_bytes(
            payload_by_path[extraction_paths[1]],
            PromptTSGRecord,
            allow_empty=False,
        )
        hypothesis_path = next(path for path in fci_paths if path.name == "hypotheses_frozen.jsonl")
        hypotheses = tuple(
            revalidate_frozen_hypothesis(item)
            for item in _parse_jsonl_bytes(
                payload_by_path[hypothesis_path],
                FrozenHypothesisRecord,
                allow_empty=False,
            )
        )
        checked_attestations = validate_prompt_role_attestations(prompts, attestations)
        validate_exact_extraction_coverage(prompts, proposals, graphs, policy)
        if len({item.contract_id for item in contracts}) != len(contracts) or len(
            {item.task_feature_id for item in contracts}
        ) != len(contracts):
            raise _stage_error("functional outcome contract coverage failed validation")
        snapshot = _StageInputSnapshot(
            files=files,
            prompts=prompts,
            attestations=checked_attestations,
            contracts=contracts,
            source_proposals=proposals,
            source_graphs=graphs,
            hypotheses=hypotheses,
            extractor_policy=policy,
        )
        _materialize_definitions(snapshot, config)
        return tuple(item.sha256 for item in files)

    def verify_input_snapshot() -> None:
        if snapshot is None:
            raise _stage_error("prompt variant input snapshot failed validation")
        _guard_no_randomization_or_future_artifacts(store)
        current_files: list[_FileSnapshot] = []
        combined_bytes = 0
        for path, empty in zip(inputs, allow_empty, strict=True):
            captured = _read_file_snapshot(path, allow_empty=empty)
            combined_bytes += len(captured.payload)
            if combined_bytes > _MAX_COMBINED_INPUT_BYTES:
                current_files.clear()
                raise _stage_error("prompt variant input snapshot exceeded bounds")
            current_files.append(captured)
        current = tuple(current_files)
        if tuple((item.sha256, item.identity) for item in current) != tuple(
            (item.sha256, item.identity) for item in snapshot.files
        ):
            raise _stage_error("prompt variant inputs changed during execution")

    def build():
        if snapshot is None:
            raise _stage_error("prompt variant input snapshot failed validation")
        executor = _executor_for_config(config, executor_transport)
        extractor = extractor_for_config(config.tsg, transport=extractor_transport)
        definitions = _materialize_definitions(snapshot, config)
        proposal_by_prompt = {item.prompt_id: item for item in snapshot.source_proposals}
        graph_by_prompt = {item.prompt_id: item for item in snapshot.source_graphs}
        prompt_by_id = {item.prompt_id: item for item in snapshot.prompts}
        attestation_by_prompt = {item.prompt_id: item for item in snapshot.attestations}
        patches: list = []
        proposals: list[PromptExtractionProposalRecord] = []
        graphs: list[PromptTSGRecord] = []
        deltas: list[GraphDeltaRecord] = []
        variants: list[PromptVariantRecord] = []
        lengths: list[LengthMatchRecord] = []
        exclusions: list[PreRandomizationExclusionRecord] = []
        pending_validation: list[
            tuple[_ProtocolInstanceBuild, tuple[VariantValidationInput, ...]]
        ] = []
        for item in definitions[4]:
            source = item.source_prompt
            counterpart = (
                prompt_by_id[item.target_instance.counterpart_prompt_id]
                if item.target_instance.counterpart_prompt_id is not None
                else None
            )
            validation_inputs: list[VariantValidationInput] = []
            execution_failure: tuple[ArmRole, PreRandomizationFailureCode] | None = None
            for arm in item.protocol.arms:
                request = InterventionExecutionRequest(
                    hypothesis=item.hypothesis,
                    target=item.target,
                    target_instance=item.target_instance,
                    protocol=item.protocol,
                    protocol_instance=item.protocol_instance,
                    arm=arm,
                    source_prompt=source,
                    prompt_bundle=snapshot.prompts,
                    functional_contract=item.functional_contract,
                    source_proposal=proposal_by_prompt[source.prompt_id],
                    source_graph=graph_by_prompt[source.prompt_id],
                    counterpart_prompt=counterpart,
                    attestations=snapshot.attestations,
                    mode=config.intervention.mode,
                )
                try:
                    if type(executor) is GraphNativeExecutor:
                        patch, candidate = executor.execute(request)
                    else:
                        patch = None
                        candidate = executor.execute(request)
                    validation_inputs.append(
                        VariantValidationInput(
                            candidate=candidate,
                            source_prompt=source,
                            target=item.target,
                            target_instance=item.target_instance,
                            protocol=item.protocol,
                            protocol_instance=item.protocol_instance,
                            arm=arm,
                            source_proposal=proposal_by_prompt[source.prompt_id],
                            source_graph=graph_by_prompt[source.prompt_id],
                            source_attestation=attestation_by_prompt[source.prompt_id],
                            intended_patch=patch,
                        )
                    )
                except (MemoryError, KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    execution_failure = (arm.role, PreRandomizationFailureCode.EXECUTION_FAILED)
                    break
            if execution_failure is not None:
                exclusions.append(
                    _exclusion(item, (execution_failure[0],), (execution_failure[1],))
                )
                continue
            pending_validation.append((item, tuple(validation_inputs)))
        rank_by_candidate_sha256 = (
            blind_occurrence_ranks(
                tuple(
                    value
                    for _item, validation_inputs in pending_validation
                    for value in validation_inputs
                ),
                policy,
            )
            if pending_validation
            else {}
        )
        for item, validation_inputs in pending_validation:
            try:
                frozen = freeze_protocol_variants(
                    validation_inputs,
                    extractor=extractor,
                    extraction_policy=policy,
                    expected_executor_policy_sha256=expected_executor_policy,
                    blind_rank_by_candidate_sha256=rank_by_candidate_sha256,
                )
            except (MemoryError, KeyboardInterrupt, SystemExit):
                raise
            except ProtocolFreezeError as failure:
                exclusions.append(_exclusion(item, failure.failed_arm_roles, failure.failure_codes))
                continue
            patches.extend(frozen.intended_patches)
            proposals.extend(frozen.proposals)
            graphs.extend(frozen.graphs)
            deltas.extend(frozen.deltas)
            variants.extend(frozen.variants)
            lengths.extend(frozen.length_matches)
        bundle = (
            definitions[0],
            definitions[1],
            definitions[2],
            definitions[3],
            tuple(sorted(patches, key=lambda value: value.patch_id)),
            tuple(sorted(proposals, key=lambda value: value.proposal_id)),
            tuple(sorted(graphs, key=lambda value: value.graph_id)),
            tuple(sorted(deltas, key=lambda value: value.delta_id)),
            tuple(sorted(variants, key=lambda value: value.variant_id)),
            tuple(sorted(lengths, key=lambda value: value.length_match_id)),
            tuple(sorted(exclusions, key=lambda value: value.exclusion_id)),
        )
        _validate_bundle_relations(snapshot=snapshot, config=config, groups=bundle)
        return bundle

    producer_outputs = {
        "extract-prompt-tsg": extraction_paths,
        "fci-discovery": fci_paths,
    }
    with ExitStack() as stack:
        stack.enter_context(store.hold_dependency_stages(tuple(producer_outputs)))
        for producer in sorted(producer_outputs):
            store.require_committed_output(
                producer,
                producer_outputs[producer],
                expected_catalog_sha256=(
                    PROMPT_FEATURE_CATALOG_SHA256 if producer == "extract-prompt-tsg" else None
                ),
            )
        execute_jsonl_stage_transaction(
            store,
            stage=_STAGE,
            inputs=inputs,
            outputs=output_specs,
            force=force,
            build=build,
            policy_sha256=stage_policy_sha256,
            catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
            capture_input_snapshot=capture_input_snapshot,
            verify_input_snapshot=verify_input_snapshot,
        )
        if snapshot is None:
            raise _stage_error("prompt variant input snapshot failed validation")
        groups = tuple(
            tuple(
                read_jsonl(
                    spec.path,
                    spec.model,
                    required=True,
                    allow_empty=not spec.require_nonempty,
                    max_records=spec.max_records,
                    max_line_chars=spec.max_line_chars,
                    max_total_chars=spec.max_total_chars,
                    stage=_STAGE,
                )
            )
            for spec in output_specs
        )
        return _validate_bundle_relations(snapshot=snapshot, config=config, groups=groups)


__all__ = [
    "PROMPT_VARIANT_OUTPUTS",
    "PromptVariantStageResult",
    "prompt_variant_stage_policy_sha256",
    "run_prompt_variant_freeze_stage",
]
