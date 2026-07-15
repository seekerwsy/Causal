"""Atomic deterministic randomization of frozen confirmation variants."""

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
from secaware.config import AppConfig, RandomizationConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.experiments.randomization import (
    RandomizationBlock,
    RandomizationError,
    RandomizationFailureCode,
    build_randomization_blocks,
    randomize_protocols,
    validate_randomization_bundle,
)
from secaware.intervention.graph_patch import IntendedGraphPatchRecord
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.pipeline.bounded_traversal import BoundedTraversalError, iter_bounded_tree
from secaware.pipeline.manifest import StageManifest
from secaware.pipeline.stages.fci_discovery import FCI_DISCOVERY_OUTPUTS
from secaware.pipeline.stages.prompt_variants import PROMPT_VARIANT_OUTPUTS
from secaware.schema.causal import FrozenHypothesisRecord
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import (
    AssignmentRecord,
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    GraphDeltaRecord,
    LengthMatchRecord,
    PreRandomizationExclusionRecord,
    PromptVariantRecord,
    RandomizationManifestRecord,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


_STAGE = "randomize-confirmation"
_MAX_INPUT_FILE_BYTES = 256_000_000
_MAX_COMBINED_INPUT_BYTES = 1_000_000_000
_MAX_JSONL_RECORDS = 100_000
_MAX_JSONL_LINE_BYTES = 4_000_000
_MAX_ASSIGNMENTS = 100_000
_MAX_FUTURE_TRAVERSAL_ENTRIES = 100_000
_MAX_FUTURE_TRAVERSAL_DEPTH = 32
_MAX_FUTURE_RELATIVE_PATH_CHARS = 4096
_MAX_FUTURE_NAME_CHARS = 255
_FUTURE_STAGE_NAMES = frozenset(
    {
        "generate-confirmation",
        "run-oracle-confirmation",
        "import-functional-outcomes",
        "analyze-jci",
        "analyze-rfci",
        "effects",
        "report",
        "jci",
        "rfci",
        "reporting",
    }
)
_FUTURE_STAGE_PREFIXES = tuple(name + "-" for name in sorted(_FUTURE_STAGE_NAMES))
_FUTURE_ARTIFACT_PREFIXES = {
    "generation": ("confirmation", "assignment"),
    "oracle": ("confirmation",),
}


RANDOMIZATION_OUTPUTS = (
    ("randomization_manifest.jsonl", RandomizationManifestRecord),
    ("assignments.jsonl", AssignmentRecord),
)


_TASK4_MODELS = (
    TargetSpecRecord,
    TargetInstanceRecord,
    ConfirmationProtocolRecord,
    ConfirmationProtocolInstanceRecord,
    IntendedGraphPatchRecord,
    PromptExtractionProposalRecord,
    PromptTSGRecord,
    GraphDeltaRecord,
    PromptVariantRecord,
    LengthMatchRecord,
    PreRandomizationExclusionRecord,
)


@dataclass(frozen=True, slots=True, repr=False)
class _FileSnapshot:
    path: Path
    sha256: str
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True, slots=True, repr=False)
class _RandomizationInputSnapshot:
    files: tuple[_FileSnapshot, ...]
    blocks: tuple[RandomizationBlock, ...]


@dataclass(frozen=True, slots=True)
class RandomizationStageResult:
    block_count: int
    assignment_count: int
    manifest_id: str


def _stage_error(message: str, *, failure_code: str | None = None) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage=_STAGE,
        message=message,
        details=({"failure_code": failure_code} if failure_code is not None else {}),
        retryable=False,
    )


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )


def _read_file_snapshot(path: Path, *, allow_empty: bool) -> tuple[bytes, _FileSnapshot]:
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
        snapshot = _FileSnapshot(path, digest.hexdigest(), _file_identity(after_path))
        return bytes(buffer), snapshot
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("randomization input snapshot failed validation") from None
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


def _json_value(payload: bytes) -> object:
    return json.loads(
        payload.decode("utf-8", errors="strict"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )


def _parse_jsonl(payload: bytes, model: type, *, allow_empty: bool) -> tuple[object, ...]:
    try:
        text = payload.decode("utf-8", errors="strict")
        records: list[object] = []
        for raw in text.splitlines():
            if not raw.strip():
                continue
            if len(raw.encode("utf-8")) > _MAX_JSONL_LINE_BYTES:
                raise ValueError
            records.append(model.model_validate(_json_value(raw.encode("utf-8"))))
            if len(records) > _MAX_JSONL_RECORDS:
                raise ValueError
        if not records and not allow_empty:
            raise ValueError
        return tuple(records)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("randomization input artifact failed validation") from None


def _parse_manifest(payload: bytes) -> StageManifest:
    try:
        return StageManifest.model_validate(_json_value(payload))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("randomization input artifact failed validation") from None


def _guard_no_generation_or_future_artifacts(store: RunStore) -> None:
    total_entries = 0

    def entries(directory: str):
        nonlocal total_entries
        for entry in iter_bounded_tree(
            store.path(directory),
            max_entries=_MAX_FUTURE_TRAVERSAL_ENTRIES,
            max_depth=_MAX_FUTURE_TRAVERSAL_DEPTH,
            max_relative_path_chars=_MAX_FUTURE_RELATIVE_PATH_CHARS,
            max_name_chars=_MAX_FUTURE_NAME_CHARS,
        ):
            total_entries += 1
            if total_entries > _MAX_FUTURE_TRAVERSAL_ENTRIES:
                raise BoundedTraversalError(limit_exceeded=True)
            yield entry

    try:
        for candidate in entries(".stages"):
            path = Path(candidate.relative_path)
            if (
                not candidate.is_file
                or path.parent != Path(".")
                or path.suffix.casefold() != ".json"
            ):
                continue
            stage_name = path.stem.casefold()
            if stage_name in _FUTURE_STAGE_NAMES or any(
                stage_name.startswith(prefix) for prefix in _FUTURE_STAGE_PREFIXES
            ):
                raise ValueError
        for directory in ("analysis", "reports"):
            if any(candidate.is_file for candidate in entries(directory)):
                raise ValueError
        for directory, prefixes in _FUTURE_ARTIFACT_PREFIXES.items():
            for candidate in entries(directory):
                if candidate.is_file and candidate.name.casefold().startswith(prefixes):
                    raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except BoundedTraversalError as error:
        raise _stage_error(
            "future confirmation artifact traversal failed validation",
            failure_code=(
                "future_artifact_traversal_limit"
                if error.limit_exceeded
                else "future_artifact_traversal_unsafe"
            ),
        ) from None
    except Exception:
        raise _stage_error("future confirmation artifact already exists") from None


def _validate_input_manifests(
    task4_manifest: StageManifest,
    fci_manifest: StageManifest,
    task4_paths: tuple[Path, ...],
    task4_snapshots: tuple[_FileSnapshot, ...],
    hypothesis_path: Path,
    hypothesis_snapshot: _FileSnapshot,
) -> None:
    try:
        task4_relative = tuple(f"interventions/{name}" for name, _model in PROMPT_VARIANT_OUTPUTS)
        hypothesis_relative = "discovery/hypotheses_frozen.jsonl"
        if (
            task4_manifest.stage != "build-confirmation-variants"
            or task4_manifest.catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
            or tuple(task4_manifest.outputs) != task4_relative
            or tuple(task4_manifest.output_sha256.get(path) for path in task4_relative)
            != tuple(item.sha256 for item in task4_snapshots)
            or fci_manifest.stage != "fci-discovery"
            or hypothesis_relative not in fci_manifest.outputs
            or fci_manifest.output_sha256.get(hypothesis_relative) != hypothesis_snapshot.sha256
            or len(task4_paths) != len(task4_snapshots)
            or hypothesis_path.name != "hypotheses_frozen.jsonl"
        ):
            raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("randomization producer provenance failed validation") from None


def _validate_output_bundle(
    manifest: RandomizationManifestRecord,
    assignments: tuple[AssignmentRecord, ...],
    blocks: tuple[RandomizationBlock, ...],
    confirmation_seeds: tuple[int, ...],
    *,
    global_seed: int,
    randomization_config: RandomizationConfig,
) -> RandomizationStageResult:
    try:
        if (
            manifest.global_seed != global_seed
            or manifest.rng_version != randomization_config.rng_version
        ):
            raise RandomizationError(RandomizationFailureCode.INVALID_INPUT)
        validate_randomization_bundle(
            manifest,
            assignments,
            blocks,
            confirmation_seeds,
            config=randomization_config,
        )
        return RandomizationStageResult(
            block_count=len(blocks),
            assignment_count=len(assignments),
            manifest_id=manifest.manifest_id,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except RandomizationError as error:
        raise _stage_error(
            "randomization output bundle failed validation",
            failure_code=error.failure_code.value,
        ) from None
    except Exception:
        raise _stage_error("randomization output bundle failed validation") from None


def validate_randomization_artifact_bundle(
    manifest: RandomizationManifestRecord,
    assignments: Sequence[AssignmentRecord],
    *,
    target_specs: Sequence[TargetSpecRecord],
    target_instances: Sequence[TargetInstanceRecord],
    protocols: Sequence[ConfirmationProtocolRecord],
    protocol_instances: Sequence[ConfirmationProtocolInstanceRecord],
    variants: Sequence[PromptVariantRecord],
    exclusions: Sequence[PreRandomizationExclusionRecord],
    hypotheses: Sequence[FrozenHypothesisRecord],
    confirmation_seeds: Sequence[int],
    global_seed: int,
    randomization_config: RandomizationConfig,
    block_builder=build_randomization_blocks,
) -> RandomizationStageResult:
    """Rebuild and authenticate the complete Task-4/randomization closure."""

    try:
        blocks = block_builder(
            target_specs=target_specs,
            target_instances=target_instances,
            protocols=protocols,
            protocol_instances=protocol_instances,
            variants=variants,
            exclusions=exclusions,
            hypotheses=hypotheses,
            max_blocks=randomization_config.max_blocks,
        )
        return _validate_output_bundle(
            RandomizationManifestRecord.model_validate(manifest.model_dump(mode="json")),
            tuple(
                AssignmentRecord.model_validate(item.model_dump(mode="json"))
                for item in assignments
            ),
            blocks,
            tuple(confirmation_seeds),
            global_seed=global_seed,
            randomization_config=randomization_config,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except RandomizationError as error:
        raise _stage_error(
            "randomization artifact bundle failed validation",
            failure_code=error.failure_code.value,
        ) from None
    except Exception:
        raise _stage_error("randomization artifact bundle failed validation") from None
    finally:
        block_builder = None


def run_confirmation_randomization_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
) -> RandomizationStageResult:
    """Freeze assignments atomically before any confirmation generation."""

    if (
        type(config) is not AppConfig
        or type(store) is not RunStore
        or store.config != config
        or not model_shape_is_intact(config)
    ):
        raise _stage_error("randomization stage configuration failed validation")
    try:
        effective_config = AppConfig.model_validate(config.model_dump(mode="json"))
        effective_store = RunStore(effective_config)
        if effective_store.root != store.root:
            raise ValueError
        effective_global_seed = effective_config.run.random_seed
        effective_confirmation_seeds = tuple(sorted(effective_config.generation.confirmation_seeds))
        effective_randomization = RandomizationConfig.model_validate(
            effective_config.randomization.model_dump(mode="json")
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("randomization stage configuration failed validation") from None
    task4_paths = tuple(
        effective_store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
    )
    task4_manifest_path = effective_store.path(".stages", "build-confirmation-variants.json")
    fci_paths = tuple(
        effective_store.path("discovery", name) for name, _model in FCI_DISCOVERY_OUTPUTS
    )
    hypothesis_path = next(path for path in fci_paths if path.name == "hypotheses_frozen.jsonl")
    fci_manifest_path = effective_store.path(".stages", "fci-discovery.json")
    inputs = (*task4_paths, task4_manifest_path, hypothesis_path, fci_manifest_path)
    output_specs = tuple(
        JsonlOutputSpec(
            effective_store.path("interventions", name),
            model,
            require_nonempty=True,
            max_records=(1 if index == 0 else _MAX_ASSIGNMENTS),
        )
        for index, (name, model) in enumerate(RANDOMIZATION_OUTPUTS)
    )
    snapshot: _RandomizationInputSnapshot | None = None
    built_manifest: RandomizationManifestRecord | None = None
    built_assignments: tuple[AssignmentRecord, ...] | None = None

    def capture_input_snapshot() -> tuple[str, ...]:
        nonlocal snapshot
        if snapshot is not None:
            raise _stage_error("randomization input snapshot failed validation")
        _guard_no_generation_or_future_artifacts(effective_store)
        payloads: list[bytes] = []
        file_snapshots: list[_FileSnapshot] = []
        combined = 0
        for index, path in enumerate(inputs):
            allow_empty = index < len(task4_paths) and index >= 4
            payload, file_snapshot = _read_file_snapshot(path, allow_empty=allow_empty)
            combined += len(payload)
            if combined > _MAX_COMBINED_INPUT_BYTES:
                payloads.clear()
                file_snapshots.clear()
                raise _stage_error("randomization input snapshot exceeded bounds")
            payloads.append(payload)
            file_snapshots.append(file_snapshot)
        task4_payloads = payloads[: len(task4_paths)]
        task4_groups = tuple(
            _parse_jsonl(payload, model, allow_empty=index >= 4)
            for index, (payload, model) in enumerate(
                zip(task4_payloads, _TASK4_MODELS, strict=True)
            )
        )
        manifest_index = len(task4_paths)
        task4_manifest = _parse_manifest(payloads[manifest_index])
        try:
            hypotheses = tuple(
                revalidate_frozen_hypothesis(item)
                for item in _parse_jsonl(
                    payloads[manifest_index + 1],
                    FrozenHypothesisRecord,
                    allow_empty=False,
                )
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise _stage_error("randomization input artifact failed validation") from None
        fci_manifest = _parse_manifest(payloads[manifest_index + 2])
        _validate_input_manifests(
            task4_manifest,
            fci_manifest,
            task4_paths,
            tuple(file_snapshots[: len(task4_paths)]),
            hypothesis_path,
            file_snapshots[manifest_index + 1],
        )
        try:
            blocks = build_randomization_blocks(
                target_specs=task4_groups[0],  # type: ignore[arg-type]
                target_instances=task4_groups[1],  # type: ignore[arg-type]
                protocols=task4_groups[2],  # type: ignore[arg-type]
                protocol_instances=task4_groups[3],  # type: ignore[arg-type]
                variants=task4_groups[8],  # type: ignore[arg-type]
                exclusions=task4_groups[10],  # type: ignore[arg-type]
                hypotheses=hypotheses,
                max_blocks=effective_randomization.max_blocks,
            )
            assignment_capacity = len(blocks) * len(effective_confirmation_seeds)
            if assignment_capacity < 1 or assignment_capacity > _MAX_ASSIGNMENTS:
                raise RandomizationError(RandomizationFailureCode.RESOURCE_LIMIT)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except RandomizationError as error:
            raise _stage_error(
                "randomization pre-assignment validation failed",
                failure_code=error.failure_code.value,
            ) from None
        snapshot = _RandomizationInputSnapshot(
            files=tuple(file_snapshots),
            blocks=blocks,
        )
        payloads.clear()
        return tuple(item.sha256 for item in snapshot.files)

    def verify_input_snapshot() -> None:
        if snapshot is None:
            raise _stage_error("randomization input snapshot failed validation")
        _guard_no_generation_or_future_artifacts(effective_store)
        for expected in snapshot.files:
            _payload, current = _read_file_snapshot(
                expected.path,
                allow_empty=expected.identity[4] == 0,
            )
            if current != expected:
                raise _stage_error("randomization inputs changed during execution")

    def build():
        nonlocal built_manifest, built_assignments
        if snapshot is None or built_manifest is not None or built_assignments is not None:
            raise _stage_error("randomization input snapshot failed validation")
        _guard_no_generation_or_future_artifacts(effective_store)
        try:
            built_manifest, built_assignments = randomize_protocols(
                snapshot.blocks,
                global_seed=effective_global_seed,
                confirmation_seeds=effective_confirmation_seeds,
                config=effective_randomization,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except RandomizationError as error:
            raise _stage_error(
                "randomization pre-assignment validation failed",
                failure_code=error.failure_code.value,
            ) from None
        _validate_output_bundle(
            built_manifest,
            built_assignments,
            snapshot.blocks,
            effective_confirmation_seeds,
            global_seed=effective_global_seed,
            randomization_config=effective_randomization,
        )
        return ((built_manifest,), built_assignments)

    def validate_staged_outputs(groups: tuple[tuple[object, ...], ...]) -> None:
        if snapshot is None or len(groups) != 2 or len(groups[0]) != 1:
            raise _stage_error("randomization output bundle failed validation")
        manifest = groups[0][0]
        assignments = groups[1]
        if not isinstance(manifest, RandomizationManifestRecord) or any(
            not isinstance(item, AssignmentRecord) for item in assignments
        ):
            raise _stage_error("randomization output bundle failed validation")
        _validate_output_bundle(
            manifest,
            assignments,  # type: ignore[arg-type]
            snapshot.blocks,
            effective_confirmation_seeds,
            global_seed=effective_global_seed,
            randomization_config=effective_randomization,
        )

    producer_outputs = {
        "build-confirmation-variants": task4_paths,
        "fci-discovery": fci_paths,
    }
    with ExitStack() as stack:
        for producer_stage in sorted(producer_outputs):
            stack.enter_context(
                effective_store.hold_committed_output(
                    producer_stage,
                    producer_outputs[producer_stage],
                    expected_catalog_sha256=(
                        PROMPT_FEATURE_CATALOG_SHA256
                        if producer_stage == "build-confirmation-variants"
                        else None
                    ),
                )
            )
        execute_jsonl_stage_transaction(
            effective_store,
            stage=_STAGE,
            inputs=inputs,
            outputs=output_specs,
            force=force,
            build=build,
            capture_input_snapshot=capture_input_snapshot,
            verify_input_snapshot=verify_input_snapshot,
            validate_staged_outputs=validate_staged_outputs,
        )
        if snapshot is None:
            raise _stage_error("randomization input snapshot failed validation")
        manifests = read_jsonl(
            output_specs[0].path,
            RandomizationManifestRecord,
            required=True,
            allow_empty=False,
            max_records=1,
            stage=_STAGE,
        )
        assignments = tuple(
            read_jsonl(
                output_specs[1].path,
                AssignmentRecord,
                required=True,
                allow_empty=False,
                max_records=_MAX_ASSIGNMENTS,
                stage=_STAGE,
            )
        )
        if len(manifests) != 1:
            raise _stage_error("randomization output bundle failed validation")
        return _validate_output_bundle(
            manifests[0],
            assignments,
            snapshot.blocks,
            effective_confirmation_seeds,
            global_seed=effective_global_seed,
            randomization_config=effective_randomization,
        )


__all__ = [
    "RANDOMIZATION_OUTPUTS",
    "RandomizationStageResult",
    "run_confirmation_randomization_stage",
    "validate_randomization_artifact_bundle",
]
