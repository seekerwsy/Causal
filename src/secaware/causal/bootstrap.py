"""Authenticated task-cluster draws and deterministic FCI bootstrap execution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType

import numpy as np

from secaware.causal.background import validate_pag_against_background
from secaware.config import FCIDiscoveryConfig
from secaware.discovery.fci_supervisor import FCIRunner
from secaware.errors import ErrorCode, SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.randomness import DeterministicRNG, RNG_VERSION
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    BootstrapDrawItem,
    BootstrapDrawRecord,
    BootstrapFailureReason,
    BootstrapFailureRecord,
    BootstrapPAGRecord,
    CausalObservationRecord,
    CausalTableRecord,
    PAGRecord,
    PAGRunKind,
    VariableRole,
)


_MAX_TASKS = 100_000
_MAX_SEEDS_PER_TASK = 10_000
_MAX_REPLICATES = 10_000
_MIN_GLOBAL_SEED = -(2**63)
_MAX_GLOBAL_SEED = 2**63 - 1


def _bootstrap_error(message: str = "bootstrap inputs failed validation") -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal.bootstrap",
        message=message,
    )


@dataclass(frozen=True, slots=True)
class BootstrapReplicateResult:
    """One persisted draw paired with exactly one PAG or typed failure."""

    draw: BootstrapDrawRecord
    pag: BootstrapPAGRecord | None = None
    failure: BootstrapFailureRecord | None = None

    def __post_init__(self) -> None:
        try:
            draw = BootstrapDrawRecord.model_validate(self.draw)
            pag = None if self.pag is None else BootstrapPAGRecord.model_validate(self.pag)
            failure = (
                None
                if self.failure is None
                else BootstrapFailureRecord.model_validate(self.failure)
            )
            if (
                draw.run_kind is not PAGRunKind.OBSERVATIONAL_BOOTSTRAP
                or draw.replicate_index is None
                or (pag is None) == (failure is None)
                or (
                    pag is not None
                    and (
                        pag.table_id != draw.table_id
                        or pag.replicate_index != draw.replicate_index
                        or pag.draw_id != draw.draw_id
                    )
                )
                or (
                    failure is not None
                    and (
                        failure.table_id != draw.table_id
                        or failure.replicate_index != draw.replicate_index
                        or failure.draw_id != draw.draw_id
                    )
                )
            ):
                raise ValueError
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise _bootstrap_error("bootstrap result failed validation") from None


@dataclass(frozen=True, slots=True)
class TaskClusterFCIBootstrapResult:
    """Reference PAG and the complete ordered bootstrap denominator."""

    reference_draw: BootstrapDrawRecord
    reference_pag: PAGRecord
    replicates: tuple[BootstrapReplicateResult, ...]

    def __post_init__(self) -> None:
        try:
            reference_draw = BootstrapDrawRecord.model_validate(self.reference_draw)
            reference_pag = PAGRecord.model_validate(self.reference_pag)
            replicates = tuple(self.replicates)
            if (
                reference_draw.run_kind is not PAGRunKind.OBSERVATIONAL_REFERENCE
                or reference_pag.run_kind is not PAGRunKind.OBSERVATIONAL_REFERENCE
                or reference_draw.table_id != reference_pag.table_id
                or tuple(item.draw.replicate_index for item in replicates)
                != tuple(range(len(replicates)))
                or any(item.draw.table_id != reference_draw.table_id for item in replicates)
            ):
                raise ValueError
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise _bootstrap_error("bootstrap result failed validation") from None

    @property
    def bootstrap_draws(self) -> tuple[BootstrapDrawRecord, ...]:
        return tuple(item.draw for item in self.replicates)

    @property
    def bootstrap_pags(self) -> tuple[BootstrapPAGRecord, ...]:
        return tuple(item.pag for item in self.replicates if item.pag is not None)

    @property
    def pag_records(self) -> tuple[PAGRecord, ...]:
        return tuple(item.pag.pag for item in self.replicates if item.pag is not None)

    @property
    def bootstrap_failures(self) -> tuple[BootstrapFailureRecord, ...]:
        return tuple(item.failure for item in self.replicates if item.failure is not None)


@dataclass(frozen=True, slots=True)
class _AuthenticatedBundle:
    table: CausalTableRecord
    rows: tuple[CausalObservationRecord, ...]
    rows_by_task: tuple[tuple[str, tuple[CausalObservationRecord, ...]], ...]
    row_by_id: Mapping[str, CausalObservationRecord]
    sampling_frame_sha256: str


@dataclass(frozen=True, slots=True)
class _AuthenticatedMatrix:
    matrix: np.ndarray
    matrix_sha256: str


@dataclass(frozen=True, slots=True)
class BootstrapDrawReplay:
    """One deterministic Task-5 draw and its authenticated matrix commitment."""

    draw: BootstrapDrawRecord
    matrix_sha256: str

    def __post_init__(self) -> None:
        try:
            draw = BootstrapDrawRecord.model_validate(self.draw)
            if (
                draw.run_kind is not PAGRunKind.OBSERVATIONAL_BOOTSTRAP
                or draw.replicate_index is None
                or len(self.matrix_sha256) != 64
                or any(character not in "0123456789abcdef" for character in self.matrix_sha256)
            ):
                raise ValueError
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise _bootstrap_error("bootstrap replay failed validation") from None


class _InvalidPAG(Exception):
    pass


class _PAGBackgroundViolation(Exception):
    pass


def _checked_global_seed(global_seed: int) -> int:
    if type(global_seed) is not int or not _MIN_GLOBAL_SEED <= global_seed <= _MAX_GLOBAL_SEED:
        raise ValueError
    return global_seed


def _checked_replicate(replicate: int) -> int:
    if type(replicate) is not int or not 0 <= replicate < _MAX_REPLICATES:
        raise ValueError
    return replicate


def _canonical_seed_material(parts: tuple[object, ...]) -> bytes:
    return json.dumps(
        parts,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sampling_frame_digest(
    table: CausalTableRecord,
    rows_by_task: tuple[tuple[str, tuple[CausalObservationRecord, ...]], ...],
) -> str:
    return canonical_sha256(
        {
            "scope_id": table.scope_id,
            "cwe": table.cwe,
            "model_id": table.model_id,
            "pre_outcome_variables": [
                variable.model_dump(mode="json")
                for variable in table.variables
                if variable.role is not VariableRole.Y
            ],
            "coordinate_universe": [
                [row.task_id, row.prompt_id, row.seed_id]
                for _task_id, task_rows in rows_by_task
                for row in task_rows
            ],
        }
    )


def _authenticate_bundle(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord],
) -> _AuthenticatedBundle:
    try:
        checked_table = CausalTableRecord.model_validate(table)
        if type(rows) not in {list, tuple} or not 2 <= len(rows) <= _MAX_TASKS:
            raise ValueError
        checked_rows = tuple(CausalObservationRecord.model_validate(row) for row in rows)
        if len(checked_rows) != checked_table.row_count:
            raise ValueError
        row_ids: set[str] = set()
        coordinates: set[tuple[str, str, int]] = set()
        groups: dict[str, list[CausalObservationRecord]] = {}
        for row in checked_rows:
            coordinate = (row.task_id, row.prompt_id, row.seed_id)
            if (
                row.table_id != checked_table.table_id
                or row.model_id != checked_table.model_id
                or row.row_id in row_ids
                or coordinate in coordinates
            ):
                raise ValueError
            row_ids.add(row.row_id)
            coordinates.add(coordinate)
            groups.setdefault(row.task_id, []).append(row)
        if (
            not 2 <= len(groups) <= _MAX_TASKS
            or len(groups) != checked_table.independent_task_count
        ):
            raise ValueError
        ordered_groups: list[tuple[str, tuple[CausalObservationRecord, ...]]] = []
        seed_profiles: set[tuple[int, ...]] = set()
        for task_id in sorted(groups):
            task_rows = tuple(
                sorted(
                    groups[task_id],
                    key=lambda item: (item.prompt_id, item.seed_id),
                )
            )
            if (
                not 1 <= len(task_rows) <= _MAX_SEEDS_PER_TASK
                or len({item.prompt_id for item in task_rows}) != 1
                or len({item.seed_id for item in task_rows}) != len(task_rows)
            ):
                raise ValueError
            seed_profiles.add(tuple(item.seed_id for item in task_rows))
            ordered_groups.append((task_id, task_rows))
        if len(seed_profiles) != 1:
            raise ValueError
        payload = tuple(
            (row.row_id, row.task_id, row.prompt_id, row.seed_id, row.values)
            for row in checked_rows
        )
        rebuilt = CausalTableRecord.from_content(
            scope_id=checked_table.scope_id,
            cwe=checked_table.cwe,
            model_id=checked_table.model_id,
            variables=checked_table.variables,
            row_count=len(checked_rows),
            independent_task_count=len(groups),
            observation_payload=payload,
        )
        if rebuilt != checked_table:
            raise ValueError
        frozen_groups = tuple(ordered_groups)
        ordered_rows = tuple(
            sorted(
                checked_rows,
                key=lambda item: (item.task_id, item.prompt_id, item.seed_id),
            )
        )
        return _AuthenticatedBundle(
            table=checked_table,
            rows=ordered_rows,
            rows_by_task=frozen_groups,
            row_by_id=MappingProxyType({row.row_id: row for row in ordered_rows}),
            sampling_frame_sha256=_sampling_frame_digest(checked_table, frozen_groups),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _bootstrap_error() from None


def _draw_item(index: int, row: CausalObservationRecord) -> BootstrapDrawItem:
    return BootstrapDrawItem(
        draw_index=index,
        task_id=row.task_id,
        prompt_id=row.prompt_id,
        seed_id=row.seed_id,
        row_id=row.row_id,
    )


def sampling_frame_sha256(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord],
) -> str:
    """Hash only pre-outcome schema and task/prompt/seed coordinates."""
    return _authenticate_bundle(table, rows).sampling_frame_sha256


def _reference_draw_from_bundle(
    bundle: _AuthenticatedBundle,
    global_seed: int,
) -> BootstrapDrawRecord:
    seed_material = _canonical_seed_material(
        (
            global_seed,
            bundle.table.scope_id,
            bundle.table.model_id,
            bundle.sampling_frame_sha256,
            "reference",
        )
    )
    rng = DeterministicRNG(seed_material)
    items = tuple(
        _draw_item(index, rng.choice(task_rows))
        for index, (_task_id, task_rows) in enumerate(bundle.rows_by_task)
    )
    return BootstrapDrawRecord.from_content(
        table_id=bundle.table.table_id,
        run_kind=PAGRunKind.OBSERVATIONAL_REFERENCE,
        replicate_index=None,
        rng_version=RNG_VERSION,
        seed_material_sha256=hashlib.sha256(seed_material).hexdigest(),
        items=items,
    )


def build_reference_draw(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord],
    global_seed: int,
) -> BootstrapDrawRecord:
    """Select exactly one seed row for every sorted task without replacement."""
    try:
        return _reference_draw_from_bundle(
            _authenticate_bundle(table, rows),
            _checked_global_seed(global_seed),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _bootstrap_error() from None


def _bootstrap_draw_from_bundle(
    bundle: _AuthenticatedBundle,
    global_seed: int,
    replicate: int,
) -> BootstrapDrawRecord:
    seed_material = _canonical_seed_material(
        (
            global_seed,
            bundle.table.scope_id,
            bundle.table.model_id,
            bundle.sampling_frame_sha256,
            "bootstrap",
            replicate,
        )
    )
    rng = DeterministicRNG(seed_material)
    tasks = bundle.rows_by_task
    items: list[BootstrapDrawItem] = []
    for draw_index in range(bundle.table.independent_task_count):
        _task_id, task_rows = rng.choice(tasks)
        items.append(_draw_item(draw_index, rng.choice(task_rows)))
    return BootstrapDrawRecord.from_content(
        table_id=bundle.table.table_id,
        run_kind=PAGRunKind.OBSERVATIONAL_BOOTSTRAP,
        replicate_index=replicate,
        rng_version=RNG_VERSION,
        seed_material_sha256=hashlib.sha256(seed_material).hexdigest(),
        items=tuple(items),
    )


def build_bootstrap_draw(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord],
    global_seed: int,
    replicate: int,
) -> BootstrapDrawRecord:
    """Sample task IDs with replacement, then independently select one task seed."""
    try:
        return _bootstrap_draw_from_bundle(
            _authenticate_bundle(table, rows),
            _checked_global_seed(global_seed),
            _checked_replicate(replicate),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _bootstrap_error() from None


def _authenticated_matrix_from_bundle(
    bundle: _AuthenticatedBundle,
    draw: BootstrapDrawRecord,
) -> _AuthenticatedMatrix:
    try:
        checked_draw = BootstrapDrawRecord.model_validate(draw)
        if (
            checked_draw.table_id != bundle.table.table_id
            or checked_draw.rng_version != RNG_VERSION
            or len(checked_draw.items) != bundle.table.independent_task_count
        ):
            raise ValueError
        selected: list[CausalObservationRecord] = []
        for item in checked_draw.items:
            row = bundle.row_by_id.get(item.row_id)
            if row is None or (
                item.task_id,
                item.prompt_id,
                item.seed_id,
            ) != (row.task_id, row.prompt_id, row.seed_id):
                raise ValueError
            selected.append(row)
        if checked_draw.run_kind is PAGRunKind.OBSERVATIONAL_REFERENCE:
            if tuple(item.task_id for item in checked_draw.items) != tuple(
                task_id for task_id, _task_rows in bundle.rows_by_task
            ):
                raise ValueError
        matrix = np.asarray(tuple(row.values for row in selected), dtype=np.int64)
        expected_shape = (
            bundle.table.independent_task_count,
            len(bundle.table.variables),
        )
        if matrix.shape != expected_shape:
            raise ValueError
        matrix = np.array(matrix, dtype=np.int64, order="C", copy=True)
        matrix.flags.writeable = False
        digest = _matrix_digest(bundle.table, checked_draw, matrix)
        return _AuthenticatedMatrix(matrix=matrix, matrix_sha256=digest)
    except (KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _bootstrap_error() from None


def _authenticated_matrix_from_draw(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord],
    draw: BootstrapDrawRecord,
) -> _AuthenticatedMatrix:
    return _authenticated_matrix_from_bundle(_authenticate_bundle(table, rows), draw)


def authenticated_matrix_from_draw(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord],
    draw: BootstrapDrawRecord,
) -> np.ndarray:
    """Reconstruct a read-only int64 matrix solely from authenticated rows and draw."""
    return _authenticated_matrix_from_draw(table, rows, draw).matrix


def replay_bootstrap_draws(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord],
    global_seed: int,
    bootstrap_samples: int,
) -> tuple[BootstrapDrawReplay, ...]:
    """Authenticate a bundle once and replay its complete deterministic denominator."""
    bundle = _authenticate_bundle(table, rows)
    try:
        checked_seed = _checked_global_seed(global_seed)
        if type(bootstrap_samples) is not int or not 1 <= bootstrap_samples <= _MAX_REPLICATES:
            raise ValueError
        result: list[BootstrapDrawReplay] = []
        for replicate in range(bootstrap_samples):
            draw = _bootstrap_draw_from_bundle(bundle, checked_seed, replicate)
            authenticated = _authenticated_matrix_from_bundle(bundle, draw)
            result.append(
                BootstrapDrawReplay(
                    draw=draw,
                    matrix_sha256=authenticated.matrix_sha256,
                )
            )
        return tuple(result)
    except (KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _bootstrap_error("bootstrap replay failed validation") from None


def _matrix_digest(
    table: CausalTableRecord,
    draw: BootstrapDrawRecord,
    matrix: np.ndarray,
) -> str:
    return canonical_sha256(
        {
            "table_sha256": table.table_sha256,
            "draw_sha256": draw.draw_sha256,
            "values": matrix.tolist(),
        }
    )


def _validated_pag(
    raw: object,
    *,
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    run_kind: PAGRunKind,
) -> PAGRecord:
    try:
        pag = PAGRecord.model_validate(raw)
        if (
            pag.run_kind is not run_kind
            or pag.table_id != table.table_id
            or pag.backend != config.backend
            or pag.backend_version != config.backend_version
            or pag.ci_test != config.ci_test
            or pag.config_sha256 != canonical_sha256(config.model_dump(mode="json"))
            or pag.background_knowledge_sha256 != knowledge.knowledge_sha256
            or pag.variable_ids != tuple(item.variable_id for item in table.variables)
        ):
            raise ValueError
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _InvalidPAG from None
    try:
        validate_pag_against_background(pag, knowledge)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _PAGBackgroundViolation from None
    return pag


def _run_authenticated_draw(
    *,
    bundle: _AuthenticatedBundle,
    draw: BootstrapDrawRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    runner: FCIRunner,
) -> tuple[PAGRecord, str]:
    authenticated = _authenticated_matrix_from_bundle(bundle, draw)
    pag = runner.run(
        authenticated.matrix,
        bundle.table,
        knowledge,
        config,
        draw.run_kind,
    )
    if _matrix_digest(bundle.table, draw, authenticated.matrix) != authenticated.matrix_sha256:
        raise _InvalidPAG
    return (
        _validated_pag(
            pag,
            table=bundle.table,
            knowledge=knowledge,
            config=config,
            run_kind=draw.run_kind,
        ),
        authenticated.matrix_sha256,
    )


def _failure_reason(error: BaseException) -> BootstrapFailureReason:
    if isinstance(error, _PAGBackgroundViolation):
        return BootstrapFailureReason.BACKGROUND_KNOWLEDGE_VIOLATION
    if isinstance(error, _InvalidPAG):
        return BootstrapFailureReason.INVALID_BACKEND_OUTPUT
    if not isinstance(error, SecAwareError):
        return BootstrapFailureReason.BACKEND_CRASH
    message = error.message.casefold()
    if "timed out" in message or "timeout" in message:
        return BootstrapFailureReason.BACKEND_TIMEOUT
    if "background knowledge" in message:
        return BootstrapFailureReason.BACKGROUND_KNOWLEDGE_VIOLATION
    if "degenerate" in message or "g-square support" in message:
        return BootstrapFailureReason.DEGENERATE_GSQ_SUPPORT
    if "worker failed validation" in message or "crash" in message:
        return BootstrapFailureReason.BACKEND_CRASH
    return BootstrapFailureReason.INVALID_BACKEND_OUTPUT


def _typed_failure(
    *,
    table: CausalTableRecord,
    draw: BootstrapDrawRecord,
    config: FCIDiscoveryConfig,
    error: BaseException,
) -> BootstrapFailureRecord:
    reason = _failure_reason(error)
    detail_sha256 = canonical_sha256(
        {
            "stage": "causal.bootstrap",
            "reason_code": reason.value,
        }
    )
    if draw.replicate_index is None:
        raise _bootstrap_error("bootstrap result failed validation")
    return BootstrapFailureRecord.from_content(
        table_id=table.table_id,
        replicate_index=draw.replicate_index,
        draw_id=draw.draw_id,
        reason_code=reason,
        fci_config_sha256=canonical_sha256(config.model_dump(mode="json")),
        detail_sha256=detail_sha256,
    )


def run_task_cluster_fci_bootstrap(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord],
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    global_seed: int,
    runner: FCIRunner,
) -> TaskClusterFCIBootstrapResult:
    """Run one reference FCI and the complete configured task-cluster denominator."""
    bundle = _authenticate_bundle(table, rows)
    try:
        checked_knowledge = BackgroundKnowledgeRecord.model_validate(knowledge)
        checked_config = FCIDiscoveryConfig.model_validate(config)
        checked_seed = _checked_global_seed(global_seed)
        if (
            checked_knowledge.table_id != bundle.table.table_id
            or checked_config.bootstrap_samples > _MAX_REPLICATES
            or not callable(getattr(runner, "run", None))
        ):
            raise ValueError
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _bootstrap_error() from None

    reference_draw = _reference_draw_from_bundle(bundle, checked_seed)
    try:
        reference_pag, _reference_matrix_sha256 = _run_authenticated_draw(
            bundle=bundle,
            draw=reference_draw,
            knowledge=checked_knowledge,
            config=checked_config,
            runner=runner,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        raise _bootstrap_error("reference FCI run failed validation") from None

    results: list[BootstrapReplicateResult] = []
    for replicate in range(checked_config.bootstrap_samples):
        draw = _bootstrap_draw_from_bundle(bundle, checked_seed, replicate)
        try:
            pag, matrix_sha256 = _run_authenticated_draw(
                bundle=bundle,
                draw=draw,
                knowledge=checked_knowledge,
                config=checked_config,
                runner=runner,
            )
            if draw.replicate_index is None:
                raise _InvalidPAG
            envelope = BootstrapPAGRecord.from_content(
                table_id=bundle.table.table_id,
                replicate_index=draw.replicate_index,
                draw_id=draw.draw_id,
                matrix_sha256=matrix_sha256,
                pag=pag,
            )
            results.append(BootstrapReplicateResult(draw=draw, pag=envelope))
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as error:
            results.append(
                BootstrapReplicateResult(
                    draw=draw,
                    failure=_typed_failure(
                        table=bundle.table,
                        draw=draw,
                        config=checked_config,
                        error=error,
                    ),
                )
            )
    return TaskClusterFCIBootstrapResult(
        reference_draw=reference_draw,
        reference_pag=reference_pag,
        replicates=tuple(results),
    )


__all__ = [
    "BootstrapDrawReplay",
    "BootstrapReplicateResult",
    "TaskClusterFCIBootstrapResult",
    "authenticated_matrix_from_draw",
    "build_bootstrap_draw",
    "build_reference_draw",
    "run_task_cluster_fci_bootstrap",
    "replay_bootstrap_draws",
    "sampling_frame_sha256",
]
