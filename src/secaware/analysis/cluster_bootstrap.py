"""Deterministic task-cluster bootstrap primitives for randomized ITT."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import math
from typing import Literal

from secaware.pipeline.artifact import canonical_sha256
from secaware.randomness import DeterministicRNG, RNG_VERSION
from secaware.schema.common import model_shape_is_intact
from secaware.schema.outcomes import AssignmentOutcomeRecord


_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_MAX_TOTAL_TASK_DRAW_ENTRIES = 1_000_000
_MAX_TASK_DRAW_MANIFEST_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ClusterBootstrapResult:
    estimates: tuple[float, ...]
    failed_replicates: int
    task_draws: tuple[tuple[str, ...], ...]
    manifest_sha256: str


def _error() -> ValueError:
    return ValueError("task-cluster bootstrap failed validation")


def linear_percentile(
    values: Sequence[float],
    quantile: float,
    *,
    method: Literal["linear-v1"] = "linear-v1",
) -> float:
    """NumPy-compatible linear interpolation pinned as ``linear-v1``."""

    if (
        isinstance(values, (str, bytes, Mapping))
        or type(quantile) is not float
        or not math.isfinite(quantile)
        or not 0.0 <= quantile <= 1.0
        or method != "linear-v1"
    ):
        raise _error()
    try:
        ordered = sorted(float(value) for value in values)
    except _FATAL:
        raise
    except Exception:
        raise _error() from None
    if not ordered or any(not math.isfinite(value) for value in ordered):
        raise _error()
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


def task_cluster_bootstrap(
    rows: Sequence[AssignmentOutcomeRecord],
    statistic: Callable[[tuple[AssignmentOutcomeRecord, ...]], float],
    *,
    samples: int,
    seed_material: bytes,
    max_failed_fraction: float,
) -> ClusterBootstrapResult:
    """Sample sorted task IDs with replacement and carry each complete task cluster."""

    if (
        isinstance(rows, (str, bytes, Mapping))
        or not callable(statistic)
        or type(samples) is not int
        or not 1 <= samples <= 10_000
        or type(seed_material) is not bytes
        or not seed_material
        or type(max_failed_fraction) is not float
        or not math.isfinite(max_failed_fraction)
        or not 0.0 <= max_failed_fraction < 1.0
    ):
        raise _error()
    by_task: dict[str, list[AssignmentOutcomeRecord]] = {}
    assignment_ids: set[str] = set()
    try:
        for index, row in enumerate(rows):
            if (
                index >= 100_000
                or type(row) is not AssignmentOutcomeRecord
                or not model_shape_is_intact(row)
                or row.assignment_id in assignment_ids
            ):
                raise _error()
            checked = AssignmentOutcomeRecord.model_validate(
                row.model_dump(mode="python", round_trip=True, warnings=False)
            )
            assignment_ids.add(checked.assignment_id)
            by_task.setdefault(checked.task_id, []).append(checked)
        task_ids = tuple(sorted(by_task))
        if not task_ids:
            raise _error()
        task_draw_entries = len(task_ids) * samples
        largest_encoded_task_id = max(
            len(
                json.dumps(
                    task_id,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            for task_id in task_ids
        )
        per_draw_bytes = 2 + len(task_ids) * (largest_encoded_task_id + 1)
        task_draw_manifest_bytes = 2 + samples * (per_draw_bytes + 1)
        if (
            task_draw_entries > _MAX_TOTAL_TASK_DRAW_ENTRIES
            or task_draw_manifest_bytes > _MAX_TASK_DRAW_MANIFEST_BYTES
        ):
            raise _error()
        clusters = {
            task_id: tuple(sorted(by_task[task_id], key=lambda item: item.assignment_id))
            for task_id in task_ids
        }
        rng = DeterministicRNG(seed_material)
        estimates: list[float] = []
        task_draws: list[tuple[str, ...]] = []
        failed_indexes: list[int] = []
        task_indexes = {task_id: index for index, task_id in enumerate(task_ids)}
        draw_stream = hashlib.sha256()
        draw_stream.update(
            bytes.fromhex(
                canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "stream_kind": "task-cluster-draw-index-stream-v1",
                        "samples": samples,
                        "draw_width": len(task_ids),
                        "task_ids": list(task_ids),
                    }
                )
            )
        )
        for replicate in range(samples):
            draw = tuple(rng.choice(task_ids) for _ in task_ids)
            task_draws.append(draw)
            for task_id in draw:
                draw_stream.update(task_indexes[task_id].to_bytes(4, "big"))
            sampled_rows = tuple(row for task_id in draw for row in clusters[task_id])
            try:
                estimate = statistic(sampled_rows)
                if type(estimate) not in {float, int}:
                    raise TypeError
                estimate = float(estimate)
                if not math.isfinite(estimate):
                    raise ValueError
            except _FATAL:
                raise
            except Exception:
                failed_indexes.append(replicate)
                continue
            estimates.append(estimate)
        failed = len(failed_indexes)
        if failed / samples > max_failed_fraction or not estimates:
            raise _error()
        manifest_sha256 = canonical_sha256(
            {
                "schema_version": "1.0",
                "bootstrap_kind": "task-cluster-risk-difference-v1",
                "rng_version": RNG_VERSION,
                "samples": samples,
                "max_failed_fraction": max_failed_fraction,
                "task_ids": list(task_ids),
                "assignment_ids": sorted(assignment_ids),
                "task_draw_stream_sha256": draw_stream.hexdigest(),
                "failed_replicate_indexes": list(failed_indexes),
                "estimates": list(estimates),
            }
        )
        return ClusterBootstrapResult(
            estimates=tuple(estimates),
            failed_replicates=failed,
            task_draws=tuple(task_draws),
            manifest_sha256=manifest_sha256,
        )
    except _FATAL:
        raise
    except Exception:
        raise _error() from None


__all__ = ["ClusterBootstrapResult", "linear_percentile", "task_cluster_bootstrap"]
