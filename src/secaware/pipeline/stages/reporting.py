"""Read-only transactional publication of final Prompt-only reports."""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
import hashlib
from io import StringIO
import json
import math
import os
from pathlib import Path
import stat
import tempfile
from typing import Callable, Literal, Sequence, TypeVar, cast

from pydantic import BaseModel

from secaware.config import AppConfig, RFCIConfig
from secaware.discovery.rfci_backend import validate_rfci_capability
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.run_store import RunStore, StageCommitLease
from secaware.io.transaction import (
    ArtifactTransaction,
    TransactionArtifact,
    TransactionStateError,
    cleanup_committed_transaction,
    recover_transaction,
    resolve_pending_transaction,
)
from secaware.pipeline.artifact import canonical_sha256
from secaware.pipeline.stages.effects import EFFECT_STAGE_OUTPUTS
from secaware.pipeline.stages.fci_discovery import FCI_DISCOVERY_OUTPUTS
from secaware.pipeline.stages.jci import JCI_STAGE_OUTPUTS
from secaware.pipeline.stages.prompt_variants import PROMPT_VARIANT_OUTPUTS
from secaware.pipeline.stages.randomization import RANDOMIZATION_OUTPUTS
from secaware.pipeline.stages.rfci import RFCI_STAGE_OUTPUTS
from secaware.reports.hypothesis_cards import build_hypothesis_cards
from secaware.reports.tables import (
    EFFECT_FIELDS,
    FAILURE_FIELDS,
    JCI_ORIENTATION_FIELDS,
    RFCI_CAPABILITY_PREFIX,
    ReportDocuments,
    build_assignment_rows,
    build_effect_rows,
    build_failure_rows,
    build_intervention_rows,
    build_jci_orientation_rows,
    canonical_csv_bytes,
    canonical_jsonl_bytes,
    canonical_markdown_code,
    decode_canonical_markdown_code,
    render_summary,
)
from secaware.schema.causal import (
    BootstrapFailureRecord,
    DiscoveryFailureRecord,
    FrozenHypothesisRecord,
    PAGRecord,
    PAGRunKind,
)
from secaware.schema.experiments import (
    AssignmentRecord,
    GraphDeltaRecord,
    PreRandomizationExclusionRecord,
    PromptVariantRecord,
)
from secaware.schema.outcomes import (
    AnalysisFailureRecord,
    AnalysisStage,
    AssignmentOutcomeRecord,
    ContrastSpecRecord,
    ITTEffectRecord,
    JCIOrientationDeltaRecord,
    RFCICapabilityRecord,
)
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


_STAGE = "report"
REPORT_PRODUCER_STAGES = (
    "build-confirmation-variants",
    "estimate-confirmation-effects",
    "fci-discovery",
    "jci-confirmation",
    "randomize-confirmation",
    "rfci-confirmation",
)

REPORT_STAGE_OUTPUTS = (
    Path("reports/discovery_pags.jsonl"),
    Path("reports/hypotheses.jsonl"),
    Path("reports/interventions.jsonl"),
    Path("reports/assignments.jsonl"),
    Path("reports/effects.csv"),
    Path("reports/jci_orientations.csv"),
    Path("reports/failures.csv"),
    Path("reports/hypothesis_cards.jsonl"),
    Path("reports/summary.md"),
)

REPORT_STAGE_INPUTS = (
    *(Path("discovery") / name for name, _model in FCI_DISCOVERY_OUTPUTS),
    *(Path("interventions") / name for name, _model in PROMPT_VARIANT_OUTPUTS),
    *(Path("interventions") / name for name, _model in RANDOMIZATION_OUTPUTS),
    *(relative for relative, _model in EFFECT_STAGE_OUTPUTS),
    *(relative for relative, _model in JCI_STAGE_OUTPUTS),
    *(relative for relative, _model in RFCI_STAGE_OUTPUTS),
    *(Path(".stages") / f"{stage}.json" for stage in REPORT_PRODUCER_STAGES),
)

_MAX_INPUT_RECORDS = 100_000
_MAX_INPUT_LINE_CHARS = 4_000_000
_MAX_INPUT_TOTAL_CHARS = 256_000_000
_MAX_REPORT_RECORDS = 300_000
_MAX_REPORT_LINE_BYTES = 8_000_000
_MAX_REPORT_INPUT_FILE_BYTES = 1_000_000_000
_MAX_REPORT_INPUT_TOTAL_BYTES = 4_000_000_000
_MAX_REPORT_FILE_BYTES = 64_000_000
_MAX_REPORT_TOTAL_BYTES = 256_000_000
_CLEANUP_ATTEMPTS = 3


@dataclass(frozen=True, slots=True)
class ReportingStageResult:
    pag_count: int
    hypothesis_count: int
    intervention_count: int
    assignment_count: int
    effect_count: int
    jci_orientation_count: int
    failure_count: int
    card_count: int
    rfci_status: str


@dataclass(frozen=True, slots=True)
class _Snapshot:
    input_paths: tuple[Path, ...]
    input_sha256: tuple[str, ...]
    producer_sha256: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]
    observational_pags: tuple[PAGRecord, ...]
    hypotheses: tuple[FrozenHypothesisRecord, ...]
    bootstrap_failures: tuple[BootstrapFailureRecord, ...]
    discovery_failures: tuple[DiscoveryFailureRecord, ...]
    deltas: tuple[GraphDeltaRecord, ...]
    variants: tuple[PromptVariantRecord, ...]
    exclusions: tuple[PreRandomizationExclusionRecord, ...]
    assignments: tuple[AssignmentRecord, ...]
    outcomes: tuple[AssignmentOutcomeRecord, ...]
    contrasts: tuple[ContrastSpecRecord, ...]
    effects: tuple[ITTEffectRecord, ...]
    effect_failures: tuple[AnalysisFailureRecord, ...]
    jci_raw_pags: tuple[PAGRecord, ...]
    jci_constrained_pags: tuple[PAGRecord, ...]
    jci_deltas: tuple[JCIOrientationDeltaRecord, ...]
    jci_failures: tuple[AnalysisFailureRecord, ...]
    rfci_config: RFCIConfig
    rfci_capability: RFCICapabilityRecord
    rfci_pags: tuple[PAGRecord, ...]
    rfci_failures: tuple[AnalysisFailureRecord, ...]


@dataclass(frozen=True, slots=True)
class _OutputSpec:
    path: Path
    kind: Literal["jsonl", "csv", "markdown"]
    fields: tuple[str, ...] = ()
    max_bytes: int = _MAX_REPORT_FILE_BYTES


@dataclass(frozen=True, slots=True)
class _InputFileSnapshot:
    path: Path
    data: bytes = field(repr=False)
    sha256: str
    st_dev: int
    st_ino: int
    st_mode: int
    st_size: int
    st_mtime_ns: int
    st_ctime_ns: int


_T = TypeVar("_T", bound=BaseModel)


def _error(message: str = "report artifact validation failed") -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage=_STAGE,
        message=message,
        details={},
        retryable=False,
    )


def _read(
    source: Path | _InputFileSnapshot,
    model: type[_T],
    *,
    allow_empty: bool,
) -> tuple[_T, ...]:
    snapshot = _capture_input_files((source,))[0] if isinstance(source, Path) else source
    try:
        text = snapshot.data.decode("utf-8", errors="strict")
        if len(text) > _MAX_INPUT_TOTAL_CHARS:
            raise ValueError
        lines = text.splitlines()
        if any(not line or len(line) > _MAX_INPUT_LINE_CHARS for line in lines):
            raise ValueError
        if len(lines) > _MAX_INPUT_RECORDS or (not allow_empty and not lines):
            raise ValueError
        records = tuple(model.model_validate(json.loads(line)) for line in lines)
        return cast(tuple[_T, ...], records)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error("report input JSONL failed validation") from None


def _producer_paths(store: RunStore) -> dict[str, tuple[Path, ...]]:
    return {
        "build-confirmation-variants": tuple(
            store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
        ),
        "estimate-confirmation-effects": tuple(
            store.root / relative for relative, _model in EFFECT_STAGE_OUTPUTS
        ),
        "fci-discovery": tuple(
            store.path("discovery", name) for name, _model in FCI_DISCOVERY_OUTPUTS
        ),
        "jci-confirmation": tuple(store.root / relative for relative, _model in JCI_STAGE_OUTPUTS),
        "randomize-confirmation": tuple(
            store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS
        ),
        "rfci-confirmation": tuple(
            store.root / relative for relative, _model in RFCI_STAGE_OUTPUTS
        ),
    }


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_size,
        value.st_mtime_ns,
    )


def _stat_stability(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        *_stat_identity(value),
        value.st_ctime_ns,
    )


def _capture_input_files(paths: Sequence[Path]) -> tuple[_InputFileSnapshot, ...]:
    total_bytes = 0
    snapshots: list[_InputFileSnapshot] = []
    for path in paths:
        descriptor: int | None = None
        try:
            before_path = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(before_path.st_mode):
                raise OSError
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            before_fd = os.fstat(descriptor)
            if not stat.S_ISREG(before_fd.st_mode) or _stat_identity(before_path) != _stat_identity(
                before_fd
            ):
                raise _error("report input identity changed before reading")
            if before_fd.st_size > _MAX_REPORT_INPUT_FILE_BYTES:
                raise _error("report input file byte bound exceeded")
            data = bytearray()
            while True:
                chunk = os.read(
                    descriptor, min(1_048_576, _MAX_REPORT_INPUT_FILE_BYTES + 1 - len(data))
                )
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > _MAX_REPORT_INPUT_FILE_BYTES:
                    raise _error("report input file byte bound exceeded")
            after_fd = os.fstat(descriptor)
            after_path = os.stat(path, follow_symlinks=False)
            if (
                _stat_stability(before_fd) != _stat_stability(after_fd)
                or _stat_stability(before_path) != _stat_stability(after_path)
                or _stat_identity(after_fd) != _stat_identity(after_path)
                or len(data) != after_fd.st_size
            ):
                raise _error("report input changed while reading")
            total_bytes += len(data)
            if total_bytes > _MAX_REPORT_INPUT_TOTAL_BYTES:
                raise _error("report input bundle byte bound exceeded")
            immutable = bytes(data)
            snapshots.append(
                _InputFileSnapshot(
                    path=path,
                    data=immutable,
                    sha256=hashlib.sha256(immutable).hexdigest(),
                    st_dev=after_fd.st_dev,
                    st_ino=after_fd.st_ino,
                    st_mode=after_fd.st_mode,
                    st_size=after_fd.st_size,
                    st_mtime_ns=after_fd.st_mtime_ns,
                    st_ctime_ns=after_fd.st_ctime_ns,
                )
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except SecAwareError:
            raise
        except (OSError, TypeError, ValueError):
            raise _error("report input byte bound failed validation") from None
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    return tuple(snapshots)


def _bounded_input_sha256(paths: Sequence[Path]) -> tuple[str, ...]:
    return tuple(snapshot.sha256 for snapshot in _capture_input_files(paths))


def _verify_input_files(expected: Sequence[_InputFileSnapshot]) -> None:
    current = _capture_input_files(tuple(snapshot.path for snapshot in expected))
    if len(current) != len(expected):
        raise _error("report producers changed during execution")
    for before, after in zip(expected, current, strict=True):
        if (
            before.path != after.path
            or before.data != after.data
            or before.sha256 != after.sha256
            or (
                before.st_dev,
                before.st_ino,
                stat.S_IFMT(before.st_mode),
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                stat.S_IFMT(after.st_mode),
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        ):
            raise _error("report producers changed during execution")


def _require_producers(
    store: RunStore,
    paths: dict[str, tuple[Path, ...]],
) -> dict[str, dict[str, str]]:
    return {
        stage: store.require_committed_output(
            stage,
            paths[stage],
            expected_catalog_sha256=(
                PROMPT_FEATURE_CATALOG_SHA256 if stage == "build-confirmation-variants" else None
            ),
        )
        for stage in REPORT_PRODUCER_STAGES
    }


def _unique(records: Sequence[BaseModel], field: str) -> None:
    values = tuple(getattr(record, field) for record in records)
    if len(values) != len(set(values)):
        raise _error()


def _unique_coordinates(records: Sequence[BaseModel], fields: tuple[str, ...]) -> None:
    values = tuple(tuple(getattr(record, field) for field in fields) for record in records)
    if len(values) != len(set(values)):
        raise _error()


def _validate_snapshot(snapshot: _Snapshot) -> None:
    record_groups: tuple[Sequence[BaseModel], ...] = (
        snapshot.observational_pags,
        snapshot.hypotheses,
        snapshot.bootstrap_failures,
        snapshot.discovery_failures,
        snapshot.deltas,
        snapshot.variants,
        snapshot.exclusions,
        snapshot.assignments,
        snapshot.outcomes,
        snapshot.contrasts,
        snapshot.effects,
        snapshot.effect_failures,
        snapshot.jci_raw_pags,
        snapshot.jci_constrained_pags,
        snapshot.jci_deltas,
        snapshot.jci_failures,
        snapshot.rfci_pags,
        snapshot.rfci_failures,
    )
    try:
        for group in record_groups:
            for record in group:
                type(record).model_validate(record.model_dump(mode="python"))
        validate_rfci_capability(snapshot.rfci_capability, snapshot.rfci_config)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error() from None
    if (
        any(item.stage is not AnalysisStage.EFFECTS for item in snapshot.effect_failures)
        or any(item.stage is not AnalysisStage.JCI for item in snapshot.jci_failures)
        or any(item.stage is not AnalysisStage.RFCI for item in snapshot.rfci_failures)
    ):
        raise _error()
    analysis_failure_ids = tuple(
        item.failure_id
        for group in (
            snapshot.effect_failures,
            snapshot.jci_failures,
            snapshot.rfci_failures,
        )
        for item in group
    )
    if len(analysis_failure_ids) != len(set(analysis_failure_ids)):
        raise _error()
    pag_groups = (
        (snapshot.observational_pags, PAGRunKind.OBSERVATIONAL_REFERENCE),
        (snapshot.jci_raw_pags, PAGRunKind.JCI_RAW),
        (snapshot.jci_constrained_pags, PAGRunKind.JCI_CONSTRAINED),
        (snapshot.rfci_pags, PAGRunKind.RFCI_SENSITIVITY),
    )
    for records, run_kind in pag_groups:
        if any(record.run_kind is not run_kind for record in records):
            raise _error()
    all_pags = tuple(record for records, _kind in pag_groups for record in records)
    _unique(all_pags, "pag_id")
    for records, id_field in (
        (snapshot.hypotheses, "hypothesis_id"),
        (snapshot.deltas, "delta_id"),
        (snapshot.variants, "variant_id"),
        (snapshot.assignments, "assignment_id"),
        (snapshot.outcomes, "assignment_id"),
        (snapshot.effects, "effect_id"),
        (snapshot.jci_deltas, "delta_id"),
    ):
        _unique(records, id_field)
    _unique_coordinates(snapshot.contrasts, ("arm_protocol_id", "contrast_id"))
    if not snapshot.hypotheses:
        raise _error("report hypothesis universe is empty")
    hypothesis_ids = {item.hypothesis_id for item in snapshot.hypotheses}
    if (
        any(item.hypothesis_id not in hypothesis_ids for item in snapshot.effects)
        or {item.assignment_id for item in snapshot.assignments}
        != {item.assignment_id for item in snapshot.outcomes}
        or {item.delta_id for item in snapshot.variants}
        != {item.delta_id for item in snapshot.deltas}
        or {(item.arm_protocol_id, item.contrast_id) for item in snapshot.effects}
        - {(item.arm_protocol_id, item.contrast_id) for item in snapshot.contrasts}
    ):
        raise _error()
    raw_ids = {item.pag_id for item in snapshot.jci_raw_pags}
    constrained_ids = {item.pag_id for item in snapshot.jci_constrained_pags}
    if any(
        item.raw_pag_id not in raw_ids or item.constrained_pag_id not in constrained_ids
        for item in snapshot.jci_deltas
    ):
        raise _error()
    if not snapshot.rfci_capability.available and snapshot.rfci_pags:
        raise _error()


def _render_documents(snapshot: _Snapshot) -> ReportDocuments:
    _validate_snapshot(snapshot)
    pags = tuple(
        sorted(
            (
                *snapshot.observational_pags,
                *snapshot.jci_raw_pags,
                *snapshot.jci_constrained_pags,
                *snapshot.rfci_pags,
            ),
            key=lambda item: (item.run_kind.value, item.pag_id),
        )
    )
    hypotheses = tuple(sorted(snapshot.hypotheses, key=lambda item: item.hypothesis_id))
    intervention_rows = build_intervention_rows(snapshot.variants, snapshot.deltas)
    assignment_rows = build_assignment_rows(snapshot.assignments, snapshot.outcomes)
    effect_rows = build_effect_rows(snapshot.effects)
    orientation_rows = build_jci_orientation_rows(snapshot.jci_deltas)
    failure_rows = build_failure_rows(
        snapshot.bootstrap_failures,
        snapshot.discovery_failures,
        snapshot.exclusions,
        snapshot.effect_failures,
        snapshot.jci_failures,
        snapshot.rfci_failures,
    )
    cards = build_hypothesis_cards(hypotheses, snapshot.effects)
    pag_counts: dict[str, int] = {}
    for pag in pags:
        pag_counts[pag.run_kind.value] = pag_counts.get(pag.run_kind.value, 0) + 1
    return ReportDocuments(
        discovery_pags=canonical_jsonl_bytes(item.model_dump(mode="json") for item in pags),
        hypotheses=canonical_jsonl_bytes(item.model_dump(mode="json") for item in hypotheses),
        interventions=canonical_jsonl_bytes(intervention_rows),
        assignments=canonical_jsonl_bytes(assignment_rows),
        effects=canonical_csv_bytes(EFFECT_FIELDS, effect_rows),
        jci_orientations=canonical_csv_bytes(JCI_ORIENTATION_FIELDS, orientation_rows),
        failures=canonical_csv_bytes(FAILURE_FIELDS, failure_rows),
        hypothesis_cards=canonical_jsonl_bytes(cards),
        summary=render_summary(
            hypotheses=hypotheses,
            variants=snapshot.variants,
            assignments=snapshot.assignments,
            effects=snapshot.effects,
            jci_deltas=snapshot.jci_deltas,
            failure_count=len(failure_rows),
            capability=snapshot.rfci_capability,
            pag_counts=pag_counts,
        ),
    )


def _build_documents(snapshot: _Snapshot) -> ReportDocuments:
    return _render_documents(snapshot)


def _jsonl_rows(data: bytes) -> tuple[dict[str, object], ...]:
    try:
        return tuple(json.loads(line) for line in _decode_utf8(data).splitlines())
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error("report typed JSONL readback failed validation") from None


def _csv_rows(data: bytes, fields: tuple[str, ...]) -> tuple[dict[str, str], ...]:
    try:
        reader = csv.DictReader(StringIO(_decode_utf8(data), newline=""))
        if tuple(reader.fieldnames or ()) != fields:
            raise ValueError
        rows = tuple(reader)
        if any(None in row or set(row) != set(fields) for row in rows):
            raise ValueError
        return rows
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error("report typed CSV readback failed validation") from None


def _strict_int_cell(value: str) -> int:
    parsed = int(value)
    if str(parsed) != value:
        raise ValueError
    return parsed


def _strict_float_cell(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or value != value.strip():
        raise ValueError
    return parsed


def _typed_effect_rows(data: bytes) -> tuple[ITTEffectRecord, ...]:
    integer_fields = {"treatment_n", "control_n", "independent_task_n"}
    float_fields = {
        "risk_difference",
        "ci_low",
        "ci_high",
        "sensitivity_low",
        "sensitivity_high",
    }
    typed: list[ITTEffectRecord] = []
    for row in _csv_rows(data, EFFECT_FIELDS):
        for column in set(EFFECT_FIELDS) - integer_fields - float_fields:
            if row[column].startswith(("=", "+", "-", "@")):
                raise _error("report CSV formula provenance failed validation")
        payload: dict[str, object] = dict(row)
        try:
            payload.update({field: _strict_int_cell(row[field]) for field in integer_fields})
            payload.update({field: _strict_float_cell(row[field]) for field in float_fields})
            typed.append(ITTEffectRecord.model_validate(payload))
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise _error("report effect row failed validation") from None
    return tuple(typed)


def _typed_jci_rows(data: bytes) -> tuple[JCIOrientationDeltaRecord, ...]:
    typed: list[JCIOrientationDeltaRecord] = []
    for row in _csv_rows(data, JCI_ORIENTATION_FIELDS):
        for column in (
            "schema_version",
            "delta_id",
            "raw_pag_id",
            "constrained_pag_id",
            "assumption_set_sha256",
        ):
            if row[column].startswith(("=", "+", "-", "@")):
                raise _error("report CSV formula provenance failed validation")
        payload: dict[str, object] = dict(row)
        try:
            payload["assumption_ids"] = json.loads(row["assumption_ids"])
            payload["changes"] = json.loads(row["changes"])
            if row["per_assumption_attribution"] not in {"true", "false"}:
                raise ValueError
            payload["per_assumption_attribution"] = row["per_assumption_attribution"] == "true"
            typed.append(JCIOrientationDeltaRecord.model_validate(payload))
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise _error("report JCI orientation row failed validation") from None
    return tuple(typed)


def _validate_projected_rows(
    snapshot: _Snapshot,
    intervention_rows: tuple[dict[str, object], ...],
    assignment_rows: tuple[dict[str, object], ...],
) -> None:
    variants = {item.variant_id: item for item in snapshot.variants}
    deltas = {item.delta_id: item for item in snapshot.deltas}
    if len(intervention_rows) != len(variants):
        raise _error("report intervention row coverage failed validation")
    for row in intervention_rows:
        variant_id = row.get("variant_id")
        variant = variants.get(variant_id) if type(variant_id) is str else None
        if variant is None:
            raise _error("report intervention row provenance failed validation")
        delta = deltas.get(variant.delta_id)
        if delta is None:
            raise _error("report intervention row provenance failed validation")
        payload = variant.model_dump(mode="json", exclude={"prompt_text"})
        payload["graph_delta"] = delta.model_dump(mode="json")
        digest = canonical_sha256(payload)
        expected = {
            **payload,
            "report_record_id": f"reported_intervention_{digest}",
            "report_record_sha256": digest,
        }
        if row != expected:
            raise _error("report intervention row provenance failed validation")

    assignments = {item.assignment_id: item for item in snapshot.assignments}
    outcomes = {item.assignment_id: item for item in snapshot.outcomes}
    if len(assignment_rows) != len(assignments):
        raise _error("report assignment row coverage failed validation")
    for row in assignment_rows:
        assignment_id = row.get("assignment_id")
        assignment = assignments.get(assignment_id) if type(assignment_id) is str else None
        outcome = outcomes.get(assignment_id) if type(assignment_id) is str else None
        if assignment is None or outcome is None:
            raise _error("report assignment row provenance failed validation")
        payload = assignment.model_dump(mode="json")
        payload["assignment_outcome"] = outcome.model_dump(mode="json")
        digest = canonical_sha256(payload)
        expected = {
            **payload,
            "report_record_id": f"reported_assignment_{digest}",
            "report_record_sha256": digest,
        }
        if row != expected:
            raise _error("report assignment row provenance failed validation")


def _validate_card_rows(
    snapshot: _Snapshot,
    rows: tuple[dict[str, object], ...],
) -> None:
    hypotheses = {item.hypothesis_id: item for item in snapshot.hypotheses}
    effects_by_hypothesis: dict[str, set[str]] = {
        hypothesis_id: set() for hypothesis_id in hypotheses
    }
    for effect in snapshot.effects:
        effects_by_hypothesis[effect.hypothesis_id].add(effect.effect_id)
    if len(rows) != len(hypotheses):
        raise _error("report hypothesis card coverage failed validation")
    for row in rows:
        hypothesis_id = row.get("hypothesis_id")
        source = hypotheses.get(hypothesis_id) if type(hypothesis_id) is str else None
        if source is None:
            raise _error("report hypothesis card provenance failed validation")
        payload = {
            key: value for key, value in row.items() if key not in {"card_id", "card_sha256"}
        }
        digest = canonical_sha256(payload)
        effects = row.get("itt_effects")
        if type(effects) is not list or any(type(item) is not dict for item in effects):
            raise _error("report hypothesis card provenance failed validation")
        effect_ids = {item.get("effect_id") for item in effects}
        if (
            row.get("card_id") != f"hypothesis_card_{digest}"
            or row.get("card_sha256") != digest
            or row.get("hypothesis_sha256") != source.hypothesis_sha256
            or row.get("hypothesis_path") != source.path.model_dump(mode="json")
            or effect_ids != effects_by_hypothesis[hypothesis_id]
        ):
            raise _error("report hypothesis card provenance failed validation")


def _validate_report_semantics(snapshot: _Snapshot, documents: ReportDocuments) -> None:
    try:
        pags = tuple(PAGRecord.model_validate(row) for row in _jsonl_rows(documents.discovery_pags))
        hypotheses = tuple(
            FrozenHypothesisRecord.model_validate(row) for row in _jsonl_rows(documents.hypotheses)
        )
        intervention_rows = _jsonl_rows(documents.interventions)
        assignment_rows = _jsonl_rows(documents.assignments)
        effects = _typed_effect_rows(documents.effects)
        jci_deltas = _typed_jci_rows(documents.jci_orientations)
        failure_rows = _csv_rows(documents.failures, FAILURE_FIELDS)
        card_rows = _jsonl_rows(documents.hypothesis_cards)
        capability = _read_summary_capability(documents.summary)
        _unique(pags, "pag_id")
        _unique(hypotheses, "hypothesis_id")
        _unique(effects, "effect_id")
        _unique(jci_deltas, "delta_id")
        if any(
            value.startswith(("=", "+", "-", "@"))
            for row in failure_rows
            for value in row.values()
            if value
        ):
            raise _error("report CSV formula provenance failed validation")
        expected_pags = (
            *snapshot.observational_pags,
            *snapshot.jci_raw_pags,
            *snapshot.jci_constrained_pags,
            *snapshot.rfci_pags,
        )
        expected_failure_ids = {
            *(item.failure_id for item in snapshot.bootstrap_failures),
            *(item.failure_id for item in snapshot.discovery_failures),
            *(item.exclusion_id for item in snapshot.exclusions),
            *(item.failure_id for item in snapshot.effect_failures),
            *(item.failure_id for item in snapshot.jci_failures),
            *(item.failure_id for item in snapshot.rfci_failures),
        }
        if (
            {item.pag_id for item in pags} != {item.pag_id for item in expected_pags}
            or {item.hypothesis_id for item in hypotheses}
            != {item.hypothesis_id for item in snapshot.hypotheses}
            or {item.effect_id for item in effects} != {item.effect_id for item in snapshot.effects}
            or {item.delta_id for item in jci_deltas}
            != {item.delta_id for item in snapshot.jci_deltas}
            or {row["record_id"] for row in failure_rows} != expected_failure_ids
            or capability != snapshot.rfci_capability
        ):
            raise _error("report cross-file provenance failed validation")
        validate_rfci_capability(capability, snapshot.rfci_config)
        _validate_projected_rows(snapshot, intervention_rows, assignment_rows)
        _validate_card_rows(snapshot, card_rows)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error("report typed semantic readback failed validation") from None


def _validate_documents(snapshot: _Snapshot, documents: ReportDocuments) -> None:
    _validate_report_semantics(snapshot, documents)
    if documents != _render_documents(snapshot):
        raise _error("report semantic readback failed validation")


def _output_specs(store: RunStore) -> tuple[_OutputSpec, ...]:
    fields = ((), (), (), (), EFFECT_FIELDS, JCI_ORIENTATION_FIELDS, FAILURE_FIELDS, (), ())
    kinds: tuple[Literal["jsonl", "csv", "markdown"], ...] = (
        "jsonl",
        "jsonl",
        "jsonl",
        "jsonl",
        "csv",
        "csv",
        "csv",
        "jsonl",
        "markdown",
    )
    return tuple(
        _OutputSpec(store.root / relative, kind, tuple(field_names))
        for relative, kind, field_names in zip(REPORT_STAGE_OUTPUTS, kinds, fields, strict=True)
    )


def _decode_utf8(data: bytes) -> str:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError:
        raise _error("report output is not canonical UTF-8") from None
    if "\r" in text or (text and not text.endswith("\n")):
        raise _error("report output newline contract failed validation")
    return text


def _read_summary_capability(summary: bytes) -> RFCICapabilityRecord:
    text = _decode_utf8(summary)
    lines = text.splitlines()
    capability_lines = tuple(line for line in lines if line.startswith(RFCI_CAPABILITY_PREFIX))
    if len(capability_lines) != 1:
        raise _error("report summary capability provenance failed validation")
    encoded_payload = capability_lines[0].removeprefix(RFCI_CAPABILITY_PREFIX)
    try:
        payload = decode_canonical_markdown_code(encoded_payload)
        capability = RFCICapabilityRecord.model_validate_json(payload)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error("report summary capability provenance failed validation") from None
    canonical = json.dumps(
        capability.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    expected_status = f"- RFCI status: {capability.status}"
    expected_reason = f"- RFCI reason: {canonical_markdown_code(capability.reason_code or 'none')}"
    if (
        capability_lines[0] != f"{RFCI_CAPABILITY_PREFIX}{canonical_markdown_code(canonical)}"
        or lines.count(expected_status) != 1
        or lines.count(expected_reason) != 1
    ):
        raise _error("report summary capability provenance failed validation")
    return capability


def _validate_output_bytes(spec: _OutputSpec, data: bytes) -> None:
    if not 0 < len(data) <= spec.max_bytes:
        raise _error("report output exceeds its byte bound")
    text = _decode_utf8(data)
    if spec.kind == "jsonl":
        records = 0
        for line in text.splitlines():
            if not line:
                raise _error("report JSONL contains a blank line")
            if len(line.encode("utf-8")) > _MAX_REPORT_LINE_BYTES:
                raise _error("report JSONL line exceeds its byte bound")
            try:
                value = json.loads(line)
            except (TypeError, ValueError):
                raise _error("report JSONL readback failed validation") from None
            if type(value) is not dict:
                raise _error("report JSONL record failed validation")
            records += 1
            if records > _MAX_REPORT_RECORDS:
                raise _error("report JSONL record bound exceeded")
        return
    if spec.kind == "csv":
        try:
            reader = csv.DictReader(StringIO(text, newline=""))
            if tuple(reader.fieldnames or ()) != spec.fields:
                raise ValueError
            rows = tuple(reader)
            if any(None in row or set(row) != set(spec.fields) for row in rows):
                raise ValueError
            if len(rows) > _MAX_REPORT_RECORDS:
                raise ValueError
        except (csv.Error, TypeError, ValueError):
            raise _error("report CSV readback failed validation") from None
        return
    if not text.startswith("# SecAware Prompt-Only Run Summary\n"):
        raise _error("report Markdown readback failed validation")
    _read_summary_capability(data)


def _transaction_path(output: Path) -> Path:
    handle = None
    try:
        handle = tempfile.NamedTemporaryFile(
            mode="w+b",
            prefix=f".{output.name}.",
            suffix=".report.candidate",
            dir=output.parent,
            delete=False,
        )
        path = Path(handle.name)
        handle.close()
        handle = None
        path.unlink()
        return path
    except OSError:
        raise _error("report output transaction is unavailable") from None
    finally:
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass


def _write_candidate(path: Path, data: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        raise _error("report candidate could not be written") from None


def _cleanup_paths(paths: Sequence[Path | None]) -> None:
    pending = list(dict.fromkeys(path for path in paths if path is not None))
    for _ in range(_CLEANUP_ATTEMPTS):
        remaining: list[Path] = []
        for path in pending:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                remaining.append(path)
        pending = remaining
        if not pending:
            return
    if pending:
        raise _error("report transaction cleanup failed")


def _cleanup_failed_stage(
    store: RunStore,
) -> MemoryError | KeyboardInterrupt | SystemExit | None:
    if not store.stage_is_active(_STAGE):
        return None
    try:
        store.abort_stage(_STAGE)
    except (MemoryError, KeyboardInterrupt, SystemExit) as error:
        return error
    except SecAwareError:
        pass
    return None


def _finalize_stage_commit(store: RunStore, lease: StageCommitLease) -> None:
    failure: BaseException | None = None
    try:
        store.finalize_stage_commit(lease)
    except BaseException as error:
        failure = error
    finally:
        try:
            store.ensure_stage_commit_released(lease)
        except BaseException as error:
            if failure is None or (
                isinstance(error, (MemoryError, KeyboardInterrupt, SystemExit))
                and not isinstance(failure, (MemoryError, KeyboardInterrupt, SystemExit))
            ):
                failure = error
    if failure is not None:
        raise failure


def _execute_report_transaction(
    store: RunStore,
    *,
    inputs: tuple[Path, ...],
    outputs: tuple[_OutputSpec, ...],
    force: bool,
    validate_only: bool,
    capture_input_snapshot: Callable[[], tuple[str, ...]],
    verify_input_snapshot: Callable[[], None],
    validate_committed: Callable[[], None],
    build: Callable[[], ReportDocuments],
) -> bool:
    if type(validate_only) is not bool:
        raise _error("report validation mode failed validation")
    output_paths = tuple(spec.path for spec in outputs)
    manifest_path = store.path(".stages", f"{_STAGE}.json")
    journal_path = store.path(".stages", f".{_STAGE}.transaction.json")
    try:
        artifacts = tuple(
            [TransactionArtifact(path, f"output{index}") for index, path in enumerate(output_paths)]
            + [TransactionArtifact(manifest_path, "manifest")]
        )
    except TransactionStateError:
        raise _error("report output transaction is invalid") from None

    def recover_or_cleanup() -> None:
        try:
            resolve_pending_transaction(journal_path, artifacts)
        except TransactionStateError:
            raise _error("report output transaction recovery failed") from None
        stale = tuple(
            path
            for output in output_paths
            for path in output.parent.glob(f".{output.name}.*.report.candidate")
        )
        _cleanup_paths(stale)

    captured: tuple[str, ...] | None = None

    def capture_once() -> tuple[str, ...]:
        nonlocal captured
        if captured is not None:
            raise _error()
        captured = capture_input_snapshot()
        return captured

    def validate_skip() -> None:
        verify_input_snapshot()
        for spec in outputs:
            data = spec.path.read_bytes()
            _validate_output_bytes(spec, data)
        validate_committed()
        verify_input_snapshot()

    if store.should_skip_stage(
        _STAGE,
        inputs,
        output_paths,
        force,
        preserve_committed=True,
        after_lease_acquired=recover_or_cleanup,
        input_snapshot=capture_once,
        before_skip=validate_skip,
    ):
        return True

    if validate_only:
        store.abort_stage(_STAGE)
        raise _error("committed report validation failed")

    candidates: list[Path | None] = [None] * len(outputs)
    transaction: ArtifactTransaction | None = None
    lease: StageCommitLease | None = None
    commit_point = False
    failure: BaseException | None = None
    try:
        transaction = ArtifactTransaction.begin(journal_path, artifacts)
        transaction.backup(len(outputs))
        documents = build()
        payloads = documents.ordered()
        if len(payloads) != len(outputs) or sum(map(len, payloads)) > _MAX_REPORT_TOTAL_BYTES:
            raise _error("report output bundle exceeds its byte bound")
        for index, (spec, data) in enumerate(zip(outputs, payloads, strict=True)):
            _validate_output_bytes(spec, data)
            candidate = _transaction_path(spec.path)
            candidates[index] = candidate
            _write_candidate(candidate, data)
            readback = candidate.read_bytes()
            _validate_output_bytes(spec, readback)
            if readback != data:
                raise _error("report candidate readback failed validation")
        for index, _spec in enumerate(outputs):
            candidate = candidates[index]
            if candidate is None:
                raise _error()
            transaction.install(index, candidate)
            candidates[index] = None
        store.seal_stage_outputs(_STAGE, output_paths)
        for spec, data in zip(outputs, payloads, strict=True):
            readback = spec.path.read_bytes()
            _validate_output_bytes(spec, readback)
            if readback != data:
                store.verify_sealed_outputs(_STAGE, output_paths)
                raise _error("report output readback failed validation")
        store.verify_sealed_outputs(_STAGE, output_paths)
        if captured is None:
            raise _error()
        verify_input_snapshot()
        lease = store.begin_stage_commit(_STAGE)
        store.record_stage(
            _STAGE,
            inputs,
            output_paths,
            lease=lease,
            input_snapshot_sha256=captured,
        )
        verify_input_snapshot()
        transaction.mark_postcommit()
        commit_point = True
        _finalize_stage_commit(store, lease)
        lease = None
        cleanup_committed_transaction(transaction)
    except BaseException as error:
        failure = error
        if transaction is not None and not commit_point:
            try:
                recover_transaction(transaction)
            except (MemoryError, KeyboardInterrupt, SystemExit) as recovery_error:
                _cleanup_failed_stage(store)
                if isinstance(error, (MemoryError, KeyboardInterrupt, SystemExit)):
                    raise error
                failure = recovery_error
                raise
            except TransactionStateError:
                cleanup_control = _cleanup_failed_stage(store)
                if isinstance(error, (MemoryError, KeyboardInterrupt, SystemExit)):
                    raise error
                if cleanup_control is not None:
                    failure = cleanup_control
                    raise cleanup_control
                raise _error("report output transaction rollback failed") from None
        if not commit_point:
            cleanup_control = _cleanup_failed_stage(store)
            if cleanup_control is not None and not isinstance(
                error,
                (MemoryError, KeyboardInterrupt, SystemExit),
            ):
                failure = cleanup_control
                raise cleanup_control
        if isinstance(error, TransactionStateError):
            raise _error("report output transaction failed") from None
        raise
    finally:
        if not commit_point:
            try:
                _cleanup_paths(candidates)
            except (MemoryError, KeyboardInterrupt, SystemExit):
                if not isinstance(failure, (MemoryError, KeyboardInterrupt, SystemExit)):
                    raise
            except SecAwareError:
                if failure is None:
                    raise
    return False


def _committed_result(outputs: tuple[_OutputSpec, ...]) -> ReportingStageResult:
    payloads = tuple(spec.path.read_bytes() for spec in outputs)
    for spec, data in zip(outputs, payloads, strict=True):
        _validate_output_bytes(spec, data)

    def jsonl_count(index: int) -> int:
        return len(payloads[index].decode("utf-8").splitlines())

    def csv_count(index: int) -> int:
        return len(tuple(csv.DictReader(StringIO(payloads[index].decode("utf-8"), newline=""))))

    capability = _read_summary_capability(payloads[8])
    return ReportingStageResult(
        pag_count=jsonl_count(0),
        hypothesis_count=jsonl_count(1),
        intervention_count=jsonl_count(2),
        assignment_count=jsonl_count(3),
        effect_count=csv_count(4),
        jci_orientation_count=csv_count(5),
        failure_count=csv_count(6),
        card_count=jsonl_count(7),
        rfci_status=capability.status,
    )


def write_reports(
    config: AppConfig,
    store: RunStore,
    force: bool = False,
    *,
    _validate_only: bool = False,
) -> ReportingStageResult:
    """Publish exactly nine reports without modifying any producer artifact."""

    if type(config) is not AppConfig or type(store) is not RunStore or store.config != config:
        raise _error("report stage configuration failed validation")
    producer_paths = _producer_paths(store)
    input_paths = tuple(store.root / relative for relative in REPORT_STAGE_INPUTS)
    outputs = _output_specs(store)
    snapshot: _Snapshot | None = None
    documents: ReportDocuments | None = None
    input_files: tuple[_InputFileSnapshot, ...] | None = None
    input_sha256: tuple[str, ...] | None = None

    with store.hold_dependency_stages(REPORT_PRODUCER_STAGES):
        try:
            held_sha256 = _require_producers(store, producer_paths)

            def capture() -> tuple[str, ...]:
                nonlocal input_files, input_sha256
                if input_files is not None or input_sha256 is not None:
                    raise _error()
                input_files = _capture_input_files(input_paths)
                input_sha256 = tuple(item.sha256 for item in input_files)
                return input_sha256

            def load_snapshot() -> _Snapshot:
                nonlocal snapshot
                if snapshot is not None or input_files is None or input_sha256 is None:
                    raise _error()
                captured_by_path = {item.path: item for item in input_files}

                def read_captured(
                    path: Path,
                    model: type[_T],
                    *,
                    allow_empty: bool,
                ) -> tuple[_T, ...]:
                    captured = captured_by_path.get(path)
                    if captured is None:
                        raise _error()
                    return _read(captured, model, allow_empty=allow_empty)

                fci = producer_paths["fci-discovery"]
                variants_bundle = producer_paths["build-confirmation-variants"]
                randomization = producer_paths["randomize-confirmation"]
                effects_bundle = producer_paths["estimate-confirmation-effects"]
                jci = producer_paths["jci-confirmation"]
                rfci = producer_paths["rfci-confirmation"]
                capabilities = read_captured(rfci[0], RFCICapabilityRecord, allow_empty=False)
                if len(capabilities) != 1:
                    raise _error()
                snapshot = _Snapshot(
                    input_paths=input_paths,
                    input_sha256=input_sha256,
                    producer_sha256=tuple(
                        (stage, tuple(sorted(hashes.items())))
                        for stage, hashes in sorted(held_sha256.items())
                    ),
                    observational_pags=read_captured(fci[1], PAGRecord, allow_empty=True),
                    hypotheses=read_captured(fci[6], FrozenHypothesisRecord, allow_empty=False),
                    bootstrap_failures=read_captured(
                        fci[4], BootstrapFailureRecord, allow_empty=True
                    ),
                    discovery_failures=read_captured(
                        fci[7], DiscoveryFailureRecord, allow_empty=True
                    ),
                    deltas=read_captured(variants_bundle[7], GraphDeltaRecord, allow_empty=False),
                    variants=read_captured(
                        variants_bundle[8], PromptVariantRecord, allow_empty=False
                    ),
                    exclusions=read_captured(
                        variants_bundle[10], PreRandomizationExclusionRecord, allow_empty=True
                    ),
                    assignments=read_captured(
                        randomization[1], AssignmentRecord, allow_empty=False
                    ),
                    outcomes=read_captured(
                        effects_bundle[0], AssignmentOutcomeRecord, allow_empty=False
                    ),
                    contrasts=read_captured(
                        effects_bundle[1], ContrastSpecRecord, allow_empty=True
                    ),
                    effects=read_captured(effects_bundle[3], ITTEffectRecord, allow_empty=True),
                    effect_failures=read_captured(
                        effects_bundle[4], AnalysisFailureRecord, allow_empty=True
                    ),
                    jci_raw_pags=read_captured(jci[2], PAGRecord, allow_empty=True),
                    jci_constrained_pags=read_captured(jci[4], PAGRecord, allow_empty=True),
                    jci_deltas=read_captured(jci[5], JCIOrientationDeltaRecord, allow_empty=True),
                    jci_failures=read_captured(jci[6], AnalysisFailureRecord, allow_empty=True),
                    rfci_config=config.rfci,
                    rfci_capability=capabilities[0],
                    rfci_pags=read_captured(rfci[1], PAGRecord, allow_empty=True),
                    rfci_failures=read_captured(rfci[2], AnalysisFailureRecord, allow_empty=True),
                )
                _validate_snapshot(snapshot)
                return snapshot

            def verify() -> None:
                if input_files is None or input_sha256 is None:
                    raise _error()
                _verify_input_files(input_files)
                expected = {
                    stage: tuple(sorted(hashes.items())) for stage, hashes in held_sha256.items()
                }
                current = _require_producers(store, producer_paths)
                if {
                    stage: tuple(sorted(hashes.items())) for stage, hashes in current.items()
                } != expected:
                    raise _error("report producers changed during execution")

            def build() -> ReportDocuments:
                nonlocal documents
                loaded = load_snapshot()
                documents = _build_documents(loaded)
                _validate_documents(loaded, documents)
                return documents

            def validate_committed() -> None:
                loaded = load_snapshot()
                payloads = tuple(spec.path.read_bytes() for spec in outputs)
                for spec, data in zip(outputs, payloads, strict=True):
                    _validate_output_bytes(spec, data)
                _validate_documents(loaded, ReportDocuments(*payloads))

            skipped = _execute_report_transaction(
                store,
                inputs=input_paths,
                outputs=outputs,
                force=force,
                validate_only=_validate_only,
                capture_input_snapshot=capture,
                verify_input_snapshot=verify,
                validate_committed=validate_committed,
                build=build,
            )
            if skipped:
                return _committed_result(outputs)
            if snapshot is None:
                raise _error()
            for spec in outputs:
                _validate_output_bytes(spec, spec.path.read_bytes())
            failure_count = sum(
                map(
                    len,
                    (
                        snapshot.bootstrap_failures,
                        snapshot.discovery_failures,
                        snapshot.exclusions,
                        snapshot.effect_failures,
                        snapshot.jci_failures,
                        snapshot.rfci_failures,
                    ),
                )
            )
            return ReportingStageResult(
                pag_count=sum(
                    map(
                        len,
                        (
                            snapshot.observational_pags,
                            snapshot.jci_raw_pags,
                            snapshot.jci_constrained_pags,
                            snapshot.rfci_pags,
                        ),
                    )
                ),
                hypothesis_count=len(snapshot.hypotheses),
                intervention_count=len(snapshot.variants),
                assignment_count=len(snapshot.assignments),
                effect_count=len(snapshot.effects),
                jci_orientation_count=len(snapshot.jci_deltas),
                failure_count=failure_count,
                card_count=len(snapshot.hypotheses),
                rfci_status=snapshot.rfci_capability.status,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except SecAwareError:
            raise
        except Exception:
            raise _error() from None


def validate_committed_reports(
    config: AppConfig,
    store: RunStore,
) -> ReportingStageResult:
    return write_reports(config, store, force=False, _validate_only=True)


__all__ = [
    "REPORT_PRODUCER_STAGES",
    "REPORT_STAGE_INPUTS",
    "REPORT_STAGE_OUTPUTS",
    "ReportingStageResult",
    "validate_committed_reports",
    "write_reports",
]
