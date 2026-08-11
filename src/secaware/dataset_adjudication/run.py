from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
import platform
import random
import re
import shutil
import subprocess
import sys
from typing import Any, Literal

from pydantic import BaseModel, TypeAdapter

from secaware.dataset_adjudication.config import AdjudicationConfig
from secaware.dataset_adjudication.packets import (
    AdjudicationPacketSet,
    build_adjudication_packets,
    subset_adjudication_packets,
)
from secaware.dataset_adjudication.reconcile import reconcile_codex_passes
from secaware.dataset_adjudication.schema import (
    AdjudicationDimension,
    BlindedPacket,
    CodexDecision,
    PacketMetadata,
)
from secaware.dataset_audit.schema import RecordAudit


_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_PREPARE_ARTIFACTS = {
    "config.json",
    "commands.jsonl",
    "environment.json",
    "source-manifest.json",
    "packet-metadata.jsonl",
    "pass-a-packets.jsonl",
    "pass-b-packets.jsonl",
    "pilot-packet-ids.json",
    "failures.jsonl",
    "report.json",
    "report.md",
}
_RECONCILE_ARTIFACTS = {
    "config.json",
    "commands.jsonl",
    "environment.json",
    "source-manifest.json",
    "packet-metadata.jsonl",
    "pass-a-packets.jsonl",
    "pass-b-packets.jsonl",
    "pass-a-decisions.jsonl",
    "pass-b-decisions.jsonl",
    "repeat-consistency.jsonl",
    "human-review-queue.jsonl",
    "human-review-template.jsonl",
    "agreement.json",
    "failures.jsonl",
    "report.json",
    "report.md",
}
_BLINDED_PACKET_ADAPTER = TypeAdapter(BlindedPacket)
_CODEX_DECISION_ADAPTER = TypeAdapter(CodexDecision)


class AdjudicationRunConflictError(RuntimeError):
    """An immutable adjudication run identifier is already occupied."""


@dataclass(frozen=True, slots=True)
class PrepareAdjudicationRequest:
    config: AdjudicationConfig
    workspace_root: Path
    source_run_dir: Path
    run_id: str
    command_argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReconcileAdjudicationRequest:
    config: AdjudicationConfig
    workspace_root: Path
    parent_run_dir: Path
    pass_a_decisions_path: Path
    pass_b_decisions_path: Path
    run_id: str
    scope: Literal["pilot", "full"]
    command_argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AdjudicationRunResult:
    run_id: str
    run_dir: Path
    status: str


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if hasattr(value, "__dataclass_fields__"):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    return value


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(_jsonable(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_jsonl(path: Path, values: Iterable[Any]) -> None:
    lines = [
        json.dumps(_jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for value in values
    ]
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8", newline="\n")


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_environment(workspace: Path) -> dict[str, object]:
    def invoke(*arguments: str) -> str | None:
        try:
            completed = subprocess.run(
                ["git", "-C", str(workspace), *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return completed.stdout.strip() if completed.returncode == 0 else None

    status = invoke("status", "--short", "--untracked-files=all")
    return {
        "git_commit": invoke("rev-parse", "HEAD"),
        "git_branch": invoke("branch", "--show-current"),
        "git_dirty_paths": status.splitlines() if status else [],
    }


def _read_source_records(path: Path) -> list[RecordAudit]:
    records: list[RecordAudit] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                raise ValueError(f"record-audit contains a blank line at {line_number}")
            records.append(RecordAudit.model_validate_json(line))
    return records


def _read_jsonl(path: Path, adapter: TypeAdapter) -> list[Any]:
    values: list[Any] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                raise ValueError(f"JSONL artifact contains a blank line at {line_number}")
            values.append(adapter.validate_json(line))
    return values


def _read_packet_set(parent: Path) -> AdjudicationPacketSet:
    metadata = tuple(
        PacketMetadata.model_validate(item)
        for item in _read_jsonl(parent / "packet-metadata.jsonl", TypeAdapter(dict))
    )
    pass_a = tuple(_read_jsonl(parent / "pass-a-packets.jsonl", _BLINDED_PACKET_ADAPTER))
    pass_b = tuple(_read_jsonl(parent / "pass-b-packets.jsonl", _BLINDED_PACKET_ADAPTER))
    expected = {item.packet_id for item in metadata}
    if {item.packet_id for item in pass_a} != expected:
        raise ValueError("parent pass A packet coverage is invalid")
    if {item.packet_id for item in pass_b} != expected:
        raise ValueError("parent pass B packet coverage is invalid")
    return AdjudicationPacketSet(metadata, pass_a, pass_b)


def _load_parent_packet_run(
    request: ReconcileAdjudicationRequest,
) -> tuple[AdjudicationPacketSet, dict[str, object]]:
    workspace = Path(request.workspace_root).resolve()
    parent = Path(request.parent_run_dir).resolve()
    expected_root = (workspace / "runs" / "dataset-adjudication").resolve()
    if parent.parent != expected_root:
        raise ValueError("parent adjudication run must be inside the workspace run root")
    report = json.loads((parent / "report.json").read_text(encoding="utf-8"))
    if report.get("status") != "PACKETS_READY":
        raise ValueError("parent adjudication run is not a packet run")
    parent_config = AdjudicationConfig.model_validate_json(
        (parent / "config.json").read_text(encoding="utf-8")
    )
    if parent_config != request.config:
        raise ValueError("parent adjudication configuration does not match")
    source_manifest = json.loads(
        (parent / "source-manifest.json").read_text(encoding="utf-8")
    )
    if source_manifest.get("manifest_sha256") != report.get("source_manifest_sha256"):
        raise ValueError("parent source manifest digest does not match its report")
    packet_set = _read_packet_set(parent)
    counts = _packet_counts(packet_set)
    if counts["neutrality"] != request.config.expected_neutrality_packets:
        raise ValueError("parent neutrality packet count does not match configuration")
    if counts["cluster_relation"] != request.config.expected_cluster_packets:
        raise ValueError("parent cluster packet count does not match configuration")
    if request.scope == "pilot":
        pilot = json.loads((parent / "pilot-packet-ids.json").read_text(encoding="utf-8"))
        selected = set(pilot.get("neutrality", ())) | set(
            pilot.get("cluster_relation", ())
        )
        packet_set = subset_adjudication_packets(packet_set, selected)
    return packet_set, source_manifest


def _human_review_templates(packet_set, result, pass_a, pass_b) -> list[dict[str, object]]:
    packets = {item.packet_id: item for item in packet_set.pass_a}
    decisions_a = {item.packet_id: item for item in pass_a}
    decisions_b = {item.packet_id: item for item in pass_b}
    templates: list[dict[str, object]] = []
    for queue_entry in result.human_review_queue:
        packet = packets[queue_entry.packet_id]
        visible = packet.model_dump(mode="json")
        visible.pop("schema_version", None)
        visible.pop("pass_id", None)
        templates.append(
            {
                "schema_version": "1.0",
                **visible,
                "review_reasons": [item.value for item in queue_entry.review_reasons],
                "codex_pass_a": decisions_a[queue_entry.packet_id].model_dump(mode="json"),
                "codex_pass_b": decisions_b[queue_entry.packet_id].model_dump(mode="json"),
                "human_label": None,
                "human_confidence": None,
                "human_evidence_quotes": [],
                "human_rationale": None,
                "reviewer_id": None,
                "review_timestamp": None,
            }
        )
    return templates


def _derived_pilot_seed(seed: int, dimension: str, source_stratum: str) -> int:
    value = f"adjudication-pilot-v1\0{seed}\0{dimension}\0{source_stratum}"
    return int.from_bytes(hashlib.sha256(value.encode()).digest()[:8], "big")


def select_pilot_packet_ids(
    metadata: tuple[PacketMetadata, ...],
    *,
    per_dimension: int,
    seed: int,
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for dimension in AdjudicationDimension:
        groups: dict[str, list[str]] = {}
        for item in metadata:
            if item.dimension is dimension:
                groups.setdefault(item.source_stratum, []).append(item.packet_id)
        for source_stratum, packet_ids in groups.items():
            packet_ids.sort()
            random.Random(
                _derived_pilot_seed(seed, dimension.value, source_stratum)
            ).shuffle(packet_ids)
        selected: list[str] = []
        source_order = sorted(groups)
        while len(selected) < per_dimension and any(groups.values()):
            for source_stratum in source_order:
                if groups[source_stratum] and len(selected) < per_dimension:
                    selected.append(groups[source_stratum].pop())
        result[dimension.value] = sorted(selected)
    return result


def _validate_source(
    request: PrepareAdjudicationRequest,
) -> tuple[dict[str, object], list[RecordAudit]]:
    source_run = Path(request.source_run_dir).resolve()
    if source_run.name != request.config.source_audit_run_id:
        raise ValueError("source run ID does not match adjudication configuration")
    report_path = source_run / "report.json"
    records_path = source_run / "record-audit.jsonl"
    if not report_path.is_file() or not records_path.is_file():
        raise ValueError("source audit artifacts are incomplete")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("status") != "COMPLETE":
        raise ValueError("source audit is not complete")
    if report.get("stable_digest") != request.config.source_stable_digest:
        raise ValueError("source audit stable digest does not match configuration")
    records = _read_source_records(records_path)
    if len(records) != request.config.expected_source_records:
        raise ValueError("source audit record count does not match configuration")
    manifest: dict[str, object] = {
        "schema_version": "1.0",
        "source_audit_run_id": request.config.source_audit_run_id,
        "source_run_directory": str(source_run),
        "source_stable_digest": request.config.source_stable_digest,
        "report_sha256": _sha256_path(report_path),
        "record_audit_sha256": _sha256_path(records_path),
        "record_count": len(records),
    }
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return manifest, records


def _packet_counts(packet_set: AdjudicationPacketSet) -> dict[str, int]:
    counts = Counter(item.dimension.value for item in packet_set.metadata)
    return {
        "cluster_relation": counts[AdjudicationDimension.CLUSTER_RELATION.value],
        "neutrality": counts[AdjudicationDimension.NEUTRALITY.value],
        "total": len(packet_set.metadata),
    }


def prepare_adjudication_run(
    request: PrepareAdjudicationRequest,
) -> AdjudicationRunResult:
    if _RUN_ID.fullmatch(request.run_id) is None:
        raise AdjudicationRunConflictError("run ID is invalid")
    workspace = Path(request.workspace_root).resolve()
    if not (workspace / "pyproject.toml").is_file() or not (
        workspace / "src" / "secaware"
    ).is_dir():
        raise ValueError("workspace root is not a repository workspace")
    run_root = workspace / "runs" / "dataset-adjudication"
    final = run_root / request.run_id
    staging = run_root / f".{request.run_id}.staging"
    if final.exists() or staging.exists() or final.is_symlink() or staging.is_symlink():
        raise AdjudicationRunConflictError("run ID already exists")

    source_manifest, records = _validate_source(request)
    packet_set = build_adjudication_packets(records, seed=request.config.seed)
    counts = _packet_counts(packet_set)
    if counts["neutrality"] != request.config.expected_neutrality_packets:
        raise ValueError("neutrality packet count does not match configuration")
    if counts["cluster_relation"] != request.config.expected_cluster_packets:
        raise ValueError("cluster relation packet count does not match configuration")
    pilot = select_pilot_packet_ids(
        packet_set.metadata,
        per_dimension=request.config.pilot_per_dimension,
        seed=request.config.seed,
    )

    run_root.mkdir(parents=True, exist_ok=True)
    staging.mkdir()
    try:
        _write_json(staging / "config.json", request.config)
        _write_jsonl(
            staging / "commands.jsonl",
            ({"argv": list(request.command_argv), "cwd": str(workspace)},),
        )
        _write_json(
            staging / "environment.json",
            {
                **_git_environment(workspace),
                "python": sys.version,
                "python_executable": sys.executable,
                "platform": platform.platform(),
                "machine": platform.node(),
                "working_directory": str(workspace),
                "source_run_directory": str(Path(request.source_run_dir).resolve()),
                "run_directory": str(final),
            },
        )
        _write_json(staging / "source-manifest.json", source_manifest)
        _write_jsonl(staging / "packet-metadata.jsonl", packet_set.metadata)
        _write_jsonl(staging / "pass-a-packets.jsonl", packet_set.pass_a)
        _write_jsonl(staging / "pass-b-packets.jsonl", packet_set.pass_b)
        _write_json(staging / "pilot-packet-ids.json", pilot)
        _write_jsonl(staging / "failures.jsonl", ())
        report = {
            "schema_version": "1.0",
            "run_id": request.run_id,
            "status": "PACKETS_READY",
            "counts": counts,
            "pilot_counts": {key: len(value) for key, value in sorted(pilot.items())},
            "source_manifest_sha256": source_manifest["manifest_sha256"],
        }
        _write_json(staging / "report.json", report)
        (staging / "report.md").write_text(
            "\n".join(
                (
                    f"# Dataset adjudication packets: {request.run_id}",
                    "",
                    "Status: `PACKETS_READY`",
                    "",
                    f"- Neutrality packets: {counts['neutrality']}",
                    f"- Cluster relation packets: {counts['cluster_relation']}",
                    f"- Total packets: {counts['total']}",
                    f"- Neutrality pilot: {len(pilot['neutrality'])}",
                    f"- Cluster pilot: {len(pilot['cluster_relation'])}",
                    "",
                    "Packets are blinded. No decision or human attestation is implied.",
                    "",
                )
            ),
            encoding="utf-8",
            newline="\n",
        )
        actual = {path.name for path in staging.iterdir()}
        if actual != _PREPARE_ARTIFACTS:
            raise ValueError("prepared adjudication artifact set is incomplete")
        staging.rename(final)
    except BaseException:
        if staging.exists() and not any(staging.iterdir()):
            shutil.rmtree(staging)
        raise
    return AdjudicationRunResult(request.run_id, final, "PACKETS_READY")


def reconcile_adjudication_run(
    request: ReconcileAdjudicationRequest,
) -> AdjudicationRunResult:
    if _RUN_ID.fullmatch(request.run_id) is None:
        raise AdjudicationRunConflictError("run ID is invalid")
    workspace = Path(request.workspace_root).resolve()
    if not (workspace / "pyproject.toml").is_file() or not (
        workspace / "src" / "secaware"
    ).is_dir():
        raise ValueError("workspace root is not a repository workspace")
    parent = Path(request.parent_run_dir).resolve()
    packet_set, source_manifest = _load_parent_packet_run(request)
    pass_a = _read_jsonl(
        Path(request.pass_a_decisions_path).resolve(), _CODEX_DECISION_ADAPTER
    )
    pass_b = _read_jsonl(
        Path(request.pass_b_decisions_path).resolve(), _CODEX_DECISION_ADAPTER
    )
    expected_manifest = source_manifest.get("manifest_sha256")
    if not isinstance(expected_manifest, str):
        raise ValueError("parent source manifest has no stable digest")
    if any(
        item.input_manifest_sha256 != expected_manifest for item in (*pass_a, *pass_b)
    ):
        raise ValueError("Codex decision input manifest digest is stale")
    result = reconcile_codex_passes(
        packet_set,
        pass_a,
        pass_b,
        audit_fraction=request.config.human_audit_fraction,
        seed=request.config.seed,
    )
    by_a = {item.packet_id: item for item in pass_a}
    by_b = {item.packet_id: item for item in pass_b}
    ordered_a = [by_a[item.packet_id] for item in packet_set.pass_a]
    ordered_b = [by_b[item.packet_id] for item in packet_set.pass_b]
    templates = _human_review_templates(packet_set, result, ordered_a, ordered_b)
    counts = _packet_counts(packet_set)

    run_root = workspace / "runs" / "dataset-adjudication"
    final = run_root / request.run_id
    staging = run_root / f".{request.run_id}.staging"
    if final.exists() or staging.exists() or final.is_symlink() or staging.is_symlink():
        raise AdjudicationRunConflictError("run ID already exists")
    run_root.mkdir(parents=True, exist_ok=True)
    staging.mkdir()
    try:
        _write_json(staging / "config.json", request.config)
        _write_jsonl(
            staging / "commands.jsonl",
            ({"argv": list(request.command_argv), "cwd": str(workspace)},),
        )
        _write_json(
            staging / "environment.json",
            {
                **_git_environment(workspace),
                "python": sys.version,
                "python_executable": sys.executable,
                "platform": platform.platform(),
                "machine": platform.node(),
                "working_directory": str(workspace),
                "parent_run_directory": str(parent),
                "run_directory": str(final),
            },
        )
        _write_json(staging / "source-manifest.json", source_manifest)
        _write_jsonl(staging / "packet-metadata.jsonl", packet_set.metadata)
        _write_jsonl(staging / "pass-a-packets.jsonl", packet_set.pass_a)
        _write_jsonl(staging / "pass-b-packets.jsonl", packet_set.pass_b)
        _write_jsonl(staging / "pass-a-decisions.jsonl", ordered_a)
        _write_jsonl(staging / "pass-b-decisions.jsonl", ordered_b)
        _write_jsonl(staging / "repeat-consistency.jsonl", result.consistency)
        _write_jsonl(staging / "human-review-queue.jsonl", result.human_review_queue)
        _write_jsonl(staging / "human-review-template.jsonl", templates)
        _write_json(staging / "agreement.json", result.summary)
        _write_jsonl(staging / "failures.jsonl", ())
        report = {
            "schema_version": "1.0",
            "run_id": request.run_id,
            "status": "AWAITING_HUMAN_AUDIT",
            "scope": request.scope,
            "parent_run_id": parent.name,
            "source_manifest_sha256": expected_manifest,
            "counts": counts,
            "human_review_count": len(result.human_review_queue),
            "codex_repeat_consistency": result.summary["raw_agreement"],
        }
        _write_json(staging / "report.json", report)
        (staging / "report.md").write_text(
            "\n".join(
                (
                    f"# Dataset adjudication reconciliation: {request.run_id}",
                    "",
                    "Status: `AWAITING_HUMAN_AUDIT`",
                    "",
                    f"- Scope: {request.scope}",
                    f"- Parent packet run: {parent.name}",
                    f"- Neutrality packets: {counts['neutrality']}",
                    f"- Cluster relation packets: {counts['cluster_relation']}",
                    f"- Human review queue: {len(result.human_review_queue)}",
                    f"- Codex repeat consistency: {result.summary['raw_agreement']:.3f}",
                    "",
                    "Human review fields remain blank; no final eligibility is implied.",
                    "",
                )
            ),
            encoding="utf-8",
            newline="\n",
        )
        actual = {path.name for path in staging.iterdir()}
        if actual != _RECONCILE_ARTIFACTS:
            raise ValueError("reconciled adjudication artifact set is incomplete")
        staging.rename(final)
    except BaseException:
        if staging.exists() and not any(staging.iterdir()):
            shutil.rmtree(staging)
        raise
    return AdjudicationRunResult(request.run_id, final, "AWAITING_HUMAN_AUDIT")


__all__ = [
    "AdjudicationRunConflictError",
    "AdjudicationRunResult",
    "PrepareAdjudicationRequest",
    "ReconcileAdjudicationRequest",
    "prepare_adjudication_run",
    "reconcile_adjudication_run",
    "select_pilot_packet_ids",
]
