from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError
import typer

from secaware.dataset_audit.catalog import LEGACY_SOURCES
from secaware.dataset_audit.run import (
    AuditRequest,
    AuditRunConflictError,
    execute_audit,
)


class AuditCLIConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    audit_version: Literal["audit-v1"]
    legacy_snapshot_id: Literal["legacy-2026-08-10"]
    neutrality_rule_version: Literal["neutrality-prescreen-v1"]
    prompt_normalization_version: Literal["prompt-normalization-v1"]
    cluster_version: Literal["task-cluster-v1"]
    split_version: Literal["cluster-split-v1"]
    split_ratios: tuple[float, ...]
    seed: int
    smoke_records_per_dataset: int = Field(ge=1, le=100)
    minimum_cluster_floor: int = Field(ge=1)


def _load_audit_config(path: Path) -> AuditCLIConfig:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return AuditCLIConfig.model_validate(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as error:
        raise typer.BadParameter("dataset audit configuration is invalid") from error


def _validate_workspace(path: Path) -> Path:
    workspace = Path(path).resolve()
    if (
        not (workspace / "pyproject.toml").is_file()
        or not (workspace / "src" / "secaware").is_dir()
    ):
        raise typer.BadParameter("workspace-root must identify a repository workspace")
    return workspace


def _validate_source_root(path: Path) -> Path:
    source_root = Path(path).resolve()
    missing = []
    for source in LEGACY_SOURCES:
        candidate = source_root / source.filename
        if not candidate.is_file() or candidate.is_symlink():
            missing.append(source.filename)
    if missing:
        raise typer.BadParameter(
            "12-file source set missing: " + ", ".join(missing)
        )
    return source_root


def _generated_run_id(config: AuditCLIConfig) -> str:
    payload = config.model_dump_json().encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:10]
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}-{digest}"


def audit_datasets_command(
    config: Path = typer.Option(..., "--config"),
    source_root: Path = typer.Option(..., "--source-root"),
    workspace_root: Path = typer.Option(..., "--workspace-root"),
    run_id: Optional[str] = typer.Option(None, "--run-id"),
    sample_only: bool = typer.Option(False, "--sample-only"),
    skip_v2_download: bool = typer.Option(False, "--skip-v2-download"),
    supersedes_run_id: Optional[str] = typer.Option(None, "--supersedes-run-id"),
) -> None:
    loaded = _load_audit_config(config)
    workspace = _validate_workspace(workspace_root)
    sources = _validate_source_root(source_root)
    selected_run_id = run_id or _generated_run_id(loaded)
    command_argv = (
        "secaware",
        "audit-datasets",
        "--config",
        str(Path(config).resolve()),
        "--source-root",
        str(sources),
        "--workspace-root",
        str(workspace),
        "--run-id",
        selected_run_id,
        *(('--sample-only',) if sample_only else ()),
        *(('--skip-v2-download',) if skip_v2_download else ()),
    )
    request = AuditRequest(
        source_root=sources,
        workspace_root=workspace,
        run_id=selected_run_id,
        catalog=LEGACY_SOURCES,
        config=loaded.model_dump(mode="json"),
        command_argv=command_argv,
        skip_v2_download=skip_v2_download,
        sample_records_per_dataset=(
            loaded.smoke_records_per_dataset if sample_only else None
        ),
        supersedes_run_id=supersedes_run_id,
    )
    try:
        result = execute_audit(request)
    except AuditRunConflictError as error:
        raise typer.BadParameter(str(error)) from error
    if result.status == "FAILED":
        typer.echo(f"Dataset audit failed: run_dir={result.run_dir}", err=True)
        raise typer.Exit(code=1)
    typer.echo(
        f"Dataset audit complete: status={result.status} "
        f"run_id={result.run_id} run_dir={result.run_dir}"
    )


__all__ = ["AuditCLIConfig", "audit_datasets_command"]
