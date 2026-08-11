from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from typing import Literal, Optional

from pydantic import ValidationError
import typer

from secaware.dataset_adjudication.config import AdjudicationConfig
from secaware.dataset_adjudication.run import (
    AdjudicationRunConflictError,
    PrepareAdjudicationRequest,
    ReconcileAdjudicationRequest,
    prepare_adjudication_run,
    reconcile_adjudication_run,
)


def _load_config(path: Path) -> AdjudicationConfig:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return AdjudicationConfig.model_validate(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as error:
        raise typer.BadParameter("dataset adjudication configuration is invalid") from error


def _workspace(path: Path) -> Path:
    workspace = Path(path).resolve()
    if not (workspace / "pyproject.toml").is_file() or not (
        workspace / "src" / "secaware"
    ).is_dir():
        raise typer.BadParameter("workspace-root must identify a repository workspace")
    return workspace


def _generated_run_id(config: AdjudicationConfig) -> str:
    digest = hashlib.sha256(config.model_dump_json().encode()).hexdigest()[:10]
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}-{digest}"


def prepare_dataset_adjudication_command(
    config: Path = typer.Option(..., "--config"),
    workspace_root: Path = typer.Option(..., "--workspace-root"),
    run_id: Optional[str] = typer.Option(None, "--run-id"),
) -> None:
    loaded = _load_config(config)
    workspace = _workspace(workspace_root)
    selected_run_id = run_id or _generated_run_id(loaded)
    source_run = (
        workspace / "runs" / "dataset-audit" / loaded.source_audit_run_id
    ).resolve()
    request = PrepareAdjudicationRequest(
        config=loaded,
        workspace_root=workspace,
        source_run_dir=source_run,
        run_id=selected_run_id,
        command_argv=(
            "secaware",
            "prepare-dataset-adjudication",
            "--config",
            str(Path(config).resolve()),
            "--workspace-root",
            str(workspace),
            "--run-id",
            selected_run_id,
        ),
    )
    try:
        result = prepare_adjudication_run(request)
    except (AdjudicationRunConflictError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error
    typer.echo(
        f"Dataset adjudication prepared: status={result.status} "
        f"run_id={result.run_id} run_dir={result.run_dir}"
    )


def reconcile_dataset_adjudication_command(
    config: Path = typer.Option(..., "--config"),
    workspace_root: Path = typer.Option(..., "--workspace-root"),
    parent_run_id: str = typer.Option(..., "--parent-run-id"),
    pass_a_decisions: Path = typer.Option(..., "--pass-a-decisions"),
    pass_b_decisions: Path = typer.Option(..., "--pass-b-decisions"),
    scope: Literal["pilot", "full"] = typer.Option("pilot", "--scope"),
    run_id: Optional[str] = typer.Option(None, "--run-id"),
) -> None:
    loaded = _load_config(config)
    workspace = _workspace(workspace_root)
    selected_run_id = run_id or _generated_run_id(loaded)
    parent = (
        workspace / "runs" / "dataset-adjudication" / parent_run_id
    ).resolve()
    request = ReconcileAdjudicationRequest(
        config=loaded,
        workspace_root=workspace,
        parent_run_dir=parent,
        pass_a_decisions_path=Path(pass_a_decisions).resolve(),
        pass_b_decisions_path=Path(pass_b_decisions).resolve(),
        run_id=selected_run_id,
        scope=scope,
        command_argv=(
            "secaware",
            "reconcile-dataset-adjudication",
            "--config",
            str(Path(config).resolve()),
            "--workspace-root",
            str(workspace),
            "--parent-run-id",
            parent_run_id,
            "--pass-a-decisions",
            str(Path(pass_a_decisions).resolve()),
            "--pass-b-decisions",
            str(Path(pass_b_decisions).resolve()),
            "--scope",
            scope,
            "--run-id",
            selected_run_id,
        ),
    )
    try:
        result = reconcile_adjudication_run(request)
    except (AdjudicationRunConflictError, ValueError, OSError) as error:
        raise typer.BadParameter(str(error)) from error
    typer.echo(
        f"Dataset adjudication reconciled: status={result.status} "
        f"run_id={result.run_id} run_dir={result.run_dir}"
    )


__all__ = [
    "prepare_dataset_adjudication_command",
    "reconcile_dataset_adjudication_command",
]
