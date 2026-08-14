from __future__ import annotations

import json
from pathlib import Path

import typer

from secaware.functional_audit import prepare_functional_audit_pilot


def prepare_functional_audit_command(
    config: Path = typer.Option(..., "--config"),
    source_record_audit: Path = typer.Option(..., "--source-record-audit"),
    run_dir: Path = typer.Option(..., "--run-dir"),
    decisions: Path | None = typer.Option(None, "--decisions"),
) -> None:
    loaded = json.loads(config.read_text(encoding="utf-8"))
    argv = (
        "secaware",
        "prepare-functional-audit",
        "--config",
        str(config.resolve()),
        "--source-record-audit",
        str(source_record_audit.resolve()),
        "--run-dir",
        str(run_dir.resolve()),
        *(("--decisions", str(decisions.resolve())) if decisions is not None else ()),
    )
    report = prepare_functional_audit_pilot(
        source_record_audit=source_record_audit,
        run_dir=run_dir,
        config=loaded,
        command_argv=argv,
        decisions_path=decisions,
    )
    typer.echo(
        f"Functional audit prepared: status={report['status']} "
        f"packets={report['counts']['packets']} contracts={report['counts']['contracts']}"
    )


__all__ = ["prepare_functional_audit_command"]
