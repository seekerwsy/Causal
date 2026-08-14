from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from secaware.oracle.calibration_audit import build_oracle_calibration_evidence_audit


def audit_oracle_calibration_command(
    config: Annotated[Path, typer.Option("--config")],
    project_root: Annotated[Path, typer.Option("--project-root")],
    coverage_contract: Annotated[Path, typer.Option("--coverage-contract")],
    pilot_packets: Annotated[Path, typer.Option("--pilot-packets")],
    scope_decisions: Annotated[Path, typer.Option("--scope-decisions")],
    run_dir: Annotated[Path, typer.Option("--run-dir")],
) -> None:
    loaded = json.loads(config.read_text(encoding="utf-8"))
    argv = (
        "secaware",
        "audit-oracle-calibration",
        "--config",
        str(config.resolve()),
        "--project-root",
        str(project_root.resolve()),
        "--coverage-contract",
        str(coverage_contract.resolve()),
        "--pilot-packets",
        str(pilot_packets.resolve()),
        "--scope-decisions",
        str(scope_decisions.resolve()),
        "--run-dir",
        str(run_dir.resolve()),
    )
    report = build_oracle_calibration_evidence_audit(
        project_root=project_root,
        config=loaded,
        coverage_contract_path=coverage_contract,
        pilot_packets_path=pilot_packets,
        scope_decisions_path=scope_decisions,
        run_dir=run_dir,
        command_argv=argv,
    )
    typer.echo(
        f"Oracle calibration evidence audited: status={report['status']} "
        f"candidates={report['counts']['dataset_code_candidates']} "
        f"admitted={report['counts']['profiles_admitted']}"
    )


__all__ = ["audit_oracle_calibration_command"]
