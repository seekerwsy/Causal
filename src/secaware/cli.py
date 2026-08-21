"""Command-line interface for reproducing and verifying the compact artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from secaware.artifact_io import read_json, verify_bundle, write_bundle
from secaware.intervention import freeze_intervention
from secaware.measurement import (
    FunctionalLabel,
    Measurement,
    SecurityLabel,
    TerminalFailure,
)
from secaware.records import canonical_value
from secaware.representation import Candidate, Operation, Task
from secaware.workflow import analyze, arm_texts, freeze_study


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secaware")
    commands = parser.add_subparsers(dest="command", required=True)

    reproduce = commands.add_parser("reproduce", help="run the frozen method on JSON inputs")
    reproduce.add_argument("spec", type=Path)
    reproduce.add_argument("output", type=Path)

    verify = commands.add_parser("verify", help="verify an artifact bundle")
    verify.add_argument("root", type=Path)

    summarize = commands.add_parser("summarize", help="print the stored ITT summary")
    summarize.add_argument("root", type=Path)

    args = parser.parse_args(argv)
    if args.command == "reproduce":
        _reproduce(args.spec, args.output)
    elif args.command == "verify":
        verify_bundle(args.root)
        print("VERIFIED")
    else:
        verify_bundle(args.root)
        print(json.dumps(read_json(args.root / "analysis.json"), indent=2, sort_keys=True))
    return 0


def _reproduce(spec_path: Path, output: Path) -> None:
    raw = read_json(spec_path)
    tasks = tuple(
        Task(item["task_id"], item["cluster_id"], item["cwe"], item["prompt"])
        for item in raw["tasks"]
    )
    candidates = tuple(
        Candidate(
            item["task_id"],
            item["feature_id"],
            Operation(item["operation"]),
            item["rationale"],
        )
        for item in raw["candidates"]
    )
    by_task = {candidate.task_id: candidate for candidate in candidates}
    interventions = tuple(
        freeze_intervention(
            by_task[item["task_id"]],
            arm_texts(
                target=item["arms"]["target"],
                noop=item["arms"]["noop"],
                placebo=item["arms"]["placebo"],
                generic=item["arms"]["generic"],
            ),
        )
        for item in raw["interventions"]
    )
    study = freeze_study(
        tasks,
        candidates,
        interventions,
        models=tuple(raw["models"]),
        slots=tuple(raw["slots"]),
        seed=raw["seed"],
    )

    artifacts: dict[str, Any] = {
        "study.json": {"study_id": study.study_id, "study": canonical_value(study)},
        "randomization.json": {
            "randomization_id": study.randomization.randomization_id,
            "randomization": canonical_value(study.randomization),
        },
    }
    if "measurements" in raw:
        measurements, failures = _measurements(raw["measurements"], study.randomization.assignments)
        result = analyze(study, measurements, failures)
        artifacts["outcomes.json"] = canonical_value(result.outcomes)
        artifacts["analysis.json"] = {
            "analysis_id": result.analysis_id,
            "security": canonical_value(result.security),
            "functionality": canonical_value(result.functionality),
            "joint": canonical_value(result.joint),
        }
    write_bundle(output, artifacts)
    print(output)


def _measurements(
    rows: list[dict[str, Any]], assignments: tuple[Any, ...]
) -> tuple[
    tuple[Measurement, ...],
    tuple[TerminalFailure, ...],
]:
    coordinates = {
        (item.task_id, item.model_id, item.request_slot): item.assignment_id for item in assignments
    }
    measurements: list[Measurement] = []
    failures: list[TerminalFailure] = []
    for row in rows:
        key = (row["task_id"], row["model_id"], row["request_slot"])
        assignment_id = coordinates.get(key)
        if assignment_id is None:
            raise ValueError(f"measurement does not bind a frozen assignment: {key}")
        if "failure_stage" in row:
            failures.append(TerminalFailure(assignment_id, row["failure_stage"]))
        else:
            measurements.append(
                Measurement(
                    assignment_id,
                    SecurityLabel(row["security"]),
                    FunctionalLabel(row["functionality"]),
                )
            )
    return tuple(measurements), tuple(failures)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
