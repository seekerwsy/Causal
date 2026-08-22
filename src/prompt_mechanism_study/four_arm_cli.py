"""Command-line entry for the bounded four-arm replication."""

from __future__ import annotations

import argparse
from pathlib import Path

from prompt_mechanism_study import four_arm


def main() -> int:
    parser = argparse.ArgumentParser(prog="prompt-mechanism-four-arm")
    parser.add_argument(
        "action",
        choices=(
            "preflight",
            "intervene-pilot",
            "intervene-remaining",
            "measure-pilot",
            "measure-remaining",
            "analyze",
        ),
    )
    parser.add_argument("output", type=Path)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--tasks", type=Path, required=True)
    parser.add_argument("--intervention-pilot", type=Path)
    parser.add_argument("--intervention-remaining", type=Path)
    parser.add_argument("--measurement-pilot", type=Path)
    parser.add_argument("--measurement-remaining", type=Path)
    parser.add_argument("--oracle-source-root", type=Path)
    parser.add_argument("--semgrep", type=Path)
    parser.add_argument("--bandit", type=Path)
    args = parser.parse_args()
    if args.action == "preflight":
        report = four_arm.preflight(args.repository_root, args.config, args.tasks, args.output)
    elif args.action.startswith("intervene-"):
        report = four_arm.run_interventions(
            args.repository_root,
            args.config,
            args.tasks,
            args.action.removeprefix("intervene-"),
            args.output,
            pilot_root=args.intervention_pilot,
        )
    elif args.action.startswith("measure-"):
        required = (args.intervention_pilot, args.oracle_source_root, args.semgrep, args.bandit)
        if any(value is None for value in required):
            parser.error(
                "measurement requires intervention-pilot, oracle-source-root, semgrep, and bandit"
            )
        report = four_arm.run_measurements(
            args.repository_root,
            args.config,
            args.tasks,
            args.action.removeprefix("measure-"),
            args.output,
            intervention_pilot=args.intervention_pilot,
            intervention_remaining=args.intervention_remaining,
            oracle_source_root=args.oracle_source_root,
            semgrep=args.semgrep,
            bandit=args.bandit,
            measurement_pilot=args.measurement_pilot,
        )
    else:
        if args.measurement_pilot is None or args.measurement_remaining is None:
            parser.error("analysis requires measurement-pilot and measurement-remaining")
        report = four_arm.analyze(
            args.config, args.tasks, args.measurement_pilot, args.measurement_remaining, args.output
        )
    print(report["status"])
    return 0 if report["status"] != "ERROR" else 2


if __name__ == "__main__":
    raise SystemExit(main())
