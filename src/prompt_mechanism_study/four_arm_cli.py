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
            "prepare-registered",
            "prepare-context-conditioned",
            "prepare-study-sample",
            "preflight",
            "intervene-pilot",
            "intervene-remaining",
            "intervene-full",
            "measure-pilot",
            "measure-remaining",
            "measure-full",
            "analyze",
            "analyze-full",
            "verify-analysis",
        ),
    )
    parser.add_argument("output", type=Path)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--config", type=Path)
    parser.add_argument("--tasks", type=Path)
    parser.add_argument("--source-tasks", type=Path)
    parser.add_argument("--sample", type=Path)
    parser.add_argument("--records", type=Path)
    parser.add_argument("--contracts", type=Path)
    parser.add_argument("--mechanism-registry", type=Path)
    parser.add_argument("--bindings", type=Path, action="append", default=[])
    parser.add_argument("--binding-report", type=Path)
    parser.add_argument("--selected-task-id", action="append", default=[])
    parser.add_argument("--intervention-pilot", type=Path)
    parser.add_argument("--intervention-remaining", type=Path)
    parser.add_argument("--measurement-pilot", type=Path)
    parser.add_argument("--measurement-remaining", type=Path)
    parser.add_argument("--measurement-full", type=Path)
    parser.add_argument("--resume-from", type=Path)
    parser.add_argument("--oracle-source-root", type=Path)
    parser.add_argument("--semgrep", type=Path)
    parser.add_argument("--bandit", type=Path)
    args = parser.parse_args()
    if args.action == "verify-analysis":
        if args.config is None or args.tasks is None:
            parser.error("analysis verification requires config and tasks")
        from prompt_mechanism_study.four_arm_verify import verify_analysis

        report = verify_analysis(args.config, args.tasks, args.output)
        print(report["status"])
        return 0
    if args.action == "prepare-registered":
        if args.source_tasks is None or args.mechanism_registry is None:
            parser.error("preparation requires source-tasks and mechanism-registry")
        report = four_arm.prepare_registered_tasks(
            args.source_tasks,
            args.mechanism_registry,
            args.selected_task_id,
            args.output,
        )
        print("FOUR_ARM_TASKS_PREPARED")
        return 0
    if args.action == "prepare-context-conditioned":
        required = (
            args.source_tasks,
            args.bindings or None,
            args.mechanism_registry,
            args.binding_report,
        )
        if any(value is None for value in required):
            parser.error(
                "context preparation requires source-tasks, bindings, registry, and binding-report"
            )
        report = four_arm.prepare_context_conditioned_tasks(
            args.source_tasks,
            args.bindings,
            args.mechanism_registry,
            args.output,
            args.binding_report,
        )
        print(report["status"])
        return 0
    if args.action == "prepare-study-sample":
        required = (args.sample, args.records, args.contracts, args.mechanism_registry)
        if any(value is None for value in required):
            parser.error("study preparation requires sample, records, contracts, and registry")
        four_arm.prepare_study_sample_tasks(
            args.sample,
            args.records,
            args.contracts,
            args.mechanism_registry,
            args.output,
        )
        print("FOUR_ARM_STUDY_TASKS_PREPARED")
        return 0
    if args.config is None or args.tasks is None:
        parser.error("this action requires config and tasks")
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
            resume_from=args.resume_from,
        )
    else:
        if args.action == "analyze-full":
            if args.measurement_full is None:
                parser.error("full analysis requires measurement-full")
            report = four_arm.analyze_full(
                args.config, args.tasks, args.measurement_full, args.output
            )
        else:
            if args.measurement_pilot is None or args.measurement_remaining is None:
                parser.error("analysis requires measurement-pilot and measurement-remaining")
            report = four_arm.analyze(
                args.config,
                args.tasks,
                args.measurement_pilot,
                args.measurement_remaining,
                args.output,
            )
    print(report["status"])
    return 0 if report["status"] != "ERROR" else 2


if __name__ == "__main__":
    raise SystemExit(main())
