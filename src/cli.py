"""Human-facing entry point for the prospective research-artifact stages."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from prompt_mechanism_study.data.commands import _run_prepare_qualification_review

CliHandler = Callable[[argparse.Namespace, argparse.ArgumentParser], int]


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    handler: CliHandler = args.handler
    return handler(args, parser)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prompt-mechanism-study",
        description="Research prototype: seven-stage reviewer smoke and independent verification.",
        epilog=(
            "Start with 'study smoke OUTPUT', then 'study verify-result OUTPUT'. "
            "Data preparation and qualification are separate author operations; "
            "they are not prerequisites for the offline reviewer smoke. "
            "Use 'GROUP --help' for their commands."
        ),
    )
    groups = parser.add_subparsers(dest="group", required=True, metavar="GROUP")
    _add_study_group(groups)
    from prompt_mechanism_study.data.commands import add_source_commands
    add_source_commands(groups)
    _add_representation_group(groups)
    _add_qualification_group(groups)
    _add_artifact_group(groups)
    return parser


def _add_study_group(groups: Any) -> None:
    study = groups.add_parser(
        "study",
        help="run reviewer smoke, authorized bounded development, or independent verification",
        description=(
            "Run the zero-network reviewer smoke, an explicitly authorized frozen "
            "development comparison, or independent result verification. "
            "Formal provider execution remains disabled."
        ),
    )
    study.set_defaults(handler=_run_study)
    study.add_argument("phase", choices=("smoke", "verify-result", "development", "verify-development"))
    study.add_argument("output", type=Path)
    study.add_argument("--development-plan", type=Path)


def _add_representation_group(groups: Any) -> None:
    group = groups.add_parser(
        "representation",
        help="freeze task roles and extract evidence-bound Prompt TSG representations",
        description=("Freeze task roles and extract evidence-bound Prompt TSG representations."),
    )
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")

    selection = _leaf(
        actions,
        "select-tsg-tasks",
        _run_select_tsg_tasks,
        "freeze formal Prompt-TSG tasks after provenance-only exclusions",
    )
    selection.add_argument("tasks", type=Path)
    selection.add_argument("output", type=Path)
    selection.add_argument("--exclude", type=Path, action="append", required=True)

    holdout = _leaf(
        actions,
        "select-tsg-holdout",
        _run_select_tsg_holdout,
        "freeze a disjoint outcome-blind Prompt TSG qualification holdout",
    )
    holdout.add_argument("tasks", type=Path)
    holdout.add_argument("output", type=Path)
    holdout.add_argument("--exclude", type=Path, action="append", required=True)
    holdout.add_argument("--cwe", action="append", required=True)
    holdout.add_argument("--task-units-per-cwe", type=int, default=3)
    holdout.add_argument("--ranking-salt", required=True)

    qualification_review = _leaf(
        actions,
        "prepare-qualification-review",
        _run_prepare_qualification_review,
        "prepare disjoint source-only qualification review packets without assigning roles",
    )
    qualification_review.add_argument("source_bundle", type=Path)
    qualification_review.add_argument("catalog", type=Path)
    qualification_review.add_argument("registry", type=Path)
    qualification_review.add_argument("output", type=Path)
    qualification_review.add_argument("--producer-commit", required=True)
    qualification_review.add_argument("--ranking-salt", required=True)
    qualification_review.add_argument("--qual-dev-count", type=int, default=28)
    qualification_review.add_argument("--qual-accept-count", type=int, default=28)

    extract_contracts = _leaf(
        actions,
        "extract-contracts",
        _run_extract_contracts,
        "extract source-only task graphs and then assess fixed source scopes",
    )
    extract_contracts.add_argument("tasks", type=Path)
    extract_contracts.add_argument("catalog", type=Path)
    extract_contracts.add_argument("evaluator", type=Path)
    extract_contracts.add_argument("annotator_prompt", type=Path)
    extract_contracts.add_argument("selection", type=Path)
    extract_contracts.add_argument("output", type=Path)
    extract_contracts.add_argument("--workers", type=int, default=1)
    extract_contracts.add_argument(
        "--qualification-reference",
        type=Path,
        help="bind an independent source reference before any extraction calls",
    )
    extract_contracts.add_argument(
        "--development-exposed",
        action="store_true",
        help="use already exposed development tasks; never grants formal admission",
    )

    candidate_request = _leaf(
        actions,
        "candidate-request",
        _run_candidate_request,
        "prepare an outcome-blind candidate request from source tasks and extracted graphs",
    )
    candidate_request.add_argument("tasks", type=Path)
    candidate_request.add_argument("extraction", type=Path)
    candidate_request.add_argument("output", type=Path)
    candidate_request.add_argument("--input-catalog", type=Path)

    candidates = _leaf(
        actions,
        "build-candidates",
        _run_build_candidates,
        "build source-bound candidate definitions from one retained or development response",
    )
    candidates.add_argument("request", type=Path)
    candidates.add_argument("design", type=Path)
    candidates.add_argument("output", type=Path)
    candidate_response = candidates.add_mutually_exclusive_group(required=True)
    candidate_response.add_argument(
        "--response", type=Path, help="replay a retained candidate response without model calls"
    )
    candidate_response.add_argument(
        "--evaluator", type=Path, help="make one explicitly bounded development model call"
    )
    candidates.add_argument("--review", type=Path)

    candidate_bindings = _leaf(
        actions,
        "bind-candidates",
        _run_bind_candidates,
        "bind reviewed candidate definitions to exact task scopes for the shared support audit",
    )
    candidate_bindings.add_argument("candidates", type=Path)
    candidate_bindings.add_argument("tasks", type=Path)
    candidate_bindings.add_argument("output", type=Path)
    candidate_bindings.add_argument(
        "--prompt-tsg-bundle", type=Path, action="append", required=True
    )
    candidate_bindings.add_argument("--qualification-bundle", type=Path)

    visualize = _leaf(
        actions,
        "visualize",
        _run_visualize_tsg,
        "export an offline source-evidence, instance-graph and assigned-arm result viewer",
    )
    visualize.add_argument("tasks", type=Path)
    visualize.add_argument("extraction", type=Path)
    visualize.add_argument("output", type=Path)
    visualize.add_argument("--additional-extraction", type=Path, action="append", default=[])
    visualize.add_argument("--results", type=Path)
    visualize.add_argument("--catalog", type=Path)
    visualize.add_argument(
        "--review", type=Path, help="saved development analysis bundle for graph debugging"
    )

def _add_qualification_group(groups: Any) -> None:
    group = groups.add_parser(
        "qualification",
        help="run Oracle, representation, support, and design qualification gates",
        description=(
            "Run Oracle, representation, support, and design qualification gates."
        ),
    )
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")

    target_security = _leaf(
        actions,
        "target-security-oracle",
        _run_target_security_oracle,
        "qualify the current Security Oracle for the declared profile scope",
    )
    target_security.add_argument("registry", type=Path)
    target_security.add_argument("output", type=Path)
    target_security.add_argument("--cases", type=Path, action="append", required=True)
    target_security.add_argument(
        "--profile", action="append",
        help="qualify only this registered local profile; repeat for the declared research scope",
    )
    target_security.add_argument("--repository-root", type=Path, default=Path.cwd())

    prompt_contract = _leaf(
        actions,
        "prompt-contract",
        _run_prompt_contract_qualification,
        "replay open-graph extraction and score independent source semantics",
    )
    prompt_contract.add_argument("tasks", type=Path)
    prompt_contract.add_argument("extraction_bundle", type=Path)
    prompt_contract.add_argument("catalog", type=Path)
    prompt_contract.add_argument("gold", type=Path)
    prompt_contract.add_argument("evaluator", type=Path)
    prompt_contract.add_argument("annotator_prompt", type=Path)
    prompt_contract.add_argument("output", type=Path)
    prompt_contract.add_argument("--assertion-review", type=Path,
                                 help="independent source review of every asserted open-graph statement")

    judge = _leaf(
        actions,
        "functional-judge",
        _run_functional_judge,
        "run the bounded Functional Judge gate",
    )
    judge.add_argument("phase", choices=("preflight", "pilot", "remaining", "finalize"))
    judge.add_argument("output", type=Path)
    judge.add_argument("--repository-root", type=Path, default=Path.cwd())
    judge.add_argument("--gate-config", type=Path)
    judge.add_argument("--pilot-root", type=Path)
    judge.add_argument("--remaining-root", type=Path)

    positivity = _leaf(
        actions,
        "positivity",
        _run_positivity,
        "audit natural Prompt-feature support before FCI",
    )
    positivity.add_argument("tasks", type=Path)
    positivity.add_argument("catalog", type=Path)
    positivity.add_argument("output", type=Path)
    positivity.add_argument("--prompt-tsg-bundle", type=Path, action="append", required=True)
    positivity.add_argument("--scope-bindings", type=Path, required=True,
                            help="frozen global factor definitions, task scopes and shared support rules for open graphs")
    positivity.add_argument(
        "--graph-artifact",
        default="graphs.json",
        choices=(
            "graphs.json",
            "discovery-graphs.json",
            "pilot-graphs.json",
            "confirm-graphs.json",
        ),
        help="graph collection inside each verified bundle",
    )


def _add_artifact_group(groups: Any) -> None:
    group = groups.add_parser(
        "artifact",
        help="verify exact-byte artifact bundles",
        description="Verify exact-byte artifact bundles.",
    )
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")
    verify = _leaf(
        actions,
        "verify",
        _run_artifact_verify,
        "verify an exact artifact bundle",
    )
    verify.add_argument("root", type=Path)


def _leaf(actions: Any, name: str, handler: CliHandler, help_text: str) -> argparse.ArgumentParser:
    parser = actions.add_parser(name, help=help_text)
    parser.set_defaults(handler=handler)
    return parser


def _run_study(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    if args.phase == "smoke":
        from prompt_mechanism_study.target_workflow import run_target_reviewer_smoke

        report = run_target_reviewer_smoke(args.output)
    elif args.phase == "development":
        from prompt_mechanism_study.target_workflow import run_target_development

        if args.development_plan is None:
            raise ValueError("development execution requires a prospectively frozen --development-plan")
        report = run_target_development(args.development_plan, args.output)
    elif args.phase == "verify-development":
        from prompt_mechanism_study.verification.reporting import verify_development_result

        report = verify_development_result(args.output)
    else:
        from prompt_mechanism_study.verification import load_and_verify_target_result_bundle

        report = load_and_verify_target_result_bundle(args.output)
    return _emit_json(report)


def _run_select_tsg_tasks(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.eligibility import freeze_prompt_tsg_task_selection

    return _emit_status(
        freeze_prompt_tsg_task_selection(args.tasks, tuple(args.exclude), args.output)
    )


def _run_select_tsg_holdout(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.eligibility import freeze_prompt_tsg_holdout_selection

    report = freeze_prompt_tsg_holdout_selection(
        args.tasks,
        tuple(args.exclude),
        args.output,
        cwes=tuple(sorted(set(args.cwe))),
        task_units_per_cwe=args.task_units_per_cwe,
        ranking_salt=args.ranking_salt,
    )
    return _emit_status(report)


def _run_visualize_tsg(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.tsg.tsg_visualization import build_tsg_viewer
    return _emit_status(build_tsg_viewer(args.tasks, (args.extraction, *args.additional_extraction),
                                       args.output, results_root=args.results, catalog_path=args.catalog,
                                       review_root=args.review))


def _run_extract_contracts(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.tsg.prompt_contract_extract import extract_contract_task_file

    report = extract_contract_task_file(
        args.tasks,
        args.catalog,
        args.evaluator,
        args.annotator_prompt,
        args.selection,
        args.output,
        max_workers=args.workers,
        qualification_reference_path=args.qualification_reference,
        review_status="development_exposed" if args.development_exposed else "prospective_frozen",
    )
    return _emit_status(report)


def _run_candidate_request(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.tsg.candidate_construction import prepare_candidate_request

    return _emit_json(prepare_candidate_request(
        args.tasks, args.extraction, args.output, input_catalog_path=args.input_catalog,
    ))


def _run_build_candidates(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.tsg.candidate_construction import build_candidate_catalog

    return _emit_json(build_candidate_catalog(
        args.request, args.design, args.output,
        response_path=args.response, evaluator_path=args.evaluator, review_path=args.review,
    ))


def _run_bind_candidates(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.tsg.candidate_construction import bind_candidate_scopes

    return _emit_json(
        bind_candidate_scopes(
            args.candidates,
            args.tasks,
            args.prompt_tsg_bundle,
            args.output,
            qualification_bundle=args.qualification_bundle,
        )
    )


def _run_target_security_oracle(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.eligibility import qualify_target_security_profiles

    report = qualify_target_security_profiles(
        args.repository_root,
        args.registry,
        tuple(args.cases),
        args.output,
        profile_ids=None if args.profile is None else tuple(args.profile),
    )
    return _emit_gate_status(report, "QUALIFIED_FOR_TARGET_MEASUREMENT_PROFILE")


def _run_prompt_contract_qualification(
    args: argparse.Namespace,
    _: argparse.ArgumentParser,
) -> int:
    from prompt_mechanism_study.tsg.prompt_contract_qualification import (
        qualify_prompt_contract_extractor,
    )

    report = qualify_prompt_contract_extractor(
        args.tasks,
        args.extraction_bundle,
        args.catalog,
        args.gold,
        args.evaluator,
        args.annotator_prompt,
        args.output,
        assertion_review_path=args.assertion_review,
    )
    return _emit_gate_status(report, "QUALIFIED_FOR_FORMAL_EXTRACTION")


def _run_functional_judge(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.measurement.evaluate import functional_judge

    if args.phase == "preflight":
        report = functional_judge.preflight(
            args.repository_root,
            args.output,
            gate_config=args.gate_config,
        )
    elif args.phase in {"pilot", "remaining"}:
        report = functional_judge.run_phase(
            args.repository_root,
            args.phase,
            args.output,
            pilot_root=args.pilot_root,
            gate_config=args.gate_config,
        )
    else:
        if args.pilot_root is None or args.remaining_root is None:
            raise ValueError("finalize requires --pilot-root and --remaining-root")
        report = functional_judge.finalize_gate(
            args.repository_root,
            args.pilot_root,
            args.remaining_root,
            args.output,
            gate_config=args.gate_config,
        )
    status = report["status"]
    print(status)
    return (
        0
        if status
        in {
            "JUDGE_GATE_PREFLIGHT_COMPLETE",
            "PILOT_PASSED",
            "REMAINING_COMPLETE",
            "JUDGE_GATE_PASSED",
        }
        else 2
    )


def _run_positivity(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.discovery_population import audit_discovery_positivity

    report = audit_discovery_positivity(
        args.tasks,
        tuple(args.prompt_tsg_bundle),
        args.catalog,
        args.output,
        graph_artifact=args.graph_artifact,
        scope_bindings_path=args.scope_bindings,
    )
    return _emit_json(report)


def _run_artifact_verify(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.artifact_io import verify_bundle

    verify_bundle(args.root)
    print("VERIFIED")
    return 0


def _emit_status(report: dict[str, Any]) -> int:
    print(report["status"])
    return 0


def _emit_gate_status(report: dict[str, Any], accepted: str) -> int:
    status = report["status"]
    print(status)
    return 0 if status == accepted else 2


def _emit_json(report: dict[str, Any]) -> int:
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
