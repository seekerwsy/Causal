"""Human-facing entry point for the prospective research-artifact stages."""

from __future__ import annotations
import argparse
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

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
    _add_prioritization_group(groups)
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
    actions = study.add_subparsers(dest="phase", required=True, metavar="ACTION")
    for name, help_text in (
        ("smoke", "run the offline seven-stage reviewer smoke"),
        ("verify-result", "independently verify a saved reviewer result"),
        ("development", "run an explicitly authorized frozen development comparison"),
        ("verify-development", "independently verify saved development results"),
    ):
        action = _leaf(actions, name, _run_study, help_text)
        action.add_argument("output", type=Path)
        if name == "development":
            action.add_argument("--development-plan", type=Path, required=True)
    repair = _leaf(actions, "verify-repair", _run_verify_repair,
                   "independently replay exposed observer checks and safety-gain decisions")
    repair.add_argument("inputs", type=Path)
    repair.add_argument("results", type=Path)
    repair.add_argument("decisions", type=Path)
    repair.add_argument("output", type=Path)
    repair.add_argument("--repository-root", type=Path, default=Path.cwd())
    sharing = _leaf(actions, "jci-sharing", _run_jci_sharing,
                    "run the authorized multi-environment JCI sharing development study")
    sharing.add_argument("output", type=Path)
    sharing.add_argument("--plan", type=Path, required=True)
    sharing.add_argument("--rscript", type=Path, required=True)
    sharing.add_argument("--limit", type=int)
    sharing.add_argument("--analyze-saved", action="store_true")
    sharing.add_argument("--recalibrate-saved", action="store_true")
    sharing.add_argument("--joint-policies", action="store_true")
    sharing.add_argument("--historical-only", action="store_true")
    sharing.add_argument("--joint-source-results", type=Path)
    sharing.add_argument("--zero-effect-refit", action="store_true")
    sharing_verify = _leaf(actions, "verify-jci-sharing", _run_verify_jci_sharing,
                          "independently verify the saved JCI sharing development study")
    sharing_verify.add_argument("output", type=Path)
    sharing_verify.add_argument("--joint-policies", action="store_true")
    sharing_verify.add_argument("--zero-effect-refit", action="store_true")
    sharing_diagnosis = _leaf(actions, "diagnose-jci-sharing", _run_diagnose_jci_sharing,
                             "localize sharing precision and query causal information in saved PAGs")
    sharing_diagnosis.add_argument("output", type=Path)
    sharing_diagnosis.add_argument("--rscript", type=Path, required=True)
    reliability = _leaf(actions, "jci-reliability", _run_jci_reliability,
                        "run the frozen bounded JCI policy reliability comparison")
    reliability.add_argument("output", type=Path)
    reliability.add_argument("--plan", type=Path, required=True)
    reliability.add_argument("--rscript", type=Path, required=True)
    reliability.add_argument("--limit", type=int)
    reliability.add_argument("--workers", type=int)
    reliability_verify = _leaf(actions, "verify-jci-reliability", _run_verify_jci_reliability,
                               "independently verify JCI reliability fits and policy comparisons")
    reliability_verify.add_argument("output", type=Path)
    reliability_verify.add_argument("--workers", type=int, default=4)
    reliability_diagnosis = _leaf(actions, "diagnose-jci-reliability", _run_diagnose_jci_reliability,
                                  "replay the exact CI deletions behind exposed false non-ancestry")
    reliability_diagnosis.add_argument("parent", type=Path)
    reliability_diagnosis.add_argument("output", type=Path)
    reliability_diagnosis.add_argument("--rscript", type=Path, required=True)
    reliability_diagnosis.add_argument("--limit", type=int)
    reliability_diagnosis.add_argument("--population", action="store_true")


def _add_prioritization_group(groups: Any) -> None:
    group = groups.add_parser("prioritization", help="prepare exposed development safety-gain decisions")
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")
    decisions = _leaf(actions, "safe-decisions", _run_safe_decisions,
                      "fit task-equal Ridge and retain baseline when no edit exceeds the threshold")
    decisions.add_argument("inputs", type=Path)
    decisions.add_argument("analysis", type=Path)
    decisions.add_argument("output", type=Path)
    decisions.add_argument("--minimum-gain", type=float, required=True)


def _add_representation_group(groups: Any) -> None:
    group = groups.add_parser(
        "representation",
        help="freeze task roles and extract evidence-bound Prompt TSG representations",
        description=("Freeze task roles and extract evidence-bound Prompt TSG representations."),
    )
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")

    for name, handler, help_text in (
        ("submit-preparation", _run_submit_preparation, "validate and save all prepared expression versions"),
        ("submit-review", _run_submit_review, "validate and save complete Atomic state and binding reviews"),
    ):
        submission = _leaf(actions, name, handler, help_text)
        submission.add_argument("inputs", type=Path)
        submission.add_argument("submission", type=Path)
        submission.add_argument("output", type=Path)

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

    controls = _leaf(actions, "controlled-inputs", _run_controlled_inputs,
                     "prepare the fixed twenty-four exposed observer controls")
    controls.add_argument("output", type=Path)
    controls.add_argument("--repository-root", type=Path, default=Path.cwd())

    observer = _leaf(actions, "controlled-observer", _run_controlled_observer,
                     "measure the fixed controls with the declared isolated Docker worker")
    observer.add_argument("inputs", type=Path)
    observer.add_argument("output", type=Path)
    observer.add_argument("--worker", type=Path, required=True)
    observer.add_argument("--image", required=True)
    observer.add_argument("--workers", type=int, choices=(1, 4), default=1)

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

        report = run_target_development(args.development_plan, args.output)
    elif args.phase == "verify-development":
        from prompt_mechanism_study.verification.reporting import verify_development_result

        report = verify_development_result(args.output)
    else:
        from prompt_mechanism_study.verification import load_and_verify_target_result_bundle

        report = load_and_verify_target_result_bundle(args.output)
    return _emit_json(report)


def _run_safe_decisions(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.discovery.safe_yield import prepare_safe_decisions

    return _emit_json(prepare_safe_decisions(args.inputs, args.analysis, args.output, args.minimum_gain))


def _run_jci_sharing(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.experiment.jci_sharing import run_jci_sharing, recalibrate_saved_sharing

    if args.joint_policies:
        if args.zero_effect_refit:
            from prompt_mechanism_study.experiment.jci_refit import run_zero_refit

            return _emit_json(run_zero_refit(args.output, args.plan, args.rscript))
        from prompt_mechanism_study.artifact_io import read_json

        if read_json(args.plan).get('budget_replay', False):
            from prompt_mechanism_study.experiment.jci_replay import run_budget_replay

            if not args.historical_only or args.joint_source_results is not None:
                raise ValueError('预算重放必须使用已暴露历史材料')
            return _emit_json(run_budget_replay(args.plan, args.output, args.rscript, args.limit))
        from prompt_mechanism_study.experiment.jci_policy import run_joint_policy

        return _emit_json(run_joint_policy(args.plan, args.output, args.rscript, args.limit, args.historical_only, args.joint_source_results))
    if args.recalibrate_saved:
        return _emit_json(recalibrate_saved_sharing(args.output))
    return _emit_json(run_jci_sharing(args.plan, args.output, args.rscript, args.limit, args.analyze_saved))


def _run_verify_jci_sharing(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    if args.joint_policies:
        if args.zero_effect_refit:
            from prompt_mechanism_study.verification.jci_refit import verify_zero_refit

            return _emit_json(verify_zero_refit(args.output))
        from prompt_mechanism_study.verification.jci_policy import verify_joint_policy

        return _emit_json(verify_joint_policy(args.output))
    from prompt_mechanism_study.verification.jci_sharing import verify_jci_sharing

    return _emit_json(verify_jci_sharing(args.output))


def _run_diagnose_jci_sharing(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.verification.jci_sharing_diagnostics import diagnose_jci_sharing

    return _emit_json(diagnose_jci_sharing(args.output, args.rscript))


def _run_jci_reliability(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.experiment.jci_reliability import run_reliability

    return _emit_json(run_reliability(args.plan, args.output, args.rscript, args.limit, args.workers))


def _run_verify_jci_reliability(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.verification.jci_reliability import verify_reliability

    return _emit_json(verify_reliability(args.output, args.workers))


def _run_diagnose_jci_reliability(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.verification.jci_reliability import diagnose_false_zeros

    if args.population:
        from prompt_mechanism_study.verification.jci_reliability import diagnose_population_information

        return _emit_json(diagnose_population_information(args.parent,args.output,args.rscript))
    return _emit_json(diagnose_false_zeros(args.parent, args.output, args.rscript, args.limit))


def _run_verify_repair(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.verification.controlled import verify_controlled_repair

    return _emit_json(verify_controlled_repair(args.inputs, args.results, args.decisions, args.output,
                                              repository_root=args.repository_root))


def _run_submit_preparation(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.tsg.prepared_prompts import submit_controlled_preparation

    return _emit_json(submit_controlled_preparation(args.inputs, args.submission, args.output))


def _run_submit_review(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.tsg.prepared_prompts import submit_controlled_review

    return _emit_json(submit_controlled_review(args.inputs, args.submission, args.output))


def _run_controlled_inputs(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.measurement.controlled_qualification import controlled_repair_inputs

    controlled_repair_inputs(args.repository_root, args.output)
    return _emit_json(dict(status="PREPARED", cases=24, output=str(args.output)))


def _run_controlled_observer(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.measurement.controlled_qualification import qualify_controlled_observer

    return _emit_json(qualify_controlled_observer(args.inputs, args.output, args.worker, args.image, args.workers))


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

    from prompt_mechanism_study.tsg.prompt_contract_qualification import prepare_source_reference
    report = extract_contract_task_file(
        args.tasks,
        args.catalog,
        args.evaluator,
        args.annotator_prompt,
        args.selection,
        args.output,
        max_workers=args.workers,
        reference_context=(prepare_source_reference(reference_path=args.qualification_reference,
            tasks_path=args.tasks, selection_path=args.selection, catalog_path=args.catalog,
            evaluator_path=args.evaluator, annotator_prompt_path=args.annotator_prompt)
            if args.qualification_reference else None),
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
