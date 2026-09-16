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
        description="Schema-3 research artifact and its prospective input pipeline.",
        epilog=(
            "Suggested flow: data -> curate -> representation -> qualification -> study. "
            "Use 'GROUP --help' to list actions in one stage."
        ),
    )
    groups = parser.add_subparsers(dest="group", required=True, metavar="GROUP")
    _add_study_group(groups)
    _add_data_group(groups)
    _add_curation_group(groups)
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


def _add_data_group(groups: Any) -> None:
    group = groups.add_parser(
        "data",
        help="normalize sources and assemble outcome-free task-unit inputs",
        description="Normalize sources and assemble outcome-free task-unit inputs.",
    )
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")

    prepare = _leaf(
        actions,
        "prepare",
        _run_data_prepare,
        "normalize external task sources without executing their code",
    )
    prepare.add_argument("output", type=Path)
    prepare.add_argument("--sallm-root", type=Path)
    prepare.add_argument("--cweval-root", type=Path)
    prepare.add_argument("--cyberseceval-path", type=Path)
    prepare.add_argument("--llmseceval-root", type=Path)
    prepare.add_argument("--securityeval-root", type=Path)
    prepare.add_argument("--codeseceval-root", type=Path)
    prepare.add_argument("--secodeplt-root", type=Path)
    prepare.add_argument("--limit-per-source", type=int)

    freeze_contracts = _leaf(
        actions,
        "freeze-contracts",
        _run_freeze_contracts,
        "freeze externally extracted functional contracts",
    )
    freeze_contracts.add_argument("prepared_root", type=Path)
    freeze_contracts.add_argument("responses", type=Path)
    freeze_contracts.add_argument("output", type=Path)

    dedup = _leaf(
        actions,
        "dedup-candidates",
        _run_dedup_candidates,
        "prepare lexical candidate pairs for semantic adjudication",
    )
    dedup.add_argument("prepared_root", type=Path)
    dedup.add_argument("output", type=Path)
    dedup.add_argument("--minimum-jaccard", type=float, default=0.35)
    dedup.add_argument("--max-neighbors-per-record", type=int, default=3)

    task_units = _leaf(
        actions,
        "task-unit-bundle",
        _run_task_unit_bundle,
        "build or verify the reviewer-facing task-unit data bundle",
    )
    task_units.add_argument("phase", choices=("build", "verify"))
    task_units.add_argument("output", type=Path)
    task_units.add_argument("--prepared-root", type=Path)
    task_units.add_argument("--clusters-root", type=Path)
    task_units.add_argument("--candidate-root", type=Path)
    task_units.add_argument("--contracts-root", type=Path)
    task_units.add_argument("--contract-reviews-root", type=Path)
    task_units.add_argument("--legacy-roles-root", type=Path)
    task_units.add_argument("--development-exclusions", type=Path)


def _add_curation_group(groups: Any) -> None:
    group = groups.add_parser(
        "curate", help="prepare, review, repair and finalize outcome-blind source data",
        description="Use the frozen source bundle for study reproduction; repair is conditional data preparation.",
    )
    stages = group.add_subparsers(dest="curation_stage", required=True, metavar="STAGE")
    _add_curation_prepare(stages)
    _add_curation_review(stages)
    _add_curation_repair(stages)
    _add_curation_finalize(stages)


def _add_curation_prepare(stages: Any) -> None:
    group = stages.add_parser("prepare", help="prepare natural tasks, contracts and blind reservations")
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")

    pool = _leaf(actions, "candidate-pool", _run_prepare_candidate_pool,
                 "include usable prepared sources and reuse three-axis candidate evidence")
    pool.add_argument("source_bundle", type=Path)
    pool.add_argument("output", type=Path)
    pool.add_argument("--qualification-manifest", type=Path, required=True,
                      help="current qualification reservations and additional method exposures")

    source_use = _leaf(actions, "source-use", _run_prepare_source_use,
                       "prepare every frozen task, replay its source assets and preserve role boundaries")
    source_use.add_argument("source_bundle", type=Path)
    source_use.add_argument("reservation_bundle", type=Path)
    source_use.add_argument("catalog", type=Path)
    source_use.add_argument("registry", type=Path)
    source_use.add_argument("output", type=Path)
    source_use.add_argument("--source-root", action="append", required=True, metavar="DATASET=PATH")
    source_use.add_argument("--source-archive", action="append", default=[], metavar="DATASET=PATH")
    source_use.add_argument("--candidate-reviews", type=Path)
    source_use.add_argument("--candidate-context-reviews", type=Path)
    source_use.add_argument("--native-asset-reviews", type=Path)
    source_use.add_argument("--contract-review-round", type=Path, action="append", nargs=6,
                            metavar=("PROPOSALS", "PACKETS", "DECISIONS", "INITIAL", "ADJUDICATIONS", "REVIEWS"))

    restored = _leaf(actions, "restored-contracts", _run_prepare_restored_contracts,
                     "propose source-backed contracts for available restored inputs")
    restored.add_argument("base_bundle", type=Path)
    restored.add_argument("source_use_bundle", type=Path)
    restored.add_argument("reservation_bundle", type=Path)
    restored.add_argument("source_root", type=Path)
    restored.add_argument("output", type=Path)
    restored.add_argument("--producer-commit", required=True)

    semantics = _leaf(
        actions,
        "semantics",
        _run_semantic_curation,
        "blindly adjudicate lexical pairs and freeze semantic clusters",
    )
    semantics.add_argument("prepared_root", type=Path)
    semantics.add_argument("candidates_root", type=Path)
    semantics.add_argument("output", type=Path)
    _add_curation_runtime_options(semantics)

    assemble = _leaf(
        actions,
        "clusters",
        _run_assemble_clusters,
        "assemble exact/lineage clusters and retain pair decisions as diagnostics",
    )
    assemble.add_argument("prepared_root", type=Path)
    assemble.add_argument("candidates_root", type=Path)
    assemble.add_argument("adjudication_root", type=Path)
    assemble.add_argument("output", type=Path)

    contracts = _leaf(
        actions,
        "contracts",
        _run_contract_curation,
        "extract one functional contract per semantic cluster",
    )
    contracts.add_argument("prepared_root", type=Path)
    contracts.add_argument("clusters_root", type=Path)
    contracts.add_argument("output", type=Path)
    _add_curation_runtime_options(contracts)
    contracts.add_argument(
        "--existing-contracts-root",
        type=Path,
        help="reuse contracts whose representative record and prompt hash still match",
    )

    content_proposals = _leaf(
        actions,
        "content",
        _run_contract_content_proposals,
        "backfill faithful contracts and repair faulty contracts without outcomes",
    )
    content_proposals.add_argument("base_bundle", type=Path)
    content_proposals.add_argument("output", type=Path)
    content_proposals.add_argument("--repository-root", type=Path, default=Path.cwd())
    content_proposals.add_argument("--producer-commit", required=True)
    content_proposals.add_argument("--max-new-batches", type=int)
    content_proposals.add_argument("--workers", type=int, default=1)
    content_proposals.add_argument("--stop-after-evidence", action="store_true")

    reserve_future = _leaf(
        actions,
        "reservation",
        _run_reserve_future_evaluation,
        "seal one prompt-blind candidate per fully unexposed near-duplicate group",
    )
    reserve_future.add_argument("base_bundle", type=Path)
    reserve_future.add_argument("output", type=Path)
    reserve_future.add_argument("--producer-commit", required=True)


def _add_curation_review(stages: Any) -> None:
    group = stages.add_parser("review", help="prepare and close independent blind reviews")
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")

    review_contracts = _leaf(
        actions,
        "contracts",
        _run_contract_review,
        "blindly triage every functional contract before independent adjudication",
    )
    review_contracts.add_argument("prepared_root", type=Path)
    review_contracts.add_argument("contracts_root", type=Path)
    review_contracts.add_argument("output", type=Path)
    _add_curation_runtime_options(review_contracts)

    prepare_subagent_review = _leaf(
        actions,
        "prepare",
        _run_prepare_subagent_contract_review,
        "freeze dual-blind subagent review assignments and packets",
    )
    prepare_subagent_review.add_argument("base_bundle", type=Path)
    prepare_subagent_review.add_argument("proposals_root", type=Path)
    prepare_subagent_review.add_argument("output", type=Path)
    prepare_subagent_review.add_argument("--repository-root", type=Path, default=Path.cwd())
    prepare_subagent_review.add_argument("--producer-commit", required=True)
    prepare_subagent_review.add_argument("--source-use-bundle", type=Path)
    prepare_subagent_review.add_argument("--reservation-bundle", type=Path)
    prepare_subagent_review.add_argument(
        "--nonterminal-reviews-root",
        type=Path,
        help="review only task IDs with a nonterminal decision in this prior review bundle",
    )

    verify_review = _leaf(actions, "verify", _run_verify_contract_review_round,
                          "independently replay dual decisions and blind third adjudication")
    for name in ("proposals_root", "packets_root", "decisions_root", "initial_root",
                 "adjudication_decisions_root", "reviews_root"):
        verify_review.add_argument(name, type=Path)

    seal_subagent_review = _leaf(
        actions,
        "seal",
        _run_seal_initial_subagent_contract_review,
        "validate dual reviews and freeze blind disagreement packets",
    )
    seal_subagent_review.add_argument("packets_root", type=Path)
    seal_subagent_review.add_argument("decisions_root", type=Path)
    seal_subagent_review.add_argument("output", type=Path)

    finalize_subagent_review = _leaf(
        actions,
        "finalize",
        _run_finalize_subagent_contract_review,
        "merge agreements and blind third decisions into the review bundle",
    )
    finalize_subagent_review.add_argument("initial_root", type=Path)
    finalize_subagent_review.add_argument("adjudication_decisions_root", type=Path)
    finalize_subagent_review.add_argument("proposals_root", type=Path)
    finalize_subagent_review.add_argument("output", type=Path)

    merge_subagent_reviews = _leaf(
        actions,
        "merge",
        _run_merge_subagent_contract_reviews,
        "merge repaired-contract review decisions into the full prior review population",
    )
    merge_subagent_reviews.add_argument("prior_reviews_root", type=Path)
    merge_subagent_reviews.add_argument("revised_reviews_root", type=Path)
    merge_subagent_reviews.add_argument("proposals_root", type=Path)
    merge_subagent_reviews.add_argument("output", type=Path)

    review_bindings = _leaf(
        actions,
        "bindings",
        _run_binding_review,
        "blindly bind ambiguous task units to registered mechanism realizations",
    )
    review_bindings.add_argument("prepared_root", type=Path)
    review_bindings.add_argument("clusters_root", type=Path)
    review_bindings.add_argument("contracts_root", type=Path)
    review_bindings.add_argument("eligibility_root", type=Path)
    review_bindings.add_argument("registry", type=Path)
    review_bindings.add_argument("output", type=Path)
    _add_curation_runtime_options(review_bindings)


def _add_curation_repair(stages: Any) -> None:
    group = stages.add_parser("repair", help="resolve nonterminal contracts and evidence only when required")
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")

    prepare_subagent_repairs = _leaf(
        actions,
        "prepare",
        _run_prepare_subagent_contract_repairs,
        "freeze source-only repair packets for nonterminal reviewed contracts",
    )
    prepare_subagent_repairs.add_argument("base_bundle", type=Path)
    prepare_subagent_repairs.add_argument("proposals_root", type=Path)
    prepare_subagent_repairs.add_argument("reviews_root", type=Path)
    prepare_subagent_repairs.add_argument("output", type=Path)
    prepare_subagent_repairs.add_argument("--repository-root", type=Path, default=Path.cwd())
    prepare_subagent_repairs.add_argument("--producer-commit", required=True)
    prepare_subagent_repairs.add_argument("--source-use-bundle", type=Path)
    prepare_subagent_repairs.add_argument("--reservation-bundle", type=Path)

    finalize_subagent_repairs = _leaf(
        actions,
        "finalize",
        _run_finalize_subagent_contract_repairs,
        "freeze repaired proposals after validating every subagent repair packet",
    )
    finalize_subagent_repairs.add_argument("base_bundle", type=Path)
    finalize_subagent_repairs.add_argument("proposals_root", type=Path)
    finalize_subagent_repairs.add_argument("reviews_root", type=Path)
    finalize_subagent_repairs.add_argument("packets_root", type=Path)
    finalize_subagent_repairs.add_argument("decisions_root", type=Path)
    finalize_subagent_repairs.add_argument("output", type=Path)
    finalize_subagent_repairs.add_argument("--producer-commit", required=True)
    finalize_subagent_repairs.add_argument("--source-use-bundle", type=Path)
    finalize_subagent_repairs.add_argument("--reservation-bundle", type=Path)

    semantic_repairs = _leaf(
        actions,
        "semantic",
        _run_contract_semantic_repairs,
        "repair faulty or evidence-escalated contracts one task per request",
    )
    semantic_repairs.add_argument("base_bundle", type=Path)
    semantic_repairs.add_argument("evidence_root", type=Path)
    semantic_repairs.add_argument("output", type=Path)
    semantic_repairs.add_argument("--repository-root", type=Path, default=Path.cwd())
    semantic_repairs.add_argument("--producer-commit", required=True)
    semantic_repairs.add_argument("--max-new-batches", type=int)
    semantic_repairs.add_argument("--workers", type=int, default=1)

    repair_evidence = _leaf(
        actions,
        "evidence",
        _run_contract_repair_evidence,
        "bind exact source evidence to immutable repaired contracts",
    )
    repair_evidence.add_argument("base_bundle", type=Path)
    repair_evidence.add_argument("repairs_root", type=Path)
    repair_evidence.add_argument("output", type=Path)
    repair_evidence.add_argument("--repository-root", type=Path, default=Path.cwd())
    repair_evidence.add_argument("--producer-commit", required=True)
    repair_evidence.add_argument("--max-new-batches", type=int)
    repair_evidence.add_argument("--workers", type=int, default=1)

    adjudicate_repair_evidence = _leaf(
        actions,
        "adjudicate-evidence",
        _run_adjudicate_contract_repair_evidence,
        "close empty evidence and independently recheck non-empty disputes",
    )
    adjudicate_repair_evidence.add_argument("base_bundle", type=Path)
    adjudicate_repair_evidence.add_argument("repairs_root", type=Path)
    adjudicate_repair_evidence.add_argument("prior_evidence_root", type=Path)
    adjudicate_repair_evidence.add_argument("output", type=Path)
    adjudicate_repair_evidence.add_argument("--repository-root", type=Path, default=Path.cwd())
    adjudicate_repair_evidence.add_argument("--producer-commit", required=True)
    adjudicate_repair_evidence.add_argument("--max-new-batches", type=int)
    adjudicate_repair_evidence.add_argument("--workers", type=int, default=1)

    correct_repair_evidence = _leaf(
        actions,
        "correct-evidence",
        _run_correct_unbound_contract_evidence,
        "correct and rebind only independently rejected non-empty contracts",
    )
    correct_repair_evidence.add_argument("base_bundle", type=Path)
    correct_repair_evidence.add_argument("repairs_root", type=Path)
    correct_repair_evidence.add_argument("prior_evidence_root", type=Path)
    correct_repair_evidence.add_argument("output", type=Path)
    correct_repair_evidence.add_argument("--repository-root", type=Path, default=Path.cwd())
    correct_repair_evidence.add_argument("--producer-commit", required=True)
    correct_repair_evidence.add_argument("--max-new-batches", type=int)
    correct_repair_evidence.add_argument("--workers", type=int, default=1)

    review_evidence = _leaf(
        actions,
        "materialize-evidence",
        _run_materialize_contract_review_evidence,
        "supply exact whole-prompt spans for unresolved independent review",
    )
    review_evidence.add_argument("base_bundle", type=Path)
    review_evidence.add_argument("repairs_root", type=Path)
    review_evidence.add_argument("prior_evidence_root", type=Path)
    review_evidence.add_argument("output", type=Path)
    review_evidence.add_argument("--producer-commit", required=True)

    repair = _leaf(
        actions,
        "contracts",
        _run_repair_contracts,
        "freeze a corrected contract bundle without response-format requirements",
    )
    repair.add_argument("contracts_root", type=Path)
    repair.add_argument("output", type=Path)

    contract_adjudications = _leaf(
        actions,
        "contract-adjudications",
        _run_contract_adjudications,
        "apply bounded outcome-blind contract and review corrections",
    )
    contract_adjudications.add_argument("contracts_root", type=Path)
    contract_adjudications.add_argument("reviews_root", type=Path)
    contract_adjudications.add_argument("adjudications", type=Path)
    contract_adjudications.add_argument("output", type=Path)

    binding_adjudications = _leaf(
        actions,
        "binding-adjudications",
        _run_binding_adjudications,
        "apply bounded outcome-blind corrections to unresolved mechanism bindings",
    )
    binding_adjudications.add_argument("prepared_root", type=Path)
    binding_adjudications.add_argument("clusters_root", type=Path)
    binding_adjudications.add_argument("bindings_root", type=Path)
    binding_adjudications.add_argument("registry", type=Path)
    binding_adjudications.add_argument("adjudications", type=Path)
    binding_adjudications.add_argument("output", type=Path)


def _add_curation_finalize(stages: Any) -> None:
    group = stages.add_parser("finalize", help="assemble and verify the frozen reviewer data")
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")

    source_use = _leaf(actions, "source-use", _run_verify_source_use,
                       "independently verify source uses, input restoration and role boundaries")
    source_use.add_argument("source_bundle", type=Path)
    source_use.add_argument("reservation_bundle", type=Path)
    source_use.add_argument("catalog", type=Path)
    source_use.add_argument("registry", type=Path)
    source_use.add_argument("output", type=Path)
    source_use.add_argument("--source-root", action="append", default=[], metavar="DATASET=PATH")
    source_use.add_argument("--source-archive", action="append", default=[], metavar="DATASET=PATH")

    assemble_proposals = _leaf(
        actions,
        "proposals",
        _run_assemble_contract_content,
        "combine closed evidence and semantic repairs into reviewed proposals",
    )
    assemble_proposals.add_argument("base_bundle", type=Path)
    assemble_proposals.add_argument("evidence_root", type=Path)
    assemble_proposals.add_argument("repairs_root", type=Path)
    assemble_proposals.add_argument("repair_evidence_root", type=Path)
    assemble_proposals.add_argument("output", type=Path)
    assemble_proposals.add_argument("--producer-commit", required=True)

    finalize_content = _leaf(
        actions,
        "task-units",
        _run_finalize_contract_content,
        "assemble or verify the terminal content-cleaned reviewer data set",
    )
    finalize_content.add_argument("phase", choices=("build", "verify"))
    finalize_content.add_argument("output", type=Path)
    finalize_content.add_argument("--base-bundle", type=Path)
    finalize_content.add_argument("--proposals-root", type=Path)
    finalize_content.add_argument("--reviews-root", type=Path)
    finalize_content.add_argument("--reservation-root", type=Path)
    finalize_content.add_argument("--producer-commit")


def _add_representation_group(groups: Any) -> None:
    group = groups.add_parser(
        "representation",
        help="freeze task roles and extract evidence-bound Prompt TSG representations",
        description=("Freeze task roles and extract evidence-bound Prompt TSG representations."),
    )
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")

    population = _leaf(
        actions,
        "freeze-population",
        _run_freeze_population,
        "freeze a natural-Prompt task-unit census without outcomes",
    )
    population.add_argument("prepared_root", type=Path)
    population.add_argument("clusters_root", type=Path)
    population.add_argument("catalog", type=Path)
    population.add_argument("output", type=Path)
    population.add_argument(
        "--scope",
        action="append",
        required=True,
        metavar="CWE=TASK_FAMILY",
        help="repeat for each preregistered local discovery scope",
    )
    population.add_argument("--language", default="python")

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

    bindings = _leaf(
        actions,
        "freeze-bindings",
        _run_freeze_bindings,
        "freeze Prompt-TSG task-to-mechanism and local-Oracle bindings",
    )
    bindings.add_argument("tasks", type=Path)
    bindings.add_argument("contracts_root", type=Path)
    bindings.add_argument("catalog", type=Path)
    bindings.add_argument("registry", type=Path)
    bindings.add_argument("output", type=Path)
    bindings.add_argument("--prompt-tsg-bundle", type=Path, action="append", required=True)

    partition = _leaf(
        actions,
        "freeze-partition",
        _run_freeze_partition,
        "freeze an outcome-blind discovery/pilot/confirmation task-unit partition",
    )
    partition.add_argument("tasks", type=Path)
    partition.add_argument("clusters_root", type=Path)
    partition.add_argument("catalog", type=Path)
    partition.add_argument("output", type=Path)
    partition.add_argument("--prompt-tsg-bundle", type=Path, action="append", required=True)
    partition.add_argument("--seed", type=int, default=2026083001)


def _add_qualification_group(groups: Any) -> None:
    group = groups.add_parser(
        "qualification",
        help="run Oracle, representation, support, and design qualification gates",
        description=(
            "Run Oracle, representation, support, and design qualification gates."
        ),
    )
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")

    security = _leaf(
        actions,
        "security-oracle",
        _run_security_oracle,
        "replay the frozen gold boundary for active local security profiles",
    )
    security.add_argument("registry", type=Path)
    security.add_argument("cases", type=Path)
    security.add_argument("output", type=Path)
    security.add_argument("--repository-root", type=Path, default=Path.cwd())

    target_security = _leaf(
        actions,
        "target-security-oracle",
        _run_target_security_oracle,
        "qualify the target-v3 local Security Oracle catalog without mutating legacy producers",
    )
    target_security.add_argument("registry", type=Path)
    target_security.add_argument("output", type=Path)
    target_security.add_argument("--cases", type=Path, action="append", required=True)
    target_security.add_argument(
        "--profile", action="append",
        help="qualify only this registered local profile; repeat for the declared research scope",
    )
    target_security.add_argument("--repository-root", type=Path, default=Path.cwd())

    prompt_tsg = _leaf(
        actions,
        "prompt-tsg",
        _run_prompt_tsg_qualification,
        "compare one extractor bundle with a prospective task-context holdout",
    )
    prompt_tsg.add_argument("tasks", type=Path)
    prompt_tsg.add_argument("graph_bundle", type=Path)
    prompt_tsg.add_argument("catalog", type=Path)
    prompt_tsg.add_argument("registry", type=Path)
    prompt_tsg.add_argument("gold", type=Path)
    prompt_tsg.add_argument("output", type=Path)
    prompt_tsg.add_argument("--repository-root", type=Path, default=Path.cwd())
    prompt_tsg.add_argument("--path-authority-annotations", type=Path)

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
    prompt_contract.add_argument("--repository-root", type=Path, default=Path.cwd())
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
    positivity.add_argument("--scope-bindings", type=Path,
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
    positivity.add_argument("--minimum-state-task-units", type=int,
                            help="archival closed-catalog replay only")
    positivity.add_argument("--minimum-shared-lineages", type=int,
                            help="archival closed-catalog replay only")

    dataset = _leaf(
        actions,
        "dataset",
        _run_dataset_eligibility,
        "audit curated clusters for current experiment readiness",
    )
    dataset.add_argument("prepared_root", type=Path)
    dataset.add_argument("clusters_root", type=Path)
    dataset.add_argument("contracts_root", type=Path)
    dataset.add_argument("output", type=Path)
    dataset.add_argument("--repository-root", type=Path, default=Path.cwd())
    dataset.add_argument("--policy", type=Path)
    dataset.add_argument(
        "--bindings-root",
        type=Path,
        help="optional outcome-blind task-to-mechanism binding bundle",
    )
    dataset.add_argument(
        "--contract-reviews-root",
        type=Path,
        help="optional complete blind functional-contract review bundle",
    )
    dataset.add_argument("--development-exclusions", type=Path)
    dataset.add_argument("--case-audit", type=Path)
    dataset.add_argument("--quality-adjudication", type=Path)
    dataset.add_argument("--extension-policy", type=Path)
    dataset.add_argument(
        "--backend-root",
        type=Path,
        help="optional BaxBench-compatible source snapshot for backend data inventory",
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


def _add_curation_runtime_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--max-new-batches", type=int)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--reuse-root", type=Path)


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
        from prompt_mechanism_study.verification import (
            load_and_verify_target_result_bundle,
        )

        report = load_and_verify_target_result_bundle(args.output)
    return _emit_json(report)


def _run_data_prepare(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.datasets import prepare_datasets

    report = prepare_datasets(
        args.output,
        sallm_root=args.sallm_root,
        cweval_root=args.cweval_root,
        cyberseceval_path=args.cyberseceval_path,
        llmseceval_root=args.llmseceval_root,
        securityeval_root=args.securityeval_root,
        codeseceval_root=args.codeseceval_root,
        secodeplt_root=args.secodeplt_root,
        limit_per_source=args.limit_per_source,
    )
    return _emit_status(report)


def _run_freeze_contracts(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.datasets import freeze_contracts

    return _emit_status(freeze_contracts(args.prepared_root, args.responses, args.output))


def _run_dedup_candidates(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.datasets import prepare_dedup_candidates

    report = prepare_dedup_candidates(
        args.prepared_root,
        args.output,
        minimum_jaccard=args.minimum_jaccard,
        max_neighbors_per_record=args.max_neighbors_per_record,
    )
    return _emit_status(report)


def _run_task_unit_bundle(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.task_unit_data import (
        compile_task_unit_data,
        verify_task_unit_data,
    )

    if args.phase == "verify":
        report = verify_task_unit_data(args.output)
    else:
        required = (
            "prepared_root",
            "clusters_root",
            "candidate_root",
            "contracts_root",
            "contract_reviews_root",
            "legacy_roles_root",
            "development_exclusions",
        )
        missing = tuple(name for name in required if getattr(args, name) is None)
        if missing:
            parser.error(
                "data task-unit-bundle build requires "
                + ", ".join("--" + name.replace("_", "-") for name in missing)
            )
        report = compile_task_unit_data(
            prepared_root=args.prepared_root,
            clusters_root=args.clusters_root,
            candidate_root=args.candidate_root,
            contracts_root=args.contracts_root,
            contract_reviews_root=args.contract_reviews_root,
            legacy_roles_root=args.legacy_roles_root,
            development_exclusions_path=args.development_exclusions,
            output=args.output,
        )
    return _emit_json(report)


def _run_semantic_curation(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.curation import run_semantic_curation

    report = run_semantic_curation(
        args.repository_root,
        args.prepared_root,
        args.candidates_root,
        args.output,
        max_new_batches=args.max_new_batches,
        workers=args.workers,
        reuse_root=args.reuse_root,
    )
    return _emit_status(report)


def _run_assemble_clusters(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.curation import assemble_semantic_clusters

    report = assemble_semantic_clusters(
        args.prepared_root,
        args.candidates_root,
        args.adjudication_root,
        args.output,
    )
    return _emit_status(report)


def _run_contract_curation(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.curation import run_contract_curation

    report = run_contract_curation(
        args.repository_root,
        args.prepared_root,
        args.clusters_root,
        args.output,
        max_new_batches=args.max_new_batches,
        workers=args.workers,
        reuse_root=args.reuse_root,
        existing_contracts_root=args.existing_contracts_root,
    )
    return _emit_status(report)


def _run_contract_review(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.curation import run_contract_quality_review

    report = run_contract_quality_review(
        args.repository_root,
        args.prepared_root,
        args.contracts_root,
        args.output,
        max_new_batches=args.max_new_batches,
        workers=args.workers,
        reuse_root=args.reuse_root,
    )
    return _emit_status(report)


def _run_contract_content_proposals(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.contract_cleaning import run_contract_content_proposals

    report = run_contract_content_proposals(
        args.repository_root,
        args.base_bundle,
        args.output,
        producer_commit=args.producer_commit,
        max_new_batches=args.max_new_batches,
        workers=args.workers,
        stop_after_evidence=args.stop_after_evidence,
    )
    return _emit_status(report)


def _run_reserve_future_evaluation(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.contract_cleaning import (
        freeze_future_evaluation_reservation,
    )

    return _emit_status(
        freeze_future_evaluation_reservation(
            args.base_bundle,
            args.output,
            producer_commit=args.producer_commit,
        )
    )


def _run_prepare_restored_contracts(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.contract_cleaning import prepare_restored_contract_proposals

    return _emit_status(prepare_restored_contract_proposals(
        args.base_bundle, args.source_use_bundle, args.reservation_bundle,
        args.source_root, args.output, producer_commit=args.producer_commit,
    ))


def _run_prepare_subagent_contract_review(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.subagent_review import prepare_subagent_contract_reviews

    return _emit_status(
        prepare_subagent_contract_reviews(
            args.repository_root,
            args.base_bundle,
            args.proposals_root,
            args.output,
            producer_commit=args.producer_commit,
            nonterminal_reviews_root=args.nonterminal_reviews_root,
            source_use_bundle=args.source_use_bundle,
            reservation_bundle=args.reservation_bundle,
        )
    )


def _run_verify_contract_review_round(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.verification.qualification import verify_contract_review_round

    return _emit_json(verify_contract_review_round(
        args.proposals_root, args.packets_root, args.decisions_root, args.initial_root,
        args.adjudication_decisions_root, args.reviews_root,
    ))


def _run_seal_initial_subagent_contract_review(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.subagent_review import seal_initial_subagent_contract_reviews

    return _emit_status(
        seal_initial_subagent_contract_reviews(
            args.packets_root,
            args.decisions_root,
            args.output,
        )
    )


def _run_finalize_subagent_contract_review(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.subagent_review import finalize_subagent_contract_reviews

    return _emit_status(
        finalize_subagent_contract_reviews(
            args.initial_root,
            args.adjudication_decisions_root,
            args.proposals_root,
            args.output,
        )
    )


def _run_prepare_subagent_contract_repairs(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.subagent_review import prepare_subagent_contract_repairs

    return _emit_status(
        prepare_subagent_contract_repairs(
            args.repository_root,
            args.base_bundle,
            args.proposals_root,
            args.reviews_root,
            args.output,
            producer_commit=args.producer_commit,
            source_use_bundle=args.source_use_bundle,
            reservation_bundle=args.reservation_bundle,
        )
    )


def _run_finalize_subagent_contract_repairs(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.subagent_review import finalize_subagent_contract_repairs

    return _emit_status(
        finalize_subagent_contract_repairs(
            args.base_bundle,
            args.proposals_root,
            args.reviews_root,
            args.packets_root,
            args.decisions_root,
            args.output,
            producer_commit=args.producer_commit,
            source_use_bundle=args.source_use_bundle,
            reservation_bundle=args.reservation_bundle,
        )
    )


def _run_merge_subagent_contract_reviews(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.subagent_review import merge_subagent_contract_reviews

    return _emit_status(
        merge_subagent_contract_reviews(
            args.prior_reviews_root,
            args.revised_reviews_root,
            args.proposals_root,
            args.output,
        )
    )


def _run_contract_semantic_repairs(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.contract_cleaning import run_single_task_semantic_repairs

    return _emit_status(
        run_single_task_semantic_repairs(
            args.repository_root,
            args.base_bundle,
            args.evidence_root,
            args.output,
            producer_commit=args.producer_commit,
            max_new_batches=args.max_new_batches,
            workers=args.workers,
        )
    )


def _run_contract_repair_evidence(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.contract_cleaning import run_repaired_contract_evidence

    return _emit_status(
        run_repaired_contract_evidence(
            args.repository_root,
            args.base_bundle,
            args.repairs_root,
            args.output,
            producer_commit=args.producer_commit,
            max_new_batches=args.max_new_batches,
            workers=args.workers,
        )
    )


def _run_adjudicate_contract_repair_evidence(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.contract_cleaning import (
        adjudicate_unbound_repaired_contract_evidence,
    )

    return _emit_status(
        adjudicate_unbound_repaired_contract_evidence(
            args.repository_root,
            args.base_bundle,
            args.repairs_root,
            args.prior_evidence_root,
            args.output,
            producer_commit=args.producer_commit,
            max_new_batches=args.max_new_batches,
            workers=args.workers,
        )
    )


def _run_correct_unbound_contract_evidence(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.contract_cleaning import (
        correct_unbound_contract_evidence,
    )

    return _emit_status(
        correct_unbound_contract_evidence(
            args.repository_root,
            args.base_bundle,
            args.repairs_root,
            args.prior_evidence_root,
            args.output,
            producer_commit=args.producer_commit,
            max_new_batches=args.max_new_batches,
            workers=args.workers,
        )
    )


def _run_materialize_contract_review_evidence(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.contract_cleaning import (
        materialize_full_prompt_evidence_for_review,
    )

    return _emit_status(
        materialize_full_prompt_evidence_for_review(
            args.base_bundle,
            args.repairs_root,
            args.prior_evidence_root,
            args.output,
            producer_commit=args.producer_commit,
        )
    )


def _run_assemble_contract_content(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.contract_cleaning import (
        assemble_contract_content_proposals,
    )

    return _emit_status(
        assemble_contract_content_proposals(
            args.base_bundle,
            args.evidence_root,
            args.repairs_root,
            args.repair_evidence_root,
            args.output,
            producer_commit=args.producer_commit,
        )
    )


def _run_finalize_contract_content(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.contract_cleaning import (
        finalize_contract_content_data,
        verify_contract_content_data,
    )

    if args.phase == "verify":
        report = verify_contract_content_data(args.output)
    else:
        required = (
            "base_bundle",
            "proposals_root",
            "reviews_root",
            "reservation_root",
            "producer_commit",
        )
        missing = [name for name in required if getattr(args, name) is None]
        if missing:
            parser.error(
                "curate finalize-contract-content build requires "
                + ", ".join("--" + name.replace("_", "-") for name in missing)
            )
        report = finalize_contract_content_data(
            args.base_bundle,
            args.proposals_root,
            args.reviews_root,
            args.reservation_root,
            args.output,
            producer_commit=args.producer_commit,
        )
    return _emit_status(report)


def _run_binding_review(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.curation import run_mechanism_binding_review

    report = run_mechanism_binding_review(
        args.repository_root,
        args.prepared_root,
        args.clusters_root,
        args.contracts_root,
        args.eligibility_root,
        args.registry,
        args.output,
        max_new_batches=args.max_new_batches,
        workers=args.workers,
        reuse_root=args.reuse_root,
    )
    return _emit_status(report)


def _run_repair_contracts(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.curation import repair_response_format_contract_leaks

    return _emit_status(
        repair_response_format_contract_leaks(args.contracts_root, args.output)
    )


def _run_contract_adjudications(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.curation import apply_contract_recovery_adjudications

    report = apply_contract_recovery_adjudications(
        args.contracts_root,
        args.reviews_root,
        args.adjudications,
        args.output,
    )
    return _emit_status(report)


def _run_binding_adjudications(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.eligibility import apply_binding_adjudications

    report = apply_binding_adjudications(
        args.prepared_root,
        args.clusters_root,
        args.bindings_root,
        args.registry,
        args.adjudications,
        args.output,
    )
    return _emit_status(report)


def _run_freeze_population(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.discovery_population import prepare_discovery_population

    scopes: dict[str, str] = {}
    for item in args.scope:
        try:
            cwe, task_family = item.split("=", 1)
        except ValueError:
            parser.error("discovery scopes must use CWE=TASK_FAMILY")
        if not cwe.strip() or not task_family.strip() or cwe in scopes:
            parser.error("discovery scopes must be unique non-empty CWE=TASK_FAMILY values")
        scopes[cwe] = task_family
    report = prepare_discovery_population(
        args.prepared_root,
        args.clusters_root,
        args.catalog,
        args.output,
        scopes=scopes,
        language=args.language,
    )
    return _emit_status(report)


def _run_select_tsg_tasks(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.eligibility import freeze_prompt_tsg_task_selection

    return _emit_status(
        freeze_prompt_tsg_task_selection(args.tasks, tuple(args.exclude), args.output)
    )


def _run_select_tsg_holdout(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.eligibility import freeze_prompt_tsg_holdout_selection

    report = freeze_prompt_tsg_holdout_selection(
        args.tasks,
        tuple(args.exclude),
        args.output,
        cwes=tuple(sorted(set(args.cwe))),
        task_units_per_cwe=args.task_units_per_cwe,
        ranking_salt=args.ranking_salt,
    )
    return _emit_status(report)


def _source_use_locations(args: argparse.Namespace, parser: argparse.ArgumentParser):
    roots = {}
    for item in args.source_root:
        name, separator, path = item.partition("=")
        if not separator or not name or not path or name in roots:
            parser.error("source roots must be unique DATASET=PATH values")
        roots[name] = Path(path)
    archives = {}
    for item in args.source_archive:
        name, separator, path = item.partition("=")
        if not separator or not name or not path or name in archives:
            parser.error("source archives must be unique DATASET=PATH values")
        archives[name] = Path(path)
    return roots, archives


def _run_prepare_candidate_pool(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.qualification_data import screen_prepared_source_pool
    return _emit_status(screen_prepared_source_pool(
        args.source_bundle, args.output, qualification_manifest=args.qualification_manifest,
    ))


def _run_prepare_source_use(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.qualification_data import prepare_source_use

    roots, archives = _source_use_locations(args, parser)
    return _emit_json(prepare_source_use(
        args.source_bundle, args.reservation_bundle, args.catalog, args.registry,
        args.output, source_roots=roots, source_archives=archives,
        candidate_reviews=args.candidate_reviews,
        contract_review_rounds=args.contract_review_round,
        native_asset_reviews=args.native_asset_reviews,
        candidate_context_reviews=args.candidate_context_reviews,
    ))


def _run_verify_source_use(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.verification.qualification import verify_source_use

    roots, archives = _source_use_locations(args, parser)
    return _emit_json(verify_source_use(
        args.output, args.source_bundle, args.reservation_bundle, args.catalog, args.registry,
        source_roots=roots or None, source_archives=archives or None,
    ))


def _run_prepare_qualification_review(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.qualification_data import (
        prepare_qualification_source_review,
    )

    report = prepare_qualification_source_review(
        args.source_bundle,
        args.catalog,
        args.registry,
        args.output,
        producer_commit=args.producer_commit,
        ranking_salt=args.ranking_salt,
        qual_dev_count=args.qual_dev_count,
        qual_accept_count=args.qual_accept_count,
    )
    return _emit_status(report)


def _run_visualize_tsg(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.tsg_visualization import build_tsg_viewer
    return _emit_status(build_tsg_viewer(args.tasks, (args.extraction, *args.additional_extraction),
                                       args.output, results_root=args.results, catalog_path=args.catalog,
                                       review_root=args.review))


def _run_extract_contracts(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.prompt_contract_extract import extract_contract_task_file

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
    from prompt_mechanism_study.candidate_construction import prepare_candidate_request

    return _emit_json(prepare_candidate_request(
        args.tasks, args.extraction, args.output, input_catalog_path=args.input_catalog,
    ))


def _run_build_candidates(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.candidate_construction import build_candidate_catalog

    return _emit_json(build_candidate_catalog(
        args.request, args.design, args.output,
        response_path=args.response, evaluator_path=args.evaluator, review_path=args.review,
    ))


def _run_bind_candidates(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.candidate_construction import bind_candidate_scopes

    return _emit_json(
        bind_candidate_scopes(
            args.candidates,
            args.tasks,
            args.prompt_tsg_bundle,
            args.output,
            qualification_bundle=args.qualification_bundle,
        )
    )


def _run_freeze_bindings(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.eligibility import freeze_tsg_realization_bindings

    report = freeze_tsg_realization_bindings(
        args.tasks,
        tuple(args.prompt_tsg_bundle),
        args.contracts_root,
        args.catalog,
        args.registry,
        args.output,
    )
    return _emit_status(report)


def _run_freeze_partition(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.discovery_population import freeze_task_unit_partition

    report = freeze_task_unit_partition(
        args.tasks,
        tuple(args.prompt_tsg_bundle),
        args.clusters_root,
        args.catalog,
        args.output,
        seed=args.seed,
    )
    return _emit_status(report)


def _run_security_oracle(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.eligibility import qualify_local_security_profiles

    report = qualify_local_security_profiles(
        args.repository_root,
        args.registry,
        args.cases,
        args.output,
    )
    return _emit_gate_status(report, "QUALIFIED_FOR_EXPERIMENT")


def _run_target_security_oracle(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.eligibility import qualify_target_security_profiles

    report = qualify_target_security_profiles(
        args.repository_root,
        args.registry,
        tuple(args.cases),
        args.output,
        profile_ids=None if args.profile is None else tuple(args.profile),
    )
    return _emit_gate_status(report, "QUALIFIED_FOR_TARGET_MEASUREMENT_PROFILE")


def _run_prompt_tsg_qualification(
    args: argparse.Namespace,
    _: argparse.ArgumentParser,
) -> int:
    from prompt_mechanism_study.eligibility import qualify_prompt_tsg_extractor

    report = qualify_prompt_tsg_extractor(
        args.repository_root,
        args.tasks,
        args.graph_bundle,
        args.catalog,
        args.registry,
        args.gold,
        args.output,
        path_authority_annotations_path=args.path_authority_annotations,
    )
    return _emit_gate_status(report, "QUALIFIED_FOR_FORMAL_EXTRACTION")


def _run_prompt_contract_qualification(
    args: argparse.Namespace,
    _: argparse.ArgumentParser,
) -> int:
    from prompt_mechanism_study.prompt_contract_qualification import (
        qualify_prompt_contract_extractor,
    )

    report = qualify_prompt_contract_extractor(
        args.repository_root,
        args.tasks,
        args.extraction_bundle,
        args.catalog,
        None,
        args.gold,
        args.evaluator,
        args.annotator_prompt,
        args.output,
        assertion_review_path=args.assertion_review,
    )
    return _emit_gate_status(report, "QUALIFIED_FOR_FORMAL_EXTRACTION")


def _run_functional_judge(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study import functional_judge

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
    from prompt_mechanism_study.discovery_population import audit_discovery_positivity

    report = audit_discovery_positivity(
        args.tasks,
        tuple(args.prompt_tsg_bundle),
        args.catalog,
        args.output,
        minimum_state_task_units=args.minimum_state_task_units,
        minimum_shared_lineages=args.minimum_shared_lineages,
        graph_artifact=args.graph_artifact,
        scope_bindings_path=args.scope_bindings,
    )
    if report["status"] == "SCOPED_SOURCE_SUPPORT_CHECK_COMPLETE":
        return _emit_json(report)
    return _emit_gate_status(report, "POSITIVITY_GATE_PASSED")


def _run_dataset_eligibility(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.eligibility import audit_dataset_eligibility

    report = audit_dataset_eligibility(
        args.repository_root,
        args.prepared_root,
        args.clusters_root,
        args.contracts_root,
        args.output,
        policy_path=args.policy,
        bindings_root=args.bindings_root,
        contract_reviews_root=args.contract_reviews_root,
        development_exclusions_path=args.development_exclusions,
        case_audit_path=args.case_audit,
        quality_adjudication_path=args.quality_adjudication,
        extension_policy_path=args.extension_policy,
        backend_root=args.backend_root,
    )
    return _emit_status(report)


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
