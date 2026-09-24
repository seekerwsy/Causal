"""Author-only source preparation commands, separate from the reviewer workflow."""
from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

CliHandler = Callable[[argparse.Namespace, argparse.ArgumentParser], int]


def add_source_commands(groups: Any) -> None:
    _add_data_group(groups)
    _add_curation_group(groups)


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
        "prepare complete source-bound proposals for independent review",
    )
    content_proposals.add_argument("base_bundle", type=Path)
    content_proposals.add_argument("output", type=Path)
    content_proposals.add_argument("--repository-root", type=Path, default=Path.cwd())
    content_proposals.add_argument("--producer-commit", required=True)
    content_proposals.add_argument("--max-new-batches", type=int)
    content_proposals.add_argument("--workers", type=int, default=1)

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


def _add_curation_finalize(stages: Any) -> None:
    group = stages.add_parser("finalize", help="assemble and verify the frozen reviewer data")
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")

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


def _add_curation_runtime_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--max-new-batches", type=int)
    parser.add_argument("--workers", type=int, default=1)


def _run_data_prepare(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.datasets import prepare_datasets

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
    from prompt_mechanism_study.data.datasets import freeze_contracts

    return _emit_status(freeze_contracts(args.prepared_root, args.responses, args.output))


def _run_dedup_candidates(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.datasets import prepare_dedup_candidates

    report = prepare_dedup_candidates(
        args.prepared_root,
        args.output,
        minimum_jaccard=args.minimum_jaccard,
        max_neighbors_per_record=args.max_neighbors_per_record,
    )
    return _emit_status(report)


def _run_task_unit_bundle(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.task_unit_data import (
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
    from prompt_mechanism_study.data.curation import run_semantic_curation

    report = run_semantic_curation(
        args.repository_root,
        args.prepared_root,
        args.candidates_root,
        args.output,
        max_new_batches=args.max_new_batches,
        workers=args.workers,
    )
    return _emit_status(report)


def _run_assemble_clusters(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.curation import assemble_semantic_clusters

    report = assemble_semantic_clusters(
        args.prepared_root,
        args.candidates_root,
        args.adjudication_root,
        args.output,
    )
    return _emit_status(report)


def _run_contract_curation(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.curation import run_contract_curation

    report = run_contract_curation(
        args.repository_root,
        args.prepared_root,
        args.clusters_root,
        args.output,
        max_new_batches=args.max_new_batches,
        workers=args.workers,
        existing_contracts_root=args.existing_contracts_root,
    )
    return _emit_status(report)


def _run_contract_review(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.curation import run_contract_quality_review

    report = run_contract_quality_review(
        args.repository_root,
        args.prepared_root,
        args.contracts_root,
        args.output,
        max_new_batches=args.max_new_batches,
        workers=args.workers,
    )
    return _emit_status(report)


def _run_contract_content_proposals(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.data.contract_cleaning import run_contract_content_proposals

    report = run_contract_content_proposals(
        args.repository_root,
        args.base_bundle,
        args.output,
        producer_commit=args.producer_commit,
        max_new_batches=args.max_new_batches,
        workers=args.workers,
    )
    return _emit_status(report)


def _run_reserve_future_evaluation(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.data.contract_cleaning import freeze_future_evaluation_reservation

    return _emit_status(
        freeze_future_evaluation_reservation(
            args.base_bundle,
            args.output,
            producer_commit=args.producer_commit,
        )
    )


def _run_prepare_restored_contracts(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.contract_cleaning import prepare_restored_contract_proposals

    return _emit_status(prepare_restored_contract_proposals(
        args.base_bundle, args.source_use_bundle, args.reservation_bundle,
        args.source_root, args.output, producer_commit=args.producer_commit,
    ))


def _run_prepare_subagent_contract_review(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.data.source_review import prepare_subagent_contract_reviews

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
    from prompt_mechanism_study.data.source_review import seal_initial_subagent_contract_reviews

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
    from prompt_mechanism_study.data.source_review import finalize_subagent_contract_reviews

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
    from prompt_mechanism_study.data.source_review import prepare_subagent_contract_repairs

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
    from prompt_mechanism_study.data.source_review import finalize_subagent_contract_repairs

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
    from prompt_mechanism_study.data.source_review import merge_subagent_contract_reviews

    return _emit_status(
        merge_subagent_contract_reviews(
            args.prior_reviews_root,
            args.revised_reviews_root,
            args.proposals_root,
            args.output,
        )
    )


def _run_finalize_contract_content(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.data.contract_cleaning import (
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
                "curate finalize task-units build requires "
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


def _run_prepare_candidate_pool(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.qualification_data import screen_prepared_source_pool
    return _emit_status(screen_prepared_source_pool(
        args.source_bundle, args.output, qualification_manifest=args.qualification_manifest,
    ))


def _run_prepare_qualification_review(
    args: argparse.Namespace, _: argparse.ArgumentParser
) -> int:
    from prompt_mechanism_study.data.qualification_data import prepare_qualification_source_review

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


def _leaf(actions: Any, name: str, handler: CliHandler, help_text: str) -> argparse.ArgumentParser:
    parser = actions.add_parser(name, help=help_text)
    parser.set_defaults(handler=handler)
    return parser


def _emit_status(report: dict[str, Any]) -> int:
    print(report["status"])
    return 0


def _emit_json(report: dict[str, Any]) -> int:
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0
