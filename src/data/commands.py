"""Thin ingestion and read-only verification commands for prepared study inputs.

Automated source-contract production and review campaigns are outside the current
prototype. Supplied judgments are inputs, never reconstructed from study outcomes.
"""
from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

CliHandler = Callable[[argparse.Namespace, argparse.ArgumentParser], int]


def add_source_commands(groups: Any) -> None:
    group = groups.add_parser("data", help="ingest sources or verify fixed task inputs")
    actions = group.add_subparsers(dest="action", required=True, metavar="ACTION")
    prepare = _leaf(actions, "prepare", _run_data_prepare, "normalize source tasks without executing code")
    prepare.add_argument("output", type=Path)
    for option in ("sallm-root", "cweval-root", "cyberseceval-path", "llmseceval-root",
                   "securityeval-root", "codeseceval-root", "secodeplt-root"):
        prepare.add_argument("--" + option, type=Path)
    prepare.add_argument("--limit-per-source", type=int)
    contracts = _leaf(actions, "freeze-contracts", _run_freeze_contracts, "import supplied source-backed contracts")
    for name in ("prepared_root", "responses", "output"):
        contracts.add_argument(name, type=Path)
    dedup = _leaf(actions, "dedup-candidates", _run_dedup_candidates, "prepare outcome-blind duplicate candidates")
    dedup.add_argument("prepared_root", type=Path)
    dedup.add_argument("output", type=Path)
    dedup.add_argument("--minimum-jaccard", type=float, default=0.35)
    dedup.add_argument("--max-neighbors-per-record", type=int, default=3)
    clusters = _leaf(actions, "clusters", _run_assemble_clusters, "assemble exact/lineage units from supplied decisions")
    for name in ("prepared_root", "candidates_root", "adjudication_root", "output"):
        clusters.add_argument(name, type=Path)
    pool = _leaf(actions, "candidate-pool", _run_prepare_candidate_pool, "screen prepared sources using frozen exposure and review evidence")
    pool.add_argument("source_bundle", type=Path)
    pool.add_argument("output", type=Path)
    pool.add_argument("--qualification-manifest", type=Path, required=True)
    verify = _leaf(actions, "verify-inputs", _run_verify_inputs, "verify the released v4/v5 task bundle without regenerating it")
    verify.add_argument("root", type=Path)
    review = _leaf(actions, "verify-source-review", _run_verify_source_review, "independently replay a supplied source-review round")
    review.add_argument("root", type=Path)


def _run_verify_inputs(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.artifact_io import read_json_exact
    from prompt_mechanism_study.data.task_unit_data import verify_task_unit_data
    from prompt_mechanism_study.data.contract_cleaning import verify_contract_content_data
    version = read_json_exact(args.root / "manifest.json").get("schema_version")
    if version == "4.0":
        report = verify_task_unit_data(args.root)
    elif version == "5.0":
        report = verify_contract_content_data(args.root)
    else:
        raise ValueError("task input verification supports the released v4/v5 schemas")
    return _emit_json(report)


def _run_verify_source_review(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.verification.qualification import verify_contract_review_round
    return _emit_json(verify_contract_review_round(args.root))


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


def _run_assemble_clusters(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.curation import assemble_semantic_clusters

    report = assemble_semantic_clusters(
        args.prepared_root,
        args.candidates_root,
        args.adjudication_root,
        args.output,
    )
    return _emit_status(report)


def _run_prepare_candidate_pool(args: argparse.Namespace, _: argparse.ArgumentParser) -> int:
    from prompt_mechanism_study.data.qualification_data import screen_prepared_source_pool
    return _emit_status(screen_prepared_source_pool(
        args.source_bundle, args.output, qualification_manifest=args.qualification_manifest,
    ))


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
