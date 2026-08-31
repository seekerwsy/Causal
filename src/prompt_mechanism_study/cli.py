"""Single entry point for the prospective research-artifact stages."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from prompt_mechanism_study import functional_judge
from prompt_mechanism_study.artifact_io import verify_bundle


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="prompt-mechanism-study")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    verify = commands.add_parser("verify", help="verify an exact artifact bundle")
    verify.add_argument("root", type=Path)

    target_study = commands.add_parser(
        "target-study",
        help=(
            "zero-network reviewer smoke or read-only verification for schema 3.0; "
            "formal provider execution remains disabled until scientific inputs are frozen"
        ),
    )
    target_study.add_argument("phase", choices=("smoke", "verify-result"))
    target_study.add_argument("output", type=Path)

    judge = commands.add_parser("judge-gate", help="run the bounded Functional Judge gate")
    judge.add_argument("phase", choices=("preflight", "pilot", "remaining", "finalize"))
    judge.add_argument("output", type=Path)
    judge.add_argument("--repository-root", type=Path, default=Path.cwd())
    judge.add_argument("--gate-config", type=Path)
    judge.add_argument("--pilot-root", type=Path)
    judge.add_argument("--remaining-root", type=Path)

    discovery_population = commands.add_parser(
        "discovery-population",
        help="freeze a natural-Prompt task-unit census without outcomes",
    )
    discovery_population.add_argument("prepared_root", type=Path)
    discovery_population.add_argument("clusters_root", type=Path)
    discovery_population.add_argument("catalog", type=Path)
    discovery_population.add_argument("output", type=Path)
    discovery_population.add_argument(
        "--scope",
        action="append",
        required=True,
        metavar="CWE=TASK_FAMILY",
        help="repeat for each preregistered local discovery scope",
    )
    discovery_population.add_argument("--language", default="python")

    task_partition = commands.add_parser(
        "task-partition",
        help="freeze an outcome-blind discovery/pilot/confirmation task-unit partition",
    )
    task_partition.add_argument("tasks", type=Path)
    task_partition.add_argument("clusters_root", type=Path)
    task_partition.add_argument("catalog", type=Path)
    task_partition.add_argument("output", type=Path)
    task_partition.add_argument(
        "--prompt-tsg-bundle", type=Path, action="append", required=True
    )
    task_partition.add_argument("--seed", type=int, default=2026083001)

    task_unit_data = commands.add_parser(
        "task-unit-data",
        help="build or verify the reviewer-facing task-unit data bundle",
    )
    task_unit_data.add_argument("phase", choices=("build", "verify"))
    task_unit_data.add_argument("output", type=Path)
    task_unit_data.add_argument("--prepared-root", type=Path)
    task_unit_data.add_argument("--clusters-root", type=Path)
    task_unit_data.add_argument("--candidate-root", type=Path)
    task_unit_data.add_argument("--legacy-roles-root", type=Path)
    task_unit_data.add_argument("--development-exclusions", type=Path)
    task_unit_data.add_argument("--role-census-root", type=Path)

    realization_bindings = commands.add_parser(
        "realization-bindings",
        help="freeze Prompt-TSG task-to-mechanism and local-Oracle bindings",
    )
    realization_bindings.add_argument("tasks", type=Path)
    realization_bindings.add_argument("contracts_root", type=Path)
    realization_bindings.add_argument("catalog", type=Path)
    realization_bindings.add_argument("registry", type=Path)
    realization_bindings.add_argument("output", type=Path)
    realization_bindings.add_argument(
        "--prompt-tsg-bundle", type=Path, action="append", required=True
    )

    security_qualification = commands.add_parser(
        "security-oracle-qualification",
        help="replay the frozen gold boundary for active local security profiles",
    )
    security_qualification.add_argument("registry", type=Path)
    security_qualification.add_argument("cases", type=Path)
    security_qualification.add_argument("output", type=Path)
    security_qualification.add_argument(
        "--repository-root", type=Path, default=Path.cwd()
    )

    target_security_qualification = commands.add_parser(
        "target-security-oracle-qualification",
        help="qualify the target-v3 local Security Oracle catalog without mutating legacy producers",
    )
    target_security_qualification.add_argument("registry", type=Path)
    target_security_qualification.add_argument("output", type=Path)
    target_security_qualification.add_argument(
        "--cases", type=Path, action="append", required=True
    )
    target_security_qualification.add_argument(
        "--repository-root", type=Path, default=Path.cwd()
    )

    tsg_qualification = commands.add_parser(
        "prompt-tsg-qualification",
        help="compare one extractor bundle with a prospective task-context holdout",
    )
    tsg_qualification.add_argument("tasks", type=Path)
    tsg_qualification.add_argument("graph_bundle", type=Path)
    tsg_qualification.add_argument("catalog", type=Path)
    tsg_qualification.add_argument("registry", type=Path)
    tsg_qualification.add_argument("gold", type=Path)
    tsg_qualification.add_argument("output", type=Path)
    tsg_qualification.add_argument("--repository-root", type=Path, default=Path.cwd())
    tsg_qualification.add_argument("--path-authority-annotations", type=Path)

    contract_qualification = commands.add_parser(
        "prompt-contract-qualification",
        help="independently replay and score the active task-level Prompt TSG Gate C",
    )
    contract_qualification.add_argument("tasks", type=Path)
    contract_qualification.add_argument("extraction_bundle", type=Path)
    contract_qualification.add_argument("catalog", type=Path)
    contract_qualification.add_argument("registry", type=Path)
    contract_qualification.add_argument("gold", type=Path)
    contract_qualification.add_argument("proposer_evaluator", type=Path)
    contract_qualification.add_argument("proposer_prompt", type=Path)
    contract_qualification.add_argument("reviewer_evaluator", type=Path)
    contract_qualification.add_argument("reviewer_prompt", type=Path)
    contract_qualification.add_argument("output", type=Path)
    contract_qualification.add_argument(
        "--repository-root", type=Path, default=Path.cwd()
    )

    tsg_selection = commands.add_parser(
        "prompt-tsg-selection",
        help="freeze formal Prompt-TSG tasks after provenance-only exclusions",
    )
    tsg_selection.add_argument("tasks", type=Path)
    tsg_selection.add_argument("output", type=Path)
    tsg_selection.add_argument("--exclude", type=Path, action="append", required=True)

    tsg_holdout = commands.add_parser(
        "prompt-tsg-holdout-selection",
        help="freeze a disjoint outcome-blind Prompt TSG qualification holdout",
    )
    tsg_holdout.add_argument("tasks", type=Path)
    tsg_holdout.add_argument("output", type=Path)
    tsg_holdout.add_argument("--exclude", type=Path, action="append", required=True)
    tsg_holdout.add_argument("--cwe", action="append", required=True)
    tsg_holdout.add_argument("--task-units-per-cwe", type=int, default=3)
    tsg_holdout.add_argument("--ranking-salt", required=True)

    prompt_tsg_extract = commands.add_parser(
        "prompt-tsg-extract",
        help="extract evidence-bound Prompt TSGs for a frozen task file",
    )
    prompt_tsg_extract.add_argument("tasks", type=Path)
    prompt_tsg_extract.add_argument("catalog", type=Path)
    prompt_tsg_extract.add_argument("evaluator", type=Path)
    prompt_tsg_extract.add_argument("extractor_prompt", type=Path)
    prompt_tsg_extract.add_argument("output", type=Path)
    prompt_tsg_extract.add_argument("--start", type=int, default=0)
    prompt_tsg_extract.add_argument("--limit", type=int)
    prompt_tsg_extract.add_argument("--task-selection", type=Path)
    prompt_tsg_extract.add_argument("--semantic-reviewer", type=Path)
    prompt_tsg_extract.add_argument("--semantic-reviewer-prompt", type=Path)
    prompt_tsg_extract.add_argument("--path-authority-annotations", type=Path)

    prompt_contract_extract = commands.add_parser(
        "prompt-contract-extract",
        help="run the active blind dual-annotation task contract extractor",
    )
    prompt_contract_extract.add_argument("tasks", type=Path)
    prompt_contract_extract.add_argument("catalog", type=Path)
    prompt_contract_extract.add_argument("proposer_evaluator", type=Path)
    prompt_contract_extract.add_argument("proposer_prompt", type=Path)
    prompt_contract_extract.add_argument("reviewer_evaluator", type=Path)
    prompt_contract_extract.add_argument("reviewer_prompt", type=Path)
    prompt_contract_extract.add_argument("selection", type=Path)
    prompt_contract_extract.add_argument("output", type=Path)
    prompt_contract_extract.add_argument("--workers", type=int, default=1)

    positivity = commands.add_parser(
        "positivity-audit",
        help="audit natural Prompt-feature support before FCI",
    )
    positivity.add_argument("tasks", type=Path)
    positivity.add_argument("catalog", type=Path)
    positivity.add_argument("output", type=Path)
    positivity.add_argument(
        "--prompt-tsg-bundle",
        type=Path,
        action="append",
        required=True,
    )
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
    positivity.add_argument("--minimum-state-task-units", type=int, default=30)
    positivity.add_argument("--minimum-shared-lineages", type=int, default=2)

    dataset_prep = commands.add_parser(
        "dataset-prep",
        help="normalize external task sources without executing their code",
    )
    dataset_prep.add_argument("output", type=Path)
    dataset_prep.add_argument("--sallm-root", type=Path)
    dataset_prep.add_argument("--cweval-root", type=Path)
    dataset_prep.add_argument("--cyberseceval-path", type=Path)
    dataset_prep.add_argument("--llmseceval-root", type=Path)
    dataset_prep.add_argument("--securityeval-root", type=Path)
    dataset_prep.add_argument("--codeseceval-root", type=Path)
    dataset_prep.add_argument("--secodeplt-root", type=Path)
    dataset_prep.add_argument("--limit-per-source", type=int)

    contracts = commands.add_parser(
        "contract-freeze",
        help="freeze externally extracted functional contracts",
    )
    contracts.add_argument("prepared_root", type=Path)
    contracts.add_argument("responses", type=Path)
    contracts.add_argument("output", type=Path)

    dedup = commands.add_parser(
        "dedup-candidates",
        help="prepare lexical candidate pairs for semantic adjudication",
    )
    dedup.add_argument("prepared_root", type=Path)
    dedup.add_argument("output", type=Path)
    dedup.add_argument("--minimum-jaccard", type=float, default=0.35)
    dedup.add_argument("--max-neighbors-per-record", type=int, default=3)

    semantic = commands.add_parser(
        "semantic-curation",
        help="blindly adjudicate lexical pairs and freeze semantic clusters",
    )
    semantic.add_argument("prepared_root", type=Path)
    semantic.add_argument("candidates_root", type=Path)
    semantic.add_argument("output", type=Path)
    semantic.add_argument("--repository-root", type=Path, default=Path.cwd())
    semantic.add_argument("--max-new-batches", type=int)
    semantic.add_argument("--workers", type=int, default=1)
    semantic.add_argument("--reuse-root", type=Path)

    assemble_clusters = commands.add_parser(
        "assemble-semantic-clusters",
        help="assemble exact/lineage clusters and retain pair decisions as diagnostics",
    )
    assemble_clusters.add_argument("prepared_root", type=Path)
    assemble_clusters.add_argument("candidates_root", type=Path)
    assemble_clusters.add_argument("adjudication_root", type=Path)
    assemble_clusters.add_argument("output", type=Path)

    curate_contracts = commands.add_parser(
        "contract-curation",
        help="extract one functional contract per semantic cluster",
    )
    curate_contracts.add_argument("prepared_root", type=Path)
    curate_contracts.add_argument("clusters_root", type=Path)
    curate_contracts.add_argument("output", type=Path)
    curate_contracts.add_argument("--repository-root", type=Path, default=Path.cwd())
    curate_contracts.add_argument("--max-new-batches", type=int)
    curate_contracts.add_argument("--workers", type=int, default=1)
    curate_contracts.add_argument("--reuse-root", type=Path)
    curate_contracts.add_argument(
        "--existing-contracts-root",
        type=Path,
        help="reuse contracts whose representative record and prompt hash still match",
    )

    review_contracts = commands.add_parser(
        "contract-quality-review",
        help="blindly triage every functional contract before independent adjudication",
    )
    review_contracts.add_argument("prepared_root", type=Path)
    review_contracts.add_argument("contracts_root", type=Path)
    review_contracts.add_argument("output", type=Path)
    review_contracts.add_argument("--repository-root", type=Path, default=Path.cwd())
    review_contracts.add_argument("--max-new-batches", type=int)
    review_contracts.add_argument("--workers", type=int, default=1)
    review_contracts.add_argument("--reuse-root", type=Path)

    binding_review = commands.add_parser(
        "mechanism-binding-review",
        help="blindly bind ambiguous task units to registered mechanism realizations",
    )
    binding_review.add_argument("prepared_root", type=Path)
    binding_review.add_argument("clusters_root", type=Path)
    binding_review.add_argument("contracts_root", type=Path)
    binding_review.add_argument("eligibility_root", type=Path)
    binding_review.add_argument("registry", type=Path)
    binding_review.add_argument("output", type=Path)
    binding_review.add_argument("--repository-root", type=Path, default=Path.cwd())
    binding_review.add_argument("--max-new-batches", type=int)
    binding_review.add_argument("--workers", type=int, default=1)
    binding_review.add_argument("--reuse-root", type=Path)

    repair_contracts = commands.add_parser(
        "repair-contract-format-leaks",
        help="freeze a successor contract bundle without response-format requirements",
    )
    repair_contracts.add_argument("contracts_root", type=Path)
    repair_contracts.add_argument("output", type=Path)

    adjudicate_contracts = commands.add_parser(
        "apply-contract-adjudications",
        help="apply bounded outcome-blind contract and review corrections",
    )
    adjudicate_contracts.add_argument("contracts_root", type=Path)
    adjudicate_contracts.add_argument("reviews_root", type=Path)
    adjudicate_contracts.add_argument("adjudications", type=Path)
    adjudicate_contracts.add_argument("output", type=Path)

    adjudicate_bindings = commands.add_parser(
        "apply-binding-adjudications",
        help="apply bounded outcome-blind corrections to unresolved mechanism bindings",
    )
    adjudicate_bindings.add_argument("prepared_root", type=Path)
    adjudicate_bindings.add_argument("clusters_root", type=Path)
    adjudicate_bindings.add_argument("bindings_root", type=Path)
    adjudicate_bindings.add_argument("registry", type=Path)
    adjudicate_bindings.add_argument("adjudications", type=Path)
    adjudicate_bindings.add_argument("output", type=Path)

    eligibility = commands.add_parser(
        "dataset-eligibility",
        help="audit curated clusters for current experiment readiness",
    )
    eligibility.add_argument("prepared_root", type=Path)
    eligibility.add_argument("clusters_root", type=Path)
    eligibility.add_argument("contracts_root", type=Path)
    eligibility.add_argument("output", type=Path)
    eligibility.add_argument("--repository-root", type=Path, default=Path.cwd())
    eligibility.add_argument("--policy", type=Path)
    eligibility.add_argument(
        "--bindings-root",
        type=Path,
        help="optional outcome-blind task-to-mechanism binding bundle",
    )
    eligibility.add_argument(
        "--contract-reviews-root",
        type=Path,
        help="optional complete blind functional-contract review bundle",
    )
    eligibility.add_argument("--development-exclusions", type=Path)
    eligibility.add_argument("--case-audit", type=Path)
    eligibility.add_argument("--extension-policy", type=Path)
    eligibility.add_argument(
        "--backend-root",
        type=Path,
        help="optional BaxBench-compatible source snapshot for backend data inventory",
    )

    study_design = commands.add_parser(
        "study-design",
        help="freeze the outcome-blind Python sample, power assumptions, and replication readiness",
    )
    study_design.add_argument("eligibility_root", type=Path)
    study_design.add_argument("task_units_root", type=Path)
    study_design.add_argument("output", type=Path)
    study_design.add_argument("--repository-root", type=Path, default=Path.cwd())
    study_design.add_argument("--seed", type=int, default=2026082301)
    study_design.add_argument("--clusters-per-family", type=int, default=15)
    study_design.add_argument(
        "--exclude-sample",
        type=Path,
        action="append",
        default=[],
        help="prior JSON/JSONL sample whose exposed task units cannot be selected",
    )
    study_design.add_argument(
        "--family",
        action="append",
        default=[],
        help="mechanism family to include; repeat to prospectively restrict the study population",
    )
    study_design.add_argument(
        "--family-quota",
        action="append",
        default=[],
        metavar="FAMILY=COUNT",
        help="explicit prospective cluster quota; repeat for an unequal stratified design",
    )

    args = parser.parse_args(argv)
    if args.command == "verify":
        verify_bundle(args.root)
        print("VERIFIED")
    elif args.command == "target-study":
        if args.phase == "smoke":
            from prompt_mechanism_study.target_workflow import (
                run_target_reviewer_smoke,
            )

            report = run_target_reviewer_smoke(args.output)
        else:
            from prompt_mechanism_study.selector_verify import (
                load_and_verify_target_result_bundle,
            )

            report = load_and_verify_target_result_bundle(args.output)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0
    elif args.command == "discovery-population":
        from prompt_mechanism_study.prioritization import prepare_discovery_population

        scopes = {}
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
        print(report["status"])
    elif args.command == "prompt-tsg-extract":
        from prompt_mechanism_study.prompt_tsg_extract import extract_task_file

        report = extract_task_file(
            args.tasks,
            args.catalog,
            args.evaluator,
            args.extractor_prompt,
            args.output,
            start=args.start,
            limit=args.limit,
            task_selection_path=args.task_selection,
            reviewer_evaluator_path=args.semantic_reviewer,
            reviewer_prompt_path=args.semantic_reviewer_prompt,
            path_authority_annotations_path=args.path_authority_annotations,
        )
        print(report["status"])
        return 0 if report["status"] == "PROMPT_TSG_EXTRACTION_COMPLETE" else 2
    elif args.command == "prompt-contract-extract":
        from prompt_mechanism_study.prompt_contract_extract import (
            extract_contract_task_file,
        )

        report = extract_contract_task_file(
            args.tasks,
            args.catalog,
            args.proposer_evaluator,
            args.proposer_prompt,
            args.reviewer_evaluator,
            args.reviewer_prompt,
            args.selection,
            args.output,
            max_workers=args.workers,
        )
        print(report["status"])
    elif args.command == "task-partition":
        from prompt_mechanism_study.prioritization import freeze_task_unit_partition

        report = freeze_task_unit_partition(
            args.tasks,
            tuple(args.prompt_tsg_bundle),
            args.clusters_root,
            args.catalog,
            args.output,
            seed=args.seed,
        )
        print(report["status"])
    elif args.command == "task-unit-data":
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
                "legacy_roles_root",
                "development_exclusions",
                "role_census_root",
            )
            missing = tuple(name for name in required if getattr(args, name) is None)
            if missing:
                parser.error(
                    "task-unit-data build requires "
                    + ", ".join("--" + name.replace("_", "-") for name in missing)
                )
            report = compile_task_unit_data(
                prepared_root=args.prepared_root,
                clusters_root=args.clusters_root,
                candidate_root=args.candidate_root,
                legacy_roles_root=args.legacy_roles_root,
                development_exclusions_path=args.development_exclusions,
                role_census_root=args.role_census_root,
                output=args.output,
            )
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    elif args.command == "realization-bindings":
        from prompt_mechanism_study.eligibility import freeze_tsg_realization_bindings

        report = freeze_tsg_realization_bindings(
            args.tasks,
            tuple(args.prompt_tsg_bundle),
            args.contracts_root,
            args.catalog,
            args.registry,
            args.output,
        )
        print(report["status"])
    elif args.command == "security-oracle-qualification":
        from prompt_mechanism_study.eligibility import qualify_local_security_profiles

        report = qualify_local_security_profiles(
            args.repository_root,
            args.registry,
            args.cases,
            args.output,
        )
        print(report["status"])
        return 0 if report["status"] == "QUALIFIED_FOR_EXPERIMENT" else 2
    elif args.command == "target-security-oracle-qualification":
        from prompt_mechanism_study.eligibility import qualify_target_security_profiles

        report = qualify_target_security_profiles(
            args.repository_root,
            args.registry,
            tuple(args.cases),
            args.output,
        )
        print(report["status"])
        return (
            0
            if report["status"] == "QUALIFIED_FOR_TARGET_MEASUREMENT_PROFILE"
            else 2
        )
    elif args.command == "prompt-tsg-qualification":
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
        print(report["status"])
        return 0 if report["status"] == "QUALIFIED_FOR_FORMAL_EXTRACTION" else 2
    elif args.command == "prompt-contract-qualification":
        from prompt_mechanism_study.prompt_contract_qualification import (
            qualify_prompt_contract_extractor,
        )

        report = qualify_prompt_contract_extractor(
            args.repository_root,
            args.tasks,
            args.extraction_bundle,
            args.catalog,
            args.registry,
            args.gold,
            args.proposer_evaluator,
            args.proposer_prompt,
            args.reviewer_evaluator,
            args.reviewer_prompt,
            args.output,
        )
        print(report["status"])
        return 0 if report["status"] == "QUALIFIED_FOR_FORMAL_EXTRACTION" else 2
    elif args.command == "prompt-tsg-selection":
        from prompt_mechanism_study.eligibility import freeze_prompt_tsg_task_selection

        report = freeze_prompt_tsg_task_selection(
            args.tasks,
            tuple(args.exclude),
            args.output,
        )
        print(report["status"])
    elif args.command == "prompt-tsg-holdout-selection":
        from prompt_mechanism_study.eligibility import freeze_prompt_tsg_holdout_selection

        report = freeze_prompt_tsg_holdout_selection(
            args.tasks,
            tuple(args.exclude),
            args.output,
            cwes=tuple(sorted(set(args.cwe))),
            task_units_per_cwe=args.task_units_per_cwe,
            ranking_salt=args.ranking_salt,
        )
        print(report["status"])
    elif args.command == "positivity-audit":
        from prompt_mechanism_study.prioritization import audit_discovery_positivity

        report = audit_discovery_positivity(
            args.tasks,
            tuple(args.prompt_tsg_bundle),
            args.catalog,
            args.output,
            minimum_state_task_units=args.minimum_state_task_units,
            minimum_shared_lineages=args.minimum_shared_lineages,
            graph_artifact=args.graph_artifact,
        )
        print(report["status"])
        return 0 if report["status"] == "POSITIVITY_GATE_PASSED" else 2
    elif args.command == "dataset-prep":
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
        print(report["status"])
    elif args.command == "contract-freeze":
        from prompt_mechanism_study.datasets import freeze_contracts

        report = freeze_contracts(args.prepared_root, args.responses, args.output)
        print(report["status"])
    elif args.command == "dedup-candidates":
        from prompt_mechanism_study.datasets import prepare_dedup_candidates

        report = prepare_dedup_candidates(
            args.prepared_root,
            args.output,
            minimum_jaccard=args.minimum_jaccard,
            max_neighbors_per_record=args.max_neighbors_per_record,
        )
        print(report["status"])
    elif args.command == "semantic-curation":
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
        print(report["status"])
    elif args.command == "contract-curation":
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
        print(report["status"])
    elif args.command == "contract-quality-review":
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
        print(report["status"])
    elif args.command == "mechanism-binding-review":
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
        print(report["status"])
    elif args.command == "repair-contract-format-leaks":
        from prompt_mechanism_study.curation import repair_response_format_contract_leaks

        report = repair_response_format_contract_leaks(
            args.contracts_root,
            args.output,
        )
        print(report["status"])
    elif args.command == "apply-contract-adjudications":
        from prompt_mechanism_study.curation import apply_contract_recovery_adjudications

        report = apply_contract_recovery_adjudications(
            args.contracts_root,
            args.reviews_root,
            args.adjudications,
            args.output,
        )
        print(report["status"])
    elif args.command == "assemble-semantic-clusters":
        from prompt_mechanism_study.curation import assemble_semantic_clusters

        report = assemble_semantic_clusters(
            args.prepared_root,
            args.candidates_root,
            args.adjudication_root,
            args.output,
        )
        print(report["status"])
    elif args.command == "dataset-eligibility":
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
            extension_policy_path=args.extension_policy,
            backend_root=args.backend_root,
        )
        print(report["status"])
    elif args.command == "apply-binding-adjudications":
        from prompt_mechanism_study.eligibility import apply_binding_adjudications

        report = apply_binding_adjudications(
            args.prepared_root,
            args.clusters_root,
            args.bindings_root,
            args.registry,
            args.adjudications,
            args.output,
        )
        print(report["status"])
    elif args.command == "study-design":
        from prompt_mechanism_study.study_design import freeze_study_design

        family_quotas = {}
        for item in args.family_quota:
            try:
                family, count = item.rsplit("=", 1)
                family_quotas[family] = int(count)
            except (ValueError, TypeError):
                parser.error("family quotas must use FAMILY=COUNT")
        report = freeze_study_design(
            args.repository_root,
            args.eligibility_root,
            args.task_units_root,
            args.output,
            seed=args.seed,
            clusters_per_family=args.clusters_per_family,
            excluded_sample_paths=args.exclude_sample or None,
            included_families=args.family or None,
            family_quotas=family_quotas or None,
        )
        print(report["status"])
    else:
        return _judge_gate(args)
    return 0


def _judge_gate(args: argparse.Namespace) -> int:
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
    print(report["status"])
    return (
        0
        if report["status"]
        in {
            "JUDGE_GATE_PREFLIGHT_COMPLETE",
            "PILOT_PASSED",
            "REMAINING_COMPLETE",
            "JUDGE_GATE_PASSED",
        }
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
