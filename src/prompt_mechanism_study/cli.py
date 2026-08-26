"""CLI for prospective freeze, external measurement import, and analysis."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from prompt_mechanism_study import functional_judge
from prompt_mechanism_study.adapters import AdapterBundle, AdapterKind, AdapterSpec
from prompt_mechanism_study.artifact_io import bundle_digest, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.inference import AnalysisPlan, Metric
from prompt_mechanism_study.intervention import (
    ARM_ORDER,
    InterventionExecution,
    RealizationSpec,
    SemanticValidation,
    SemanticVerdict,
    freeze_bundle,
    freeze_policy,
    intervention_spec,
)
from prompt_mechanism_study.measurement import (
    CodeStatus,
    FunctionalStatus,
    InfrastructureFailure,
    Measurement,
    OracleStatus,
)
from prompt_mechanism_study.records import canonical_value
from prompt_mechanism_study.representation import (
    Candidate,
    ExpectedDirection,
    Operation,
    Split,
    Task,
)
from prompt_mechanism_study.workflow import StudyFreeze, analyze, freeze_study


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="prompt-mechanism-study")
    commands = parser.add_subparsers(dest="command", required=True)

    freeze = commands.add_parser("freeze", help="freeze the pre-outcome study protocol")
    freeze.add_argument("protocol", type=Path)
    freeze.add_argument("output", type=Path)

    analyze_command = commands.add_parser(
        "analyze",
        help="analyze external measurements against a frozen study",
    )
    analyze_command.add_argument("freeze_root", type=Path)
    analyze_command.add_argument("measurements", type=Path)
    analyze_command.add_argument("output", type=Path)

    verify = commands.add_parser("verify", help="verify an exact artifact bundle")
    verify.add_argument("root", type=Path)

    summarize = commands.add_parser("summarize", help="print a stored analysis summary")
    summarize.add_argument("root", type=Path)

    judge = commands.add_parser("judge-gate", help="run the bounded Functional Judge gate")
    judge.add_argument("phase", choices=("preflight", "pilot", "remaining", "finalize"))
    judge.add_argument("output", type=Path)
    judge.add_argument("--repository-root", type=Path, default=Path.cwd())
    judge.add_argument("--gate-config", type=Path)
    judge.add_argument("--pilot-root", type=Path)
    judge.add_argument("--remaining-root", type=Path)

    formal = commands.add_parser(
        "formal-interventions",
        help="freeze the formal ADD/REMOVE intervention policies before generation",
    )
    formal.add_argument("phase", choices=("preflight", "pilot", "remaining", "finalize"))
    formal.add_argument("output", type=Path)
    formal.add_argument("--repository-root", type=Path, default=Path.cwd())
    formal.add_argument("--config", type=Path)
    formal.add_argument("--pilot-root", type=Path)
    formal.add_argument("--remaining-root", type=Path)

    measurements = commands.add_parser(
        "formal-measurements",
        help="run frozen generator and Oracle adapters for formal assignments",
    )
    measurements.add_argument("phase", choices=("pilot", "remaining"))
    measurements.add_argument("output", type=Path)
    measurements.add_argument("--repository-root", type=Path, default=Path.cwd())
    measurements.add_argument("--add-freeze", type=Path, required=True)
    measurements.add_argument("--remove-freeze", type=Path, required=True)
    measurements.add_argument("--interventions", type=Path, required=True)
    measurements.add_argument("--oracle-source-root", type=Path, required=True)
    measurements.add_argument("--semgrep", type=Path, required=True)
    measurements.add_argument("--bandit", type=Path, required=True)
    measurements.add_argument("--pilot-root", type=Path)

    factorial = commands.add_parser(
        "factorial-experiment",
        help="preflight or run the frozen pairwise factorial study",
    )
    factorial.add_argument("phase", choices=("preflight", "run"))
    factorial.add_argument("output", type=Path)
    factorial.add_argument("--repository-root", type=Path, default=Path.cwd())
    factorial.add_argument(
        "--config",
        type=Path,
        default=Path("configs/formal/factorial-sql-confirm-qwen35-v3.json"),
    )

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
    if args.command == "freeze":
        _freeze(args.protocol, args.output)
    elif args.command == "analyze":
        _analyze(args.freeze_root, args.measurements, args.output)
    elif args.command == "verify":
        verify_bundle(args.root)
        print("VERIFIED")
    elif args.command == "summarize":
        verify_bundle(args.root)
        print(json.dumps(read_json(args.root / "analysis.json"), indent=2, sort_keys=True))
    elif args.command == "formal-interventions":
        return _formal_interventions(args)
    elif args.command == "formal-measurements":
        from prompt_mechanism_study.formal_measurement import run_measurement_phase

        report = run_measurement_phase(
            args.repository_root,
            args.phase,
            args.output,
            add_freeze=args.add_freeze,
            remove_freeze=args.remove_freeze,
            interventions=args.interventions,
            oracle_source_root=args.oracle_source_root,
            semgrep=args.semgrep,
            bandit=args.bandit,
            pilot_root=args.pilot_root,
        )
        print(report["status"])
        return 0 if report["status"] in {"PILOT_COMPLETE", "REMAINING_COMPLETE"} else 2
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
        )
        print(report["status"])
        return 0 if report["status"] == "PROMPT_TSG_EXTRACTION_COMPLETE" else 2
    elif args.command == "positivity-audit":
        from prompt_mechanism_study.prioritization import audit_discovery_positivity

        report = audit_discovery_positivity(
            args.tasks,
            tuple(args.prompt_tsg_bundle),
            args.catalog,
            args.output,
            minimum_state_task_units=args.minimum_state_task_units,
            minimum_shared_lineages=args.minimum_shared_lineages,
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
    elif args.command == "factorial-experiment":
        from prompt_mechanism_study.factorial_experiment import (
            preflight_factorial_experiment,
            run_factorial_experiment,
        )

        if args.phase == "preflight":
            report = preflight_factorial_experiment(args.repository_root, args.config)
            write_bundle(args.output, {"report.json": report})
        else:
            report = run_factorial_experiment(
                args.repository_root,
                args.config,
                args.output,
            )
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0
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


def _formal_interventions(args: argparse.Namespace) -> int:
    from prompt_mechanism_study.formal import (
        finalize_interventions,
        preflight_interventions,
        run_intervention_phase,
    )

    if args.phase == "preflight":
        report = preflight_interventions(
            args.repository_root,
            args.output,
            config_path=args.config,
        )
    elif args.phase in {"pilot", "remaining"}:
        report = run_intervention_phase(
            args.repository_root,
            args.phase,
            args.output,
            pilot_root=args.pilot_root,
            config_path=args.config,
        )
    else:
        if args.pilot_root is None or args.remaining_root is None:
            raise ValueError("finalize requires --pilot-root and --remaining-root")
        report = finalize_interventions(
            args.repository_root,
            args.pilot_root,
            args.remaining_root,
            args.output,
            config_path=args.config,
        )
    print(report["status"])
    return (
        0
        if report["status"]
        in {
            "FORMAL_INTERVENTION_PREFLIGHT_COMPLETE",
            "PILOT_PASSED",
            "REMAINING_COMPLETE",
            "FORMAL_INTERVENTIONS_FROZEN",
        }
        else 2
    )


def _freeze(protocol_path: Path, output: Path) -> None:
    protocol = read_json(protocol_path)
    study = build_study(protocol)
    write_bundle(
        output,
        {
            "protocol.json": protocol,
            "freeze.json": {
                "study_id": study.study_id,
                "study": canonical_value(study),
            },
            "randomization.json": canonical_value(study.randomization),
        },
    )
    print(study.study_id)


def _analyze(freeze_root: Path, measurement_path: Path, output: Path) -> None:
    verify_bundle(freeze_root)
    study = build_study(read_json(freeze_root / "protocol.json"))
    frozen = _exact(read_json(freeze_root / "freeze.json"), {"study_id", "study"})
    if frozen["study_id"] != study.study_id or frozen["study"] != canonical_value(study):
        raise ValueError("frozen study does not replay from its protocol")
    measurement_input = read_json(measurement_path)
    measurements, failures = _measurement_input(measurement_input, study)
    result = analyze(study, measurements, infrastructure_failures=failures)
    write_bundle(
        output,
        {
            "source.json": {
                "freeze_manifest_sha256": bundle_digest(freeze_root),
                "study_id": study.study_id,
            },
            "measurements.json": measurement_input,
            "outcomes.json": canonical_value(result.outcomes),
            "inference.json": canonical_value(result.inference),
            "analysis.json": {
                "analysis_id": result.analysis_id,
                "study_id": result.study_id,
                "ledger_id": result.ledger.ledger_id,
                "inference_id": result.inference.inference_id,
                "estimates": canonical_value(result.inference.estimates),
                "intervals": canonical_value(result.inference.intervals),
            },
        },
    )
    print(result.analysis_id)


def build_study(raw: object) -> StudyFreeze:
    data = _exact(
        raw,
        {
            "tasks",
            "candidates",
            "selector",
            "policies",
            "adapters",
            "analysis",
            "models",
            "slots",
            "randomization_seed",
        },
    )
    adapters = _adapters(data["adapters"])
    tasks = tuple(_task(item) for item in _list(data["tasks"], "tasks"))
    candidates = tuple(_candidate(item) for item in _list(data["candidates"], "candidates"))
    by_key = {item.candidate_key: item for item in candidates}
    if len(by_key) != len(candidates):
        raise ValueError("candidate keys must be unique")
    selector = _exact(data["selector"], {"top_k", "scores"})
    raw_scores = _mapping(selector["scores"], "selector scores")
    if set(raw_scores) != set(by_key):
        raise ValueError("selector scores must bind every candidate key")
    scores = {by_key[key].candidate_id: value for key, value in raw_scores.items()}
    task_by_id = {item.task_id: item for item in tasks}
    policies = tuple(
        _policy(item, by_key, task_by_id, adapters) for item in _list(data["policies"], "policies")
    )
    analysis = _exact(
        data["analysis"],
        {"metrics", "bootstrap_seed", "bootstrap_draws", "alpha"},
    )
    plan = AnalysisPlan(
        tuple(Metric(item) for item in _list(analysis["metrics"], "analysis metrics")),
        analysis["bootstrap_seed"],
        analysis["bootstrap_draws"],
        analysis["alpha"],
    )
    return freeze_study(
        tasks,
        candidates,
        scores,
        policies,
        adapters,
        plan,
        top_k=selector["top_k"],
        models=tuple(_list(data["models"], "models")),
        slots=tuple(_list(data["slots"], "slots")),
        randomization_seed=data["randomization_seed"],
    )


def _task(raw: object) -> Task:
    data = _exact(
        raw,
        {"task_id", "semantic_cluster_id", "cwe", "archetype", "split", "prompt"},
        {"weight"},
    )
    return Task(
        data["task_id"],
        data["semantic_cluster_id"],
        data["cwe"],
        data["archetype"],
        Split(data["split"]),
        data["prompt"],
        data.get("weight", 1),
    )


def _candidate(raw: object) -> Candidate:
    data = _exact(
        raw,
        {
            "candidate_key",
            "context_query_id",
            "actionable_feature_id",
            "operation",
            "cwe",
            "outcome_id",
            "expected_direction",
        },
    )
    return Candidate(
        data["candidate_key"],
        data["context_query_id"],
        data["actionable_feature_id"],
        Operation(data["operation"]),
        data["cwe"],
        data["outcome_id"],
        ExpectedDirection(data["expected_direction"]),
    )


def _policy(
    raw: object,
    candidates: Mapping[str, Candidate],
    tasks: Mapping[str, Task],
    adapters: AdapterBundle,
) -> object:
    data = _exact(raw, {"candidate_key", "arm_instructions", "realizations", "bundles"})
    candidate = candidates.get(data["candidate_key"])
    if candidate is None:
        raise ValueError("policy references an unknown candidate")
    raw_instructions = _exact(data["arm_instructions"], {arm.value for arm in ARM_ORDER})
    spec = intervention_spec(
        candidate,
        {arm: raw_instructions[arm.value] for arm in ARM_ORDER},
    )
    realizations = tuple(
        RealizationSpec(
            item["label"],
            item["weight"],
            adapters.intervention_executor.adapter_id,
        )
        for item in (
            _exact(value, {"label", "weight"})
            for value in _list(data["realizations"], "realizations")
        )
    )
    by_label = {item.label: item for item in realizations}
    if len(by_label) != len(realizations):
        raise ValueError("realization labels must be unique")
    bundles = []
    for value in _list(data["bundles"], "bundles"):
        item = _exact(value, {"task_id", "realization_label", "arms"})
        task = tasks.get(item["task_id"])
        realization = by_label.get(item["realization_label"])
        if task is None or realization is None or task.split is not Split.CONFIRM:
            raise ValueError("bundle references an invalid confirm task or realization")
        arm_values = _exact(item["arms"], {arm.value for arm in ARM_ORDER})
        arm_records = {
            arm: _exact(
                arm_values[arm.value],
                {
                    "intervention_text",
                    "executor_evidence_sha256",
                    "validation",
                },
            )
            for arm in ARM_ORDER
        }
        validations = {}
        for arm, record in arm_records.items():
            values = _exact(
                record["validation"],
                {
                    "task_preserved",
                    "contract_satisfied",
                    "unintended_changes",
                    "contradiction",
                    "evidence_sha256",
                },
            )
            validations[arm] = SemanticValidation(
                SemanticVerdict(values["task_preserved"]),
                SemanticVerdict(values["contract_satisfied"]),
                SemanticVerdict(values["unintended_changes"]),
                SemanticVerdict(values["contradiction"]),
                adapters.intervention_validator.adapter_id,
                values["evidence_sha256"],
            )
        bundles.append(
            freeze_bundle(
                candidate,
                spec=spec,
                task_id=task.task_id,
                semantic_cluster_id=task.semantic_cluster_id,
                source_prompt=task.prompt,
                realization=realization,
                executions={
                    arm: InterventionExecution(
                        record["intervention_text"],
                        adapters.intervention_executor.adapter_id,
                        record["executor_evidence_sha256"],
                    )
                    for arm, record in arm_records.items()
                },
                validations=validations,
            )
        )
    return freeze_policy(candidate, spec, realizations, tuple(bundles))


def _adapters(raw: object) -> AdapterBundle:
    values = _exact(
        raw,
        {
            "representation",
            "selector",
            "intervention_executor",
            "intervention_validator",
            "generator",
            "security_oracle",
            "functional_evaluator",
        },
    )
    return AdapterBundle(
        _adapter(AdapterKind.REPRESENTATION, values["representation"]),
        _adapter(AdapterKind.SELECTOR, values["selector"]),
        _adapter(AdapterKind.INTERVENTION_EXECUTOR, values["intervention_executor"]),
        _adapter(AdapterKind.INTERVENTION_VALIDATOR, values["intervention_validator"]),
        _adapter(AdapterKind.GENERATOR, values["generator"]),
        _adapter(AdapterKind.SECURITY_ORACLE, values["security_oracle"]),
        _adapter(AdapterKind.FUNCTIONAL_EVALUATOR, values["functional_evaluator"]),
    )


def _adapter(kind: AdapterKind, raw: object) -> AdapterSpec:
    data = _exact(raw, {"name", "version", "policy_sha256"})
    return AdapterSpec(kind, data["name"], data["version"], data["policy_sha256"])


def _measurement_input(
    raw: object,
    study: StudyFreeze,
) -> tuple[tuple[Measurement, ...], tuple[InfrastructureFailure, ...]]:
    data = _exact(
        raw,
        {"study_id", "adapter_ids", "records", "infrastructure_failures"},
    )
    if data["study_id"] != study.study_id:
        raise ValueError("measurement input does not bind the frozen study")
    adapter_ids = _exact(
        data["adapter_ids"],
        {"generator", "security_oracle", "functional_evaluator"},
    )
    expected = {
        "generator": study.adapters.generator.adapter_id,
        "security_oracle": study.adapters.security_oracle.adapter_id,
        "functional_evaluator": study.adapters.functional_evaluator.adapter_id,
    }
    if adapter_ids != expected:
        raise ValueError("measurement adapter identity drift")
    records = []
    for value in _list(data["records"], "measurement records"):
        item = _exact(
            value,
            {
                "assignment_id",
                "code_status",
                "oracle_status",
                "functional_status",
                "generator_evidence_sha256",
            },
            {
                "code_sha256",
                "oracle_evidence_sha256",
                "functional_evidence_sha256",
                "terminal_reason",
            },
        )
        records.append(
            Measurement(
                item["assignment_id"],
                CodeStatus(item["code_status"]),
                OracleStatus(item["oracle_status"]),
                FunctionalStatus(item["functional_status"]),
                item["generator_evidence_sha256"],
                item.get("code_sha256"),
                item.get("oracle_evidence_sha256"),
                item.get("functional_evidence_sha256"),
                item.get("terminal_reason"),
            )
        )
    failures = tuple(
        InfrastructureFailure(item["assignment_id"], item["producer"], item["reason"])
        for item in (
            _exact(value, {"assignment_id", "producer", "reason"})
            for value in _list(data["infrastructure_failures"], "infrastructure failures")
        )
    )
    return tuple(records), failures


def _exact(
    raw: object,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise ValueError("record must be an object with string keys")
    optional = optional or set()
    if not required <= set(raw) or set(raw) - required - optional:
        raise ValueError("record keys are not exact")
    return raw


def _list(raw: object, name: str) -> list[Any]:
    if not isinstance(raw, list):
        raise TypeError(f"{name} must be a list")
    return raw


def _mapping(raw: object, name: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise ValueError(f"{name} must be an object")
    return raw


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_study", "main"]
