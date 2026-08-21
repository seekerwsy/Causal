"""CLI for prospective freeze, external measurement import, and analysis."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

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

    args = parser.parse_args(argv)
    if args.command == "freeze":
        _freeze(args.protocol, args.output)
    elif args.command == "analyze":
        _analyze(args.freeze_root, args.measurements, args.output)
    elif args.command == "verify":
        verify_bundle(args.root)
        print("VERIFIED")
    else:
        verify_bundle(args.root)
        print(json.dumps(read_json(args.root / "analysis.json"), indent=2, sort_keys=True))
    return 0


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
        raise ValueError(f"{name} must be a list")
    return raw


def _mapping(raw: object, name: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise ValueError(f"{name} must be an object")
    return raw


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_study", "main"]
