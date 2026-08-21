from __future__ import annotations

from copy import deepcopy
from typing import Callable

from prompt_mechanism_study.cli import build_study
from prompt_mechanism_study.measurement import (
    CodeStatus,
    FunctionalStatus,
    Measurement,
    OracleStatus,
)
from prompt_mechanism_study.randomization import Assignment
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.workflow import StudyFreeze


def protocol_spec(*, models: tuple[str, ...] = ("model.a",)) -> dict:
    tasks = [
        _task("discover.1", "discover.cluster.1", "discover"),
        _task("discover.2", "discover.cluster.2", "discover"),
        _task("confirm.1a", "confirm.cluster.1", "confirm", weight=1),
        _task("confirm.1b", "confirm.cluster.1", "confirm", weight=3),
        _task("confirm.2", "confirm.cluster.2", "confirm", weight=1),
    ]
    candidate = {
        "candidate_key": "sql.parameterization",
        "context_query_id": "sql.user_input",
        "actionable_feature_id": "sql.parameterized_query",
        "operation": "add",
        "cwe": "CWE-89",
        "outcome_id": "oracle_evaluable_secure_code_yield",
        "expected_direction": "increase",
    }
    bundles = []
    for task in tasks:
        if task["split"] != "confirm":
            continue
        for realization in ("direct", "constraint"):
            bundles.append(
                {
                    "task_id": task["task_id"],
                    "realization_label": realization,
                    "arms": {
                        arm: _arm_record(task["task_id"], realization, arm)
                        for arm in ("target", "noop", "placebo", "generic")
                    },
                }
            )
    return {
        "tasks": tasks,
        "candidates": [candidate],
        "selector": {
            "top_k": 1,
            "scores": {"sql.parameterization": 0.75},
        },
        "policies": [
            {
                "candidate_key": "sql.parameterization",
                "arm_instructions": {
                    "target": "Add SQL value parameterization.",
                    "noop": "Add neutral guidance without changing SQL construction.",
                    "placebo": "Add unrelated length-matched engineering guidance.",
                    "generic": "Add a generic security reminder without the target mechanism.",
                },
                "realizations": [
                    {"label": "direct", "weight": 1},
                    {"label": "constraint", "weight": 3},
                ],
                "bundles": bundles,
            }
        ],
        "adapters": {
            "representation": _adapter("representation"),
            "selector": _adapter("selector"),
            "intervention_executor": _adapter("intervention"),
            "intervention_validator": _adapter("intervention-validator"),
            "generator": _adapter("generator"),
            "security_oracle": _adapter("oracle"),
            "functional_evaluator": _adapter("functional"),
        },
        "analysis": {
            "metrics": [
                "code_valid",
                "oracle_evaluable",
                "secure_yield",
                "functionality",
                "joint",
            ],
            "bootstrap_seed": 73001,
            "bootstrap_draws": 200,
            "alpha": 0.05,
        },
        "models": list(models),
        "slots": [0, 1, 2, 3],
        "randomization_seed": 41021,
    }


def example_study(*, models: tuple[str, ...] = ("model.a",)) -> StudyFreeze:
    return build_study(protocol_spec(models=models))


def complete_measurements(
    study: StudyFreeze,
    classify: Callable[
        [Assignment],
        tuple[CodeStatus, OracleStatus, FunctionalStatus],
    ]
    | None = None,
) -> tuple[Measurement, ...]:
    classify = classify or _default_labels
    rows = []
    for assignment in study.randomization.assignments:
        code, oracle, functional = classify(assignment)
        rows.append(
            Measurement(
                assignment_id=assignment.assignment_id,
                code_status=code,
                oracle_status=oracle,
                functional_status=functional,
                generator_evidence_sha256=content_hash({"generator": assignment.assignment_id}),
                code_sha256=(
                    content_hash({"assignment_id": assignment.assignment_id})
                    if code is CodeStatus.VALID
                    else None
                ),
                oracle_evidence_sha256=(
                    content_hash({"oracle": assignment.assignment_id})
                    if code is CodeStatus.VALID
                    else None
                ),
                functional_evidence_sha256=(
                    content_hash({"functional": assignment.assignment_id})
                    if code is CodeStatus.VALID
                    else None
                ),
                terminal_reason=None if code is CodeStatus.VALID else code.value,
            )
        )
    return tuple(rows)


def measurement_document(study: StudyFreeze, rows: tuple[Measurement, ...]) -> dict:
    return {
        "study_id": study.study_id,
        "adapter_ids": {
            "generator": study.adapters.generator.adapter_id,
            "security_oracle": study.adapters.security_oracle.adapter_id,
            "functional_evaluator": study.adapters.functional_evaluator.adapter_id,
        },
        "records": [
            {
                "assignment_id": row.assignment_id,
                "code_status": row.code_status.value,
                "oracle_status": row.oracle_status.value,
                "functional_status": row.functional_status.value,
                "generator_evidence_sha256": row.generator_evidence_sha256,
                **({"code_sha256": row.code_sha256} if row.code_sha256 else {}),
                **(
                    {"oracle_evidence_sha256": row.oracle_evidence_sha256}
                    if row.oracle_evidence_sha256
                    else {}
                ),
                **(
                    {"functional_evidence_sha256": row.functional_evidence_sha256}
                    if row.functional_evidence_sha256
                    else {}
                ),
                **({"terminal_reason": row.terminal_reason} if row.terminal_reason else {}),
            }
            for row in rows
        ],
        "infrastructure_failures": [],
    }


def changed_spec() -> dict:
    return deepcopy(protocol_spec())


def _default_labels(
    assignment: Assignment,
) -> tuple[CodeStatus, OracleStatus, FunctionalStatus]:
    oracle = OracleStatus.SECURE if assignment.arm.value == "target" else OracleStatus.INSECURE
    return CodeStatus.VALID, oracle, FunctionalStatus.PASS


def _adapter(name: str) -> dict[str, str]:
    return {"name": name, "version": "1", "policy_sha256": content_hash(name)}


def _arm_record(task_id: str, realization: str, arm: str) -> dict:
    return {
        "intervention_text": f"{task_id} {realization} {arm}",
        "executor_evidence_sha256": content_hash(
            {"executor": task_id, "realization": realization, "arm": arm}
        ),
        "validation": {
            "task_preserved": "yes",
            "contract_satisfied": "yes",
            "unintended_changes": "no",
            "contradiction": "no",
            "evidence_sha256": content_hash(
                {"validator": task_id, "realization": realization, "arm": arm}
            ),
        },
    }


def _task(task_id: str, cluster: str, split: str, *, weight: int = 1) -> dict:
    return {
        "task_id": task_id,
        "semantic_cluster_id": cluster,
        "cwe": "CWE-89",
        "archetype": "database",
        "split": split,
        "prompt": f"Task {task_id}",
        "weight": weight,
    }
