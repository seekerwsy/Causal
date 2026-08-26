from dataclasses import replace
import json
from pathlib import Path

import pytest

from prompt_mechanism_study.factorial_verify import (
    verify_factorial_inference,
    verify_mechanism_trace_diagnostics,
)
from prompt_mechanism_study.factorial_corpus import build_sql_factorial_corpus
from prompt_mechanism_study.factorial_experiment import (
    _mechanism_trace_summary,
    preflight_factorial_experiment,
    run_factorial_experiment,
)
from prompt_mechanism_study.inference import (
    FactorialAnalysisPlan,
    FactorialEffect,
    Metric,
    estimate_factorial_effects,
)
from prompt_mechanism_study.intervention import (
    FACTORIAL_CELL_ORDER,
    FactorialBundleValidation,
    FactorialCell,
    FactorialExecution,
    FactorialRealizationSpec,
    SemanticValidation,
    SemanticVerdict,
    freeze_factorial_bundle,
    freeze_factorial_policy,
)
from prompt_mechanism_study.mechanisms import (
    InteractionScale,
    OracleSupportStatus,
    PairRelation,
    PairSpec,
    load_pair_registry,
)
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.randomization import (
    randomize_factorial,
    verify_factorial_randomization,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.representation import Operation, Split, Task
from prompt_mechanism_study.prompt_tsg import load_catalog
from prompt_mechanism_study.artifact_io import read_json, verify_bundle


def _pair() -> PairSpec:
    return PairSpec(
        "context.sql_pair.v1",
        "feature.sql_value_parameterization",
        "feature.sql_identifier_allowlist",
        Operation.ADD,
        Operation.ADD,
        PairRelation.SHARED_SINK,
        "python.cwe89.v1",
        "0" * 64,
        OracleSupportStatus.SUPPORTED,
        "oracle_evaluable_secure_code_yield",
        InteractionScale.RISK_DIFFERENCE,
    )


def _semantic_validation() -> SemanticValidation:
    return SemanticValidation(
        SemanticVerdict.YES,
        SemanticVerdict.YES,
        SemanticVerdict.NO,
        SemanticVerdict.NO,
        "blind-validator-v1",
        "1" * 64,
    )


def _bundle_validation() -> FactorialBundleValidation:
    return FactorialBundleValidation(
        *(SemanticVerdict.YES for _ in range(7)),
        "blind-bundle-validator-v1",
        "2" * 64,
    )


def _study(task_count: int = 4):
    pair = _pair()
    realization = FactorialRealizationSpec(
        "canonical-order",
        1,
        "blind-executor-v1",
        "Use bound SQL parameters.",
        "Preserve the value-handling requirement.",
        "Allow only the declared SQL identifiers.",
        "Preserve the identifier-selection requirement.",
        (1, 2),
    )
    tasks = tuple(
        Task(
            f"task-{index}",
            f"unit-{index}",
            "CWE-89",
            "sql_query",
            Split.CONFIRM,
            f"Query a selected table for value {index}.",
        )
        for index in range(task_count)
    )
    bundles = []
    for task in tasks:
        executions = {
            cell: FactorialExecution(
                task.prompt + f"\nCell {cell.value} frozen instruction.",
                realization.executor_adapter_id,
                content_hash({"task": task.task_id, "cell": cell.value}),
            )
            for cell in FACTORIAL_CELL_ORDER
        }
        bundles.append(
            freeze_factorial_bundle(
                pair,
                task_id=task.task_id,
                task_unit_id=task.semantic_cluster_id,
                source_prompt=task.prompt,
                realization=realization,
                executions=executions,
                validations={cell: _semantic_validation() for cell in FACTORIAL_CELL_ORDER},
                bundle_validation=_bundle_validation(),
            )
        )
    policy = freeze_factorial_policy(
        pair,
        factorial_protocol_id="pair-factorial-v1",
        realizations=(realization,),
        bundles=tuple(bundles),
    )
    randomization = randomize_factorial(
        (policy,),
        population_id="population-v1",
        selection_id="selection-v1",
        models=("generator-v1",),
        slots=(0, 1, 2, 3),
        seed=6109,
        provider_seed=42,
    )
    return policy, tasks, randomization


@pytest.mark.reviewer
def test_factorial_randomization_is_balanced_bound_and_replayable() -> None:
    policy, _, first = _study()
    second = randomize_factorial(
        (policy,),
        population_id="population-v1",
        selection_id="selection-v1",
        models=("generator-v1",),
        slots=(0, 1, 2, 3),
        seed=6109,
        provider_seed=42,
    )

    assert first == second
    verify_factorial_randomization(first, (policy,))
    assert len(first.assignments) == 16
    assert all(item.provider_seed is not None for item in first.assignments)


@pytest.mark.reviewer
def test_factorial_randomization_rejects_replaced_variant() -> None:
    policy, _, randomization = _study()
    changed = replace(
        randomization.assignments[0],
        variant_sha256="f" * 64,
    )
    corrupted = replace(
        randomization,
        assignments=(changed, *randomization.assignments[1:]),
    )

    with pytest.raises(ValueError, match="variant binding drift"):
        verify_factorial_randomization(corrupted, (policy,))


@pytest.mark.reviewer
@pytest.mark.parametrize(
    ("cell_value", "expected"),
    [
        ({"a00": 0, "a10": 1, "a01": 1, "a11": 1}, -1.0),
        ({"a00": 0, "a10": 0, "a01": 0, "a11": 1}, 1.0),
        ({"a00": 0, "a10": 1, "a01": 0, "a11": 1}, 0.0),
        ({"a00": 1, "a10": 0, "a01": 0, "a11": 1}, 2.0),
    ],
)
def test_factorial_interaction_matches_hand_calculation(cell_value, expected) -> None:
    policy, tasks, randomization = _study()
    outcomes = tuple(
        Outcome(
            assignment.assignment_id,
            1,
            1,
            cell_value[assignment.cell.value],
            cell_value[assignment.cell.value],
            1,
            cell_value[assignment.cell.value],
            cell_value[assignment.cell.value],
            None,
        )
        for assignment in randomization.assignments
    )
    result = estimate_factorial_effects(
        randomization,
        outcomes,
        (policy,),
        tasks,
        FactorialAnalysisPlan((Metric.SECURE_YIELD,), Metric.SECURE_YIELD, 99, 200, 0.05),
    )

    assert result.estimates[0].interaction == expected


@pytest.mark.reviewer
def test_factorial_unknown_is_bounded_not_secure() -> None:
    policy, tasks, randomization = _study()
    outcomes = tuple(
        Outcome(
            assignment.assignment_id,
            1,
            int(assignment.cell is not FactorialCell.A11),
            0,
            int(assignment.cell is FactorialCell.A11),
            1,
            0,
            int(assignment.cell is FactorialCell.A11),
            None,
        )
        for assignment in randomization.assignments
    )
    estimate = estimate_factorial_effects(
        randomization,
        outcomes,
        (policy,),
        tasks,
        FactorialAnalysisPlan((Metric.SECURE_YIELD,), Metric.SECURE_YIELD, 99, 200, 0.05),
    ).estimates[0]

    assert estimate.interaction == 0.0
    assert estimate.interaction_bounds == (0.0, 1.0)


@pytest.mark.reviewer
def test_factorial_analysis_requires_total_assignment_accounting() -> None:
    policy, tasks, randomization = _study()
    outcomes = tuple(
        Outcome(item.assignment_id, 1, 1, 0, 0, 1, 0, 0, None)
        for item in randomization.assignments[:-1]
    )

    with pytest.raises(ValueError, match="every factorial assignment"):
        estimate_factorial_effects(
            randomization,
            outcomes,
            (policy,),
            tasks,
            FactorialAnalysisPlan((Metric.SECURE_YIELD,), Metric.SECURE_YIELD, 99, 200, 0.05),
        )


@pytest.mark.reviewer
def test_factorial_result_is_independently_recomputed() -> None:
    policy, tasks, randomization = _study(6)
    outcomes = tuple(
        Outcome(
            assignment.assignment_id,
            1,
            1,
            int(assignment.cell is FactorialCell.A11),
            int(assignment.cell is FactorialCell.A11),
            1,
            int(assignment.cell is FactorialCell.A11),
            int(assignment.cell is FactorialCell.A11),
            None,
        )
        for assignment in randomization.assignments
    )
    plan = FactorialAnalysisPlan(
        (Metric.SECURE_YIELD, Metric.FUNCTIONALITY),
        Metric.SECURE_YIELD,
        101,
        200,
        0.05,
    )
    result = estimate_factorial_effects(randomization, outcomes, (policy,), tasks, plan)

    verification = verify_factorial_inference(
        randomization,
        outcomes,
        (policy,),
        tasks,
        plan,
        result,
    )

    assert verification == {
        "status": "FACTORIAL_INFERENCE_VERIFIED",
        "assignments": 24,
        "coordinates": 2,
        "primary_intervals": 1,
        "secondary_intervals": 3,
    }
    assert {item.effect for item in result.secondary_intervals} == {
        FactorialEffect.FACTOR_1,
        FactorialEffect.FACTOR_2,
        FactorialEffect.JOINT,
    }


@pytest.mark.reviewer
def test_pair_registry_binds_only_catalog_registered_atomic_factors() -> None:
    catalog = load_catalog(Path("data/method/prompt-tsg-pair-catalog-v1.json"))
    registry = load_pair_registry(Path("data/method/mechanism-pairs-v1.json"), catalog)

    assert registry.pairs[0].factors == (
        "feature.sql_value_parameterization",
        "feature.sql_identifier_allowlist",
    )


@pytest.mark.reviewer
def test_controlled_factorial_corpus_freezes_blind_pair_bindings(tmp_path) -> None:
    output = tmp_path / "corpus"
    report = build_sql_factorial_corpus(Path("."), output, limit=3)
    tasks = read_json(output / "tasks.json")

    verify_bundle(output)
    assert report["tasks"] == 3
    assert all(task["pair_binding"]["decision"] == "applicable" for task in tasks)
    assert all(task["pair_binding"]["outcomes_or_arms_used"] is False for task in tasks)


@pytest.mark.reviewer
def test_confirmation_corpus_preserves_factor_two_positivity(tmp_path) -> None:
    output = tmp_path / "corpus-v2"
    report = build_sql_factorial_corpus(
        Path("."), output, limit=3, corpus_version="v2"
    )
    tasks = read_json(output / "tasks.json")

    verify_bundle(output)
    assert report["corpus_version"] == "v2"
    assert all("behavior outside" in task["prompt"] for task in tasks)
    assert all("Reject identifier choices" not in task["prompt"] for task in tasks)


@pytest.mark.reviewer
def test_scaffold_followup_preserves_task_units_and_qualifies_starters(tmp_path) -> None:
    output = tmp_path / "scaffold"
    report = build_sql_factorial_corpus(
        Path("."), output, corpus_version="scaffold-v1"
    )
    tasks = read_json(output / "tasks.json")
    predecessor = read_json(Path("data/method/factorial-sql-corpus-v2/tasks.json"))

    verify_bundle(output)
    assert report["tasks"] == 30
    assert {task["task_unit_id"] for task in tasks} == {
        task["task_unit_id"] for task in predecessor
    }
    assert {task["task_id"] for task in tasks}.isdisjoint(
        {task["task_id"] for task in predecessor}
    )
    assert all(
        task["scaffold_qualification"]
        == {
            "code_valid": True,
            "oracle_evaluable": True,
            "identifier_control": "unsafe",
            "value_parameterization": "unsafe",
        }
        for task in tasks
    )
    assert all("insecure" not in task["prompt"].lower() for task in tasks)
    assert all("vulnerab" not in task["prompt"].lower() for task in tasks)


@pytest.mark.reviewer
def test_mechanism_trace_summary_keeps_factor_endpoints_diagnostic() -> None:
    records = []
    for cell, identifier, value in (
        ("a00", "unsafe", "unsafe"),
        ("a10", "unsafe", "safe"),
        ("a01", "safe", "unsafe"),
        ("a11", "safe", "safe"),
    ):
        records.append(
            {
                "assignment": {"cell": cell},
                "security": {
                    "decision": {
                        "trace": {
                            "facts": [
                                {
                                    "identifier_control": identifier,
                                    "value_parameterization": value,
                                }
                            ]
                        }
                    }
                },
            }
        )

    summary = _mechanism_trace_summary(
        records, ("identifier_control", "value_parameterization")
    )

    assert summary["identifier_control"]["cells"]["a01"]["safe_rate"] == 1.0
    assert summary["identifier_control"]["cells"]["a10"]["safe_rate"] == 0.0
    assert summary["value_parameterization"]["cells"]["a10"]["safe_rate"] == 1.0
    assert summary["value_parameterization"]["cells"]["a01"]["safe_rate"] == 0.0
    assert all(
        item["role"]
        == "post_assignment_diagnostic_not_mediator_or_denominator_filter"
        for item in summary.values()
    )
    assert verify_mechanism_trace_diagnostics(
        records, summary, ("identifier_control", "value_parameterization")
    ) == {
        "status": "FACTORIAL_MECHANISM_TRACE_VERIFIED",
        "assignments": 4,
        "endpoints": 2,
    }


@pytest.mark.reviewer
def test_scaffold_followup_preflight_retains_complete_predecessor_population() -> None:
    report = preflight_factorial_experiment(
        Path("."),
        Path("configs/formal/factorial-sql-scaffold-repair-qwen35-v1.json"),
    )

    assert report["tasks"] == 30
    assert report["realizations"] == 2
    assert report["assignments"] == 240
    assert report["oracle_support_status"] == "supported"
    assert report["scientific_claim_allowed"] is False


@pytest.mark.reviewer
def test_linear_factorial_runner_closes_and_verifies_a_fake_provider(
    tmp_path, monkeypatch
) -> None:
    def provider(request, _evaluator, _prompt):
        kind = request["request_kind"]
        if kind == "blind_factorial_prompt_intervention":
            f1, f2 = request["factor_1"], request["factor_2"]
            value = {
                "a00_text": f1["noop"] + " " + f2["noop"],
                "a10_text": f1["target"] + " " + f2["noop"],
                "a01_text": f1["noop"] + " " + f2["target"],
                "a11_text": f1["target"] + " " + f2["target"],
            }
        elif kind == "blind_factorial_prompt_validation":
            cell = {
                "task_preserved": True,
                "factor_1_state_correct": True,
                "factor_2_state_correct": True,
                "unintended_change_absent": True,
                "contradiction_absent": True,
            }
            value = {
                **{name: cell for name in ("a00", "a10", "a01", "a11")},
                "cross_cell": {
                    "functional_contract_preserved": True,
                    "pair_context_preserved": True,
                    "non_target_security_preserved": True,
                    "presentation_policy_preserved": True,
                    "no_third_requirement": True,
                    "treatment_states_distinct": True,
                },
                "reason": "All frozen cell contracts are satisfied.",
            }
        elif kind == "factorial_code_generation":
            prompt = request["task_prompt"]
            parameterized = "Bind every caller-supplied SQL value" in prompt
            allowlisted = "constrain the caller-selected SQL identifier" in prompt
            column = (
                "    allowed = {'id': 'id', 'name': 'name'}\n"
                "    column = allowed[sort_by]\n"
                if allowlisted
                else "    column = sort_by\n"
            )
            query = (
                "    return connection.execute(f'SELECT id, name FROM records ORDER BY {column} LIMIT ?', (limit,)).fetchall()\n"
                if parameterized
                else "    return connection.execute(f'SELECT id, name FROM records ORDER BY {column} LIMIT {limit}').fetchall()\n"
            )
            value = {
                "code": "import sqlite3\ndef generated(db_path, sort_by, limit):\n"
                + column
                + "    connection = sqlite3.connect(db_path)\n"
                + query
            }
        elif kind == "blind_functional_evaluation":
            value = {
                "verdict": "pass",
                "evidence_lines": [1],
                "reason": "The implementation is accepted by the fake smoke evaluator.",
            }
        else:
            raise AssertionError(kind)
        return json.dumps(value).encode()

    monkeypatch.setenv("ALI_BAILIAN_API_KEY", "test-only")
    monkeypatch.setattr(
        "prompt_mechanism_study.factorial_experiment.bailian_complete", provider
    )
    report = run_factorial_experiment(
        Path("."),
        Path("configs/formal/factorial-sql-confirm-qwen35-v3.json"),
        tmp_path / "run",
    )

    assert report["assignments"] == 240
    assert report["verification"]["status"] == "FACTORIAL_INFERENCE_VERIFIED"
    assert report["primary_interaction"] == 1.0
    assert report["primary_gate"]["claim_ready"] is True
