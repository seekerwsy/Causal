"""Independent recomputation of the pairwise factorial result.

This module deliberately does not import the production inference module.
"""

from __future__ import annotations

import math
import random
import statistics
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from prompt_mechanism_study.artifact_io import read_json, verify_bundle
from prompt_mechanism_study.intervention import FACTORIAL_CELL_ORDER, FactorialCell
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.records import content_hash, content_id


def verify_factorial_inference(
    randomization: Any,
    outcomes: Iterable[Outcome],
    policies: Iterable[Any],
    tasks: Iterable[Any],
    plan: Any,
    reported: Any,
) -> dict[str, Any]:
    """Recompute assignment support, four cell means, delta, and max-|T| intervals."""

    assignments = tuple(randomization.assignments)
    frozen_outcomes = tuple(outcomes)
    outcome_by_id = {item.assignment_id: item for item in frozen_outcomes}
    if len(outcome_by_id) != len(frozen_outcomes) or set(outcome_by_id) != {
        item.assignment_id for item in assignments
    }:
        raise ValueError("independent verifier found incomplete or duplicate outcomes")
    policy_by_pair = {item.pair.pair_id: item for item in policies}
    task_by_id = {item.task_id: item for item in tasks}
    _verify_assignment_support(randomization, policy_by_pair)

    recomputed = []
    for estimate in reported.estimates:
        pair_id = estimate.pair_id
        model_id = estimate.model_id
        metric = _name(estimate.metric)
        policy = policy_by_pair.get(pair_id)
        if policy is None:
            raise ValueError("reported factorial pair is not frozen")
        coordinate_assignments = tuple(
            item
            for item in assignments
            if item.block.pair_id == pair_id and item.block.model_id == model_id
        )
        unit_ids = sorted({item.block.task_unit_id for item in coordinate_assignments})
        unit_rows = []
        for unit_id in unit_ids:
            cells = {
                cell: _unit_cell(
                    coordinate_assignments,
                    outcome_by_id,
                    policy,
                    task_by_id,
                    unit_id,
                    cell,
                    metric,
                )
                for cell in FACTORIAL_CELL_ORDER
            }
            points = {cell: cells[cell][0] for cell in FACTORIAL_CELL_ORDER}
            unit_rows.append(
                {
                    "task_unit_id": unit_id,
                    "cells": cells,
                    "interaction": _interaction(points),
                }
            )
        cell_rows = {
            cell: (
                _mean_or_none([row["cells"][cell][0] for row in unit_rows]),
                _mean([row["cells"][cell][1] for row in unit_rows]),
                _mean([row["cells"][cell][2] for row in unit_rows]),
                sum(item.cell is cell for item in coordinate_assignments),
            )
            for cell in FACTORIAL_CELL_ORDER
        }
        points = {cell: cell_rows[cell][0] for cell in FACTORIAL_CELL_ORDER}
        lower = {cell: cell_rows[cell][1] for cell in FACTORIAL_CELL_ORDER}
        upper = {cell: cell_rows[cell][2] for cell in FACTORIAL_CELL_ORDER}
        expected = {
            "cells": cell_rows,
            "factor_1": _difference(points[FactorialCell.A10], points[FactorialCell.A00]),
            "factor_2": _difference(points[FactorialCell.A01], points[FactorialCell.A00]),
            "joint": _difference(points[FactorialCell.A11], points[FactorialCell.A00]),
            "interaction": _interaction(points),
            "factor_1_bounds": (
                lower[FactorialCell.A10] - upper[FactorialCell.A00],
                upper[FactorialCell.A10] - lower[FactorialCell.A00],
            ),
            "factor_2_bounds": (
                lower[FactorialCell.A01] - upper[FactorialCell.A00],
                upper[FactorialCell.A01] - lower[FactorialCell.A00],
            ),
            "joint_bounds": (
                lower[FactorialCell.A11] - upper[FactorialCell.A00],
                upper[FactorialCell.A11] - lower[FactorialCell.A00],
            ),
            "interaction_bounds": _interaction_bounds(cell_rows),
            "unit_rows": unit_rows,
        }
        _verify_estimate(estimate, expected)
        recomputed.append((estimate, expected))

    intervals, critical = _bootstrap_intervals(recomputed, plan)
    _same(critical, reported.simultaneous_critical_value)
    stored_intervals = {item.coordinate_id: item for item in reported.intervals}
    if set(stored_intervals) != set(intervals):
        raise ValueError("independent verifier found interval coordinate drift")
    for coordinate_id, expected in intervals.items():
        stored = stored_intervals[coordinate_id]
        _same(expected[0], stored.standard_error)
        _same(expected[1], stored.lower)
        _same(expected[2], stored.upper)
    secondary, secondary_critical = _secondary_bootstrap_intervals(recomputed, plan)
    _same(secondary_critical, reported.secondary_critical_value)
    stored_secondary = {
        (item.coordinate_id, _name(item.effect)): item
        for item in reported.secondary_intervals
    }
    if set(stored_secondary) != set(secondary):
        raise ValueError("independent verifier found secondary interval drift")
    for key, expected in secondary.items():
        stored = stored_secondary[key]
        _same(expected[0], stored.standard_error)
        _same(expected[1], stored.lower)
        _same(expected[2], stored.upper)
    return {
        "status": "FACTORIAL_INFERENCE_VERIFIED",
        "assignments": len(assignments),
        "coordinates": len(recomputed),
        "primary_intervals": len(intervals),
        "secondary_intervals": len(secondary),
    }


def verify_mechanism_trace_diagnostics(
    records: Iterable[Mapping[str, Any]],
    reported: Mapping[str, Any],
    endpoints: Iterable[str],
) -> dict[str, Any]:
    """Independently recompute assignment-level Oracle trace diagnostics."""

    frozen_records = tuple(records)
    frozen_endpoints = tuple(endpoints)
    if set(reported) != set(frozen_endpoints):
        raise ValueError("independent verifier found mechanism endpoint drift")
    for endpoint in frozen_endpoints:
        endpoint_report = reported[endpoint]
        if (
            endpoint_report.get("role")
            != "post_assignment_diagnostic_not_mediator_or_denominator_filter"
            or set(endpoint_report.get("cells", {}))
            != {cell.value for cell in FACTORIAL_CELL_ORDER}
        ):
            raise ValueError("independent verifier found mechanism trace schema drift")
        for cell in FACTORIAL_CELL_ORDER:
            selected = tuple(
                item
                for item in frozen_records
                if item["assignment"]["cell"] == cell.value
            )
            states = tuple(
                _trace_state(item.get("security"), endpoint) for item in selected
            )
            safe = states.count("safe")
            expected = {
                "assignments": len(selected),
                "safe": safe,
                "unsafe": states.count("unsafe"),
                "unknown": states.count("unknown"),
                "safe_rate": safe / len(selected) if selected else None,
            }
            observed = endpoint_report["cells"][cell.value]
            if set(observed) != set(expected):
                raise ValueError("independent verifier found mechanism trace field drift")
            for key, value in expected.items():
                _same(value, observed[key])
    return {
        "status": "FACTORIAL_MECHANISM_TRACE_VERIFIED",
        "assignments": len(frozen_records),
        "endpoints": len(frozen_endpoints),
    }



def verify_factorial_result_bundle(root: Path) -> dict[str, Any]:
    """Recompute a stored active-path result without importing production inference."""

    verify_bundle(root)
    study = read_json(root / "study-freeze.json")
    records = read_json(root / "measurement-records.json")
    analysis = read_json(root / "analysis.json")
    report = read_json(root / "report.json")
    config = read_json(root / "effective-config.json")
    stored_verification = read_json(root / "verification.json")
    envelopes = (study, analysis, report, config, stored_verification)
    if not all(isinstance(item, dict) for item in envelopes):
        raise ValueError("stored factorial result envelope is invalid")
    if not isinstance(records, list) or not records:
        raise ValueError("stored factorial measurement records are empty")

    raw_assignments = tuple(study.get("randomization", {}).get("assignments", ()))
    assignment_by_id = {
        content_id("factorial_assignment_", item): item for item in raw_assignments
    }
    if not raw_assignments or len(assignment_by_id) != len(raw_assignments):
        raise ValueError("stored factorial assignments are empty or duplicated")

    record_by_id: dict[str, Mapping[str, Any]] = {}
    derived_outcomes: dict[str, dict[str, Any]] = {}
    for record in records:
        measurement = record.get("measurement", {})
        assignment_id = measurement.get("assignment_id")
        if (
            assignment_id not in assignment_by_id
            or assignment_id in record_by_id
            or record.get("assignment") != assignment_by_id[assignment_id]
        ):
            raise ValueError("stored factorial measurement-to-assignment binding drift")
        record_by_id[assignment_id] = record
        derived_outcomes[assignment_id] = _stored_outcome(measurement)
    if set(record_by_id) != set(assignment_by_id):
        raise ValueError("stored factorial measurements do not cover every assignment")

    stored_outcomes = {
        item["assignment_id"]: item for item in analysis.get("outcomes", ())
    }
    if stored_outcomes != derived_outcomes:
        raise ValueError("stored factorial outcome derivation drift")

    randomization, outcomes, policies, tasks, plan, reported = _stored_views(
        study, analysis["inference"], derived_outcomes
    )
    inference_verification = verify_factorial_inference(
        randomization, outcomes, policies, tasks, plan, reported
    )
    if inference_verification != stored_verification:
        raise ValueError("stored factorial inference verification drift")

    endpoints = tuple(report.get("mechanism_trace_diagnostics", {}))
    trace_verification = verify_mechanism_trace_diagnostics(
        records, report.get("mechanism_trace_diagnostics", {}), endpoints
    )
    _verify_stored_report(
        report,
        config,
        study,
        analysis["inference"],
        trace_verification,
        inference_verification,
        len(raw_assignments),
    )
    return {
        "status": "FACTORIAL_RESULT_BUNDLE_VERIFIED",
        "assignments": len(raw_assignments),
        "task_units": len(
            {item["block"]["task_unit_id"] for item in raw_assignments}
        ),
        "coordinates": inference_verification["coordinates"],
        "primary_intervals": inference_verification["primary_intervals"],
        "secondary_intervals": inference_verification["secondary_intervals"],
        "mechanism_trace_endpoints": len(endpoints),
    }


def _stored_outcome(measurement: Mapping[str, Any]) -> dict[str, Any]:
    assignment_id = measurement["assignment_id"]
    code_status = measurement["code_status"]
    if code_status != "valid":
        return {
            "assignment_id": assignment_id,
            "code_valid": 0,
            "oracle_evaluable": 0,
            "secure_yield": 0,
            "latent_secure_upper": 0,
            "functionality": 0,
            "joint": 0,
            "latent_joint_upper": 0,
            "terminal_status": code_status,
        }
    oracle = measurement["oracle_status"]
    functional = measurement["functional_status"]
    functionality = 1 if functional == "pass" else 0 if functional == "fail" else None
    evaluable = int(oracle in {"secure", "insecure"})
    secure = int(oracle == "secure")
    latent_upper = int(oracle in {"secure", "unknown"})
    if oracle == "insecure" or functionality == 0:
        joint = 0
    elif oracle == "unknown" or functionality is None:
        joint = None
    else:
        joint = 1
    return {
        "assignment_id": assignment_id,
        "code_valid": 1,
        "oracle_evaluable": evaluable,
        "secure_yield": secure,
        "latent_secure_upper": latent_upper,
        "functionality": functionality,
        "joint": joint,
        "latent_joint_upper": int(latent_upper == 1 and functionality != 0),
        "terminal_status": None,
    }


def _stored_views(
    study: Mapping[str, Any],
    inference: Mapping[str, Any],
    outcomes: Mapping[str, Mapping[str, Any]],
) -> tuple[Any, tuple[Any, ...], tuple[Any, ...], tuple[Any, ...], Any, Any]:
    raw_randomization = study["randomization"]
    assignments = tuple(
        SimpleNamespace(
            assignment_id=content_id("factorial_assignment_", item),
            block=SimpleNamespace(**item["block"]),
            cell=FactorialCell(item["cell"]),
            request_slot=item["request_slot"],
            variant_sha256=item["variant_sha256"],
        )
        for item in raw_randomization["assignments"]
    )
    randomization = SimpleNamespace(
        assignments=assignments,
        models=tuple(raw_randomization["models"]),
        slots=tuple(raw_randomization["slots"]),
    )

    policies = []
    for raw_policy in study["policies"]:
        raw_pair = raw_policy["pair"]
        pair = SimpleNamespace(
            pair_id=content_id("pair_", raw_pair),
            pair_context_query_id=raw_pair["pair_context_query_id"],
        )
        realizations = tuple(
            SimpleNamespace(
                realization_id=content_id("factorial_realization_", item),
                weight=item["weight"],
            )
            for item in raw_policy["realizations"]
        )
        realization_ids = {item.realization_id for item in realizations}
        bundles = []
        for raw_bundle in raw_policy["bundles"]:
            if (
                raw_bundle["pair_id"] != pair.pair_id
                or raw_bundle["realization_id"] not in realization_ids
            ):
                raise ValueError("stored factorial bundle policy binding drift")
            variants = {
                FactorialCell(item["cell"]): SimpleNamespace(
                    variant_sha256=content_hash(item["execution"]["prompt_text"])
                )
                for item in raw_bundle["variants"]
            }
            if set(variants) != set(FACTORIAL_CELL_ORDER):
                raise ValueError("stored factorial bundle cell support drift")
            bundle = SimpleNamespace(
                task_unit_id=raw_bundle["task_unit_id"],
                task_id=raw_bundle["task_id"],
                realization_id=raw_bundle["realization_id"],
                task_bundle_id=content_id("factorial_task_bundle_", raw_bundle),
            )
            bundle.variant = variants.__getitem__
            bundles.append(bundle)
        policies.append(
            SimpleNamespace(
                pair=pair,
                realizations=realizations,
                bundles=tuple(bundles),
                factorial_protocol_id=raw_policy["factorial_protocol_id"],
            )
        )

    tasks = tuple(
        SimpleNamespace(task_id=item["task_id"], weight=item["weight"])
        for item in study["tasks"]
    )
    plan_raw = study["analysis_plan"]
    plan = SimpleNamespace(
        primary_metric=plan_raw["primary_metric"],
        bootstrap_seed=plan_raw["bootstrap_seed"],
        bootstrap_draws=plan_raw["bootstrap_draws"],
        alpha=plan_raw["alpha"],
        secondary_effects=tuple(plan_raw["secondary_effects"]),
    )
    estimates = tuple(_stored_estimate_view(item) for item in inference["estimates"])
    reported = SimpleNamespace(
        estimates=estimates,
        simultaneous_critical_value=inference["simultaneous_critical_value"],
        intervals=tuple(SimpleNamespace(**item) for item in inference["intervals"]),
        secondary_critical_value=inference["secondary_critical_value"],
        secondary_intervals=tuple(
            SimpleNamespace(**item) for item in inference["secondary_intervals"]
        ),
    )
    outcome_views = tuple(SimpleNamespace(**item) for item in outcomes.values())
    return randomization, outcome_views, tuple(policies), tasks, plan, reported


def _stored_estimate_view(item: Mapping[str, Any]) -> Any:
    coordinate_id = content_id(
        "factorial_coordinate_",
        {
            "pair_id": item["pair_id"],
            "model_id": item["model_id"],
            "metric": item["metric"],
        },
    )
    return SimpleNamespace(
        coordinate_id=coordinate_id,
        pair_id=item["pair_id"],
        model_id=item["model_id"],
        metric=item["metric"],
        cells=tuple(
            SimpleNamespace(**{**cell, "cell": FactorialCell(cell["cell"])})
            for cell in item["cells"]
        ),
        factor_1=item["factor_1"],
        factor_2=item["factor_2"],
        joint=item["joint"],
        interaction=item["interaction"],
        factor_1_bounds=tuple(item["factor_1_bounds"]),
        factor_2_bounds=tuple(item["factor_2_bounds"]),
        joint_bounds=tuple(item["joint_bounds"]),
        interaction_bounds=tuple(item["interaction_bounds"]),
        task_unit_effects=tuple(
            SimpleNamespace(
                task_unit_id=unit["task_unit_id"],
                interaction=unit["interaction"],
            )
            for unit in item["task_unit_effects"]
        ),
    )


def _verify_stored_report(
    report: Mapping[str, Any],
    config: Mapping[str, Any],
    study: Mapping[str, Any],
    inference: Mapping[str, Any],
    trace_verification: Mapping[str, Any],
    inference_verification: Mapping[str, Any],
    assignment_count: int,
) -> None:
    analysis_estimates = {
        (item["pair_id"], item["model_id"], item["metric"]): item
        for item in inference["estimates"]
    }
    report_estimates = {
        (item["pair_id"], item["model_id"], item["metric"]): item
        for item in report.get("estimates", ())
    }
    if set(report_estimates) != set(analysis_estimates):
        raise ValueError("stored factorial report estimate support drift")
    for key, source in analysis_estimates.items():
        observed = report_estimates[key]
        expected_cells = {
            item["cell"]: {
                name: item[name] for name in ("point", "lower", "upper", "assignments")
            }
            for item in source["cells"]
        }
        if observed.get("cells") != expected_cells:
            raise ValueError("stored factorial report cell estimate drift")
        for name in (
            "factor_1",
            "factor_2",
            "joint",
            "interaction",
            "factor_1_bounds",
            "factor_2_bounds",
            "joint_bounds",
            "interaction_bounds",
        ):
            if observed.get(name) != source[name]:
                raise ValueError("stored factorial report effect estimate drift")

    analysis_config = config["analysis"]
    primary_keys = [
        key
        for key in analysis_estimates
        if key[2] == analysis_config["primary_metric"]
    ]
    intervals = inference["intervals"]
    if len(primary_keys) != 1 or len(intervals) != 1:
        raise ValueError("stored factorial report requires one primary coordinate")
    pair_id, model_id, _ = primary_keys[0]
    primary = analysis_estimates[primary_keys[0]]
    interval = intervals[0]
    if report.get("primary_simultaneous_interval") != interval:
        raise ValueError("stored factorial report primary interval drift")
    significant = interval["lower"] > 0.0 or interval["upper"] < 0.0
    _same(primary["interaction"], report.get("primary_interaction"))
    if report.get("primary_interval_excludes_zero") is not significant:
        raise ValueError("stored factorial report significance drift")

    expected_secondary = [
        {
            **item,
            "excludes_zero": item["lower"] > 0.0 or item["upper"] < 0.0,
        }
        for item in inference["secondary_intervals"]
    ]
    if report.get("secondary_intervals") != expected_secondary:
        raise ValueError("stored factorial report secondary interval drift")

    functionality = analysis_estimates[(pair_id, model_id, "functionality")]
    evaluability = analysis_estimates[(pair_id, model_id, "oracle_evaluable")]
    practical_margin = float(analysis_config["practical_interaction_margin"])
    functionality_margin = float(
        analysis_config["functionality_noninferiority_margin"]
    )
    unknown_limit = float(analysis_config["maximum_unknown_fraction"])
    minimum_evaluability = min(
        item["point"] for item in evaluability["cells"] if item["point"] is not None
    )
    expected_gate = {
        "security_interval_excludes_zero": significant,
        "practical_interaction_margin": practical_margin,
        "practical_interaction_met": primary["interaction"] is not None
        and abs(primary["interaction"]) >= practical_margin,
        "functionality_contrast": "a11_minus_a00",
        "functionality_difference": functionality["joint"],
        "functionality_noninferiority_margin": functionality_margin,
        "functionality_noninferior": functionality["joint"] is not None
        and functionality["joint"] >= -functionality_margin,
        "maximum_unknown_fraction": unknown_limit,
        "minimum_oracle_evaluability": minimum_evaluability,
        "unknown_gate_passed": minimum_evaluability >= 1.0 - unknown_limit,
    }
    expected_gate["claim_ready"] = bool(
        config.get("scientific_claim_allowed", False)
        and all(
            expected_gate[name]
            for name in (
                "security_interval_excludes_zero",
                "practical_interaction_met",
                "functionality_noninferior",
                "unknown_gate_passed",
            )
        )
    )
    if report.get("primary_gate") != expected_gate:
        raise ValueError("stored factorial report claim gate drift")

    expected_status = {
        "development_canary": "FACTORIAL_CANARY_COMPLETE",
        "confirmatory": "FACTORIAL_CONFIRMATION_COMPLETE",
        "prospective_followup": "FACTORIAL_FOLLOWUP_COMPLETE",
    }.get(config.get("phase"))
    if (
        expected_status is None
        or report.get("status") != expected_status
        or report.get("phase") not in (None, config.get("phase"))
        or report.get("study_name") != config.get("study_name")
        or report.get("tasks") != len(study.get("tasks", ()))
        or report.get("realizations") != len(study["policies"][0]["realizations"])
        or report.get("assignments") != assignment_count
        or report.get("verification") != inference_verification
        or report.get("mechanism_trace_verification")
        not in (None, trace_verification)
        or report.get("scientific_claim_allowed")
        is not bool(config.get("scientific_claim_allowed", False))
        or report.get("claim_boundary") != config["corpus"]["generalization_boundary"]
        or report.get("scale_gate") != config["scale_gate"]
    ):
        raise ValueError("stored factorial report envelope drift")
    _same(
        inference["simultaneous_critical_value"],
        report.get("simultaneous_critical_value"),
    )
    _same(
        inference["secondary_critical_value"],
        report.get("secondary_critical_value"),
    )


def _trace_state(security: Mapping[str, Any] | None, endpoint: str) -> str:
    if not security:
        return "unknown"
    facts = security.get("decision", {}).get("trace", {}).get("facts", ())
    states = [item.get(endpoint) for item in facts if isinstance(item, Mapping)]
    if not states or any(item not in {"safe", "unsafe", "unknown"} for item in states):
        return "unknown"
    if "unsafe" in states:
        return "unsafe"
    return "safe" if all(item == "safe" for item in states) else "unknown"


def _verify_assignment_support(randomization: Any, policies: Mapping[str, Any]) -> None:
    expected_blocks = {}
    for policy in policies.values():
        for bundle in policy.bundles:
            for model_id in randomization.models:
                key = (
                    bundle.task_unit_id,
                    bundle.task_id,
                    policy.pair.pair_id,
                    policy.pair.pair_context_query_id,
                    bundle.realization_id,
                    bundle.task_bundle_id,
                    model_id,
                    policy.factorial_protocol_id,
                )
                expected_blocks[key] = bundle
    observed_blocks: dict[tuple[str, ...], list[Any]] = {}
    for assignment in randomization.assignments:
        block = assignment.block
        key = (
            block.task_unit_id,
            block.task_instance_id,
            block.pair_id,
            block.pair_context_query_id,
            block.joint_realization_id,
            block.factorial_task_bundle_id,
            block.model_id,
            block.factorial_protocol_id,
        )
        observed_blocks.setdefault(key, []).append(assignment)
    if set(observed_blocks) != set(expected_blocks):
        raise ValueError("independent verifier found factorial block support drift")
    for key, block in observed_blocks.items():
        bundle = expected_blocks[key]
        if len(block) != len(randomization.slots) or {item.request_slot for item in block} != set(
            randomization.slots
        ):
            raise ValueError("independent verifier found slot support drift")
        counts = Counter(item.cell for item in block)
        if set(counts) != set(FACTORIAL_CELL_ORDER) or len(set(counts.values())) != 1:
            raise ValueError("independent verifier found unbalanced factorial cells")
        if any(
            item.variant_sha256 != bundle.variant(item.cell).variant_sha256 for item in block
        ):
            raise ValueError("independent verifier found replaced prompt variant")


def _unit_cell(
    assignments: tuple[Any, ...],
    outcomes: Mapping[str, Outcome],
    policy: Any,
    tasks: Mapping[str, Any],
    task_unit_id: str,
    cell: FactorialCell,
    metric: str,
) -> tuple[float | None, float, float]:
    task_ids = sorted(
        {
            item.block.task_instance_id
            for item in assignments
            if item.block.task_unit_id == task_unit_id
        }
    )
    task_total = sum(tasks[task_id].weight for task_id in task_ids)
    realization_total = sum(item.weight for item in policy.realizations)
    point = lower = upper = 0.0
    known = True
    for task_id in task_ids:
        for realization in policy.realizations:
            block = [
                item
                for item in assignments
                if item.block.task_unit_id == task_unit_id
                and item.block.task_instance_id == task_id
                and item.block.joint_realization_id == realization.realization_id
                and item.cell is cell
            ]
            if not block:
                raise ValueError("independent verifier found missing task-realization cell")
            values = [_metric(outcomes[item.assignment_id], metric) for item in block]
            weight = tasks[task_id].weight / task_total * realization.weight / realization_total
            if any(value[0] is None for value in values):
                known = False
            else:
                point += weight * _mean([float(value[0]) for value in values])
            lower += weight * _mean([value[1] for value in values])
            upper += weight * _mean([value[2] for value in values])
    return point if known else None, lower, upper


def _metric(outcome: Outcome, metric: str) -> tuple[int | None, int, int]:
    if metric == "secure_yield":
        return outcome.secure_yield, outcome.secure_yield, outcome.latent_secure_upper
    if metric == "joint":
        return outcome.joint, outcome.joint or 0, outcome.latent_joint_upper
    value = getattr(outcome, metric)
    return (None, 0, 1) if value is None else (value, value, value)


def _verify_estimate(estimate: Any, expected: Mapping[str, Any]) -> None:
    stored_cells = {item.cell: item for item in estimate.cells}
    if set(stored_cells) != set(FACTORIAL_CELL_ORDER):
        raise ValueError("reported factorial cells are incomplete")
    for cell, values in expected["cells"].items():
        stored = stored_cells[cell]
        _same(values[0], stored.point)
        _same(values[1], stored.lower)
        _same(values[2], stored.upper)
        if values[3] != stored.assignments:
            raise ValueError("reported factorial assignment count drift")
    for name in ("factor_1", "factor_2", "joint", "interaction"):
        _same(expected[name], getattr(estimate, name))
    for name in (
        "factor_1_bounds",
        "factor_2_bounds",
        "joint_bounds",
        "interaction_bounds",
    ):
        _same(expected[name], getattr(estimate, name))
    stored_units = {item.task_unit_id: item for item in estimate.task_unit_effects}
    if set(stored_units) != {item["task_unit_id"] for item in expected["unit_rows"]}:
        raise ValueError("reported task-unit support drift")
    for row in expected["unit_rows"]:
        _same(row["interaction"], stored_units[row["task_unit_id"]].interaction)


def _bootstrap_intervals(
    rows: list[tuple[Any, Mapping[str, Any]]], plan: Any
) -> tuple[dict[str, tuple[float, float, float]], float]:
    eligible = [
        row
        for row in rows
        if _name(row[0].metric) == _name(plan.primary_metric)
        and row[0].interaction is not None
        and all(unit["interaction"] is not None for unit in row[1]["unit_rows"])
    ]
    if not eligible:
        return {}, 0.0
    support_by_coordinate = {
        estimate.coordinate_id: tuple(unit["task_unit_id"] for unit in expected["unit_rows"])
        for estimate, expected in eligible
    }
    rng_by_support = {
        support: random.Random(
            int(content_id("bootstrap_", {"seed": plan.bootstrap_seed, "support": support})[-16:], 16)
        )
        for support in set(support_by_coordinate.values())
    }
    draws = {estimate.coordinate_id: [] for estimate, _ in eligible}
    for _ in range(plan.bootstrap_draws):
        indexes = {
            support: [rng.randrange(len(support)) for _ in support]
            for support, rng in rng_by_support.items()
        }
        for estimate, expected in eligible:
            values = [unit["interaction"] for unit in expected["unit_rows"]]
            sample = indexes[support_by_coordinate[estimate.coordinate_id]]
            draws[estimate.coordinate_id].append(_mean([float(values[index]) for index in sample]))
    errors = {coordinate: statistics.stdev(values) for coordinate, values in draws.items()}
    maxima = []
    for draw in range(plan.bootstrap_draws):
        values = []
        for estimate, _ in eligible:
            error = errors[estimate.coordinate_id]
            if error > 0.0:
                values.append(
                    abs(draws[estimate.coordinate_id][draw] - float(estimate.interaction)) / error
                )
        maxima.append(max(values, default=0.0))
    critical = _quantile(maxima, 1.0 - plan.alpha)
    return {
        estimate.coordinate_id: (
            errors[estimate.coordinate_id],
            max(-2.0, float(estimate.interaction) - critical * errors[estimate.coordinate_id]),
            min(2.0, float(estimate.interaction) + critical * errors[estimate.coordinate_id]),
        )
        for estimate, _ in eligible
    }, critical


def _secondary_bootstrap_intervals(
    rows: list[tuple[Any, Mapping[str, Any]]], plan: Any
) -> tuple[dict[tuple[str, str], tuple[float, float, float]], float]:
    effects = tuple(_name(item) for item in plan.secondary_effects)
    eligible = [
        (estimate, expected, effect)
        for estimate, expected in rows
        if _name(estimate.metric) == _name(plan.primary_metric)
        for effect in effects
        if expected[effect] is not None
        and all(_unit_effect(unit, effect) is not None for unit in expected["unit_rows"])
    ]
    if not eligible:
        return {}, 0.0
    keys = [(estimate.coordinate_id, effect) for estimate, _, effect in eligible]
    support_by_key = {
        key: tuple(unit["task_unit_id"] for unit in expected["unit_rows"])
        for key, (_, expected, _) in zip(keys, eligible, strict=True)
    }
    rng_by_support = {
        support: random.Random(
            int(
                content_id(
                    "factorial_secondary_bootstrap_",
                    {"seed": plan.bootstrap_seed, "support": support},
                )[-16:],
                16,
            )
        )
        for support in set(support_by_key.values())
    }
    draws = {key: [] for key in keys}
    for _ in range(plan.bootstrap_draws):
        indexes = {
            support: [rng.randrange(len(support)) for _ in support]
            for support, rng in rng_by_support.items()
        }
        for key, (_, expected, effect) in zip(keys, eligible, strict=True):
            values = [_unit_effect(unit, effect) for unit in expected["unit_rows"]]
            sample = indexes[support_by_key[key]]
            draws[key].append(_mean([float(values[index]) for index in sample]))
    errors = {key: statistics.stdev(values) for key, values in draws.items()}
    maxima = []
    for draw in range(plan.bootstrap_draws):
        values = []
        for key, (_, expected, effect) in zip(keys, eligible, strict=True):
            error = errors[key]
            if error > 0.0:
                values.append(abs(draws[key][draw] - float(expected[effect])) / error)
        maxima.append(max(values, default=0.0))
    critical = _quantile(maxima, 1.0 - plan.alpha)
    return {
        key: (
            errors[key],
            max(-1.0, float(expected[effect]) - critical * errors[key]),
            min(1.0, float(expected[effect]) + critical * errors[key]),
        )
        for key, (_, expected, effect) in zip(keys, eligible, strict=True)
    }, critical


def _unit_effect(unit: Mapping[str, Any], effect: str) -> float | None:
    cells = unit["cells"]
    if effect == "factor_1":
        return _difference(cells[FactorialCell.A10][0], cells[FactorialCell.A00][0])
    if effect == "factor_2":
        return _difference(cells[FactorialCell.A01][0], cells[FactorialCell.A00][0])
    if effect == "joint":
        return _difference(cells[FactorialCell.A11][0], cells[FactorialCell.A00][0])
    return unit["interaction"]


def _interaction(values: Mapping[FactorialCell, float | None]) -> float | None:
    if any(values[cell] is None for cell in FACTORIAL_CELL_ORDER):
        return None
    return (
        float(values[FactorialCell.A11])
        - float(values[FactorialCell.A10])
        - float(values[FactorialCell.A01])
        + float(values[FactorialCell.A00])
    )


def _interaction_bounds(cells: Mapping[FactorialCell, tuple[Any, float, float, Any]]) -> tuple[float, float]:
    return (
        cells[FactorialCell.A11][1]
        - cells[FactorialCell.A10][2]
        - cells[FactorialCell.A01][2]
        + cells[FactorialCell.A00][1],
        cells[FactorialCell.A11][2]
        - cells[FactorialCell.A10][1]
        - cells[FactorialCell.A01][1]
        + cells[FactorialCell.A00][2],
    )


def _difference(left: float | None, right: float | None) -> float | None:
    return None if left is None or right is None else left - right


def _mean(values: list[float]) -> float:
    return sum(values) / len(values)


def _mean_or_none(values: list[float | None]) -> float | None:
    return None if any(value is None for value in values) else _mean([float(value) for value in values])


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))]


def _name(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _same(expected: Any, observed: Any) -> None:
    if isinstance(expected, tuple):
        if not isinstance(observed, tuple) or len(expected) != len(observed):
            raise ValueError("independent verifier found sequence drift")
        for left, right in zip(expected, observed, strict=True):
            _same(left, right)
    elif isinstance(expected, float):
        if not isinstance(observed, (int, float)) or not math.isclose(
            expected, observed, rel_tol=0.0, abs_tol=1e-12
        ):
            raise ValueError("independent verifier found numeric drift")
    elif expected != observed:
        raise ValueError("independent verifier found value drift")


__all__ = [
    "verify_factorial_inference",
    "verify_factorial_result_bundle",
    "verify_mechanism_trace_diagnostics",
]
