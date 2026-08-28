"""Independent recomputation of the pairwise factorial result.

This module deliberately does not import the production inference module.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import statistics
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.functional_judge import (
    build_review_request,
    python_syntax_valid,
    validate_review_response,
)
from prompt_mechanism_study.interaction_selector_experiment import (
    INTERACTION_SELECTION_ARTIFACT_FILES,
    verify_interaction_selection_bundle,
)
from prompt_mechanism_study.intervention import FACTORIAL_CELL_ORDER, FactorialCell
from prompt_mechanism_study.measurement import (
    CodeStatus,
    FunctionalStatus,
    Measurement,
    OracleStatus,
)
from prompt_mechanism_study.mechanisms import (
    load_pair_registry,
    validate_active_factorial_relation,
)
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.prompt_tsg import catalog_sha256, load_catalog
from prompt_mechanism_study.records import canonical_value, content_hash, content_id
from prompt_mechanism_study.security_profiles import evaluate_security_profile


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
            "factor_1_given_factor_2": _difference(
                points[FactorialCell.A11], points[FactorialCell.A01]
            ),
            "factor_2_given_factor_1": _difference(
                points[FactorialCell.A11], points[FactorialCell.A10]
            ),
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
            "factor_1_given_factor_2_bounds": (
                lower[FactorialCell.A11] - upper[FactorialCell.A01],
                upper[FactorialCell.A11] - lower[FactorialCell.A01],
            ),
            "factor_2_given_factor_1_bounds": (
                lower[FactorialCell.A11] - upper[FactorialCell.A10],
                upper[FactorialCell.A11] - lower[FactorialCell.A10],
            ),
            "joint_bounds": (
                lower[FactorialCell.A11] - upper[FactorialCell.A00],
                upper[FactorialCell.A11] - lower[FactorialCell.A00],
            ),
            "interaction_bounds": _interaction_bounds(cell_rows),
            "unit_rows": unit_rows,
            "response_pattern": _classify_pattern(points),
        }
        expected["realization_diagnostics"] = _realization_diagnostics(
            coordinate_assignments,
            outcome_by_id,
            policy,
            task_by_id,
            unit_ids,
            metric,
            expected["interaction"],
        )
        _verify_estimate(estimate, expected)
        recomputed.append((estimate, expected))

    prospective = hasattr(plan, "minimum_task_units")
    if not prospective:
        primary_supports = [
            {row["task_unit_id"] for row in expected["unit_rows"]}
            for estimate, expected in recomputed
            if _name(estimate.metric) == _name(plan.primary_metric)
        ]
        for index, left in enumerate(primary_supports):
            for right in primary_supports[index + 1 :]:
                if left & right and left != right:
                    raise ValueError(
                        "independent verifier found partially overlapping factorial "
                        "task-unit support"
                    )

    primary_diagnostics = None
    if prospective:
        raw_intervals, critical, primary_diagnostics = (
            _studentized_effect_bootstrap_intervals(
                recomputed,
                plan,
                metric=_name(plan.primary_metric),
                effects=("interaction",),
                seed_namespace="factorial_primary_studentized_v2_",
            )
        )
        intervals = {
            coordinate_id: values
            for (coordinate_id, _effect), values in raw_intervals.items()
        }
    else:
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
    secondary_diagnostics = None
    if prospective:
        secondary, secondary_critical, secondary_diagnostics = (
            _studentized_effect_bootstrap_intervals(
                recomputed,
                plan,
                metric=_name(plan.primary_metric),
                effects=tuple(_name(item) for item in plan.secondary_effects),
                seed_namespace="factorial_secondary_studentized_v2_",
            )
        )
    else:
        secondary, secondary_critical = _secondary_bootstrap_intervals(
            recomputed, plan
        )
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
    metric_family_count = _verify_metric_families(recomputed, plan, reported)
    verification = {
        "status": "FACTORIAL_INFERENCE_VERIFIED",
        "assignments": len(assignments),
        "coordinates": len(recomputed),
        "primary_intervals": len(intervals),
        "secondary_intervals": len(secondary),
    }
    if metric_family_count is not None:
        verification["metric_families"] = metric_family_count
    if prospective:
        verification["primary_bootstrap"] = primary_diagnostics
        verification["secondary_bootstrap"] = secondary_diagnostics
    return verification


def verify_mechanism_trace_diagnostics(
    records: Iterable[Mapping[str, Any]],
    reported: Mapping[str, Any],
    endpoints: Iterable[str] | Mapping[str, Iterable[str]],
) -> dict[str, Any]:
    """Independently recompute assignment-level Oracle trace diagnostics."""

    frozen_records = tuple(records)
    if isinstance(endpoints, Mapping):
        expected_pairs = set(endpoints)
        if set(reported) != expected_pairs:
            raise ValueError("independent verifier found mechanism pair drift")
        coordinates = 0
        endpoint_coordinates = 0
        for pair_id, pair_endpoints_raw in endpoints.items():
            pair_endpoints = tuple(pair_endpoints_raw)
            pair_records = tuple(
                item
                for item in frozen_records
                if item.get("assignment", {}).get("block", {}).get("pair_id")
                == pair_id
            )
            models = {
                item["assignment"]["block"]["model_id"] for item in pair_records
            }
            pair_report = reported[pair_id]
            if not pair_records or set(pair_report) != models:
                raise ValueError("independent verifier found mechanism model drift")
            for model_id in sorted(models):
                selected = tuple(
                    item
                    for item in pair_records
                    if item["assignment"]["block"]["model_id"] == model_id
                )
                verify_mechanism_trace_diagnostics(
                    selected, pair_report[model_id], pair_endpoints
                )
                coordinates += 1
                endpoint_coordinates += len(pair_endpoints)
        return {
            "status": "FACTORIAL_MECHANISM_TRACE_VERIFIED",
            "assignments": len(frozen_records),
            "coordinates": coordinates,
            "endpoints": endpoint_coordinates,
        }
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


_INTERVENTION_CALL_FIELDS = {
    "stage",
    "pair_id",
    "task_id",
    "realization_id",
    "executor_adapter_id",
    "executor_request",
    "executor_response_sha256",
    "executor_response",
    "validator_adapter_id",
    "validator_request",
    "validator_response_sha256",
    "validator_response",
}
_GENERATION_CALL_FIELDS = {
    "stage",
    "assignment_id",
    "pair_id",
    "model_id",
    "generator_adapter_id",
    "request",
    "response_sha256",
    "response",
}
_FUNCTIONAL_CALL_FIELDS = {
    "stage",
    "assignment_id",
    "pair_id",
    "model_id",
    "functional_evaluator_adapter_id",
    "request",
    "response_sha256",
    "response",
}


def _verify_v11_raw_evidence(
    study: Mapping[str, Any],
    records: Iterable[Mapping[str, Any]],
    config: Mapping[str, Any],
    calls: Any,
    measurement_inputs: Any,
    assignment_by_id: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Replay every prospective provider response into the frozen measurement."""

    if not isinstance(calls, list):
        raise TypeError("stored factorial provider calls are invalid")
    if (
        not isinstance(measurement_inputs, Mapping)
        or set(measurement_inputs) != {"schema_version", "tasks"}
        or measurement_inputs.get("schema_version") != "1.1"
        or not isinstance(measurement_inputs.get("tasks"), list)
    ):
        raise ValueError("stored factorial measurement inputs are invalid")

    study_tasks = {item["task_id"]: item for item in study.get("tasks", ())}
    task_inputs: dict[str, Mapping[str, Any]] = {}
    for item in measurement_inputs["tasks"]:
        if (
            not isinstance(item, Mapping)
            or set(item)
            != {
                "task_id",
                "task_unit_id",
                "cwe",
                "archetype",
                "prompt",
                "prompt_tsg",
                "functional_contract",
            }
            or item.get("task_id") in task_inputs
            or item.get("task_id") not in study_tasks
            or item.get("prompt") != study_tasks[item["task_id"]].get("prompt")
            or not isinstance(item.get("functional_contract"), Mapping)
        ):
            raise ValueError("stored factorial measurement task input drift")
        task_inputs[item["task_id"]] = item
    if set(task_inputs) != set(study_tasks):
        raise ValueError("stored factorial measurement task support drift")

    adapters = study.get("adapters")
    if not isinstance(adapters, Mapping):
        raise TypeError("stored factorial adapters are missing")
    adapter_ids = {
        name: content_id("adapter_", adapters[name])
        for name in (
            "intervention_executor",
            "intervention_validator",
            "generator",
            "functional_evaluator",
        )
        if name in adapters
    }
    if len(adapter_ids) != 4:
        raise ValueError("stored factorial measurement adapters are incomplete")

    intervention_calls: dict[tuple[str, str, str], Mapping[str, Any]] = {}
    generation_calls: dict[str, Mapping[str, Any]] = {}
    functional_calls: dict[str, Mapping[str, Any]] = {}
    for call in calls:
        if not isinstance(call, Mapping):
            raise TypeError("stored factorial provider call is invalid")
        stage = call.get("stage")
        if stage == "intervention":
            if set(call) != _INTERVENTION_CALL_FIELDS:
                raise ValueError("stored factorial intervention call schema drift")
            key = (call.get("pair_id"), call.get("task_id"), call.get("realization_id"))
            if key in intervention_calls:
                raise ValueError("stored factorial intervention call is duplicated")
            intervention_calls[key] = call
        elif stage == "generation":
            if set(call) != _GENERATION_CALL_FIELDS:
                raise ValueError("stored factorial generation call schema drift")
            assignment_id = call.get("assignment_id")
            if assignment_id in generation_calls:
                raise ValueError("stored factorial generation call is duplicated")
            generation_calls[assignment_id] = call
        elif stage == "functional":
            if set(call) != _FUNCTIONAL_CALL_FIELDS:
                raise ValueError("stored factorial functional call schema drift")
            assignment_id = call.get("assignment_id")
            if assignment_id in functional_calls:
                raise ValueError("stored factorial functional call is duplicated")
            functional_calls[assignment_id] = call
        else:
            raise ValueError("stored factorial provider call stage is unsupported")

    protocols = {
        item["pair_id"]: item for item in config.get("pair_protocols", ())
    }
    if not protocols or len(protocols) != len(config.get("pair_protocols", ())):
        raise ValueError("stored factorial pair protocol dispatch is invalid")
    bundles_by_id: dict[str, Mapping[str, Any]] = {}
    expected_interventions: set[tuple[str, str, str]] = set()
    for policy in study.get("policies", ()):
        raw_pair = policy.get("pair", {})
        pair_id = content_id("pair_", raw_pair)
        protocol = protocols.get(pair_id)
        oracle = protocol.get("security_oracle", {}) if protocol else {}
        if (
            protocol is None
            or oracle.get("profile_id") != raw_pair.get("oracle_profile_id")
            or oracle.get("policy_sha256")
            != raw_pair.get("oracle_policy_sha256")
        ):
            raise ValueError("stored factorial policy lacks a pair protocol")
        maximum = protocol.get("intervention", {}).get("maximum_suffix_characters")
        if type(maximum) is not int or maximum <= 0:
            raise ValueError("stored factorial intervention limit is invalid")
        realizations = {
            content_id("factorial_realization_", item): item
            for item in policy.get("realizations", ())
        }
        if not realizations:
            raise ValueError("stored factorial realizations are empty")
        for bundle in policy.get("bundles", ()):
            task_id = bundle.get("task_id")
            realization_id = bundle.get("realization_id")
            task_input = task_inputs.get(task_id)
            realization = realizations.get(realization_id)
            coordinate = (pair_id, task_id, realization_id)
            call = intervention_calls.get(coordinate)
            if (
                task_input is None
                or realization is None
                or call is None
                or bundle.get("pair_id") != pair_id
                or bundle.get("source_prompt_sha256")
                != content_hash(task_input["prompt"])
            ):
                raise ValueError("stored factorial intervention coordinate drift")
            expected_interventions.add(coordinate)
            _verify_v11_intervention_call(
                call,
                bundle,
                task_input,
                realization,
                raw_pair,
                maximum,
                adapter_ids,
            )
            bundle_id = content_id("factorial_task_bundle_", bundle)
            if bundle_id in bundles_by_id:
                raise ValueError("stored factorial task bundle is duplicated")
            bundles_by_id[bundle_id] = bundle
    if set(intervention_calls) != expected_interventions:
        raise ValueError("stored factorial intervention call support drift")

    record_by_id = {
        item.get("measurement", {}).get("assignment_id"): item for item in records
    }
    if len(record_by_id) != len(tuple(records)):
        raise ValueError("stored factorial measurement record is duplicated")
    execution_ordinals = set()
    for assignment_id, record in record_by_id.items():
        execution = record.get("execution")
        assignment = assignment_by_id.get(assignment_id, {})
        block = assignment.get("block", {})
        expected_state = {
            "model_id": block.get("model_id"),
            "provider_seed": assignment.get("provider_seed"),
            "request_slot": assignment.get("request_slot"),
        }
        if (
            not isinstance(execution, Mapping)
            or set(execution)
            != {
                "ordinal",
                "started_unix_ns",
                "finished_unix_ns",
                "elapsed_ns",
                "provider_observable_state",
            }
            or type(execution.get("ordinal")) is not int
            or execution["ordinal"] < 0
            or execution["ordinal"] in execution_ordinals
            or type(execution.get("started_unix_ns")) is not int
            or type(execution.get("finished_unix_ns")) is not int
            or type(execution.get("elapsed_ns")) is not int
            or execution["finished_unix_ns"] < execution["started_unix_ns"]
            or execution["elapsed_ns"]
            != execution["finished_unix_ns"] - execution["started_unix_ns"]
            or execution.get("provider_observable_state") != expected_state
        ):
            raise ValueError("stored factorial execution-order evidence drift")
        execution_ordinals.add(execution["ordinal"])
    if execution_ordinals != set(range(len(record_by_id))):
        raise ValueError("stored factorial execution ordinals are incomplete")
    reconstructed: dict[str, dict[str, Any]] = {}
    valid_assignments: set[str] = set()
    for assignment_id, assignment in assignment_by_id.items():
        record = record_by_id.get(assignment_id)
        call = generation_calls.get(assignment_id)
        block = assignment.get("block", {})
        pair_id = block.get("pair_id")
        protocol = protocols.get(pair_id)
        bundle = bundles_by_id.get(block.get("factorial_task_bundle_id"))
        if record is None or call is None or protocol is None or bundle is None:
            raise ValueError("stored factorial generation coordinate drift")
        task_input = task_inputs.get(block.get("task_instance_id"))
        variants = {
            item.get("cell"): item for item in bundle.get("variants", ())
        }
        variant = variants.get(assignment.get("cell"))
        if task_input is None or variant is None:
            raise ValueError("stored factorial generation task binding drift")
        measurement, valid = _replay_v11_measurement(
            assignment_id,
            assignment,
            record,
            call,
            functional_calls.get(assignment_id),
            protocol,
            task_input,
            variant,
            adapter_ids,
        )
        reconstructed[assignment_id] = canonical_value(measurement)
        if valid:
            valid_assignments.add(assignment_id)
    if set(generation_calls) != set(assignment_by_id):
        raise ValueError("stored factorial generation call support drift")
    if set(functional_calls) != valid_assignments:
        raise ValueError("stored factorial functional call support drift")
    return reconstructed


def _verify_v11_intervention_call(
    call: Mapping[str, Any],
    bundle: Mapping[str, Any],
    task_input: Mapping[str, Any],
    realization: Mapping[str, Any],
    raw_pair: Mapping[str, Any],
    maximum: int,
    adapter_ids: Mapping[str, str],
) -> None:
    requirements = task_input["functional_contract"].get("requirements")
    if not isinstance(requirements, list):
        raise TypeError("stored factorial functional requirements are invalid")
    executor_request = {
        "request_kind": "blind_factorial_complete_prompt_rewrite",
        "source_prompt": task_input["prompt"],
        "source_prompt_tsg": task_input["prompt_tsg"],
        "functional_requirements": requirements,
        "factor_1": {
            "target": realization["factor_1_target_instruction"],
            "noop": realization["factor_1_noop_instruction"],
        },
        "factor_2": {
            "target": realization["factor_2_target_instruction"],
            "noop": realization["factor_2_noop_instruction"],
        },
        "application_order": list(realization["application_order"]),
        "factor_operations": [raw_pair["operation_1"], raw_pair["operation_2"]],
        "factor_ids": [raw_pair["factor_1_id"], raw_pair["factor_2_id"]],
        "blindness": {
            "generated_code": False,
            "oracle_outcomes": False,
            "effect_direction": False,
        },
    }
    executor_value, executor_digest = _provider_response(call, "executor")
    expected_cells = {cell.value for cell in FACTORIAL_CELL_ORDER}
    if (
        call.get("executor_adapter_id") != adapter_ids["intervention_executor"]
        or call.get("executor_request") != executor_request
        or set(executor_value) != expected_cells
    ):
        raise ValueError("stored factorial executor evidence drift")
    complete_prompts: dict[str, str] = {}
    for cell in FACTORIAL_CELL_ORDER:
        row = executor_value.get(cell.value)
        if not isinstance(row, Mapping) or set(row) != {
            "prompt_text",
            "facts",
            "relations",
            "unresolved_semantics",
        }:
            raise ValueError("stored factorial executor cell schema drift")
        text = row.get("prompt_text")
        if (
            not isinstance(text, str)
            or not text.strip()
            or text != text.strip()
            or len(text) > len(task_input["prompt"]) + maximum
        ):
            raise ValueError("stored factorial executor complete prompt drift")
        complete_prompts[cell.value] = text
    if len(set(complete_prompts.values())) != len(FACTORIAL_CELL_ORDER):
        raise ValueError("stored factorial executor collapsed treatment cells")

    variants = {
        item.get("cell"): item for item in bundle.get("variants", ())
    }
    if tuple(item.get("cell") for item in bundle.get("variants", ())) != tuple(
        cell.value for cell in FACTORIAL_CELL_ORDER
    ):
        raise ValueError("stored factorial intervention cell order drift")
    validator_request = {
        "request_kind": "blind_factorial_prompt_validation",
        "source_prompt": task_input["prompt"],
        "functional_requirements": requirements,
        "factor_1": executor_request["factor_1"],
        "factor_2": executor_request["factor_2"],
        "application_order": executor_request["application_order"],
        "variants": complete_prompts,
        "blindness": {
            "generated_code": False,
            "oracle_outcomes": False,
            "model_identity": False,
        },
    }
    validator_value, validator_digest = _provider_response(call, "validator")
    cell_fields = {
        "task_preserved",
        "factor_1_state_correct",
        "factor_2_state_correct",
        "unintended_change_absent",
        "contradiction_absent",
    }
    cross_fields = {
        "functional_contract_preserved",
        "pair_context_preserved",
        "non_target_security_preserved",
        "presentation_policy_preserved",
        "no_third_requirement",
        "treatment_states_distinct",
    }
    if (
        call.get("validator_adapter_id")
        != adapter_ids["intervention_validator"]
        or call.get("validator_request") != validator_request
        or set(validator_value) != {
            "a00",
            "a10",
            "a01",
            "a11",
            "cross_cell",
            "reason",
        }
        or not isinstance(validator_value.get("reason"), str)
        or not validator_value["reason"].strip()
        or not isinstance(validator_value.get("cross_cell"), Mapping)
        or set(validator_value["cross_cell"]) != cross_fields
        or any(
            not isinstance(validator_value.get(cell.value), Mapping)
            or set(validator_value[cell.value]) != cell_fields
            for cell in FACTORIAL_CELL_ORDER
        )
    ):
        raise ValueError("stored factorial validator evidence drift")
    flags = [
        value
        for cell in FACTORIAL_CELL_ORDER
        for value in validator_value[cell.value].values()
    ] + list(validator_value["cross_cell"].values())
    if any(type(value) is not bool for value in flags) or not all(flags):
        raise ValueError("stored factorial semantic validation failed")

    expected_validation = {
        "task_preserved": "yes",
        "contract_satisfied": "yes",
        "unintended_changes": "no",
        "contradiction": "no",
        "validator_adapter_id": adapter_ids["intervention_validator"],
        "evidence_sha256": validator_digest,
    }
    for cell in FACTORIAL_CELL_ORDER:
        observed = variants.get(cell.value)
        expected_execution = {
            "prompt_text": complete_prompts[cell.value],
            "executor_adapter_id": adapter_ids["intervention_executor"],
            "evidence_sha256": executor_digest,
        }
        if (
            not isinstance(observed, Mapping)
            or set(observed) != {"cell", "execution", "validation"}
            or observed.get("execution") != expected_execution
            or observed.get("validation") != expected_validation
        ):
            raise ValueError("stored factorial intervention replay drift")
    expected_bundle_validation = {
        "task_semantics_preserved": "yes",
        "functional_contract_preserved": "yes",
        "pair_context_preserved": "yes",
        "non_target_security_preserved": "yes",
        "presentation_policy_preserved": "yes",
        "no_third_requirement": "yes",
        "treatment_states_distinct": "yes",
        "validator_adapter_id": adapter_ids["intervention_validator"],
        "evidence_sha256": validator_digest,
    }
    if bundle.get("bundle_validation") != expected_bundle_validation:
        raise ValueError("stored factorial bundle validation replay drift")


def _replay_v11_measurement(
    assignment_id: str,
    assignment: Mapping[str, Any],
    record: Mapping[str, Any],
    generation_call: Mapping[str, Any],
    functional_call: Mapping[str, Any] | None,
    protocol: Mapping[str, Any],
    task_input: Mapping[str, Any],
    variant: Mapping[str, Any],
    adapter_ids: Mapping[str, str],
) -> tuple[Measurement, bool]:
    block = assignment["block"]
    pair_id = block["pair_id"]
    model_id = block["model_id"]
    prompt = variant.get("execution", {}).get("prompt_text")
    request = {
        "request_kind": "factorial_code_generation",
        "task_prompt": prompt,
        "language": "python",
        "output_schema": {"code": "complete Python source string"},
    }
    response, generator_digest = _provider_response(generation_call)
    if (
        generation_call.get("assignment_id") != assignment_id
        or generation_call.get("pair_id") != pair_id
        or generation_call.get("model_id") != model_id
        or generation_call.get("generator_adapter_id") != adapter_ids["generator"]
        or generation_call.get("request") != request
        or set(response) != {"code"}
        or not isinstance(response.get("code"), str)
    ):
        raise ValueError("stored factorial generation evidence drift")
    code = response["code"]
    if (
        record.get("generation_model_id") != model_id
        or record.get("generation_request") != request
        or record.get("generation_response") != generation_call.get("response")
        or record.get("code") != code
    ):
        raise ValueError("stored factorial generation record drift")

    valid = bool(code.strip()) and python_syntax_valid(code)
    if not valid:
        status = CodeStatus.NO_CODE if not code.strip() else CodeStatus.INVALID
        expected_fields = {
            "assignment",
            "measurement",
            "execution",
            "generation_model_id",
            "security_profile_id",
            "security_policy_sha256",
            "generation_request",
            "generation_response",
            "code",
            "security",
            "functional_request",
            "functional_response",
        }
        if (
            set(record) != expected_fields
            or record.get("security") is not None
            or record.get("functional_request") is not None
            or record.get("functional_response") is not None
            or functional_call is not None
        ):
            raise ValueError("stored factorial terminal measurement evidence drift")
        return (
            Measurement(
                assignment_id,
                status,
                OracleStatus.NOT_RUN,
                FunctionalStatus.NOT_RUN,
                generator_digest,
                content_hash(code) if code else None,
                terminal_reason=status.value,
            ),
            False,
        )

    oracle = protocol.get("security_oracle", {})
    profile_id = oracle.get("profile_id")
    policy_sha256 = oracle.get("policy_sha256")
    if (
        record.get("security_profile_id") != profile_id
        or record.get("security_policy_sha256") != policy_sha256
    ):
        raise ValueError("stored factorial Security Oracle dispatch drift")
    try:
        security = evaluate_security_profile(code, profile_id)
    except Exception as error:  # deterministic local replay must fail closed
        raise ValueError("stored factorial Security Oracle replay failed") from error
    if record.get("security") != security:
        raise ValueError("stored factorial Security Oracle findings drift")

    contract = task_input["functional_contract"]
    requirements = contract.get("requirements")
    dependencies = contract.get("environment_dependencies")
    if not isinstance(requirements, list) or not isinstance(dependencies, list):
        raise TypeError("stored factorial functional contract is invalid")
    functional_request = build_review_request(
        code,
        task_input["prompt"],
        requirements=requirements,
        environment_dependencies=dependencies,
    )
    if functional_call is None:
        raise ValueError("stored factorial functional provider call is missing")
    functional_response, functional_digest = _provider_response(functional_call)
    del functional_response  # parsed above only to enforce an exact JSON object
    if (
        functional_call.get("assignment_id") != assignment_id
        or functional_call.get("pair_id") != pair_id
        or functional_call.get("model_id") != model_id
        or functional_call.get("functional_evaluator_adapter_id")
        != adapter_ids["functional_evaluator"]
        or functional_call.get("request") != functional_request
        or record.get("functional_request") != functional_request
        or record.get("functional_response") != functional_call.get("response")
    ):
        raise ValueError("stored factorial functional provider evidence drift")
    try:
        functional = validate_review_response(
            functional_call["response"].encode("utf-8"), code
        )
    except Exception as error:  # deterministic response validation must fail closed
        raise ValueError("stored factorial functional response replay failed") from error
    expected_fields = {
        "assignment",
        "measurement",
        "execution",
        "generation_model_id",
        "security_profile_id",
        "security_policy_sha256",
        "generation_request",
        "generation_response",
        "code",
        "security",
        "functional_request",
        "functional_response",
        "functional_validated",
    }
    if set(record) != expected_fields or record.get("functional_validated") != functional:
        raise ValueError("stored factorial functional validation drift")
    return (
        Measurement(
            assignment_id,
            CodeStatus.VALID,
            OracleStatus(security["security_label"]),
            FunctionalStatus(functional["status"]),
            generator_digest,
            content_hash(code),
            content_hash(security),
            functional_digest,
        ),
        True,
    )


def _provider_response(
    call: Mapping[str, Any], prefix: str | None = None
) -> tuple[dict[str, Any], str]:
    response_field = f"{prefix}_response" if prefix else "response"
    digest_field = f"{prefix}_response_sha256" if prefix else "response_sha256"
    response = call.get(response_field)
    if not isinstance(response, str):
        raise TypeError("stored factorial provider response is not text")
    raw = response.encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    if call.get(digest_field) != digest:
        raise ValueError("stored factorial provider response digest drift")
    try:
        value = json.loads(
            response,
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except Exception as error:
        raise ValueError("stored factorial provider response is invalid JSON") from error
    if not isinstance(value, dict):
        raise TypeError("stored factorial provider response is not an object")
    return value, digest


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _verify_portable_factorial_freeze(root: Path) -> None:
    metadata = read_json(root / "factorial-freeze.json")
    if (
        not isinstance(metadata, Mapping)
        or set(metadata) != {"bundle_sha256", "verification"}
    ):
        raise ValueError("stored factorial freeze provenance is invalid")
    artifacts = {
        path.name.removeprefix("freeze-"): read_json(path)
        for path in root.glob("freeze-*.json")
    }
    if not artifacts:
        raise ValueError("stored factorial portable freeze is missing")
    with tempfile.TemporaryDirectory(prefix="factorial-freeze-verify-") as directory:
        portable = Path(directory) / "freeze"
        write_bundle(portable, artifacts)
        if bundle_digest(portable) != metadata.get("bundle_sha256"):
            raise ValueError("stored factorial freeze digest drift")
        from prompt_mechanism_study.factorial_experiment import (
            verify_factorial_freeze_bundle,
        )

        verified = verify_factorial_freeze_bundle(portable)
    if verified != metadata.get("verification"):
        raise ValueError("stored factorial freeze semantic verification drift")


def _independent_json_object(payload: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (TypeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"stored factorial {label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"stored factorial {label} is not an object")
    return value


def _verify_active_analysis_contract(analysis: Any) -> None:
    if not isinstance(analysis, Mapping):
        raise ValueError("stored prospective factorial analysis is invalid")
    separately_powered = analysis.get(
        "functionality_noninferiority_separately_powered"
    )
    required = {
        "metrics",
        "primary_metric",
        "secondary_effects",
        "bootstrap_seed",
        "bootstrap_draws",
        "familywise_alpha",
        "minimum_task_units",
        "minimum_valid_bootstrap_fraction",
        "bootstrap_quantile_method",
        "practical_interaction_margin",
        "maximum_unknown_fraction",
        "functionality_noninferiority_margin",
        "functionality_noninferiority_separately_powered",
    }
    if separately_powered is True:
        required.add("functionality_power_qualification")
    if (
        set(analysis) != required
        or analysis.get("metrics")
        != [
            "secure_yield",
            "code_valid",
            "oracle_evaluable",
            "functionality",
            "joint",
        ]
        or type(separately_powered) is not bool
    ):
        raise ValueError("stored prospective factorial endpoint contract drifts")
    if separately_powered:
        reference = analysis["functionality_power_qualification"]
        if (
            not isinstance(reference, Mapping)
            or set(reference) != {"path", "sha256"}
            or not isinstance(reference["sha256"], str)
            or len(reference["sha256"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in reference["sha256"]
            )
        ):
            raise ValueError("stored functionality power reference is invalid")


def _verify_independent_power_payload(
    payload: Any,
    analysis: Mapping[str, Any],
) -> None:
    coordinate = payload.get("analysis_coordinate", {}) if isinstance(payload, dict) else {}
    assumptions = payload.get("assumptions", {}) if isinstance(payload, dict) else {}
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "schema_version",
            "qualification_status",
            "analysis_coordinate",
            "planned_task_units_per_coordinate",
            "target_power",
            "familywise_alpha",
            "noninferiority_margin",
            "power_method",
            "assumptions",
        }
        or payload["schema_version"] != "1.0"
        or payload["qualification_status"] != "supported"
        or coordinate
        != {
            "metric": "functionality",
            "contrast": "a11_minus_a00",
            "unit": "task_unit",
            "scope": "each_pair_model_coordinate",
        }
        or type(payload["planned_task_units_per_coordinate"]) is not int
        or payload["planned_task_units_per_coordinate"]
        < analysis["minimum_task_units"]
        or type(payload["target_power"]) is not float
        or not 0.8 <= payload["target_power"] < 1.0
        or payload["familywise_alpha"] != analysis["familywise_alpha"]
        or payload["noninferiority_margin"]
        != analysis["functionality_noninferiority_margin"]
        or not isinstance(payload["power_method"], str)
        or not payload["power_method"].strip()
        or not isinstance(assumptions, dict)
        or set(assumptions)
        != {
            "baseline_functionality_rate",
            "alternative_difference",
            "paired_task_unit_correlation",
        }
        or type(assumptions["baseline_functionality_rate"]) is not float
        or not 0.0 <= assumptions["baseline_functionality_rate"] <= 1.0
        or type(assumptions["alternative_difference"]) is not float
        or not -1.0 <= assumptions["alternative_difference"] <= 1.0
        or assumptions["alternative_difference"]
        <= -analysis["functionality_noninferiority_margin"]
        or type(assumptions["paired_task_unit_correlation"]) is not float
        or not -1.0 <= assumptions["paired_task_unit_correlation"] <= 1.0
    ):
        raise ValueError("stored functionality power qualification drifts")


def _verify_frozen_active_protocol_evidence(
    root: Path,
    study: Mapping[str, Any],
    config: Mapping[str, Any],
) -> None:
    analysis = config["analysis"]
    _verify_active_analysis_contract(analysis)
    _verify_independent_functional_qualification(root, study, config)
    oracle = read_json(root / "freeze-factorial-oracle-qualifications.json")
    if not isinstance(oracle, Mapping) or set(oracle) != {
        "schema_version",
        "producer",
        "pairs",
    } or oracle["schema_version"] != "1.0":
        raise ValueError("stored factorial Oracle evidence envelope drifts")
    producer = oracle["producer"]
    if not isinstance(producer, Mapping) or set(producer) != {
        "implementation_id",
        "sha256",
    }:
        raise ValueError("stored factorial Oracle producer envelope drifts")
    active_producer_sha256 = hashlib.sha256(
        Path(__file__).with_name("security_profiles.py").read_bytes()
    ).hexdigest()
    if (
        producer["implementation_id"]
        != "prompt_mechanism_study.security_profiles:evaluate_security_profile"
        or producer["sha256"] != active_producer_sha256
    ):
        raise ValueError("stored factorial Oracle producer identity drifts")
    pair_by_id = {
        content_id("pair_", policy["pair"]): policy["pair"]
        for policy in study.get("policies", ())
    }
    rows = oracle["pairs"]
    if (
        not isinstance(rows, list)
        or [row.get("pair_id") for row in rows] != sorted(pair_by_id)
    ):
        raise ValueError("stored factorial Oracle pair support drifts")
    expected_fields = {
        "pair_id",
        "profile_id",
        "policy_sha256",
        "policy_payload",
        "qualification_sha256",
        "qualification_payload",
        "producer_implementation_id",
        "producer_sha256",
    }
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != expected_fields:
            raise ValueError("stored factorial Oracle pair evidence is invalid")
        pair = pair_by_id[row["pair_id"]]
        policy_payload = row["policy_payload"]
        qualification_payload = row["qualification_payload"]
        if (
            row["profile_id"] != pair["oracle_profile_id"]
            or row["policy_sha256"] != pair["oracle_policy_sha256"]
            or row["producer_implementation_id"] != producer["implementation_id"]
            or row["producer_sha256"] != producer["sha256"]
            or not isinstance(policy_payload, str)
            or hashlib.sha256(policy_payload.encode("utf-8")).hexdigest()
            != row["policy_sha256"]
            or not isinstance(qualification_payload, str)
            or hashlib.sha256(qualification_payload.encode("utf-8")).hexdigest()
            != row["qualification_sha256"]
        ):
            raise ValueError("stored factorial Oracle pair identity drifts")
        policy = _independent_json_object(policy_payload, "Oracle policy")
        qualification = _independent_json_object(
            qualification_payload, "Oracle qualification"
        )
        if (
            policy.get("schema_version") != "1.0"
            or policy.get("profile_id") != pair["oracle_profile_id"]
            or qualification.get("profile_id") != pair["oracle_profile_id"]
            or qualification.get("policy_sha256") != pair["oracle_policy_sha256"]
            or qualification.get("qualification_status") != "supported"
            or qualification.get("label_mismatches") != 0
            or set(qualification.get("gold_cells", ()))
            != {cell.value for cell in FACTORIAL_CELL_ORDER}
            or qualification.get("implementation_sha256") != producer["sha256"]
        ):
            raise ValueError("stored factorial Oracle qualification semantics drift")

    oracle_material = tuple(
        {
            "pair_id": row["pair_id"],
            "profile_id": row["profile_id"],
            "policy_sha256": row["policy_sha256"],
            "qualification_sha256": row["qualification_sha256"],
            "producer_implementation_id": row["producer_implementation_id"],
            "producer_sha256": row["producer_sha256"],
        }
        for row in rows
    )
    dispatch_material = tuple(
        {
            "pair_id": row["pair_id"],
            "profile_id": row["profile_id"],
            "policy_sha256": row["policy_sha256"],
        }
        for row in rows
    )
    if study.get("adapters", {}).get("security_oracle") != {
        "kind": "security_oracle",
        "name": f"factorial-oracle-set-{content_hash(oracle_material)[:16]}",
        "version": "1",
        "policy_sha256": content_hash(dispatch_material),
    }:
        raise ValueError(
            "stored factorial Oracle adapter does not bind qualification evidence"
        )

    power_path = root / "freeze-factorial-functionality-power-qualification.json"
    requested = analysis["functionality_noninferiority_separately_powered"]
    plan = study.get("analysis_plan", {})
    if not requested:
        if power_path.exists() or plan.get("functionality_power_qualification_sha256") is not None:
            raise ValueError("unrequested functionality power evidence entered the result")
        return
    if not power_path.is_file():
        raise ValueError("stored functionality power evidence is missing")
    power = read_json(power_path)
    if not isinstance(power, Mapping) or set(power) != {
        "schema_version",
        "qualification_sha256",
        "qualification_payload",
    } or power["schema_version"] != "1.0":
        raise ValueError("stored functionality power envelope drifts")
    payload_text = power["qualification_payload"]
    if (
        not isinstance(payload_text, str)
        or hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
        != power["qualification_sha256"]
        or power["qualification_sha256"]
        != analysis["functionality_power_qualification"]["sha256"]
        or plan.get("functionality_power_qualification_sha256")
        != power["qualification_sha256"]
    ):
        raise ValueError("stored functionality power digest drifts")
    payload = _independent_json_object(
        payload_text, "functionality power qualification"
    )
    _verify_independent_power_payload(payload, analysis)
    planned_units = payload["planned_task_units_per_coordinate"]
    if any(
        len({bundle["task_unit_id"] for bundle in policy["bundles"]})
        < planned_units
        for policy in study.get("policies", ())
    ):
        raise ValueError(
            "stored factorial support is smaller than its functionality power plan"
        )


def _verify_independent_functional_qualification(
    root: Path,
    study: Mapping[str, Any],
    config: Mapping[str, Any],
) -> None:
    sealed = read_json(root / "freeze-factorial-functional-qualification.json")
    if not isinstance(sealed, Mapping) or set(sealed) != {
        "qualification_path",
        "qualification_sha256",
        "qualification",
        "qualification_payload",
        "qualification_identity",
    }:
        raise ValueError("stored functional qualification envelope drifts")
    payload = sealed["qualification_payload"]
    qualification = sealed["qualification"]
    identity = sealed["qualification_identity"]
    section = config["functional_oracle"]
    identity_fields = {
        "qualification_id",
        "status",
        "candidate_id",
        "model_id",
        "evaluator_config_sha256",
        "prompt_sha256",
        "provider",
        "fixture_only",
        "evaluator_scientific_claim_allowed",
    }
    if (
        not isinstance(payload, str)
        or not payload
        or not isinstance(qualification, Mapping)
        or not isinstance(identity, Mapping)
        or set(identity) != identity_fields
    ):
        raise ValueError("stored functional qualification identity drifts")
    parsed = _independent_json_object(payload, "functional qualification")
    candidate = qualification.get("candidate", {})
    if not isinstance(candidate, Mapping):
        raise ValueError("stored functional qualification candidate drifts")
    expected_identity = {
        "qualification_id": content_id(
            "functional_judge_qualification_v1_", qualification
        ),
        "status": qualification.get("status"),
        "candidate_id": candidate.get("candidate_id"),
        "model_id": candidate.get("model_id"),
        "evaluator_config_sha256": candidate.get("evaluator_config_sha256"),
        "prompt_sha256": candidate.get("prompt_sha256"),
        "provider": identity.get("provider"),
        "fixture_only": identity.get("fixture_only"),
        "evaluator_scientific_claim_allowed": identity.get(
            "evaluator_scientific_claim_allowed"
        ),
    }
    status = identity.get("status")
    structural_smoke = status == "STRUCTURAL_SMOKE_ONLY"
    if structural_smoke and not (
        config.get("phase") == "development_canary"
        and config.get("scientific_claim_allowed") is False
        and identity.get("provider") == "offline_deterministic_test_fixture"
        and identity.get("fixture_only") is True
        and identity.get("evaluator_scientific_claim_allowed") is False
        and qualification.get("semantic_accuracy_claimed") is False
        and qualification.get("scientific_claim_allowed") is False
    ):
        raise ValueError("stored structural-smoke qualification is not allowed")
    if (
        qualification.get("schema_version") != "1.0"
        or status not in {"QUALIFIED_FOR_EXPERIMENT", "STRUCTURAL_SMOKE_ONLY"}
        or parsed != qualification
        or sealed.get("qualification_path") != section.get("qualification_path")
        or sealed.get("qualification_sha256")
        != section.get("qualification_sha256")
        or hashlib.sha256(payload.encode("utf-8")).hexdigest()
        != section.get("qualification_sha256")
        or identity != expected_identity
        or identity.get("evaluator_config_sha256")
        != section.get("evaluator_config_sha256")
        or identity.get("prompt_sha256") != section.get("prompt_sha256")
    ):
        raise ValueError("stored functional qualification semantics drift")
    adapter_material = {
        "evaluator_config_sha256": identity["evaluator_config_sha256"],
        "prompt_sha256": identity["prompt_sha256"],
        "qualification_sha256": sealed["qualification_sha256"],
        "qualification_identity": identity,
    }
    if study.get("adapters", {}).get("functional_evaluator") != {
        "kind": "functional_evaluator",
        "name": identity["candidate_id"],
        "version": "1",
        "policy_sha256": content_hash(adapter_material),
    }:
        raise ValueError("stored functional adapter qualification binding drifts")



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
    schema_version = config.get("schema_version")
    if schema_version not in {"1.0", "1.1"}:
        raise ValueError("stored factorial result schema is unsupported")

    raw_assignments = tuple(study.get("randomization", {}).get("assignments", ()))
    assignment_by_id = {
        content_id("factorial_assignment_", item): item for item in raw_assignments
    }
    if not raw_assignments or len(assignment_by_id) != len(raw_assignments):
        raise ValueError("stored factorial assignments are empty or duplicated")

    replayed_measurements: dict[str, dict[str, Any]] | None = None
    if schema_version == "1.1":
        _verify_frozen_active_protocol_evidence(root, study, config)
        _verify_portable_factorial_freeze(root)
        expected_order = read_json(root / "freeze-execution-order.json").get(
            "assignment_ids"
        )
        observed_order = [
            item["measurement"]["assignment_id"]
            for item in sorted(records, key=lambda value: value["execution"]["ordinal"])
        ]
        if observed_order != expected_order:
            raise ValueError("stored factorial run execution order drifts from its freeze")
        replayed_measurements = _verify_v11_raw_evidence(
            study,
            records,
            config,
            read_json(root / "provider-calls.json"),
            read_json(root / "factorial-measurement-inputs.json"),
            assignment_by_id,
        )

    record_by_id: dict[str, Mapping[str, Any]] = {}
    derived_outcomes: dict[str, dict[str, Any]] = {}
    for record in records:
        measurement = record.get("measurement", {})
        assignment_id = measurement.get("assignment_id")
        if (
            assignment_id not in assignment_by_id
            or assignment_id in record_by_id
            or record.get("assignment") != assignment_by_id[assignment_id]
            or (
                replayed_measurements is not None
                and measurement != replayed_measurements.get(assignment_id)
            )
        ):
            raise ValueError("stored factorial measurement evidence or assignment drift")
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

    if schema_version == "1.1":
        _verify_pair_selection_provenance(root, study, config)
        _verify_oracle_dispatch_records(records, config)
        endpoints: Any = {
            item["pair_id"]: tuple(item.get("mechanism_trace_diagnostics", ()))
            for item in config.get("pair_protocols", ())
        }
    else:
        endpoints = tuple(config.get("analysis", {}).get("mechanism_trace_diagnostics", ()))
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
        "mechanism_trace_endpoints": (
            sum(len(tuple(value)) for value in endpoints.values())
            if isinstance(endpoints, Mapping)
            else len(endpoints)
        ),
    }


def _verify_pair_selection_provenance(
    root: Path, study: Mapping[str, Any], config: Mapping[str, Any]
) -> None:
    catalog = load_catalog(root / "factorial-prompt-tsg-catalog.json")
    if catalog_sha256(catalog) != study.get("prompt_tsg_catalog_sha256"):
        raise ValueError("stored factorial Prompt TSG catalog drift")
    registry = load_pair_registry(root / "factorial-pair-registry.json", catalog)
    for pair in registry.pairs:
        validate_active_factorial_relation(pair.relation_type)
    frozen = study.get("pair_selection")
    if not isinstance(frozen, Mapping):
        raise TypeError("stored factorial pair-selection provenance is missing")
    selected_pair_ids = tuple(
        sorted(content_id("pair_", item["pair"]) for item in study["policies"])
    )
    registry_by_id = {item.pair_id: item for item in registry.pairs}
    if any(
        pair_id not in registry_by_id
        or canonical_value(registry_by_id[pair_id]) != policy["pair"]
        for pair_id, policy in (
            (content_id("pair_", item["pair"]), item) for item in study["policies"]
        )
    ):
        raise ValueError("stored factorial policy leaves the frozen pair registry")
    if (
        tuple(frozen.get("selected_pair_ids", ())) != selected_pair_ids
        or frozen.get("selection_id")
        != study.get("randomization", {}).get("selection_id")
    ):
        raise ValueError("stored factorial pair-selection binding drift")
    configured = config.get("pair_selection")
    if configured is None:
        registry_pair_ids = tuple(sorted(registry_by_id))
        expected_selection_id = content_id(
            "factorial_registry_selection_",
            {
                "registry_sha256": content_hash(registry),
                "selected_pair_ids": registry_pair_ids,
            },
        )
        if (
            frozen.get("source") != "registry_selected"
            or frozen.get("artifact_bundle_sha256") is not None
            or selected_pair_ids != registry_pair_ids
            or frozen.get("selection_id") != expected_selection_id
        ):
            raise ValueError("stored factorial registry selection drift")
        return
    if (
        not isinstance(configured, Mapping)
        or set(configured) != {"artifact_path"}
        or not isinstance(configured.get("artifact_path"), str)
        or not configured["artifact_path"].strip()
        or frozen.get("source") != "selector_artifact"
        or not isinstance(frozen.get("artifact_bundle_sha256"), str)
        or len(frozen["artifact_bundle_sha256"]) != 64
        or any(
            character not in "0123456789abcdef"
            for character in frozen["artifact_bundle_sha256"]
        )
    ):
        raise ValueError("stored factorial selector provenance drift")
    selector_artifacts = {
        name: read_json(root / f"pair-selection-{name}")
        for name in INTERACTION_SELECTION_ARTIFACT_FILES
    }
    with tempfile.TemporaryDirectory(prefix="factorial-selector-verify-") as directory:
        portable_root = Path(directory) / "selection"
        write_bundle(portable_root, selector_artifacts)
        verified = verify_interaction_selection_bundle(portable_root)
    if (
        verified["freeze_id"] != frozen.get("selection_id")
        or verified["bundle_sha256"] != frozen.get("artifact_bundle_sha256")
        or tuple(sorted(verified["selected_pair_ids"])) != selected_pair_ids
        or verified["prompt_tsg_catalog_sha256"]
        != registry.prompt_tsg_catalog_sha256
        or verified["pair_registry_id"] != registry.registry_id
    ):
        raise ValueError("stored factorial selector artifact does not bind the study")


def _verify_oracle_dispatch_records(
    records: Iterable[Mapping[str, Any]], config: Mapping[str, Any]
) -> None:
    expected = {
        item["pair_id"]: (
            item["security_oracle"]["profile_id"],
            item["security_oracle"]["policy_sha256"],
        )
        for item in config.get("pair_protocols", ())
    }
    if not expected:
        raise ValueError("stored factorial Oracle dispatch is empty")
    for record in records:
        pair_id = record.get("assignment", {}).get("block", {}).get("pair_id")
        if pair_id not in expected or (
            record.get("security_profile_id"),
            record.get("security_policy_sha256"),
        ) != expected[pair_id]:
            raise ValueError("stored factorial pair-level Oracle dispatch drift")


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
                application_order=tuple(item["application_order"]),
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
    plan_fields = {
        "metrics": tuple(plan_raw["metrics"]),
        "primary_metric": plan_raw["primary_metric"],
        "bootstrap_seed": plan_raw["bootstrap_seed"],
        "bootstrap_draws": plan_raw["bootstrap_draws"],
        "alpha": plan_raw["alpha"],
        "secondary_effects": tuple(plan_raw["secondary_effects"]),
    }
    for name in (
        "minimum_task_units",
        "minimum_valid_bootstrap_fraction",
        "bootstrap_quantile_method",
        "practical_interaction_margin",
        "maximum_unknown_fraction",
        "functionality_noninferiority_margin",
        "functionality_noninferiority_separately_powered",
        "functionality_power_qualification_sha256",
    ):
        if name in plan_raw:
            plan_fields[name] = plan_raw[name]
    plan = SimpleNamespace(**plan_fields)
    estimates = tuple(_stored_estimate_view(item) for item in inference["estimates"])
    reported = SimpleNamespace(
        estimates=estimates,
        simultaneous_critical_value=inference["simultaneous_critical_value"],
        intervals=tuple(SimpleNamespace(**item) for item in inference["intervals"]),
        secondary_critical_value=inference["secondary_critical_value"],
        secondary_intervals=tuple(
            SimpleNamespace(**item) for item in inference["secondary_intervals"]
        ),
        metric_families=tuple(
            SimpleNamespace(
                family=item["family"],
                metric=item["metric"],
                simultaneous_critical_value=item["simultaneous_critical_value"],
                intervals=tuple(
                    SimpleNamespace(**interval) for interval in item["intervals"]
                ),
            )
            for item in inference.get("metric_families", ())
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
        factor_1_given_factor_2=item.get("factor_1_given_factor_2"),
        factor_2_given_factor_1=item.get("factor_2_given_factor_1"),
        joint=item["joint"],
        interaction=item["interaction"],
        factor_1_bounds=tuple(item["factor_1_bounds"]),
        factor_2_bounds=tuple(item["factor_2_bounds"]),
        factor_1_given_factor_2_bounds=tuple(
            item.get("factor_1_given_factor_2_bounds", ())
        ),
        factor_2_given_factor_1_bounds=tuple(
            item.get("factor_2_given_factor_1_bounds", ())
        ),
        joint_bounds=tuple(item["joint_bounds"]),
        interaction_bounds=tuple(item["interaction_bounds"]),
        response_pattern=item.get("response_pattern"),
        realization_diagnostics=item.get("realization_diagnostics"),
        task_unit_effects=tuple(
            SimpleNamespace(
                task_unit_id=unit["task_unit_id"],
                interaction=unit["interaction"],
            )
            for unit in item["task_unit_effects"]
        ),
    )


def _independent_unknown_coverage_summary(
    code_valid_points: Mapping[str, Any],
    oracle_evaluable_points: Mapping[str, Any],
    limit: float,
) -> dict[str, Any]:
    if set(code_valid_points) != set(oracle_evaluable_points):
        raise ValueError("stored factorial unknown-coverage cell support drifts")
    valid_yield: dict[str, float | None] = {}
    evaluable_yield: dict[str, float | None] = {}
    unknown_fraction: dict[str, float | None] = {}
    for cell in sorted(code_valid_points):
        valid = code_valid_points[cell]
        evaluable = oracle_evaluable_points[cell]
        valid_yield[cell] = valid
        evaluable_yield[cell] = evaluable
        if valid is None or evaluable is None:
            unknown_fraction[cell] = None
            continue
        if not 0.0 <= evaluable <= valid <= 1.0:
            raise ValueError(
                "stored factorial Oracle evaluability is not a subset of valid code"
            )
        unknown_fraction[cell] = (
            None if valid == 0.0 else (valid - evaluable) / valid
        )
    observed = [item for item in unknown_fraction.values() if item is not None]
    gate_evaluable = len(observed) == len(unknown_fraction)
    maximum = max(observed) if observed else None
    return {
        "code_valid_yield_by_cell": valid_yield,
        "oracle_evaluable_yield_by_cell": evaluable_yield,
        "unknown_fraction_among_valid_code_by_cell": unknown_fraction,
        "maximum_observed_unknown_fraction_among_valid_code": maximum,
        "unknown_gate_evaluable": gate_evaluable,
        "unknown_gate_passed": bool(
            gate_evaluable and maximum is not None and maximum <= limit
        ),
    }


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
        expected_coordinate_id = content_id(
            "factorial_coordinate_",
            {"pair_id": key[0], "model_id": key[1], "metric": key[2]},
        )
        if (
            "coordinate_id" in observed
            and observed["coordinate_id"] != expected_coordinate_id
        ):
            raise ValueError("stored factorial report coordinate identity drift")
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
        for name in (
            "factor_1_given_factor_2",
            "factor_2_given_factor_1",
            "factor_1_given_factor_2_bounds",
            "factor_2_given_factor_1_bounds",
            "response_pattern",
            "realization_diagnostics",
        ):
            if name in source and observed.get(name) != source[name]:
                raise ValueError("stored factorial report extended effect drift")

    analysis_config = config["analysis"]
    primary_keys = [
        key
        for key in analysis_estimates
        if key[2] == analysis_config["primary_metric"]
    ]
    intervals = inference["intervals"]
    interval_by_coordinate = {item["coordinate_id"]: item for item in intervals}
    if not primary_keys or len(interval_by_coordinate) != len(intervals):
        raise ValueError("stored factorial report primary coordinate support is invalid")

    expected_secondary = [
        {
            **item,
            "excludes_zero": item["lower"] > 0.0 or item["upper"] < 0.0,
        }
        for item in inference["secondary_intervals"]
    ]
    if report.get("secondary_intervals") != expected_secondary:
        raise ValueError("stored factorial report secondary interval drift")
    if "metric_families" in inference and report.get("metric_families") != inference[
        "metric_families"
    ]:
        raise ValueError("stored factorial report metric-family drift")

    practical_margin = float(analysis_config["practical_interaction_margin"])
    functionality_margin = float(
        analysis_config["functionality_noninferiority_margin"]
    )
    unknown_limit = float(analysis_config["maximum_unknown_fraction"])
    functionality_intervals = {
        (item["coordinate_id"], item["effect"]): item
        for family in inference.get("metric_families", [])
        if family["family"] == "functionality"
        for item in family["intervals"]
    }
    schema_version = config["schema_version"]
    expected_primary_results = []
    for pair_id, model_id, metric in sorted(primary_keys):
        primary = analysis_estimates[(pair_id, model_id, metric)]
        coordinate_id = content_id(
            "factorial_coordinate_",
            {"pair_id": pair_id, "model_id": model_id, "metric": metric},
        )
        interval = interval_by_coordinate.get(coordinate_id)
        significant = bool(
            interval and (interval["lower"] > 0.0 or interval["upper"] < 0.0)
        )
        functionality = analysis_estimates[(pair_id, model_id, "functionality")]
        evaluability = analysis_estimates[(pair_id, model_id, "oracle_evaluable")]
        code_valid = analysis_estimates.get((pair_id, model_id, "code_valid"))
        minimum_evaluability = min(
            item["point"]
            for item in evaluability["cells"]
            if item["point"] is not None
        )
        separately_powered = bool(
            analysis_config.get(
                "functionality_noninferiority_separately_powered", False
            )
        )
        functionality_coordinate_id = content_id(
            "factorial_coordinate_",
            {"pair_id": pair_id, "model_id": model_id, "metric": "functionality"},
        )
        functionality_interval = functionality_intervals.get(
            (functionality_coordinate_id, "joint")
        )
        functionality_lower = (
            None if functionality_interval is None else functionality_interval["lower"]
        )
        if schema_version == "1.0":
            functionality_status = "legacy_point_estimate"
            functionality_noninferior: bool | None = (
                functionality["joint"] is not None
                and functionality["joint"] >= -functionality_margin
            )
        elif not separately_powered:
            functionality_status = "not_requested"
            functionality_noninferior = None
        elif functionality_lower is None:
            functionality_status = "not_evaluable"
            functionality_noninferior = None
        elif functionality_lower >= -functionality_margin:
            functionality_status = "passed"
            functionality_noninferior = True
        else:
            functionality_status = "failed"
            functionality_noninferior = False
        gate: dict[str, Any] = {
            "security_interval_excludes_zero": significant,
            "practical_interaction_margin": practical_margin,
            "practical_interaction_met": primary["interaction"] is not None
            and abs(primary["interaction"]) >= practical_margin,
            "functionality_contrast": "a11_minus_a00",
            "functionality_difference": functionality["joint"],
            "functionality_noninferiority_margin": functionality_margin,
            "functionality_noninferior": functionality_noninferior,
            "maximum_unknown_fraction": unknown_limit,
        }
        if schema_version == "1.0":
            gate.update(
                {
                    "minimum_oracle_evaluability": minimum_evaluability,
                    "unknown_gate_passed": minimum_evaluability
                    >= 1.0 - unknown_limit,
                }
            )
            gate["claim_ready"] = bool(
                config.get("scientific_claim_allowed", False)
                and all(
                    gate[name]
                    for name in (
                        "security_interval_excludes_zero",
                        "practical_interaction_met",
                        "functionality_noninferior",
                        "unknown_gate_passed",
                    )
                )
            )
        else:
            if code_valid is None:
                raise ValueError(
                    "stored prospective factorial report lacks code-validity endpoint"
                )
            gate.update(
                _independent_unknown_coverage_summary(
                    {
                        item["cell"]: item["point"]
                        for item in code_valid["cells"]
                    },
                    {
                        item["cell"]: item["point"]
                        for item in evaluability["cells"]
                    },
                    unknown_limit,
                )
            )
            gate.update(
                {
                    "functionality_noninferiority_separately_powered": separately_powered,
                    "functionality_power_qualification_sha256": (
                        analysis_config["functionality_power_qualification"]["sha256"]
                        if separately_powered
                        else None
                    ),
                    "functionality_simultaneous_lower": functionality_lower,
                    "functionality_gate_status": functionality_status,
                }
            )
            gate["security_interaction_claim_ready"] = bool(
                config.get("scientific_claim_allowed", False)
                and all(
                    gate[name]
                    for name in (
                        "security_interval_excludes_zero",
                        "practical_interaction_met",
                        "unknown_gate_passed",
                    )
                )
            )
            gate["practical_success_claim_ready"] = bool(
                gate["security_interaction_claim_ready"]
                and functionality_status == "passed"
                and functionality_noninferior
            )
            gate["claim_ready"] = gate["practical_success_claim_ready"]
        expected_primary_results.append(
            {
                "coordinate_id": coordinate_id,
                "pair_id": pair_id,
                "model_id": model_id,
                "interaction": primary["interaction"],
                "simultaneous_interval": interval,
                "interval_excludes_zero": significant,
                "gate": gate,
            }
        )
    observed_primary_results = report.get("primary_results")
    if observed_primary_results is not None and observed_primary_results != expected_primary_results:
        raise ValueError("stored factorial report primary coordinate drift")
    expected_ready = [
        item["coordinate_id"]
        for item in expected_primary_results
        if item["gate"]["claim_ready"]
    ]
    if "claim_ready_coordinates" in report and report["claim_ready_coordinates"] != expected_ready:
        raise ValueError("stored factorial report claim-ready coordinate drift")
    if schema_version == "1.1":
        expected_security_ready = [
            item["coordinate_id"]
            for item in expected_primary_results
            if item["gate"]["security_interaction_claim_ready"]
        ]
        expected_practical_ready = [
            item["coordinate_id"]
            for item in expected_primary_results
            if item["gate"]["practical_success_claim_ready"]
        ]
        if report.get("security_interaction_claim_ready_coordinates") != (
            expected_security_ready
        ):
            raise ValueError(
                "stored factorial report security-claim coordinate drift"
            )
        if report.get("practical_success_claim_ready_coordinates") != (
            expected_practical_ready
        ):
            raise ValueError(
                "stored factorial report practical-claim coordinate drift"
            )
    if len(expected_primary_results) == 1:
        only = expected_primary_results[0]
        _same(only["interaction"], report.get("primary_interaction"))
        if (
            report.get("primary_simultaneous_interval") != only["simultaneous_interval"]
            or report.get("primary_interval_excludes_zero")
            is not only["interval_excludes_zero"]
            or report.get("primary_gate") != only["gate"]
        ):
            raise ValueError("stored factorial report single-coordinate alias drift")
    elif any(
        name in report
        for name in (
            "primary_interaction",
            "primary_simultaneous_interval",
            "primary_interval_excludes_zero",
            "primary_gate",
        )
    ):
        raise ValueError("stored factorial report has ambiguous primary aliases")

    expected_status = {
        "development_canary": "FACTORIAL_CANARY_COMPLETE",
        "confirmatory": "FACTORIAL_CONFIRMATION_COMPLETE",
        "prospective_followup": "FACTORIAL_FOLLOWUP_COMPLETE",
    }.get(config.get("phase"))
    expected_realizations = (
        len(study["policies"][0]["realizations"])
        if len(study["policies"]) == 1
        else None
    )
    expected_realizations_by_pair = {
        content_id("pair_", item["pair"]): len(item["realizations"])
        for item in study["policies"]
    }
    if (
        expected_status is None
        or report.get("status") != expected_status
        or report.get("phase") not in (None, config.get("phase"))
        or report.get("study_name") != config.get("study_name")
        or report.get("tasks") != len(study.get("tasks", ()))
        or report.get("realizations") != expected_realizations
        or (
            "realizations_by_pair" in report
            and report["realizations_by_pair"] != expected_realizations_by_pair
        )
        or (
            "models" in report
            and report["models"] != study["randomization"]["models"]
        )
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
    realizations: tuple[Any, ...] | None = None,
) -> tuple[float | None, float, float]:
    task_ids = sorted(
        {
            item.block.task_instance_id
            for item in assignments
            if item.block.task_unit_id == task_unit_id
        }
    )
    task_total = sum(tasks[task_id].weight for task_id in task_ids)
    selected_realizations = policy.realizations if realizations is None else realizations
    if not selected_realizations:
        raise ValueError("independent verifier found an empty realization subset")
    realization_total = sum(item.weight for item in selected_realizations)
    point = lower = upper = 0.0
    known = True
    for task_id in task_ids:
        for realization in selected_realizations:
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


def _realization_diagnostics(
    assignments: tuple[Any, ...],
    outcomes: Mapping[str, Outcome],
    policy: Any,
    tasks: Mapping[str, Any],
    unit_ids: list[str],
    metric: str,
    aggregate: float | None,
) -> dict[str, Any]:
    realization_rows = tuple(
        {
            "realization_id": realization.realization_id,
            "application_order": tuple(realization.application_order),
            "weight": realization.weight,
            **_subset_interaction(
                assignments,
                outcomes,
                policy,
                tasks,
                unit_ids,
                metric,
                (realization,),
            ),
        }
        for realization in policy.realizations
    )
    order_rows = []
    for order in sorted({tuple(item.application_order) for item in policy.realizations}):
        subset = tuple(
            item for item in policy.realizations if tuple(item.application_order) == order
        )
        order_rows.append(
            {
                "application_order": order,
                "total_weight": sum(item.weight for item in subset),
                **_subset_interaction(
                    assignments,
                    outcomes,
                    policy,
                    tasks,
                    unit_ids,
                    metric,
                    subset,
                ),
            }
        )
    leave_one_out = tuple(
        {
            "omitted_realization_id": omitted.realization_id,
            **_subset_interaction(
                assignments,
                outcomes,
                policy,
                tasks,
                unit_ids,
                metric,
                tuple(
                    item
                    for item in policy.realizations
                    if item.realization_id != omitted.realization_id
                ),
            ),
        }
        for omitted in policy.realizations
        if len(policy.realizations) > 1
    )
    points = tuple(item["point"] for item in realization_rows) + tuple(
        item["point"] for item in order_rows
    ) + tuple(item["point"] for item in leave_one_out)
    return {
        "realization_interactions": realization_rows,
        "order_interactions": tuple(order_rows),
        "leave_one_realization_out": leave_one_out,
        "direction_robustness": _direction_robustness(aggregate, points),
    }


def _subset_interaction(
    assignments: tuple[Any, ...],
    outcomes: Mapping[str, Outcome],
    policy: Any,
    tasks: Mapping[str, Any],
    unit_ids: list[str],
    metric: str,
    realizations: tuple[Any, ...],
) -> dict[str, float | None]:
    cell_rows = tuple(
        {
            cell: _unit_cell(
                assignments,
                outcomes,
                policy,
                tasks,
                unit_id,
                cell,
                metric,
                realizations,
            )
            for cell in FACTORIAL_CELL_ORDER
        }
        for unit_id in unit_ids
    )
    points = tuple(
        _interaction({cell: cells[cell][0] for cell in FACTORIAL_CELL_ORDER})
        for cells in cell_rows
    )
    bounds = tuple(
        _interaction_bounds(
            {cell: (*cells[cell], None) for cell in FACTORIAL_CELL_ORDER}
        )
        for cells in cell_rows
    )
    return {
        "point": None
        if any(item is None for item in points)
        else _mean([float(item) for item in points]),
        "lower": _mean([item[0] for item in bounds]),
        "upper": _mean([item[1] for item in bounds]),
    }


def _direction_robustness(
    aggregate: float | None,
    diagnostics: tuple[float | None, ...],
    tolerance: float = 1e-12,
) -> str:
    if aggregate is None or any(item is None for item in diagnostics):
        return "not_evaluable"
    if len(diagnostics) <= 2:
        return "average_effect_only"
    if abs(aggregate) <= tolerance:
        return "no_average_direction"
    signed = tuple(float(item) * aggregate for item in diagnostics)
    if any(item < -(tolerance**2) for item in signed):
        return "direction_reversal"
    if all(item > tolerance**2 for item in signed):
        return "direction_robust"
    return "direction_fragile"


def _verify_realization_diagnostics(observed: Any, expected: Mapping[str, Any]) -> None:
    for name in (
        "realization_interactions",
        "order_interactions",
        "leave_one_realization_out",
    ):
        raw = observed[name] if isinstance(observed, Mapping) else getattr(observed, name)
        rows = tuple(raw)
        expected_rows = expected[name]
        if len(rows) != len(expected_rows):
            raise ValueError("independent verifier found realization diagnostic support drift")
        for left, right in zip(rows, expected_rows, strict=True):
            for key, value in right.items():
                actual = left[key] if isinstance(left, Mapping) else getattr(left, key)
                if key == "application_order":
                    actual = tuple(actual)
                _same(value, actual)
    observed_label = (
        observed["direction_robustness"]
        if isinstance(observed, Mapping)
        else observed.direction_robustness
    )
    _same(expected["direction_robustness"], observed_label)


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
    for name in ("factor_1_given_factor_2", "factor_2_given_factor_1"):
        observed = getattr(estimate, name, None)
        if observed is not None:
            _same(expected[name], observed)
    for name in (
        "factor_1_given_factor_2_bounds",
        "factor_2_given_factor_1_bounds",
    ):
        observed = getattr(estimate, name, ())
        if observed:
            _same(expected[name], observed)
    stored_units = {item.task_unit_id: item for item in estimate.task_unit_effects}
    if set(stored_units) != {item["task_unit_id"] for item in expected["unit_rows"]}:
        raise ValueError("reported task-unit support drift")
    for row in expected["unit_rows"]:
        _same(row["interaction"], stored_units[row["task_unit_id"]].interaction)
    diagnostics = getattr(estimate, "realization_diagnostics", None)
    if diagnostics is not None:
        _verify_realization_diagnostics(
            diagnostics, expected["realization_diagnostics"]
        )
    pattern = getattr(estimate, "response_pattern", None)
    if pattern is not None:
        _same(expected["response_pattern"], _name(pattern))


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
    return _effect_bootstrap_intervals(
        rows,
        plan,
        metric=_name(plan.primary_metric),
        effects=tuple(_name(item) for item in plan.secondary_effects),
        seed_namespace="factorial_secondary_bootstrap_",
    )


def _effect_bootstrap_intervals(
    rows: list[tuple[Any, Mapping[str, Any]]],
    plan: Any,
    *,
    metric: str,
    effects: tuple[str, ...],
    seed_namespace: str,
) -> tuple[dict[tuple[str, str], tuple[float, float, float]], float]:
    eligible = [
        (estimate, expected, effect)
        for estimate, expected in rows
        if _name(estimate.metric) == metric
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
                    seed_namespace,
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
            max(
                -2.0 if effect == "interaction" else -1.0,
                float(expected[effect]) - critical * errors[key],
            ),
            min(
                2.0 if effect == "interaction" else 1.0,
                float(expected[effect]) + critical * errors[key],
            ),
        )
        for key, (_, expected, effect) in zip(keys, eligible, strict=True)
    }, critical


def _verify_metric_families(
    rows: list[tuple[Any, Mapping[str, Any]]], plan: Any, reported: Any
) -> int | None:
    families = tuple(getattr(reported, "metric_families", ()))
    if not families:
        return None
    expected_metrics = {"functionality", "joint"} & {
        _name(item.metric) for item, _ in rows
    }
    observed_metrics = {_name(item.metric) for item in families}
    if observed_metrics != expected_metrics or len(families) != len(observed_metrics):
        raise ValueError("independent verifier found factorial metric-family drift")
    effects = ("interaction", *tuple(_name(item) for item in plan.secondary_effects))
    interval_count = 0
    for family in families:
        metric = _name(family.metric)
        if hasattr(plan, "minimum_task_units"):
            expected, critical, _diagnostics = _studentized_effect_bootstrap_intervals(
                rows,
                plan,
                metric=metric,
                effects=effects,
                seed_namespace=f"factorial_{metric}_studentized_v2_",
            )
        else:
            expected, critical = _effect_bootstrap_intervals(
                rows,
                plan,
                metric=metric,
                effects=effects,
                seed_namespace=f"factorial_{metric}_bootstrap_",
            )
        _same(critical, family.simultaneous_critical_value)
        observed = {
            (item.coordinate_id, _name(item.effect)): item
            for item in family.intervals
        }
        if set(observed) != set(expected):
            raise ValueError(
                "independent verifier found factorial metric-family interval drift"
            )
        for key, values in expected.items():
            _same(values[0], observed[key].standard_error)
            _same(values[1], observed[key].lower)
            _same(values[2], observed[key].upper)
        interval_count += len(expected)
    return interval_count


def _studentized_effect_bootstrap_intervals(
    rows: list[tuple[Any, Mapping[str, Any]]],
    plan: Any,
    *,
    metric: str,
    effects: tuple[str, ...],
    seed_namespace: str,
) -> tuple[
    dict[tuple[str, str], tuple[float, float, float]],
    float,
    dict[str, Any],
]:
    candidates = []
    insufficient_support = []
    zero_standard_error = []
    for estimate, expected in rows:
        if _name(estimate.metric) != metric:
            continue
        for effect in effects:
            point = expected[effect]
            values = tuple(
                (unit["task_unit_id"], _unit_effect(unit, effect))
                for unit in expected["unit_rows"]
            )
            key = (estimate.coordinate_id, effect)
            if (
                point is None
                or len(values) < plan.minimum_task_units
                or any(value is None for _, value in values)
            ):
                insufficient_support.append(key)
                continue
            numeric = tuple(float(value) for _, value in values)
            standard_error = _mean_standard_error(numeric)
            if standard_error <= 0.0:
                zero_standard_error.append(key)
                continue
            candidates.append(
                (
                    key,
                    float(point),
                    {unit_id: float(value) for unit_id, value in values},
                    standard_error,
                )
            )
    base = {
        "algorithm": "global_task_unit_union_replicate_studentized_max_abs_t_v2",
        "quantile_method": plan.bootstrap_quantile_method,
        "minimum_task_units": plan.minimum_task_units,
        "minimum_valid_bootstrap_fraction": plan.minimum_valid_bootstrap_fraction,
        "insufficient_support_members": [list(item) for item in insufficient_support],
        "zero_standard_error_members": [list(item) for item in zero_standard_error],
    }
    if not candidates:
        status = (
            "zero_standard_error"
            if zero_standard_error
            else "no_eligible_coordinates"
        )
        return {}, 0.0, {
            **base,
            "status": status,
            "task_unit_union_size": 0,
            "valid_bootstrap_draws": 0,
            "invalid_bootstrap_draws": plan.bootstrap_draws,
        }

    task_unit_union = tuple(
        sorted({unit_id for _, _, values, _ in candidates for unit_id in values})
    )
    family_members = tuple(key for key, *_ in candidates)
    rng = random.Random(
        int(
            content_id(
                seed_namespace,
                {
                    "seed": plan.bootstrap_seed,
                    "task_unit_union": task_unit_union,
                    "family_members": family_members,
                    "quantile_method": plan.bootstrap_quantile_method,
                },
            )[-16:],
            16,
        )
    )
    maxima = []
    invalid = 0
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        statistics_for_draw = []
        valid = True
        for _key, point, value_by_unit, _standard_error in candidates:
            sample = tuple(
                value_by_unit[unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit
            )
            if len(sample) < plan.minimum_task_units:
                valid = False
                break
            replicate_error = _mean_standard_error(sample)
            if replicate_error <= 0.0:
                valid = False
                break
            statistics_for_draw.append(
                abs(sum(sample) / len(sample) - point) / replicate_error
            )
        if valid:
            maxima.append(max(statistics_for_draw))
        else:
            invalid += 1
    minimum_valid = math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    )
    diagnostics = {
        **base,
        "task_unit_union_size": len(task_unit_union),
        "valid_bootstrap_draws": len(maxima),
        "invalid_bootstrap_draws": invalid,
    }
    if len(maxima) < minimum_valid:
        return {}, 0.0, {**diagnostics, "status": "insufficient_valid_bootstrap"}
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = {}
    for key, point, _value_by_unit, standard_error in candidates:
        effect = key[1]
        lower_limit = -2.0 if effect == "interaction" else -1.0
        upper_limit = 2.0 if effect == "interaction" else 1.0
        intervals[key] = (
            standard_error,
            max(lower_limit, point - critical * standard_error),
            min(upper_limit, point + critical * standard_error),
        )
    return intervals, critical, {**diagnostics, "status": "evaluable"}


def _unit_effect(unit: Mapping[str, Any], effect: str) -> float | None:
    cells = unit["cells"]
    if effect == "factor_1":
        return _difference(cells[FactorialCell.A10][0], cells[FactorialCell.A00][0])
    if effect == "factor_2":
        return _difference(cells[FactorialCell.A01][0], cells[FactorialCell.A00][0])
    if effect == "factor_1_given_factor_2":
        return _difference(cells[FactorialCell.A11][0], cells[FactorialCell.A01][0])
    if effect == "factor_2_given_factor_1":
        return _difference(cells[FactorialCell.A11][0], cells[FactorialCell.A10][0])
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


def _classify_pattern(
    values: Mapping[FactorialCell, float | None], tolerance: float = 1e-12
) -> str:
    if any(values[cell] is None for cell in FACTORIAL_CELL_ORDER):
        return "not_evaluable"
    cells = tuple(float(values[cell]) for cell in FACTORIAL_CELL_ORDER)
    binary = tuple(
        round(value) if abs(value - round(value)) <= tolerance else None
        for value in cells
    )
    if binary == (0, 1, 1, 0):
        return "xor"
    if binary == (0, 1, 1, 1):
        return "redundant"
    if binary == (0, 0, 0, 1):
        return "prerequisite"
    if (
        (cells[1] - cells[0]) * (cells[3] - cells[2]) < -(tolerance**2)
        or (cells[2] - cells[0]) * (cells[3] - cells[1]) < -(tolerance**2)
    ):
        return "reversal"
    interaction = cells[3] - cells[1] - cells[2] + cells[0]
    if abs(interaction) <= tolerance:
        return "additive"
    return "positive_interaction" if interaction > 0.0 else "negative_interaction"


def _interaction_bounds(
    cells: Mapping[FactorialCell, tuple[Any, float, float, Any]],
) -> tuple[float, float]:
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


def _mean_standard_error(values: tuple[float, ...]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(
        sum((value - mean) ** 2 for value in values)
        / (len(values) * (len(values) - 1))
    )


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
