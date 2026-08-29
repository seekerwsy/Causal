"""Validation rules for the single active pairwise-factorial protocol."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from prompt_mechanism_study.artifact_io import is_sha256
from prompt_mechanism_study.mechanisms import validate_active_factorial_relation
from prompt_mechanism_study.qualification import (
    QualificationError,
    validate_functionality_power_payload,
)


class FactorialExperimentError(ValueError):
    """A frozen factorial input or provider output failed closed."""


def validate_factorial_analysis(config: Mapping[str, Any]) -> None:
    analysis = config.get("analysis")
    if not isinstance(analysis, dict):
        raise FactorialExperimentError("factorial schema 1.1 analysis is invalid")
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
    separately_powered = analysis.get("functionality_noninferiority_separately_powered")
    power_field = "functionality_power_qualification"
    expected = required | ({power_field} if separately_powered is True else set())
    if set(analysis) != expected:
        raise FactorialExperimentError("factorial schema 1.1 analysis fields are not exact")
    if analysis.get("metrics") != [
        "secure_yield",
        "code_valid",
        "oracle_evaluable",
        "functionality",
        "joint",
    ]:
        raise FactorialExperimentError(
            "factorial schema 1.1 requires the five ordered, distinct outcome endpoints"
        )
    effects = analysis.get("secondary_effects")
    if not isinstance(effects, list) or not {
        "factor_1",
        "factor_2",
        "factor_1_given_factor_2",
        "factor_2_given_factor_1",
        "joint",
    } <= set(effects):
        raise FactorialExperimentError(
            "factorial schema 1.1 requires both conditional simple effects"
        )
    if analysis.get("primary_metric") != "secure_yield":
        raise FactorialExperimentError("factorial schema 1.1 primary metric must be secure_yield")
    if (
        type(analysis.get("bootstrap_seed")) is not int
        or type(analysis.get("bootstrap_draws")) is not int
        or analysis["bootstrap_draws"] < 100
        or type(analysis.get("familywise_alpha")) is not float
        or not 0.0 < analysis["familywise_alpha"] < 1.0
        or type(analysis.get("minimum_task_units")) is not int
        or analysis["minimum_task_units"] < 2
        or type(analysis.get("minimum_valid_bootstrap_fraction")) is not float
        or not 0.0 < analysis["minimum_valid_bootstrap_fraction"] <= 1.0
        or analysis.get("bootstrap_quantile_method") != "higher"
        or type(analysis.get("functionality_noninferiority_separately_powered")) is not bool
        or any(
            type(analysis.get(name)) is not float or not 0.0 <= analysis[name] <= 1.0
            for name in (
                "practical_interaction_margin",
                "maximum_unknown_fraction",
                "functionality_noninferiority_margin",
            )
        )
    ):
        raise FactorialExperimentError(
            "factorial schema 1.1 bootstrap and functionality-gate rules are invalid"
        )
    if separately_powered:
        reference = analysis[power_field]
        if (
            not isinstance(reference, dict)
            or set(reference) != {"path", "sha256"}
            or not isinstance(reference["path"], str)
            or not reference["path"].strip()
            or not is_sha256(reference["sha256"])
        ):
            raise FactorialExperimentError(
                "factorial functionality power qualification reference is invalid"
            )


def validate_factorial_config(config: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "study_name",
        "phase",
        "purpose",
        "corpus",
        "pair_registry_path",
        "prompt_tsg_catalog_path",
        "pair_protocols",
        "generation",
        "functional_oracle",
        "randomization",
        "analysis",
        "scale_gate",
        "scientific_claim_allowed",
    }
    if set(config) not in (required, required | {"pair_selection"}):
        raise FactorialExperimentError("factorial schema 1.1 top-level fields are not exact")
    exact_sections = {
        "corpus": {
            "path",
            "bundle_sha256",
            "task_ids",
            "selection_outcomes_consulted",
            "generalization_boundary",
        },
        "functional_oracle": {
            "evaluator_config_path",
            "evaluator_config_sha256",
            "prompt_path",
            "prompt_sha256",
            "qualification_path",
            "qualification_sha256",
        },
        "randomization": {"seed", "slots"},
    }
    for name, fields in exact_sections.items():
        if not isinstance(config.get(name), Mapping) or set(config[name]) != fields:
            raise FactorialExperimentError(f"factorial schema 1.1 {name} fields are not exact")


def validate_factorial_intervention_design(
    intervention: Mapping[str, Any],
) -> None:
    commutative = intervention.get("joint_application_commutative")
    realizations = intervention.get("joint_realizations")
    if type(commutative) is not bool or not isinstance(realizations, list) or not realizations:
        raise FactorialExperimentError(
            "factorial schema 1.1 must declare joint-application commutativity"
        )
    orders = set()
    for item in realizations:
        if (
            not isinstance(item, dict)
            or type(item.get("weight")) is not int
            or item["weight"] <= 0
            or item.get("application_order") not in ([1, 2], [2, 1])
        ):
            raise FactorialExperimentError("factorial joint-realization order support is invalid")
        orders.add(tuple(item["application_order"]))
    if not commutative and orders != {(1, 2), (2, 1)}:
        raise FactorialExperimentError(
            "non-commutative factorial pairs require both application orders"
        )


def validate_factorial_pair_relations(pairs: tuple[Any, ...]) -> None:
    try:
        for pair in pairs:
            validate_active_factorial_relation(pair.relation_type)
    except (AttributeError, TypeError, ValueError) as error:
        raise FactorialExperimentError(
            "factorial pair relation is outside the active successor vocabulary"
        ) from error


def validate_factorial_functionality_power(
    payload: Any,
    analysis: Mapping[str, Any],
) -> int:
    """Validate the factorial study's prospective functionality power plan."""

    try:
        return validate_functionality_power_payload(
            payload,
            analysis,
            expected_coordinate={
                "metric": "functionality",
                "contrast": "a11_minus_a00",
                "unit": "task_unit",
                "scope": "each_pair_model_coordinate",
            },
            expected_assumption_keys=frozenset(
                {
                    "baseline_functionality_rate",
                    "alternative_difference",
                    "paired_task_unit_correlation",
                }
            ),
        )
    except QualificationError as error:
        raise FactorialExperimentError(str(error)) from error


__all__ = [
    "FactorialExperimentError",
    "validate_factorial_analysis",
    "validate_factorial_config",
    "validate_factorial_functionality_power",
    "validate_factorial_intervention_design",
    "validate_factorial_pair_relations",
]
