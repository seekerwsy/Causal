"""Linear runner for the prospectively frozen pairwise factorial study."""

from __future__ import annotations

import hashlib
import os
import platform
import random
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from prompt_mechanism_study.adapters import AdapterBundle, AdapterKind, AdapterSpec
from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    json_object as parse_json_object,
    read_json,
    read_json_exact as read_strict_json,
    require_file_hash as verify_file_hash,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.factorial_freeze import (
    validate_factorial_variant_graphs,
    verify_factorial_freeze_bundle as _verify_factorial_freeze_bundle,
)
from prompt_mechanism_study.factorial_protocol import (
    FactorialExperimentError,
    validate_factorial_analysis,
    validate_factorial_config,
    validate_factorial_functionality_power,
    validate_factorial_intervention_design,
    validate_factorial_pair_relations,
)
from prompt_mechanism_study.factorial_verify import (
    verify_factorial_inference,
    verify_factorial_result_bundle,
    verify_mechanism_trace_diagnostics,
)
from prompt_mechanism_study.functional_judge import (
    bailian_complete,
)
from prompt_mechanism_study.inference import (
    FactorialAnalysisPlan,
    FactorialEffect,
    Metric,
)
from prompt_mechanism_study.interaction_selector_experiment import (
    INTERACTION_SELECTION_ARTIFACT_FILES,
    verify_interaction_selection_bundle,
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
from prompt_mechanism_study.measurement import (
    Measurement,
    MeasurementExecutionError,
    measure_generated_code,
)
from prompt_mechanism_study.mechanisms import (
    PairBinding,
    PairEligibility,
    bind_pair,
    load_pair_registry,
)
from prompt_mechanism_study.prompt_tsg import (
    QueryState,
    build_prompt_tsg,
    load_catalog,
    prompt_tsg_record,
    prompt_tsg_from_record,
    validate_prompt_tsg,
)
from prompt_mechanism_study.qualification import (
    QualificationError,
    load_functional_qualification,
    validate_functional_qualification,
)
from prompt_mechanism_study.records import canonical_value, content_hash, content_id
from prompt_mechanism_study.representation import Split, Task
from prompt_mechanism_study.security_profiles import (
    evaluate_security_profile,
    security_profile_producer_sha256,
)
from prompt_mechanism_study.workflow import (
    FactorialPairSelection,
    analyze_factorial,
    factorial_oracle_dispatch_policy_sha256,
    freeze_factorial_study,
)


def preflight_factorial_experiment(
    repository_root: Path,
    config_path: Path,
) -> dict[str, Any]:
    inputs = _load_inputs(repository_root, config_path)
    credentials = tuple(
        sorted(
            {
                item["api_key_env"]
                for item in inputs["generation_models"]
            }
        )
    )
    assignments = sum(
        len(protocol["task_rows"])
        * len(protocol["realizations"])
        * len(FACTORIAL_CELL_ORDER)
        * len(inputs["generation_models"])
        for protocol in inputs["pair_protocols"]
    )
    return {
        "schema_version": "1.1",
        "status": "FACTORIAL_PREFLIGHT_COMPLETE",
        "study_name": inputs["config"]["study_name"],
        "tasks": len(inputs["task_rows"]),
        "realizations": sum(
            len(item["realizations"]) for item in inputs["pair_protocols"]
        ),
        "assignments": assignments,
        "credentials": [
            {"env": name, "present": bool(os.environ.get(name, "").strip())}
            for name in credentials
        ],
        "models": [item["model_id"] for item in inputs["generation_models"]],
        "pair_ids": [item.pair_id for item in inputs["pairs"]],
        "oracle_support_by_pair": {
            item.pair_id: item.oracle_support_status.value for item in inputs["pairs"]
        },
        "configured_scientific_claim_allowed": bool(
            inputs["config"].get("scientific_claim_allowed", False)
        ),
        "scientific_claim_allowed": False,
    }


def freeze_factorial_experiment(
    repository_root: Path,
    config_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Materialize the prospective intervention and randomization before outcomes."""

    inputs = _load_inputs(repository_root, config_path)
    if inputs["config"]["schema_version"] != "1.1":
        raise FactorialExperimentError(
            "factorial freeze is reserved for the active schema 1.1 protocol"
        )
    credential_names = tuple(
        sorted({item["api_key_env"] for item in inputs["generation_models"]})
    )
    if any(not os.environ.get(name, "").strip() for name in credential_names):
        raise FactorialExperimentError("provider credential is unavailable")
    study, _policies, calls, variant_tsgs = _materialize_factorial_study(inputs)
    assignment_ids = [item.assignment_id for item in study.randomization.assignments]
    rng = random.Random(
        int(
            content_hash(
                {
                    "namespace": "factorial_global_execution_order_v1",
                    "seed": inputs["config"]["randomization"]["seed"],
                    "assignment_ids": sorted(assignment_ids),
                }
            )[:16],
            16,
        )
    )
    rng.shuffle(assignment_ids)
    artifacts = _prospective_freeze_artifacts(
        inputs,
        study,
        calls,
        variant_tsgs,
        assignment_ids,
    )
    write_bundle(output, artifacts)
    verified = _verify_factorial_freeze_bundle(output)
    return {
        "status": "FACTORIAL_FREEZE_COMPLETE",
        "study_id": study.study_id,
        "assignments": len(assignment_ids),
        "freeze_bundle_sha256": bundle_digest(output),
        "verification": verified,
    }


def _prospective_freeze_artifacts(
    inputs: Mapping[str, Any],
    study: Any,
    calls: list[dict[str, Any]],
    variant_tsgs: Mapping[str, Mapping[str, Any]],
    assignment_ids: list[str],
) -> dict[str, Any]:
    artifacts: dict[str, Any] = {
        "effective-config.json": inputs["config"],
        "study-freeze.json": canonical_value(study),
        "intervention-calls.json": calls,
        "factorial-variant-tsgs.json": {
            "schema_version": "1.0",
            "variants": dict(variant_tsgs),
        },
        "factorial-measurement-inputs.json": {
            "schema_version": "1.1",
            "tasks": [
                {
                    name: item[name]
                    for name in (
                        "task_id",
                        "task_unit_id",
                        "cwe",
                        "archetype",
                        "prompt",
                        "prompt_tsg",
                        "functional_contract",
                    )
                }
                for item in inputs["task_rows"]
            ],
        },
        "execution-order.json": {
            "schema_version": "1.0",
            "assignment_ids": assignment_ids,
        },
        "factorial-pair-registry.json": inputs["registry_value"],
        "factorial-prompt-tsg-catalog.json": inputs["catalog"],
        "factorial-oracle-qualifications.json": inputs[
            "oracle_qualification_artifact"
        ],
        "factorial-functional-qualification.json": inputs[
            "functional_qualification"
        ],
    }
    if inputs["functionality_power_qualification"] is not None:
        artifacts["factorial-functionality-power-qualification.json"] = inputs[
            "functionality_power_qualification"
        ]
    selector_root = inputs["pair_selection_artifact_root"]
    if selector_root is not None:
        artifacts.update(
            {
                f"pair-selection-{name}": read_json(selector_root / name)
                for name in INTERACTION_SELECTION_ARTIFACT_FILES
            }
        )
    return artifacts










def run_factorial_experiment(
    repository_root: Path,
    config_path: Path,
    output: Path,
    *,
    freeze_root: Path | None = None,
) -> dict[str, Any]:
    """Run intervention, randomization, measurement, analysis, and verification once."""

    root = repository_root.resolve()
    config_file = config_path if config_path.is_absolute() else root / config_path
    requested_config = _read_exact_json(config_file)
    if requested_config.get("schema_version") != "1.1":
        raise FactorialExperimentError("factorial run requires active schema 1.1")
    if freeze_root is None:
        raise FactorialExperimentError("active factorial run requires --freeze")
    freeze_path = freeze_root.resolve()
    freeze_verification = _verify_factorial_freeze_bundle(freeze_path)
    frozen_config = read_json(freeze_path / "effective-config.json")
    if frozen_config != requested_config:
        raise FactorialExperimentError("factorial run config drifts from its freeze")
    frozen_functional_qualification = read_json(
        freeze_path / "factorial-functional-qualification.json"
    )
    inputs = _load_inputs(
        repository_root,
        config_path,
        frozen_functional_qualification=frozen_functional_qualification,
    )
    config = inputs["config"]
    credential_names = tuple(
        sorted({item["api_key_env"] for item in inputs["generation_models"]})
    )
    if any(not os.environ.get(name, "").strip() for name in credential_names):
        raise FactorialExperimentError("provider credential is unavailable")
    if inputs["functional_qualification"] != frozen_functional_qualification:
        raise FactorialExperimentError(
            "factorial run functional qualification drifts from its freeze"
        )
    frozen_oracle_evidence = read_json(
        freeze_path / "factorial-oracle-qualifications.json"
    )
    if frozen_oracle_evidence != inputs["oracle_qualification_artifact"]:
        raise FactorialExperimentError(
            "factorial run Oracle producer or qualification drifts from its freeze"
        )
    power_path = freeze_path / "factorial-functionality-power-qualification.json"
    frozen_power = read_json(power_path) if power_path.is_file() else None
    if frozen_power != inputs["functionality_power_qualification"]:
        raise FactorialExperimentError(
            "factorial run functionality power qualification drifts from its freeze"
        )
    frozen_calls = read_json(freeze_path / "intervention-calls.json")
    inputs = {**inputs, "frozen_intervention_calls": frozen_calls}
    study, policies, calls, variant_tsgs = _materialize_factorial_study(inputs)
    if calls != frozen_calls:
        raise FactorialExperimentError(
            "factorial intervention evidence drifts from its freeze"
        )
    if canonical_value(study) != read_json(freeze_path / "study-freeze.json"):
        raise FactorialExperimentError(
            "factorial run rematerialization drifts from its freeze"
        )
    execution_order = read_json(freeze_path / "execution-order.json")[
        "assignment_ids"
    ]
    task_by_id = {row["task_id"]: row for row in inputs["task_rows"]}
    bundle_by_id = {
        item.task_bundle_id: item for policy in policies for item in policy.bundles
    }
    measurements = []
    measurement_records = []
    assignment_by_id = {
        item.assignment_id: item for item in study.randomization.assignments
    }
    for execution_ordinal, assignment_id in enumerate(execution_order):
        assignment = assignment_by_id[assignment_id]
        task = task_by_id[assignment.block.task_instance_id]
        bundle = bundle_by_id[assignment.block.factorial_task_bundle_id]
        prompt = bundle.variant(assignment.cell).prompt_text
        started_ns = time.time_ns()
        measurement, record, assignment_calls = _measure_assignment(
            inputs,
            assignment,
            task,
            prompt,
        )
        finished_ns = time.time_ns()
        calls.extend(assignment_calls)
        measurements.append(measurement)
        measurement_records.append(
            {
                "assignment": canonical_value(assignment),
                "measurement": canonical_value(measurement),
                "execution": {
                    "ordinal": execution_ordinal,
                    "started_unix_ns": started_ns,
                    "finished_unix_ns": finished_ns,
                    "elapsed_ns": finished_ns - started_ns,
                    "provider_observable_state": {
                        "model_id": assignment.block.model_id,
                        "provider_seed": assignment.provider_seed,
                        "request_slot": assignment.request_slot,
                    },
                },
                **record,
            }
        )
    analysis = analyze_factorial(study, measurements)
    verification = verify_factorial_inference(
        study.randomization,
        analysis.outcomes,
        study.policies,
        study.tasks,
        study.analysis_plan,
        analysis.inference,
    )
    report = _report(
        config,
        study,
        analysis,
        verification,
        measurement_records,
        inputs["trace_endpoints_by_pair"],
    )
    environment = {
        "python": sys.version,
        "platform": platform.platform(),
        "python_dont_write_bytecode": os.environ.get("PYTHONDONTWRITEBYTECODE"),
        "credential_names": list(credential_names),
        "credential_value_recorded": False,
    }
    artifacts = {
        "effective-config.json": config,
        "environment.json": environment,
        "study-freeze.json": canonical_value(study),
        "provider-calls.json": calls,
        "measurement-records.json": measurement_records,
        "analysis.json": canonical_value(analysis),
        "verification.json": verification,
        "report.json": report,
    }
    artifacts.update(
        {
            "factorial-pair-registry.json": inputs["registry_value"],
            "factorial-prompt-tsg-catalog.json": inputs["catalog"],
            "factorial-measurement-inputs.json": read_json(
                freeze_path / "factorial-measurement-inputs.json"
            ),
            "factorial-variant-tsgs.json": read_json(
                freeze_path / "factorial-variant-tsgs.json"
            ),
            "factorial-freeze.json": {
                "bundle_sha256": bundle_digest(freeze_path),
                "verification": freeze_verification,
            },
        }
    )
    artifacts.update(
        {
            f"freeze-{path.name}": read_json(path)
            for path in freeze_path.glob("*.json")
            if path.name != "manifest.json"
        }
    )
    selector_root = inputs["pair_selection_artifact_root"]
    if selector_root is not None:
        artifacts.update(
            {
                f"pair-selection-{name}": read_json(selector_root / name)
                for name in INTERACTION_SELECTION_ARTIFACT_FILES
            }
        )
    write_bundle(output, artifacts)
    verify_factorial_result_bundle(output)
    return report


def _materialize_factorial_study(
    inputs: Mapping[str, Any],
) -> tuple[Any, tuple[Any, ...], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    config = inputs["config"]
    calls: list[dict[str, Any]] = []
    variant_tsgs: dict[str, dict[str, Any]] = {}
    policies = []
    for protocol in inputs["pair_protocols"]:
        bundles = []
        for task in protocol["task_rows"]:
            for realization in protocol["realizations"]:
                prompts, graphs, executor_raw, executor_request = _execute_intervention(
                    inputs, protocol, task, realization
                )
                validation, validator_raw, validator_request = _validate_intervention(
                    inputs, protocol, task, realization, prompts
                )
                executor_digest = hashlib.sha256(executor_raw).hexdigest()
                validator_digest = hashlib.sha256(validator_raw).hexdigest()
                executions = {
                    cell: FactorialExecution(
                        prompts[cell],
                        inputs["adapters"].intervention_executor.adapter_id,
                        executor_digest,
                    )
                    for cell in FACTORIAL_CELL_ORDER
                }
                for cell, graph in graphs.items():
                    variant_tsgs[content_hash(prompts[cell])] = prompt_tsg_record(graph)
                validations = {
                    cell: _cell_validation(
                        validation[cell.value],
                        inputs["adapters"].intervention_validator.adapter_id,
                        validator_digest,
                    )
                    for cell in FACTORIAL_CELL_ORDER
                }
                cross = validation["cross_cell"]
                bundles.append(
                    freeze_factorial_bundle(
                        protocol["pair"],
                        task_id=task["task_id"],
                        task_unit_id=task["task_unit_id"],
                        source_prompt=task["prompt"],
                        realization=realization,
                        executions=executions,
                        validations=validations,
                        bundle_validation=FactorialBundleValidation(
                            SemanticVerdict.YES,
                            _yes(cross["functional_contract_preserved"]),
                            _yes(cross["pair_context_preserved"]),
                            _yes(cross["non_target_security_preserved"]),
                            _yes(cross["presentation_policy_preserved"]),
                            _yes(cross["no_third_requirement"]),
                            _yes(cross["treatment_states_distinct"]),
                            inputs["adapters"].intervention_validator.adapter_id,
                            validator_digest,
                        ),
                    )
                )
                calls.append(
                    {
                        "stage": "intervention",
                        "pair_id": protocol["pair"].pair_id,
                        "task_id": task["task_id"],
                        "realization_id": realization.realization_id,
                        "executor_adapter_id": inputs[
                            "adapters"
                        ].intervention_executor.adapter_id,
                        "executor_request": executor_request,
                        "executor_response_sha256": executor_digest,
                        "executor_response": executor_raw.decode("utf-8"),
                        "validator_adapter_id": inputs[
                            "adapters"
                        ].intervention_validator.adapter_id,
                        "validator_request": validator_request,
                        "validator_response_sha256": validator_digest,
                        "validator_response": validator_raw.decode("utf-8"),
                    }
                )
        policies.append(
            freeze_factorial_policy(
                protocol["pair"],
                factorial_protocol_id=_factorial_protocol_id(config, protocol),
                realizations=protocol["realizations"],
                bundles=tuple(bundles),
            )
        )
    analysis = config["analysis"]
    analysis_plan = FactorialAnalysisPlan(
        tuple(Metric(item) for item in analysis["metrics"]),
        Metric(analysis["primary_metric"]),
        analysis["bootstrap_seed"],
        analysis["bootstrap_draws"],
        float(analysis["familywise_alpha"]),
        tuple(
            FactorialEffect(item)
            for item in analysis.get(
                "secondary_effects", ["factor_1", "factor_2", "joint"]
            )
        ),
        minimum_task_units=analysis["minimum_task_units"],
        minimum_valid_bootstrap_fraction=analysis[
            "minimum_valid_bootstrap_fraction"
        ],
        bootstrap_quantile_method=analysis["bootstrap_quantile_method"],
        practical_interaction_margin=analysis["practical_interaction_margin"],
        maximum_unknown_fraction=analysis["maximum_unknown_fraction"],
        functionality_noninferiority_margin=analysis[
            "functionality_noninferiority_margin"
        ],
        functionality_noninferiority_separately_powered=analysis[
            "functionality_noninferiority_separately_powered"
        ],
        functionality_power_qualification_sha256=(
            None
            if inputs["functionality_power_qualification"] is None
            else inputs["functionality_power_qualification"]["qualification_sha256"]
        ),
    )
    study = freeze_factorial_study(
        tuple(_task(row) for row in inputs["task_rows"]),
        inputs["pair_bindings"],
        tuple(policies),
        inputs["adapters"],
        analysis_plan,
        prompt_tsg_catalog_sha256=inputs["registry"].prompt_tsg_catalog_sha256,
        models=tuple(item["model_id"] for item in inputs["generation_models"]),
        slots=tuple(config["randomization"]["slots"]),
        randomization_seed=config["randomization"]["seed"],
        provider_seed=inputs["provider_seed"],
        pair_selection=inputs["pair_selection"],
    )
    return study, tuple(policies), calls, variant_tsgs


def _factorial_protocol_id(
    config: Mapping[str, Any], protocol: Mapping[str, Any]
) -> str:
    return content_id(
        "factorial_protocol_v11_",
        {
            "study_name": config["study_name"],
            "pair_id": protocol["pair"].pair_id,
            "joint_application_commutative": protocol["intervention"][
                "joint_application_commutative"
            ],
            "realization_ids": tuple(
                item.realization_id for item in protocol["realizations"]
            ),
        },
    )


def _load_inputs(
    repository_root: Path,
    config_path: Path,
    *,
    frozen_functional_qualification: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    root = repository_root.resolve()
    config_file = config_path if config_path.is_absolute() else root / config_path
    config = _read_exact_json(config_file)
    phase = config.get("phase")
    if config.get("schema_version") != "1.1" or phase not in {
        "development_canary",
        "confirmatory",
        "prospective_followup",
    }:
        raise FactorialExperimentError("factorial config envelope is invalid")
    validate_factorial_config(config)
    validate_factorial_analysis(config)
    functionality_power_qualification = _functionality_power_qualification(
        root, config["analysis"]
    )
    claim_allowed = config.get("scientific_claim_allowed")
    if type(claim_allowed) is not bool or (
        phase == "development_canary" and claim_allowed
    ):
        raise FactorialExperimentError("factorial claim boundary is invalid")
    corpus_root = root / config["corpus"]["path"]
    verify_bundle(corpus_root)
    if bundle_digest(corpus_root) != config["corpus"]["bundle_sha256"]:
        raise FactorialExperimentError("factorial corpus bundle drift")
    all_tasks = read_json(corpus_root / "tasks.json")
    by_task = {item["task_id"]: item for item in all_tasks}
    selected_ids = config["corpus"]["task_ids"]
    if (
        not selected_ids
        or len(selected_ids) != len(set(selected_ids))
        or any(item not in by_task for item in selected_ids)
    ):
        raise FactorialExperimentError("factorial task selection is invalid")
    task_rows = tuple(by_task[item] for item in selected_ids)
    if len({item["task_unit_id"] for item in task_rows}) != len(task_rows):
        raise FactorialExperimentError("factorial tasks must be unique task units")
    if phase in {"confirmatory", "prospective_followup"} and any(
        item.get("split") != "confirm" for item in task_rows
    ):
        raise FactorialExperimentError("confirmatory factorial task entered from another split")
    if config["corpus"].get("selection_outcomes_consulted") is not False or any(
        item.get("source_records_used_as_outcomes") is not False for item in task_rows
    ):
        raise FactorialExperimentError("factorial task selection is not outcome blind")
    if phase == "prospective_followup":
        _validate_followup(root, config, task_rows)
    catalog_path = root / config["prompt_tsg_catalog_path"]
    registry_path = root / config["pair_registry_path"]
    _read_exact_json(catalog_path)
    _read_exact_json(registry_path)
    catalog = load_catalog(catalog_path)
    registry_value = _read_exact_json(registry_path)
    registry = load_pair_registry(registry_path, catalog)
    pair_by_id = {item.pair_id: item for item in registry.pairs}
    raw_protocols = _pair_protocols(config, pair_by_id, selected_ids)
    generation_models = _generation_models(config)

    model_ids = tuple(item["model_id"] for item in generation_models)
    if (
        any(not isinstance(item, str) or not item.strip() for item in model_ids)
        or len(model_ids) != len(set(model_ids))
        or any(
            not isinstance(item.get("api_key_env"), str)
            or not item["api_key_env"].strip()
            for item in generation_models
        )
    ):
        raise FactorialExperimentError("factorial generation models must be unique")
    seed_values = tuple(item.get("seed") for item in generation_models)
    if any(type(item) is not int or item < 0 for item in seed_values) or len(
        set(seed_values)
    ) != 1:
        raise FactorialExperimentError(
            "factorial generation models require one shared non-negative provider seed"
        )
    provider_seed = seed_values[0]
    generation_prompt_by_model = {
        item["model_id"]: _locked_text(root, item, "prompt")
        for item in generation_models
    }

    graph_by_task_id = {}
    for row in task_rows:
        graph = prompt_tsg_from_record(row["prompt_tsg"])
        validate_prompt_tsg(graph, prompt=row["prompt"], catalog=catalog)
        graph_by_task_id[row["task_id"]] = graph
    all_bindings = {
        (binding.pair_id, binding.task_id): binding
        for row in task_rows
        for binding in _row_pair_bindings(row)
    }
    if len(all_bindings) != sum(len(_row_pair_bindings(row)) for row in task_rows):
        raise FactorialExperimentError("factorial pair-task bindings are duplicated")

    loaded_protocols = []
    task_by_id = {item["task_id"]: item for item in task_rows}
    for raw in raw_protocols:
        pair = pair_by_id[raw["pair_id"]]
        security = raw["security_oracle"]
        if (
            pair.oracle_profile_id != security.get("profile_id")
            or pair.oracle_policy_sha256 != security.get("policy_sha256")
        ):
            raise FactorialExperimentError("factorial Oracle configuration drift")
        qualification = _oracle_qualification(
            root,
            security,
            pair,
        )
        oracle_qualification_evidence = _oracle_qualification_evidence(
            root, security, pair, qualification
        )
        protocol_tasks = tuple(task_by_id[item] for item in raw["task_ids"])
        for row in protocol_tasks:
            binding = all_bindings.get((pair.pair_id, row["task_id"]))
            query = next(
                (
                    item
                    for item in catalog["queries"]
                    if item["query_id"] == pair.pair_context_query_id
                ),
                None,
            )
            if query is None:
                raise FactorialExperimentError(
                    "factorial pair context query is absent from the catalog"
                )
            expected_binding = bind_pair(
                row,
                graph_by_task_id[row["task_id"]],
                pair,
                query,
                neutral_counterparts=(
                    dict(binding.neutral_counterpart_ids)
                    if binding is not None
                    else None
                ),
            )
            if (
                binding is None
                or binding != expected_binding
                or binding.decision is not PairEligibility.APPLICABLE
                or binding.task_id != row["task_id"]
            ):
                raise FactorialExperimentError(
                    "factorial pair binding does not recompute from the task graph"
                )
        intervention = raw["intervention"]
        loaded_protocols.append(
            {
                "pair": pair,
                "task_rows": protocol_tasks,
                "intervention": intervention,
                "security_oracle": security,
                "oracle_qualification": qualification,
                "oracle_qualification_evidence": oracle_qualification_evidence,
                "executor": _locked_json(root, intervention, "executor_config"),
                "validator": _locked_json(root, intervention, "validator_config"),
                "executor_prompt": _locked_text(root, intervention, "executor_prompt"),
                "validator_prompt": _locked_text(root, intervention, "validator_prompt"),
                "trace_endpoints": _trace_endpoints(
                    raw.get("mechanism_trace_diagnostics", ())
                ),
            }
        )
    functional = config["functional_oracle"]
    functional_evaluator = _locked_json(root, functional, "evaluator_config")
    functional_prompt = _locked_text(root, functional, "prompt")
    structural_smoke_allowed = phase == "development_canary" and claim_allowed is False
    functional_qualification = (
        _functional_qualification(
            root,
            functional,
            functional_evaluator,
            structural_smoke_allowed=structural_smoke_allowed,
        )
        if frozen_functional_qualification is None
        else _validate_frozen_functional_qualification(
            functional,
            functional_evaluator,
            frozen_functional_qualification,
            structural_smoke_allowed=structural_smoke_allowed,
        )
    )
    adapters = _generalized_adapters(
        registry,
        tuple(loaded_protocols),
        generation_models,
        generation_prompt_by_model,
        functional_evaluator,
        functional_qualification,
    )
    for protocol in loaded_protocols:
        intervention = protocol["intervention"]
        protocol["realizations"] = tuple(
            sorted(
                (
                    FactorialRealizationSpec(
                        row["label"],
                        row["weight"],
                        adapters.intervention_executor.adapter_id,
                        intervention["factor_1_target"],
                        intervention["factor_1_noop"],
                        intervention["factor_2_target"],
                        intervention["factor_2_noop"],
                        tuple(row["application_order"]),
                    )
                    for row in intervention["joint_realizations"]
                ),
                key=lambda item: item.realization_id,
            )
        )
    pairs = tuple(item["pair"] for item in loaded_protocols)
    validate_factorial_pair_relations(pairs)
    pair_selection = _pair_selection(
        config,
        registry,
        pairs,
        repository_root=root,
        config_root=config_file.parent.resolve(),
    )
    pair_selection_artifact_root = None
    if pair_selection is not None and pair_selection.source == "selector_artifact":
        pair_selection_artifact_root = _resolve_pair_selection_artifact(
            config["pair_selection"]["artifact_path"],
            repository_root=root,
            config_root=config_file.parent.resolve(),
        )
    selected_pair_ids = {item.pair_id for item in pairs}
    oracle_qualification_artifact = _oracle_qualification_artifact(
        tuple(loaded_protocols)
    )
    if functionality_power_qualification is not None:
        power_payload = _json_object(
            functionality_power_qualification["qualification_payload"].encode(
                "utf-8"
            )
        )
        planned_units = power_payload["planned_task_units_per_coordinate"]
        if any(
            len({row["task_unit_id"] for row in protocol["task_rows"]})
            < planned_units
            for protocol in loaded_protocols
        ):
            raise FactorialExperimentError(
                "factorial task support is smaller than the functionality power plan"
            )
    return {
        "root": root,
        "config": config,
        "catalog": catalog,
        "registry": registry,
        "registry_value": registry_value,
        "pairs": pairs,
        "pair_by_id": {item.pair_id: item for item in pairs},
        "pair_selection": pair_selection,
        "pair_selection_artifact_root": pair_selection_artifact_root,
        "task_rows": task_rows,
        "pair_bindings": tuple(
            sorted(
                (
                    item
                    for item in all_bindings.values()
                    if item.pair_id in selected_pair_ids
                ),
                key=lambda item: (item.pair_id, item.task_id),
            )
        ),
        "pair_protocols": tuple(loaded_protocols),
        "generation_models": generation_models,
        "generation_by_model": {item["model_id"]: item for item in generation_models},
        "generation_prompt_by_model": generation_prompt_by_model,
        "provider_seed": provider_seed,
        "functional_evaluator": functional_evaluator,
        "functional_prompt": functional_prompt,
        "functional_qualification": functional_qualification,
        "functionality_power_qualification": functionality_power_qualification,
        "adapters": adapters,
        "trace_endpoints_by_pair": {
            item["pair"].pair_id: item["trace_endpoints"] for item in loaded_protocols
        },
        "oracle_qualification_artifact": oracle_qualification_artifact,
    }


def _pair_protocols(
    config: Mapping[str, Any], pair_by_id: Mapping[str, Any], selected_ids: list[str]
) -> tuple[dict[str, Any], ...]:
    rows = config.get("pair_protocols")
    if not isinstance(rows, list) or not rows or any(not isinstance(item, dict) for item in rows):
        raise FactorialExperimentError("factorial pair_protocols must be a non-empty list")
    required = {
        "pair_id",
        "task_ids",
        "intervention",
        "security_oracle",
        "interaction_claim_scope",
        "factorial_compatibility",
    }
    allowed = required | {"mechanism_trace_diagnostics"}
    if any(not required <= set(item) or not set(item) <= allowed for item in rows):
        raise FactorialExperimentError("factorial pair protocol is incomplete")
    pair_ids = [item["pair_id"] for item in rows]
    if (
        any(not isinstance(item, str) or not item for item in pair_ids)
        or len(pair_ids) != len(set(pair_ids))
        or not set(pair_ids) <= set(pair_by_id)
    ):
        raise FactorialExperimentError("factorial pair protocol support drifts from the registry")
    selected = set(selected_ids)
    covered: set[str] = set()
    result = []
    for item in rows:
        task_ids = item["task_ids"]
        if (
            not isinstance(task_ids, list)
            or not task_ids
            or any(not isinstance(task_id, str) or not task_id for task_id in task_ids)
            or len(task_ids) != len(set(task_ids))
            or not set(task_ids) <= selected
            or not isinstance(item["intervention"], dict)
            or not isinstance(item["security_oracle"], dict)
            or item["interaction_claim_scope"] not in {
                "policy_only",
                "mechanism_eligible",
            }
        ):
            raise FactorialExperimentError("factorial pair protocol task support is invalid")
        if item["factorial_compatibility"] != "compatible":
            raise FactorialExperimentError(
                "factorial pair protocol is not factorial-compatible"
            )
        validate_factorial_intervention_design(item["intervention"])
        covered.update(task_ids)
        result.append(dict(item))
    if covered != selected:
        raise FactorialExperimentError("factorial pair protocols do not cover every selected task")
    return tuple(result)




def _generation_models(config: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    generation = config.get("generation")
    if not isinstance(generation, dict) or not isinstance(generation.get("models"), list):
        raise FactorialExperimentError("factorial generation.models must be a list")
    rows = generation["models"]
    if not rows or any(not isinstance(item, dict) for item in rows):
        raise FactorialExperimentError("factorial generation.models is empty or invalid")
    common = {key: value for key, value in generation.items() if key != "models"}
    result = tuple({**common, **item} for item in rows)
    required = {
        "api_key_env",
        "base_url",
        "model_id",
        "temperature",
        "top_p",
        "seed",
        "timeout_seconds",
        "max_response_bytes",
        "enable_thinking",
        "prompt_path",
        "prompt_sha256",
    }
    if any(not required <= set(item) for item in result):
        raise FactorialExperimentError("factorial generation model configuration is incomplete")
    return result


def _pair_selection(
    config: Mapping[str, Any],
    registry: Any,
    pairs: tuple[Any, ...],
    *,
    repository_root: Path,
    config_root: Path,
) -> FactorialPairSelection:
    selected_pair_ids = tuple(sorted(item.pair_id for item in pairs))
    raw = config.get("pair_selection")
    if raw is None:
        registry_pair_ids = tuple(sorted(item.pair_id for item in registry.pairs))
        if selected_pair_ids != registry_pair_ids:
            raise FactorialExperimentError(
                "registry-selected factorial protocols must cover the full pair registry"
            )
        return FactorialPairSelection(
            "registry_selected",
            content_id(
                "factorial_registry_selection_",
                {
                    "registry_sha256": content_hash(registry),
                    "selected_pair_ids": selected_pair_ids,
                },
            ),
            selected_pair_ids,
        )
    if not isinstance(raw, dict) or set(raw) != {"artifact_path"}:
        raise FactorialExperimentError("factorial pair-selection provenance is invalid")
    artifact_root = _resolve_pair_selection_artifact(
        raw["artifact_path"],
        repository_root=repository_root,
        config_root=config_root,
    )
    try:
        verified = verify_interaction_selection_bundle(artifact_root)
    except (OSError, ValueError) as error:
        raise FactorialExperimentError(
            "factorial interaction-selection artifact did not verify"
        ) from error
    if (
        verified["prompt_tsg_catalog_sha256"]
        != registry.prompt_tsg_catalog_sha256
        or verified["pair_registry_id"] != registry.registry_id
    ):
        raise FactorialExperimentError(
            "verified interaction selection uses a different catalog or pair registry"
        )
    artifact_pair_ids = tuple(sorted(verified["selected_pair_ids"]))
    if artifact_pair_ids != selected_pair_ids:
        raise FactorialExperimentError(
            "verified interaction selection drifts from factorial pair protocols"
        )
    try:
        return FactorialPairSelection(
            "selector_artifact",
            verified["freeze_id"],
            selected_pair_ids,
            verified["bundle_sha256"],
        )
    except (TypeError, ValueError):
        raise FactorialExperimentError(
            "factorial pair-selection provenance is invalid"
        ) from None


def _resolve_pair_selection_artifact(
    value: Any,
    *,
    repository_root: Path,
    config_root: Path,
) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise FactorialExperimentError(
            "factorial pair-selection artifact path is invalid"
        )
    raw = Path(value)
    allowed_roots = (repository_root.resolve(), config_root.resolve())
    if raw.is_absolute():
        resolved = raw.resolve()
    else:
        config_candidate = (allowed_roots[1] / raw).resolve()
        repository_candidate = (allowed_roots[0] / raw).resolve()
        resolved = (
            config_candidate
            if config_candidate.exists() or not repository_candidate.exists()
            else repository_candidate
        )
    if not any(_path_is_within(resolved, root) for root in allowed_roots):
        raise FactorialExperimentError(
            "factorial pair-selection artifact escapes the repository/config root"
        )
    return resolved


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _row_pair_bindings(row: Mapping[str, Any]) -> tuple[PairBinding, ...]:
    if "pair_bindings" in row:
        values = row["pair_bindings"]
        if not isinstance(values, list) or not values:
            raise FactorialExperimentError("factorial task pair_bindings is invalid")
    elif "pair_binding" in row:
        values = [row["pair_binding"]]
    else:
        raise FactorialExperimentError("factorial task lacks a pair binding")
    try:
        return tuple(_binding(item) for item in values)
    except (KeyError, TypeError, ValueError):
        raise FactorialExperimentError("factorial task pair binding is invalid") from None


def _trace_endpoints(values: Any) -> tuple[str, ...]:
    if (
        not isinstance(values, (list, tuple))
        or len(values) != len(set(values))
        or any(not isinstance(item, str) or not item.strip() for item in values)
    ):
        raise FactorialExperimentError("factorial mechanism-trace diagnostics are invalid")
    return tuple(values)


def _functional_qualification(
    root: Path,
    section: Mapping[str, Any],
    evaluator: Mapping[str, Any],
    *,
    structural_smoke_allowed: bool = False,
) -> dict[str, Any]:
    """Load and seal active Functional Judge qualification evidence."""

    try:
        return load_functional_qualification(
            root,
            section,
            evaluator,
            structural_smoke_allowed=structural_smoke_allowed,
            include_evaluator_metadata=True,
            confine_to_root=False,
        )
    except QualificationError as error:
        raise FactorialExperimentError(str(error)) from error


def _validate_frozen_functional_qualification(
    section: Mapping[str, Any],
    evaluator: Mapping[str, Any],
    sealed: Mapping[str, Any],
    *,
    structural_smoke_allowed: bool,
) -> dict[str, Any]:
    try:
        return validate_functional_qualification(
            section,
            evaluator,
            sealed,
            structural_smoke_allowed=structural_smoke_allowed,
            include_evaluator_metadata=True,
        )
    except QualificationError as error:
        raise FactorialExperimentError(str(error)) from error


def _functionality_power_qualification(
    root: Path,
    analysis: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Validate and seal the prospective evidence for a powered functionality gate."""

    if analysis["functionality_noninferiority_separately_powered"] is False:
        return None
    reference = analysis["functionality_power_qualification"]
    path = root / reference["path"]
    _require_file_hash(path, reference["sha256"])
    payload_text = path.read_bytes().decode("utf-8")
    payload = _read_exact_json(path)
    validate_factorial_functionality_power(payload, analysis)
    return {
        "schema_version": "1.0",
        "qualification_sha256": reference["sha256"],
        "qualification_payload": payload_text,
    }




def _execute_intervention(
    inputs: Mapping[str, Any],
    protocol: Mapping[str, Any],
    task: Mapping[str, Any],
    realization: FactorialRealizationSpec,
) -> tuple[dict[FactorialCell, str], dict[FactorialCell, Any], bytes, dict[str, Any]]:
    request = {
        "request_kind": "blind_factorial_complete_prompt_rewrite",
        "source_prompt": task["prompt"],
        "source_prompt_tsg": task["prompt_tsg"],
        "functional_requirements": task["functional_contract"]["requirements"],
        "factor_1": {
            "target": realization.factor_1_target_instruction,
            "noop": realization.factor_1_noop_instruction,
        },
        "factor_2": {
            "target": realization.factor_2_target_instruction,
            "noop": realization.factor_2_noop_instruction,
        },
        "application_order": list(realization.application_order),
        "factor_operations": [item.value for item in protocol["pair"].operations],
        "factor_ids": list(protocol["pair"].factors),
        "blindness": {"generated_code": False, "oracle_outcomes": False, "effect_direction": False},
    }
    frozen_call = _frozen_intervention_call(inputs, protocol, task, realization)
    if frozen_call is not None:
        if frozen_call.get("executor_request") != request:
            raise FactorialExperimentError("frozen factorial executor request drift")
        raw = frozen_call["executor_response"].encode("utf-8")
    else:
        raw = bailian_complete(request, protocol["executor"], protocol["executor_prompt"])
    value = _json_object(raw)
    maximum = protocol["intervention"]["maximum_suffix_characters"]
    prompts: dict[FactorialCell, str] = {}
    graphs: dict[FactorialCell, Any] = {}
    expected = {cell.value for cell in FACTORIAL_CELL_ORDER}
    if set(value) != expected:
        raise FactorialExperimentError("factorial complete-rewrite response schema drift")
    for cell in FACTORIAL_CELL_ORDER:
        row = value[cell.value]
        if not isinstance(row, Mapping) or set(row) != {
            "prompt_text",
            "facts",
            "relations",
            "unresolved_semantics",
        }:
            raise FactorialExperimentError(
                "factorial complete-rewrite cell schema drift"
            )
        prompt = row["prompt_text"]
        if (
            not isinstance(prompt, str)
            or not prompt.strip()
            or prompt != prompt.strip()
            or len(prompt) > len(task["prompt"]) + maximum
        ):
            raise FactorialExperimentError("factorial complete prompt is invalid")
        prompts[cell] = prompt
        try:
            graphs[cell] = build_prompt_tsg(
                task_id=task["task_id"],
                prompt=prompt,
                extractor_id=inputs["adapters"].intervention_executor.adapter_id,
                catalog=inputs["catalog"],
                facts=row["facts"],
                relations=row["relations"],
                unresolved_semantics=row["unresolved_semantics"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise FactorialExperimentError(
                "factorial complete-rewrite Prompt TSG is invalid"
            ) from error
    validate_factorial_variant_graphs(
        inputs["catalog"], protocol["pair"], task, graphs
    )
    if len(set(prompts.values())) != len(FACTORIAL_CELL_ORDER):
        raise FactorialExperimentError("factorial executor collapsed treatment cells")
    return prompts, graphs, raw, request


def _validate_intervention(
    inputs: Mapping[str, Any],
    protocol: Mapping[str, Any],
    task: Mapping[str, Any],
    realization: FactorialRealizationSpec,
    prompts: Mapping[FactorialCell, str],
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    request = {
        "request_kind": "blind_factorial_prompt_validation",
        "source_prompt": task["prompt"],
        "functional_requirements": task["functional_contract"]["requirements"],
        "factor_1": {
            "target": realization.factor_1_target_instruction,
            "noop": realization.factor_1_noop_instruction,
        },
        "factor_2": {
            "target": realization.factor_2_target_instruction,
            "noop": realization.factor_2_noop_instruction,
        },
        "application_order": list(realization.application_order),
        "variants": {cell.value: prompts[cell] for cell in FACTORIAL_CELL_ORDER},
        "blindness": {"generated_code": False, "oracle_outcomes": False, "model_identity": False},
    }
    frozen_call = _frozen_intervention_call(inputs, protocol, task, realization)
    if frozen_call is not None:
        if frozen_call.get("validator_request") != request:
            raise FactorialExperimentError("frozen factorial validator request drift")
        raw = frozen_call["validator_response"].encode("utf-8")
    else:
        raw = bailian_complete(request, protocol["validator"], protocol["validator_prompt"])
    value = _json_object(raw)
    if set(value) != {"a00", "a10", "a01", "a11", "cross_cell", "reason"}:
        raise FactorialExperimentError("factorial validator response schema drift")
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
    for cell in FACTORIAL_CELL_ORDER:
        if not isinstance(value[cell.value], dict) or set(value[cell.value]) != cell_fields:
            raise FactorialExperimentError("factorial validator cell schema drift")
    if not isinstance(value["cross_cell"], dict) or set(value["cross_cell"]) != cross_fields:
        raise FactorialExperimentError("factorial validator cross-cell schema drift")
    flags = [
        flag
        for cell in FACTORIAL_CELL_ORDER
        for flag in value[cell.value].values()
    ] + list(value["cross_cell"].values())
    if any(type(flag) is not bool for flag in flags) or not all(flags):
        raise FactorialExperimentError("factorial semantic validation failed")
    if not isinstance(value["reason"], str) or not value["reason"].strip():
        raise FactorialExperimentError("factorial validator reason is empty")
    return value, raw, request


def _frozen_intervention_call(
    inputs: Mapping[str, Any],
    protocol: Mapping[str, Any],
    task: Mapping[str, Any],
    realization: FactorialRealizationSpec,
) -> Mapping[str, Any] | None:
    calls = inputs.get("frozen_intervention_calls")
    if calls is None:
        return None
    matches = [
        item
        for item in calls
        if isinstance(item, Mapping)
        and item.get("stage") == "intervention"
        and item.get("pair_id") == protocol["pair"].pair_id
        and item.get("task_id") == task["task_id"]
        and item.get("realization_id") == realization.realization_id
    ]
    if len(matches) != 1:
        raise FactorialExperimentError(
            "frozen factorial intervention coordinate is missing or duplicated"
        )
    return matches[0]




def _measure_assignment(
    inputs: Mapping[str, Any],
    assignment: Any,
    task: Mapping[str, Any],
    prompt: str,
) -> tuple[Measurement, dict[str, Any], list[dict[str, Any]]]:
    assignment_id = assignment.assignment_id
    provider_seed = assignment.provider_seed
    model_id = assignment.block.model_id
    pair_id = assignment.block.pair_id
    try:
        evaluator = dict(inputs["generation_by_model"][model_id])
        generation_prompt = inputs["generation_prompt_by_model"][model_id]
        pair = inputs["pair_by_id"][pair_id]
    except KeyError:
        raise FactorialExperimentError("factorial assignment dispatch coordinate is not frozen") from None
    if provider_seed is None:
        raise FactorialExperimentError("factorial assignment lacks a frozen provider seed")
    evaluator["seed"] = provider_seed
    request = {
        "request_kind": "factorial_code_generation",
        "task_prompt": prompt,
        "language": "python",
        "output_schema": {"code": "complete Python source string"},
    }
    try:
        measurement, evidence = measure_generated_code(
            assignment_id=assignment_id,
            generation_request=request,
            generation_evaluator=evaluator,
            generation_prompt=generation_prompt,
            source_task_prompt=task["prompt"],
            functional_contract=task["functional_contract"],
            functional_evaluator=inputs["functional_evaluator"],
            functional_prompt=inputs["functional_prompt"],
            security_profile_id=pair.oracle_profile_id,
            complete=bailian_complete,
            security_evaluate=evaluate_security_profile,
        )
    except MeasurementExecutionError as error:
        raise FactorialExperimentError(str(error)) from error
    provider_calls = [
        {
            "stage": "generation",
            "assignment_id": assignment_id,
            "pair_id": pair_id,
            "model_id": model_id,
            "generator_adapter_id": inputs["adapters"].generator.adapter_id,
            "request": request,
            "response_sha256": evidence["generation_response_sha256"],
            "response": evidence["generation_response"],
        }
    ]
    if evidence["functional_response"] is not None:
        provider_calls.append(
            {
                "stage": "functional",
                "assignment_id": assignment_id,
                "pair_id": pair_id,
                "model_id": model_id,
                "functional_evaluator_adapter_id": inputs[
                    "adapters"
                ].functional_evaluator.adapter_id,
                "request": evidence["functional_request"],
                "response_sha256": evidence["functional_response_sha256"],
                "response": evidence["functional_response"],
            }
        )
    record = {
        "generation_model_id": model_id,
        "security_profile_id": pair.oracle_profile_id,
        "security_policy_sha256": pair.oracle_policy_sha256,
        "generation_request": request,
        "generation_response": evidence["generation_response"],
        "code": evidence["code"],
        "security": evidence["security"],
        "functional_request": evidence["functional_request"],
        "functional_response": evidence["functional_response"],
    }
    if evidence["functional_validated"] is not None:
        record["functional_validated"] = evidence["functional_validated"]
    return (
        measurement,
        record,
        provider_calls,
    )


def _unknown_coverage_summary(
    code_valid_cells: Mapping[str, Mapping[str, Any]],
    oracle_evaluable_cells: Mapping[str, Mapping[str, Any]],
    limit: float,
) -> dict[str, Any]:
    """Keep invalid-code yield separate from Oracle unknown among valid code."""

    if set(code_valid_cells) != set(oracle_evaluable_cells):
        raise FactorialExperimentError("factorial unknown-coverage cell support drifts")
    code_valid_yield: dict[str, float | None] = {}
    oracle_evaluable_yield: dict[str, float | None] = {}
    unknown_fraction: dict[str, float | None] = {}
    for cell in sorted(code_valid_cells):
        valid = code_valid_cells[cell]["point"]
        evaluable = oracle_evaluable_cells[cell]["point"]
        code_valid_yield[cell] = valid
        oracle_evaluable_yield[cell] = evaluable
        if valid is None or evaluable is None:
            unknown_fraction[cell] = None
            continue
        if not 0.0 <= evaluable <= valid <= 1.0:
            raise FactorialExperimentError(
                "factorial Oracle evaluability is not a subset of valid code"
            )
        unknown_fraction[cell] = (
            None if valid == 0.0 else (valid - evaluable) / valid
        )
    observed = [item for item in unknown_fraction.values() if item is not None]
    gate_evaluable = len(observed) == len(unknown_fraction)
    maximum = max(observed) if observed else None
    return {
        "code_valid_yield_by_cell": code_valid_yield,
        "oracle_evaluable_yield_by_cell": oracle_evaluable_yield,
        "unknown_fraction_among_valid_code_by_cell": unknown_fraction,
        "maximum_observed_unknown_fraction_among_valid_code": maximum,
        "unknown_gate_evaluable": gate_evaluable,
        "unknown_gate_passed": bool(
            gate_evaluable and maximum is not None and maximum <= limit
        ),
    }


def _report(
    config: Mapping[str, Any],
    study: Any,
    analysis: Any,
    verification: Mapping[str, Any],
    measurement_records: list[dict[str, Any]],
    trace_endpoints_by_pair: Mapping[str, tuple[str, ...]],
) -> dict[str, Any]:
    estimates = []
    for estimate in analysis.inference.estimates:
        estimates.append(
            {
                "coordinate_id": estimate.coordinate_id,
                "pair_id": estimate.pair_id,
                "model_id": estimate.model_id,
                "metric": estimate.metric.value,
                "cells": {
                    item.cell.value: {
                        "point": item.point,
                        "lower": item.lower,
                        "upper": item.upper,
                        "assignments": item.assignments,
                    }
                    for item in estimate.cells
                },
                "factor_1": estimate.factor_1,
                "factor_2": estimate.factor_2,
                "factor_1_given_factor_2": estimate.factor_1_given_factor_2,
                "factor_2_given_factor_1": estimate.factor_2_given_factor_1,
                "joint": estimate.joint,
                "interaction": estimate.interaction,
                "factor_1_bounds": list(estimate.factor_1_bounds),
                "factor_2_bounds": list(estimate.factor_2_bounds),
                "factor_1_given_factor_2_bounds": list(
                    estimate.factor_1_given_factor_2_bounds
                ),
                "factor_2_given_factor_1_bounds": list(
                    estimate.factor_2_given_factor_1_bounds
                ),
                "joint_bounds": list(estimate.joint_bounds),
                "interaction_bounds": list(estimate.interaction_bounds),
                "response_pattern": estimate.response_pattern.value,
                "response_surface_pattern": _paper_response_pattern(
                    estimate.response_pattern.value
                ),
                "realization_diagnostics": canonical_value(
                    estimate.realization_diagnostics
                ),
            }
        )
    intervals = [
        {
            "coordinate_id": item.coordinate_id,
            "effect": item.effect.value,
            "standard_error": item.standard_error,
            "lower": item.lower,
            "upper": item.upper,
        }
        for item in analysis.inference.intervals
    ]
    secondary_intervals = [
        {
            "coordinate_id": item.coordinate_id,
            "effect": item.effect.value,
            "standard_error": item.standard_error,
            "lower": item.lower,
            "upper": item.upper,
            "excludes_zero": item.lower > 0.0 or item.upper < 0.0,
        }
        for item in analysis.inference.secondary_intervals
    ]
    analysis_config = config["analysis"]
    claim_scope_by_pair = {
        item["pair_id"]: item["interaction_claim_scope"]
        for item in config["pair_protocols"]
    }
    functionality_margin = float(analysis_config["functionality_noninferiority_margin"])
    unknown_limit = float(analysis_config.get("maximum_unknown_fraction", 1.0))
    practical_margin = float(analysis_config.get("practical_interaction_margin", 0.0))
    estimate_by_key = {
        (item["pair_id"], item["model_id"], item["metric"]): item
        for item in estimates
    }
    interval_by_coordinate = {item["coordinate_id"]: item for item in intervals}
    functionality_intervals = {
        (item.coordinate_id, item.effect.value): item
        for family in analysis.inference.metric_families
        if family.family.value == "functionality"
        for item in family.intervals
    }
    primary_results = []
    for primary in sorted(
        (item for item in estimates if item["metric"] == "secure_yield"),
        key=lambda item: (item["pair_id"], item["model_id"]),
    ):
        key = (primary["pair_id"], primary["model_id"])
        functionality = estimate_by_key[(*key, "functionality")]
        evaluability = estimate_by_key[(*key, "oracle_evaluable")]
        code_valid = estimate_by_key.get((*key, "code_valid"))
        interval = interval_by_coordinate.get(primary["coordinate_id"])
        significant = bool(
            interval and (interval["lower"] > 0.0 or interval["upper"] < 0.0)
        )
        separately_powered = bool(
            analysis_config.get(
                "functionality_noninferiority_separately_powered", False
            )
        )
        functionality_interval = functionality_intervals.get(
            (functionality["coordinate_id"], "joint")
        )
        functionality_lower = (
            None if functionality_interval is None else functionality_interval.lower
        )
        if not separately_powered:
            functionality_status = "not_requested"
            functionality_noninferior: bool | None = None
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
            "interaction_claim_scope": claim_scope_by_pair[primary["pair_id"]],
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
        if code_valid is None:
            raise FactorialExperimentError(
                "prospective factorial report lacks code-validity endpoint"
            )
        gate.update(
            _unknown_coverage_summary(
                code_valid["cells"], evaluability["cells"], unknown_limit
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
        gate["security_policy_interaction_claim_ready"] = bool(
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
        gate["mechanism_interaction_claim_ready"] = bool(
            gate["security_policy_interaction_claim_ready"]
            and gate["interaction_claim_scope"] == "mechanism_eligible"
        )
        gate["practical_success_claim_ready"] = bool(
            gate["security_policy_interaction_claim_ready"]
            and functionality_status == "passed"
            and functionality_noninferior
        )
        gate["claim_ready"] = gate["practical_success_claim_ready"]
        primary_results.append(
            {
                "coordinate_id": primary["coordinate_id"],
                "pair_id": primary["pair_id"],
                "model_id": primary["model_id"],
                "interaction": primary["interaction"],
                "simultaneous_interval": interval,
                "interval_excludes_zero": significant,
                "gate": gate,
            }
        )
    phase = config["phase"]
    status_by_phase = {
        "development_canary": "FACTORIAL_CANARY_COMPLETE",
        "confirmatory": "FACTORIAL_CONFIRMATION_COMPLETE",
        "prospective_followup": "FACTORIAL_FOLLOWUP_COMPLETE",
    }
    trace_spec: Any = trace_endpoints_by_pair
    trace_summary = _mechanism_trace_summary(measurement_records, trace_spec)
    trace_verification = verify_mechanism_trace_diagnostics(
        measurement_records, trace_summary, trace_spec
    )
    report = {
        "schema_version": "1.1",
        "status": status_by_phase[phase],
        "phase": phase,
        "study_name": config["study_name"],
        "study_id": study.study_id,
        "tasks": len(study.tasks),
        "realizations": (
            len(study.policies[0].realizations) if len(study.policies) == 1 else None
        ),
        "realizations_by_pair": {
            item.pair.pair_id: len(item.realizations) for item in study.policies
        },
        "models": list(study.randomization.models),
        "assignments": len(study.randomization.assignments),
        "primary_estimand": "assigned-cell task-unit ITT interaction on risk difference",
        "primary_results": primary_results,
        "claim_ready_coordinates": [
            item["coordinate_id"] for item in primary_results if item["gate"]["claim_ready"]
        ],
        "estimates": estimates,
        "simultaneous_critical_value": analysis.inference.simultaneous_critical_value,
        "secondary_intervals": secondary_intervals,
        "secondary_critical_value": analysis.inference.secondary_critical_value,
        "metric_families": canonical_value(analysis.inference.metric_families),
        "mechanism_trace_diagnostics": trace_summary,
        "mechanism_trace_verification": trace_verification,
        "verification": dict(verification),
        "scientific_claim_allowed": bool(config.get("scientific_claim_allowed", False)),
        "claim_boundary": config["corpus"]["generalization_boundary"],
        "scale_gate": config["scale_gate"],
    }
    report.update(
        {
            "security_policy_interaction_claim_ready_coordinates": [
                item["coordinate_id"]
                for item in primary_results
                if item["gate"]["security_policy_interaction_claim_ready"]
            ],
            "mechanism_interaction_claim_ready_coordinates": [
                item["coordinate_id"]
                for item in primary_results
                if item["gate"]["mechanism_interaction_claim_ready"]
            ],
            "practical_success_claim_ready_coordinates": [
                item["coordinate_id"]
                for item in primary_results
                if item["gate"]["practical_success_claim_ready"]
            ],
        }
    )
    if len(primary_results) == 1:
        only = primary_results[0]
        report.update(
            {
                "primary_interaction": only["interaction"],
                "primary_simultaneous_interval": only["simultaneous_interval"],
                "primary_interval_excludes_zero": only["interval_excludes_zero"],
                "primary_gate": only["gate"],
            }
        )
    return report


def _paper_response_pattern(value: str) -> str:
    """Map implementation fixtures to non-mechanistic paper-facing descriptions."""

    mapping = {
        "additive": "no_additional_pattern",
        "positive_interaction": "positive_nonadditive_pattern",
        "negative_interaction": "negative_nonadditive_pattern",
        "xor": "xor_response_pattern",
        "redundant": "subadditive_joint_benefit_pattern",
        "prerequisite": "conditional_activation_pattern",
        "reversal": "simple_effect_sign_reversal",
        "not_evaluable": "not_evaluable",
    }
    try:
        return mapping[value]
    except KeyError:
        raise FactorialExperimentError("factorial response pattern is unsupported") from None


def _validate_followup(
    root: Path,
    config: Mapping[str, Any],
    task_rows: tuple[Mapping[str, Any], ...],
) -> None:
    section = config.get("followup")
    required = {
        "predecessor_study_name",
        "predecessor_result_path",
        "predecessor_report_sha256",
        "design_informed_by_predecessor_aggregate",
        "task_specific_outcomes_used_for_selection",
        "all_predecessor_task_units_retained",
        "estimand_boundary",
    }
    if not isinstance(section, dict) or set(section) != required:
        raise FactorialExperimentError("prospective follow-up declaration is invalid")
    if (
        section["design_informed_by_predecessor_aggregate"] is not True
        or section["task_specific_outcomes_used_for_selection"] is not False
        or section["all_predecessor_task_units_retained"] is not True
        or not isinstance(section["estimand_boundary"], str)
        or not section["estimand_boundary"].strip()
    ):
        raise FactorialExperimentError("prospective follow-up evidence boundary is invalid")
    predecessor_root = root / section["predecessor_result_path"]
    verify_bundle(predecessor_root)
    _require_file_hash(
        predecessor_root / "report.json", section["predecessor_report_sha256"]
    )
    predecessor_report = read_json(predecessor_root / "report.json")
    predecessor_study = read_json(predecessor_root / "study-freeze.json")
    if (
        predecessor_report.get("study_name") != section["predecessor_study_name"]
        or predecessor_report.get("status") != "FACTORIAL_CONFIRMATION_COMPLETE"
    ):
        raise FactorialExperimentError("prospective follow-up predecessor is invalid")
    predecessor_by_unit = {
        item["semantic_cluster_id"]: item["task_id"]
        for item in predecessor_study.get("tasks", ())
    }
    predecessor_units = set(predecessor_by_unit)
    current_units = {item["task_unit_id"] for item in task_rows}
    if (
        not predecessor_units
        or current_units != predecessor_units
        or len(current_units) != len(task_rows)
        or any(
            item.get("predecessor_task_id")
            != predecessor_by_unit.get(item["task_unit_id"])
            for item in task_rows
        )
    ):
        raise FactorialExperimentError(
            "prospective follow-up did not retain every predecessor task unit"
        )


def _mechanism_trace_summary(
    records: list[dict[str, Any]],
    endpoints: tuple[str, ...] | Mapping[str, tuple[str, ...]],
) -> dict[str, Any]:
    if isinstance(endpoints, Mapping):
        result: dict[str, Any] = {}
        for pair_id, pair_endpoints in endpoints.items():
            selected_pair = [
                item
                for item in records
                if item.get("assignment", {}).get("block", {}).get("pair_id") == pair_id
            ]
            models = sorted(
                {
                    item["assignment"]["block"]["model_id"]
                    for item in selected_pair
                }
            )
            result[pair_id] = {
                model_id: _flat_mechanism_trace_summary(
                    [
                        item
                        for item in selected_pair
                        if item["assignment"]["block"]["model_id"] == model_id
                    ],
                    pair_endpoints,
                )
                for model_id in models
            }
        return result
    return _flat_mechanism_trace_summary(records, endpoints)


def _flat_mechanism_trace_summary(
    records: list[dict[str, Any]], endpoints: tuple[str, ...]
) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for endpoint in endpoints:
        cells: dict[str, dict[str, Any]] = {}
        for cell in FACTORIAL_CELL_ORDER:
            selected = [
                item for item in records if item["assignment"]["cell"] == cell.value
            ]
            states = [_trace_endpoint_state(item.get("security"), endpoint) for item in selected]
            safe = states.count("safe")
            cells[cell.value] = {
                "assignments": len(selected),
                "safe": safe,
                "unsafe": states.count("unsafe"),
                "unknown": states.count("unknown"),
                "safe_rate": safe / len(selected) if selected else None,
            }
        summary[endpoint] = {
            "role": "post_assignment_diagnostic_not_mediator_or_denominator_filter",
            "cells": cells,
        }
    return summary


def _trace_endpoint_state(
    security: Mapping[str, Any] | None, endpoint: str
) -> str:
    if not security:
        return "unknown"
    facts = security.get("decision", {}).get("trace", {}).get("facts", ())
    states = [item.get(endpoint) for item in facts if isinstance(item, dict)]
    if not states or any(item not in {"safe", "unsafe", "unknown"} for item in states):
        return "unknown"
    if "unsafe" in states:
        return "unsafe"
    if all(item == "safe" for item in states):
        return "safe"
    return "unknown"


def _cell_validation(
    value: Mapping[str, bool], validator_adapter_id: str, evidence_sha256: str
) -> SemanticValidation:
    return SemanticValidation(
        _yes(value["task_preserved"]),
        _yes(value["factor_1_state_correct"] and value["factor_2_state_correct"]),
        SemanticVerdict.NO if value["unintended_change_absent"] else SemanticVerdict.YES,
        SemanticVerdict.NO if value["contradiction_absent"] else SemanticVerdict.YES,
        validator_adapter_id,
        evidence_sha256,
    )


def _yes(value: bool) -> SemanticVerdict:
    return SemanticVerdict.YES if value else SemanticVerdict.NO


def _task(row: Mapping[str, Any]) -> Task:
    return Task(
        row["task_id"],
        row["task_unit_id"],
        row["cwe"],
        row["archetype"],
        Split(row["split"]),
        row["prompt"],
        row["weight"],
    )


def _binding(value: Mapping[str, Any]) -> PairBinding:
    return PairBinding(
        value["pair_id"],
        value["task_id"],
        value["prompt_tsg_id"],
        PairEligibility(value["decision"]),
        value["context_query_id"],
        QueryState(value["context_state"]),
        tuple((feature, QueryState(state)) for feature, state in value["factor_states"]),
        tuple(tuple(item) for item in value["neutral_counterpart_ids"]),
        tuple(value["evidence_node_ids"]),
        tuple(value["evidence_edge_ids"]),
        value["outcomes_or_arms_used"],
    )


def _generalized_adapters(
    registry: Any,
    protocols: tuple[Mapping[str, Any], ...],
    generation_models: tuple[Mapping[str, Any], ...],
    generation_prompts: Mapping[str, str],
    functional_evaluator: Mapping[str, Any],
    functional_qualification: Mapping[str, Any],
) -> AdapterBundle:
    executor_material = tuple(
        {
            "pair_id": item["pair"].pair_id,
            "candidate_id": item["executor"]["candidate_id"],
            "config_sha256": content_hash(item["executor"]),
            "prompt_sha256": content_hash(item["executor_prompt"]),
        }
        for item in sorted(protocols, key=lambda value: value["pair"].pair_id)
    )
    validator_material = tuple(
        {
            "pair_id": item["pair"].pair_id,
            "candidate_id": item["validator"]["candidate_id"],
            "config_sha256": content_hash(item["validator"]),
            "prompt_sha256": content_hash(item["validator_prompt"]),
        }
        for item in sorted(protocols, key=lambda value: value["pair"].pair_id)
    )
    generator_material = tuple(
        {
            "model_id": item["model_id"],
            "config": dict(item),
            "prompt_sha256": content_hash(generation_prompts[item["model_id"]]),
        }
        for item in sorted(generation_models, key=lambda value: value["model_id"])
    )
    oracle_material = tuple(
        {
            "pair_id": item["pair"].pair_id,
            "profile_id": item["pair"].oracle_profile_id,
            "policy_sha256": item["pair"].oracle_policy_sha256,
            "qualification_sha256": item["oracle_qualification_evidence"][
                "qualification_sha256"
            ],
            "producer_implementation_id": item["oracle_qualification_evidence"][
                "producer_implementation_id"
            ],
            "producer_sha256": item["oracle_qualification_evidence"][
                "producer_sha256"
            ],
        }
        for item in sorted(protocols, key=lambda value: value["pair"].pair_id)
    )
    return AdapterBundle(
        AdapterSpec(
            AdapterKind.REPRESENTATION,
            "prompt-tsg-pair-catalog",
            "1",
            registry.prompt_tsg_catalog_sha256,
        ),
        AdapterSpec(
            AdapterKind.SELECTOR,
            "preregistered-pair-registry",
            "1",
            content_hash(registry),
        ),
        AdapterSpec(
            AdapterKind.INTERVENTION_EXECUTOR,
            f"factorial-intervention-executor-set-{content_hash(executor_material)[:16]}",
            "1",
            content_hash(executor_material),
        ),
        AdapterSpec(
            AdapterKind.INTERVENTION_VALIDATOR,
            f"factorial-intervention-validator-set-{content_hash(validator_material)[:16]}",
            "1",
            content_hash(validator_material),
        ),
        AdapterSpec(
            AdapterKind.GENERATOR,
            f"factorial-generator-set-{content_hash(generator_material)[:16]}",
            "1",
            content_hash(generator_material),
        ),
        AdapterSpec(
            AdapterKind.SECURITY_ORACLE,
            f"factorial-oracle-set-{content_hash(oracle_material)[:16]}",
            "1",
            factorial_oracle_dispatch_policy_sha256(
                item["pair"] for item in protocols
            ),
        ),
        AdapterSpec(
            AdapterKind.FUNCTIONAL_EVALUATOR,
            functional_evaluator["candidate_id"],
            "1",
            content_hash(
                {
                    "evaluator_config_sha256": functional_qualification[
                        "qualification_identity"
                    ]["evaluator_config_sha256"],
                    "prompt_sha256": functional_qualification[
                        "qualification_identity"
                    ]["prompt_sha256"],
                    "qualification_sha256": functional_qualification[
                        "qualification_sha256"
                    ],
                    "qualification_identity": functional_qualification[
                        "qualification_identity"
                    ],
                }
            ),
        ),
    )


def _oracle_qualification(
    root: Path,
    section: Mapping[str, Any],
    pair: Any,
) -> dict[str, Any]:
    path = root / section["qualification_path"]
    if "qualification_sha256" in section:
        _require_file_hash(path, section["qualification_sha256"])
    qualification = _read_exact_json(path)
    if not isinstance(qualification, dict):
        raise FactorialExperimentError("Oracle qualification must be a JSON object")
    if (
        qualification.get("profile_id") != pair.oracle_profile_id
        or qualification.get("policy_sha256") != pair.oracle_policy_sha256
        or qualification.get("qualification_status") != "supported"
        or qualification.get("label_mismatches") != 0
        or set(qualification.get("gold_cells", [])) != {
            cell.value for cell in FACTORIAL_CELL_ORDER
        }
    ):
        raise FactorialExperimentError("Oracle qualification is unsupported or incomplete")
    for stem in ("implementation", "fixture"):
        locked_path = root / qualification[f"{stem}_path"]
        _require_file_hash(locked_path, qualification[f"{stem}_sha256"])
    policy_path = root / qualification.get("policy_path", "")
    _require_file_hash(policy_path, pair.oracle_policy_sha256)
    policy = _read_exact_json(policy_path)
    if (
        not isinstance(policy, Mapping)
        or policy.get("schema_version") != "1.0"
        or policy.get("profile_id") != pair.oracle_profile_id
    ):
        raise FactorialExperimentError(
            "factorial Oracle policy does not canonically bind the profile"
        )
    implementation_path = (root / qualification["implementation_path"]).resolve()
    producer_path = (Path(__file__).resolve().parent / "security_profiles.py").resolve()
    if implementation_path != producer_path:
        raise FactorialExperimentError(
            "factorial Oracle qualification does not bind the active producer"
        )
    return qualification


def _oracle_qualification_evidence(
    root: Path,
    section: Mapping[str, Any],
    pair: Any,
    qualification: Mapping[str, Any],
) -> dict[str, Any]:
    qualification_path = root / section["qualification_path"]
    policy_path = root / qualification["policy_path"]
    producer_path = root / qualification["implementation_path"]
    producer_sha256 = hashlib.sha256(producer_path.read_bytes()).hexdigest()
    if producer_sha256 != security_profile_producer_sha256():
        raise FactorialExperimentError(
            "factorial Oracle producer identity does not match the active implementation"
        )
    return {
        "pair_id": pair.pair_id,
        "profile_id": pair.oracle_profile_id,
        "policy_sha256": pair.oracle_policy_sha256,
        "policy_payload": policy_path.read_bytes().decode("utf-8"),
        "qualification_sha256": section["qualification_sha256"],
        "qualification_payload": qualification_path.read_bytes().decode("utf-8"),
        "producer_implementation_id": (
            "prompt_mechanism_study.security_profiles:evaluate_security_profile"
        ),
        "producer_sha256": producer_sha256,
    }


def _oracle_qualification_artifact(
    protocols: tuple[Mapping[str, Any], ...],
) -> dict[str, Any]:
    pairs = sorted(
        (dict(item["oracle_qualification_evidence"]) for item in protocols),
        key=lambda item: item["pair_id"],
    )
    producer_path = (Path(__file__).resolve().parent / "security_profiles.py").resolve()
    producer_sha256 = hashlib.sha256(producer_path.read_bytes()).hexdigest()
    if any(item["producer_sha256"] != producer_sha256 for item in pairs):
        raise FactorialExperimentError("factorial Oracle producer identities disagree")
    return {
        "schema_version": "1.0",
        "producer": {
            "implementation_id": (
                "prompt_mechanism_study.security_profiles:evaluate_security_profile"
            ),
            "sha256": producer_sha256,
        },
        "pairs": pairs,
    }


def _locked_json(root: Path, section: Mapping[str, Any], stem: str) -> dict[str, Any]:
    path = root / section[f"{stem}_path"]
    _require_file_hash(path, section[f"{stem}_sha256"])
    value = _read_exact_json(path)
    if not isinstance(value, dict):
        raise FactorialExperimentError(f"{stem} must be a JSON object")
    return value


def _locked_text(root: Path, section: Mapping[str, Any], stem: str) -> str:
    path = root / section[f"{stem}_path"]
    _require_file_hash(path, section[f"{stem}_sha256"])
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise FactorialExperimentError(f"{stem} is empty")
    return value


def _require_file_hash(path: Path, expected: str) -> None:
    try:
        verify_file_hash(path, expected)
    except ValueError as error:
        raise FactorialExperimentError(str(error)) from error


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        return parse_json_object(raw)
    except ValueError:
        raise FactorialExperimentError("provider response is not valid JSON") from None


def _read_exact_json(path: Path) -> Any:
    try:
        return read_strict_json(path)
    except ValueError:
        raise FactorialExperimentError(f"JSON input is invalid or duplicated: {path}") from None


__all__ = [
    "FactorialExperimentError",
    "freeze_factorial_experiment",
    "preflight_factorial_experiment",
    "run_factorial_experiment",
]
