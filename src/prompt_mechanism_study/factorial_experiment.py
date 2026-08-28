"""Linear runner for the prospectively frozen pairwise factorial study."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from prompt_mechanism_study.adapters import AdapterBundle, AdapterKind, AdapterSpec
from prompt_mechanism_study.artifact_io import bundle_digest, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.factorial_verify import (
    verify_factorial_inference,
    verify_factorial_result_bundle,
    verify_mechanism_trace_diagnostics,
)
from prompt_mechanism_study.functional_judge import (
    bailian_complete,
    build_review_request,
    python_syntax_valid,
    validate_review_response,
)
from prompt_mechanism_study.inference import (
    FactorialAnalysisPlan,
    FactorialAnalysisPlanV2,
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
    CodeStatus,
    FunctionalStatus,
    Measurement,
    OracleStatus,
)
from prompt_mechanism_study.mechanisms import (
    PairBinding,
    PairEligibility,
    bind_pair,
    load_pair_registry,
    validate_active_factorial_relation,
)
from prompt_mechanism_study.prompt_tsg import (
    QueryState,
    build_prompt_tsg,
    feature_state,
    load_catalog,
    prompt_tsg_record,
    prompt_tsg_from_record,
    query_context,
    validate_prompt_tsg,
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


class FactorialExperimentError(ValueError):
    """A frozen factorial input or provider output failed closed."""


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
    legacy = inputs["config"]["schema_version"] == "1.0"
    return {
        "schema_version": inputs["config"]["schema_version"],
        "status": "FACTORIAL_PREFLIGHT_COMPLETE",
        "study_name": inputs["config"]["study_name"],
        "tasks": len(inputs["task_rows"]),
        "realizations": (
            len(inputs["pair_protocols"][0]["realizations"])
            if legacy
            else sum(len(item["realizations"]) for item in inputs["pair_protocols"])
        ),
        "assignments": assignments,
        "credential_env": credentials[0] if legacy else None,
        "credential_present": (
            bool(os.environ.get(credentials[0], "").strip()) if legacy else None
        ),
        "credentials": [
            {"env": name, "present": bool(os.environ.get(name, "").strip())}
            for name in credentials
        ],
        "models": [item["model_id"] for item in inputs["generation_models"]],
        "pair_id": inputs["pairs"][0].pair_id if legacy else None,
        "pair_ids": [item.pair_id for item in inputs["pairs"]],
        "oracle_support_status": (
            inputs["pairs"][0].oracle_support_status.value if legacy else None
        ),
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
    verified = verify_factorial_freeze_bundle(output)
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


def _verify_frozen_oracle_qualifications(
    artifact: Any,
    study: Mapping[str, Any],
    pair_by_id: Mapping[str, Any],
) -> None:
    if not isinstance(artifact, dict) or set(artifact) != {
        "schema_version",
        "producer",
        "pairs",
    } or artifact["schema_version"] != "1.0":
        raise FactorialExperimentError("factorial frozen Oracle evidence is invalid")
    producer = artifact["producer"]
    if not isinstance(producer, dict) or set(producer) != {
        "implementation_id",
        "sha256",
    }:
        raise FactorialExperimentError("factorial frozen Oracle producer is invalid")
    if (
        producer["implementation_id"]
        != "prompt_mechanism_study.security_profiles:evaluate_security_profile"
        or producer["sha256"] != security_profile_producer_sha256()
    ):
        raise FactorialExperimentError("factorial frozen Oracle producer digest drifts")
    rows = artifact["pairs"]
    expected_pair_ids = {
        content_id("pair_", policy["pair"]) for policy in study.get("policies", ())
    }
    if (
        not isinstance(rows, list)
        or [item.get("pair_id") for item in rows]
        != sorted(expected_pair_ids)
        or any(
            not isinstance(item, dict)
            or set(item)
            != {
                "pair_id",
                "profile_id",
                "policy_sha256",
                "policy_payload",
                "qualification_sha256",
                "qualification_payload",
                "producer_implementation_id",
                "producer_sha256",
            }
            for item in rows
        )
    ):
        raise FactorialExperimentError("factorial frozen Oracle pair support drifts")
    for row in rows:
        pair = pair_by_id.get(row["pair_id"])
        policy_payload = row["policy_payload"]
        qualification_payload = row["qualification_payload"]
        if (
            pair is None
            or row["profile_id"] != pair.oracle_profile_id
            or row["policy_sha256"] != pair.oracle_policy_sha256
            or row["producer_implementation_id"] != producer["implementation_id"]
            or row["producer_sha256"] != producer["sha256"]
            or not isinstance(policy_payload, str)
            or hashlib.sha256(policy_payload.encode("utf-8")).hexdigest()
            != row["policy_sha256"]
            or not isinstance(qualification_payload, str)
            or hashlib.sha256(qualification_payload.encode("utf-8")).hexdigest()
            != row["qualification_sha256"]
        ):
            raise FactorialExperimentError("factorial frozen Oracle identity drifts")
        policy = _json_object(policy_payload.encode("utf-8"))
        qualification = _json_object(qualification_payload.encode("utf-8"))
        if (
            policy.get("schema_version") != "1.0"
            or policy.get("profile_id") != pair.oracle_profile_id
            or qualification.get("profile_id") != pair.oracle_profile_id
            or qualification.get("policy_sha256") != pair.oracle_policy_sha256
            or qualification.get("qualification_status") != "supported"
            or qualification.get("label_mismatches") != 0
            or set(qualification.get("gold_cells", ()))
            != {cell.value for cell in FACTORIAL_CELL_ORDER}
            or qualification.get("implementation_sha256") != producer["sha256"]
        ):
            raise FactorialExperimentError(
                "factorial frozen Oracle qualification semantics drift"
            )
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
    adapter = study.get("adapters", {}).get("security_oracle", {})
    if adapter != {
        "kind": "security_oracle",
        "name": f"factorial-oracle-set-{content_hash(oracle_material)[:16]}",
        "version": "1",
        "policy_sha256": content_hash(dispatch_material),
    }:
        raise FactorialExperimentError(
            "factorial frozen Oracle adapter does not bind its qualification evidence"
        )


def _verify_frozen_functionality_power(
    root: Path,
    config: Mapping[str, Any],
    study: Mapping[str, Any],
) -> None:
    analysis = config["analysis"]
    requested = analysis["functionality_noninferiority_separately_powered"]
    path = root / "factorial-functionality-power-qualification.json"
    plan = study.get("analysis_plan", {})
    if not requested:
        if path.exists() or plan.get("functionality_power_qualification_sha256") is not None:
            raise FactorialExperimentError(
                "unrequested functionality power evidence entered the freeze"
            )
        return
    if not path.is_file():
        raise FactorialExperimentError(
            "separately powered functionality gate lacks frozen evidence"
        )
    artifact = read_json(path)
    if not isinstance(artifact, dict) or set(artifact) != {
        "schema_version",
        "qualification_sha256",
        "qualification_payload",
    } or artifact["schema_version"] != "1.0":
        raise FactorialExperimentError(
            "frozen functionality power qualification is invalid"
        )
    payload_text = artifact["qualification_payload"]
    if (
        not isinstance(payload_text, str)
        or hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
        != artifact["qualification_sha256"]
        or artifact["qualification_sha256"]
        != analysis["functionality_power_qualification"]["sha256"]
        or plan.get("functionality_power_qualification_sha256")
        != artifact["qualification_sha256"]
    ):
        raise FactorialExperimentError(
            "frozen functionality power qualification digest drifts"
        )
    payload = _json_object(payload_text.encode("utf-8"))
    _validate_functionality_power_payload(payload, analysis)
    planned_units = payload["planned_task_units_per_coordinate"]
    if any(
        len({bundle["task_unit_id"] for bundle in policy["bundles"]})
        < planned_units
        for policy in study.get("policies", ())
    ):
        raise FactorialExperimentError(
            "frozen factorial support is smaller than the functionality power plan"
        )


def _verify_bundled_functional_qualification(
    config: Mapping[str, Any],
    study: Mapping[str, Any],
    sealed: Any,
) -> None:
    if not isinstance(sealed, Mapping) or set(sealed) != {
        "qualification_path",
        "qualification_sha256",
        "qualification",
        "qualification_payload",
        "qualification_identity",
    }:
        raise FactorialExperimentError(
            "bundled functional Oracle qualification fields are not exact"
        )
    payload = sealed["qualification_payload"]
    qualification = sealed["qualification"]
    identity = sealed["qualification_identity"]
    section = config["functional_oracle"]
    if (
        not isinstance(payload, str)
        or not payload
        or not isinstance(qualification, Mapping)
        or not isinstance(identity, Mapping)
        or set(identity)
        != {
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
    ):
        raise FactorialExperimentError(
            "bundled functional Oracle qualification envelope drifts"
        )
    parsed = _json_object(payload.encode("utf-8"))
    candidate = qualification.get("candidate", {})
    if not isinstance(candidate, Mapping):
        raise FactorialExperimentError(
            "bundled functional Oracle qualification candidate drifts"
        )
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
        raise FactorialExperimentError(
            "bundled structural-smoke functional qualification is not allowed"
        )
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
        raise FactorialExperimentError(
            "bundled functional Oracle qualification drifts"
        )
    adapter_material = {
        "evaluator_config_sha256": identity["evaluator_config_sha256"],
        "prompt_sha256": identity["prompt_sha256"],
        "qualification_sha256": sealed["qualification_sha256"],
        "qualification_identity": identity,
    }
    adapter = study.get("adapters", {}).get("functional_evaluator", {})
    if adapter != {
        "kind": "functional_evaluator",
        "name": identity["candidate_id"],
        "version": "1",
        "policy_sha256": content_hash(adapter_material),
    }:
        raise FactorialExperimentError(
            "functional evaluator adapter does not bind its qualification"
        )


def verify_factorial_freeze_bundle(root: Path) -> dict[str, Any]:
    """Semantically replay the active pre-outcome freeze without provider calls."""

    verify_bundle(root)
    config = _read_exact_json(root / "effective-config.json")
    study = _read_exact_json(root / "study-freeze.json")
    task_inputs = _read_exact_json(root / "factorial-measurement-inputs.json")
    variant_payload = _read_exact_json(root / "factorial-variant-tsgs.json")
    execution = _read_exact_json(root / "execution-order.json")
    calls = _read_exact_json(root / "intervention-calls.json")
    if (
        config.get("schema_version") != "1.1"
        or not isinstance(study, Mapping)
        or set(task_inputs) != {"schema_version", "tasks"}
        or task_inputs.get("schema_version") != "1.1"
        or set(variant_payload) != {"schema_version", "variants"}
        or variant_payload.get("schema_version") != "1.0"
        or set(execution) != {"schema_version", "assignment_ids"}
        or execution.get("schema_version") != "1.0"
        or not isinstance(calls, list)
    ):
        raise FactorialExperimentError("factorial freeze envelope is invalid")
    _validate_v11_config_shape(config)
    _validate_v11_analysis(config)
    catalog = load_catalog(root / "factorial-prompt-tsg-catalog.json")
    registry = load_pair_registry(root / "factorial-pair-registry.json", catalog)
    pair_by_id = {item.pair_id: item for item in registry.pairs}
    tasks = {item["task_id"]: item for item in task_inputs["tasks"]}
    if len(tasks) != len(task_inputs["tasks"]):
        raise FactorialExperimentError("factorial freeze task inputs are duplicated")
    graphs = variant_payload["variants"]
    expected_variants = {}
    for policy in study.get("policies", ()):
        pair_id = content_id("pair_", policy["pair"])
        if pair_id not in pair_by_id or canonical_value(pair_by_id[pair_id]) != policy["pair"]:
                raise FactorialExperimentError("factorial freeze pair leaves the registry")
        for bundle in policy["bundles"]:
            for variant in bundle["variants"]:
                prompt = variant["execution"]["prompt_text"]
                expected_variants[content_hash(prompt)] = (prompt, bundle["task_id"])
    if set(graphs) != set(expected_variants):
        raise FactorialExperimentError("factorial freeze variant Prompt TSG support drift")
    for variant_id, (prompt, task_id) in expected_variants.items():
        graph = prompt_tsg_from_record(graphs[variant_id])
        if graph.task_id != task_id:
            raise FactorialExperimentError("factorial freeze variant graph task drift")
        validate_prompt_tsg(graph, prompt=prompt, catalog=catalog)
    for policy in study["policies"]:
        pair_id = content_id("pair_", policy["pair"])
        pair = pair_by_id[pair_id]
        for bundle in policy["bundles"]:
            cell_graphs = {
                FactorialCell(item["cell"]): prompt_tsg_from_record(
                    graphs[content_hash(item["execution"]["prompt_text"])]
                )
                for item in bundle["variants"]
            }
            _validate_variant_graphs(
                {"catalog": catalog},
                {"pair": pair},
                tasks[bundle["task_id"]],
                cell_graphs,
            )

    _verify_frozen_oracle_qualifications(
        read_json(root / "factorial-oracle-qualifications.json"),
        study,
        pair_by_id,
    )
    _verify_frozen_functionality_power(root, config, study)
    _verify_bundled_functional_qualification(
        config,
        study,
        read_json(root / "factorial-functional-qualification.json"),
    )

    binding_rows = {
        (item["pair_id"], item["task_id"]): item
        for item in study.get("pair_bindings", ())
    }
    for (pair_id, task_id), raw_binding in binding_rows.items():
        task = tasks.get(task_id)
        pair = pair_by_id.get(pair_id)
        if task is None or pair is None:
            raise FactorialExperimentError("factorial freeze pair binding coordinate drift")
        graph = prompt_tsg_from_record(task["prompt_tsg"])
        validate_prompt_tsg(graph, prompt=task["prompt"], catalog=catalog)
        query = next(
            item
            for item in catalog["queries"]
            if item["query_id"] == pair.pair_context_query_id
        )
        expected = bind_pair(
            task,
            graph,
            pair,
            query,
            neutral_counterparts=dict(raw_binding["neutral_counterpart_ids"]),
        )
        if canonical_value(expected) != raw_binding:
            raise FactorialExperimentError("factorial freeze pair binding replay drift")

    assignments = study.get("randomization", {}).get("assignments", ())
    assignment_ids = [content_id("factorial_assignment_", item) for item in assignments]
    order = execution["assignment_ids"]
    if (
        not isinstance(order, list)
        or len(order) != len(set(order))
        or set(order) != set(assignment_ids)
    ):
        raise FactorialExperimentError("factorial global execution order drift")
    call_coordinates = {
        (item.get("pair_id"), item.get("task_id"), item.get("realization_id"))
        for item in calls
        if isinstance(item, Mapping) and item.get("stage") == "intervention"
    }
    expected_coordinates = {
        (content_id("pair_", policy["pair"]), bundle["task_id"], bundle["realization_id"])
        for policy in study["policies"]
        for bundle in policy["bundles"]
    }
    if len(call_coordinates) != len(calls) or call_coordinates != expected_coordinates:
        raise FactorialExperimentError("factorial freeze intervention evidence support drift")
    bundle_by_coordinate = {
        (
            content_id("pair_", policy["pair"]),
            bundle["task_id"],
            bundle["realization_id"],
        ): bundle
        for policy in study["policies"]
        for bundle in policy["bundles"]
    }
    for call in calls:
        coordinate = (call["pair_id"], call["task_id"], call["realization_id"])
        bundle = bundle_by_coordinate[coordinate]
        task = tasks[call["task_id"]]
        executor_raw = call.get("executor_response")
        validator_raw = call.get("validator_response")
        if (
            not isinstance(executor_raw, str)
            or hashlib.sha256(executor_raw.encode("utf-8")).hexdigest()
            != call.get("executor_response_sha256")
            or not isinstance(validator_raw, str)
            or hashlib.sha256(validator_raw.encode("utf-8")).hexdigest()
            != call.get("validator_response_sha256")
        ):
            raise FactorialExperimentError("factorial freeze intervention digest drift")
        executor = _json_object(executor_raw.encode("utf-8"))
        validator = _json_object(validator_raw.encode("utf-8"))
        if set(executor) != {cell.value for cell in FACTORIAL_CELL_ORDER}:
            raise FactorialExperimentError("factorial freeze executor schema drift")
        variants = {item["cell"]: item for item in bundle["variants"]}
        for cell in FACTORIAL_CELL_ORDER:
            row = executor[cell.value]
            if not isinstance(row, Mapping) or set(row) != {
                "prompt_text",
                "facts",
                "relations",
                "unresolved_semantics",
            }:
                raise FactorialExperimentError("factorial freeze executor cell drift")
            prompt = row["prompt_text"]
            graph = build_prompt_tsg(
                task_id=task["task_id"],
                prompt=prompt,
                extractor_id=call["executor_adapter_id"],
                catalog=catalog,
                facts=row["facts"],
                relations=row["relations"],
                unresolved_semantics=row["unresolved_semantics"],
            )
            if (
                variants[cell.value]["execution"]["prompt_text"] != prompt
                or variants[cell.value]["execution"]["evidence_sha256"]
                != call["executor_response_sha256"]
                or prompt_tsg_record(graph) != graphs[content_hash(prompt)]
            ):
                raise FactorialExperimentError(
                    "factorial freeze executor-to-variant replay drift"
                )
        if (
            set(validator)
            != {"a00", "a10", "a01", "a11", "cross_cell", "reason"}
            or any(
                type(flag) is not bool or not flag
                for name, section in validator.items()
                if name != "reason"
                for flag in section.values()
            )
            or any(
                item["validation"]["evidence_sha256"]
                != call["validator_response_sha256"]
                for item in bundle["variants"]
            )
        ):
            raise FactorialExperimentError("factorial freeze validator replay drift")
    return {
        "status": "FACTORIAL_FREEZE_VERIFIED",
        "study_id": content_id("factorial_study_", study),
        "assignments": len(assignment_ids),
        "variants": len(expected_variants),
    }


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
    active = requested_config.get("schema_version") == "1.1"
    if active:
        if freeze_root is None:
            raise FactorialExperimentError(
                "active factorial schema 1.1 run requires --freeze"
            )
        freeze_path = freeze_root.resolve()
        freeze_verification = verify_factorial_freeze_bundle(freeze_path)
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
    else:
        if freeze_root is not None:
            raise FactorialExperimentError(
                "archival schema 1.0 run does not accept a prospective freeze"
            )
        freeze_path = None
        freeze_verification = None
        inputs = _load_inputs(repository_root, config_path)
    config = inputs["config"]
    credential_names = tuple(
        sorted({item["api_key_env"] for item in inputs["generation_models"]})
    )
    if any(not os.environ.get(name, "").strip() for name in credential_names):
        raise FactorialExperimentError("provider credential is unavailable")
    if config["schema_version"] == "1.1":
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
    else:
        study, policies, calls, variant_tsgs = _materialize_factorial_study(inputs)
        execution_order = [
            item.assignment_id for item in study.randomization.assignments
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
    if config["schema_version"] == "1.1":
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
    plan_type = (
        FactorialAnalysisPlanV2
        if config["schema_version"] == "1.1"
        else FactorialAnalysisPlan
    )
    plan_kwargs: dict[str, Any] = {}
    if config["schema_version"] == "1.1":
        plan_kwargs = {
            "minimum_task_units": analysis["minimum_task_units"],
            "minimum_valid_bootstrap_fraction": analysis[
                "minimum_valid_bootstrap_fraction"
            ],
            "bootstrap_quantile_method": analysis["bootstrap_quantile_method"],
            "practical_interaction_margin": analysis[
                "practical_interaction_margin"
            ],
            "maximum_unknown_fraction": analysis["maximum_unknown_fraction"],
            "functionality_noninferiority_margin": analysis[
                "functionality_noninferiority_margin"
            ],
            "functionality_noninferiority_separately_powered": analysis[
                "functionality_noninferiority_separately_powered"
            ],
            "functionality_power_qualification_sha256": (
                None
                if inputs["functionality_power_qualification"] is None
                else inputs["functionality_power_qualification"][
                    "qualification_sha256"
                ]
            ),
        }
    analysis_plan = plan_type(
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
        **plan_kwargs,
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
    if config["schema_version"] == "1.0":
        return config["study_name"]
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
    schema_version = config.get("schema_version")
    if schema_version not in {"1.0", "1.1"} or phase not in {
        "development_canary",
        "confirmatory",
        "prospective_followup",
    }:
        raise FactorialExperimentError("factorial config envelope is invalid")
    if schema_version == "1.1":
        _validate_v11_config_shape(config)
        _validate_v11_analysis(config)
        functionality_power_qualification = _functionality_power_qualification(
            root, config["analysis"]
        )
    else:
        functionality_power_qualification = None
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
    if schema_version == "1.0":
        if len(registry.pairs) != 1:
            raise FactorialExperimentError("factorial study requires exactly one frozen pair")
        raw_protocols = (
            {
                "pair_id": registry.pairs[0].pair_id,
                "task_ids": list(selected_ids),
                "intervention": config["intervention"],
                "security_oracle": config["security_oracle"],
                "mechanism_trace_diagnostics": config["analysis"].get(
                    "mechanism_trace_diagnostics", []
                ),
            },
        )
        generation_models = (dict(config["generation"]),)
    else:
        raw_protocols = _v11_pair_protocols(config, pair_by_id, selected_ids)
        generation_models = _v11_generation_models(config)

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
            prospective=schema_version == "1.1",
        )
        oracle_qualification_evidence = (
            _oracle_qualification_evidence(root, security, pair, qualification)
            if schema_version == "1.1"
            else None
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
    if schema_version == "1.1":
        structural_smoke_allowed = (
            phase == "development_canary" and claim_allowed is False
        )
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
    else:
        if frozen_functional_qualification is not None:
            raise FactorialExperimentError(
                "archival factorial schema cannot consume a frozen functional qualification"
            )
        functional_qualification = None
        protocol = loaded_protocols[0]
        adapters = _adapters(
            registry,
            protocol["executor"],
            protocol["validator"],
            generation_models[0],
            protocol["pair"].oracle_profile_id,
            protocol["pair"].oracle_policy_sha256,
            functional_evaluator,
            functional_prompt,
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
    if schema_version == "1.1":
        _validate_v11_pair_relations(pairs)
    pair_selection = (
        _v11_pair_selection(
            config,
            registry,
            pairs,
            repository_root=root,
            config_root=config_file.parent.resolve(),
        )
        if schema_version == "1.1"
        else None
    )
    pair_selection_artifact_root = None
    if pair_selection is not None and pair_selection.source == "selector_artifact":
        pair_selection_artifact_root = _resolve_pair_selection_artifact(
            config["pair_selection"]["artifact_path"],
            repository_root=root,
            config_root=config_file.parent.resolve(),
        )
    selected_pair_ids = {item.pair_id for item in pairs}
    oracle_qualification_artifact = (
        _oracle_qualification_artifact(tuple(loaded_protocols))
        if schema_version == "1.1"
        else None
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
        "pair": pairs[0] if schema_version == "1.0" else None,
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
        "realizations": loaded_protocols[0]["realizations"] if schema_version == "1.0" else (),
        "trace_endpoints_by_pair": {
            item["pair"].pair_id: item["trace_endpoints"] for item in loaded_protocols
        },
        "oracle_qualification_artifact": oracle_qualification_artifact,
    }


def _v11_pair_protocols(
    config: Mapping[str, Any], pair_by_id: Mapping[str, Any], selected_ids: list[str]
) -> tuple[dict[str, Any], ...]:
    rows = config.get("pair_protocols")
    if not isinstance(rows, list) or not rows or any(not isinstance(item, dict) for item in rows):
        raise FactorialExperimentError("factorial pair_protocols must be a non-empty list")
    required = {"pair_id", "task_ids", "intervention", "security_oracle"}
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
        ):
            raise FactorialExperimentError("factorial pair protocol task support is invalid")
        _validate_v11_intervention_design(item["intervention"])
        covered.update(task_ids)
        result.append(dict(item))
    if covered != selected:
        raise FactorialExperimentError("factorial pair protocols do not cover every selected task")
    return tuple(result)


def _validate_v11_analysis(config: Mapping[str, Any]) -> None:
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
    separately_powered = analysis.get(
        "functionality_noninferiority_separately_powered"
    )
    power_field = "functionality_power_qualification"
    expected = required | ({power_field} if separately_powered is True else set())
    if set(analysis) != expected:
        raise FactorialExperimentError(
            "factorial schema 1.1 analysis fields are not exact"
        )
    metrics = analysis.get("metrics")
    effects = analysis.get("secondary_effects")
    if metrics != [
        "secure_yield",
        "code_valid",
        "oracle_evaluable",
        "functionality",
        "joint",
    ]:
        raise FactorialExperimentError(
            "factorial schema 1.1 requires the five ordered, distinct outcome endpoints"
        )
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
        raise FactorialExperimentError(
            "factorial schema 1.1 primary metric must be secure_yield"
        )
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
        or type(analysis.get("functionality_noninferiority_separately_powered"))
        is not bool
        or any(
            type(analysis.get(name)) is not float
            or not 0.0 <= analysis[name] <= 1.0
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
            or not _is_sha256(reference["sha256"])
        ):
            raise FactorialExperimentError(
                "factorial functionality power qualification reference is invalid"
            )


def _validate_v11_config_shape(config: Mapping[str, Any]) -> None:
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
            raise FactorialExperimentError(
                f"factorial schema 1.1 {name} fields are not exact"
            )
def _validate_v11_intervention_design(intervention: Mapping[str, Any]) -> None:
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
            raise FactorialExperimentError(
                "factorial joint-realization order support is invalid"
            )
        orders.add(tuple(item["application_order"]))
    if not commutative and orders != {(1, 2), (2, 1)}:
        raise FactorialExperimentError(
            "non-commutative factorial pairs require both application orders"
        )


def _validate_v11_pair_relations(pairs: tuple[Any, ...]) -> None:
    try:
        for pair in pairs:
            validate_active_factorial_relation(pair.relation_type)
    except (AttributeError, TypeError, ValueError) as error:
        raise FactorialExperimentError(
            "factorial pair relation is outside the active successor vocabulary"
        ) from error


def _v11_generation_models(config: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
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


def _v11_pair_selection(
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
        path = root / section["qualification_path"]
        expected = section["qualification_sha256"]
    except KeyError:
        raise FactorialExperimentError("functional Oracle qualification is not frozen") from None
    _require_file_hash(path, expected)
    try:
        payload = path.read_bytes()
        payload_text = payload.decode("utf-8")
    except (OSError, UnicodeError):
        raise FactorialExperimentError(
            "functional Oracle qualification is unreadable"
        ) from None
    qualification = _json_object(payload)
    sealed = {
        "qualification_path": section["qualification_path"],
        "qualification_sha256": hashlib.sha256(payload).hexdigest(),
        "qualification": qualification,
        "qualification_payload": payload_text,
        "qualification_identity": _functional_qualification_identity(
            qualification,
            section,
            evaluator,
            structural_smoke_allowed=structural_smoke_allowed,
        ),
    }
    return _validate_frozen_functional_qualification(
        section,
        evaluator,
        sealed,
        structural_smoke_allowed=structural_smoke_allowed,
    )


def _validate_frozen_functional_qualification(
    section: Mapping[str, Any],
    evaluator: Mapping[str, Any],
    sealed: Mapping[str, Any],
    *,
    structural_smoke_allowed: bool,
) -> dict[str, Any]:
    expected_fields = {
        "qualification_path",
        "qualification_sha256",
        "qualification",
        "qualification_payload",
        "qualification_identity",
    }
    if set(sealed) != expected_fields:
        raise FactorialExperimentError(
            "frozen functional Oracle qualification fields are not exact"
        )
    payload = sealed.get("qualification_payload")
    if not isinstance(payload, str) or not payload:
        raise FactorialExperimentError(
            "frozen functional Oracle qualification payload is invalid"
        )
    qualification = sealed.get("qualification")
    if not isinstance(qualification, Mapping):
        raise FactorialExperimentError(
            "frozen functional Oracle qualification is not an object"
        )
    parsed = _json_object(payload.encode("utf-8"))
    expected_identity = _functional_qualification_identity(
        qualification,
        section,
        evaluator,
        structural_smoke_allowed=structural_smoke_allowed,
    )
    if (
        sealed.get("qualification_path") != section.get("qualification_path")
        or sealed.get("qualification_sha256")
        != section.get("qualification_sha256")
        or hashlib.sha256(payload.encode("utf-8")).hexdigest()
        != section.get("qualification_sha256")
        or parsed != qualification
        or sealed.get("qualification_identity") != expected_identity
    ):
        raise FactorialExperimentError("functional Oracle qualification drift")
    return dict(sealed)


def _functional_qualification_identity(
    qualification: Mapping[str, Any],
    section: Mapping[str, Any],
    evaluator: Mapping[str, Any],
    *,
    structural_smoke_allowed: bool,
) -> dict[str, Any]:
    candidate = qualification.get("candidate", {})
    if not isinstance(candidate, Mapping):
        raise FactorialExperimentError("functional Oracle candidate is invalid")
    status = qualification.get("status")
    structural_smoke = status == "STRUCTURAL_SMOKE_ONLY"
    if structural_smoke and not (
        structural_smoke_allowed
        and evaluator.get("provider") == "offline_deterministic_test_fixture"
        and evaluator.get("fixture_only") is True
        and evaluator.get("scientific_claim_allowed") is False
        and qualification.get("semantic_accuracy_claimed") is False
        and qualification.get("scientific_claim_allowed") is False
    ):
        raise FactorialExperimentError(
            "structural-smoke-only functional Oracle qualification is not allowed"
        )
    if (
        status not in {"QUALIFIED_FOR_EXPERIMENT", "STRUCTURAL_SMOKE_ONLY"}
        or candidate.get("candidate_id") != evaluator.get("candidate_id")
        or candidate.get("model_id") != evaluator.get("model_id")
        or candidate.get("evaluator_config_sha256")
        != section.get("evaluator_config_sha256")
        or candidate.get("prompt_sha256") != section.get("prompt_sha256")
    ):
        raise FactorialExperimentError("functional Oracle qualification drift")
    if qualification.get("schema_version") != "1.0":
        raise FactorialExperimentError("functional Oracle qualification drift")
    return {
        "qualification_id": content_id(
            "functional_judge_qualification_v1_", qualification
        ),
        "status": status,
        "candidate_id": candidate.get("candidate_id"),
        "model_id": candidate.get("model_id"),
        "evaluator_config_sha256": candidate.get("evaluator_config_sha256"),
        "prompt_sha256": candidate.get("prompt_sha256"),
        "provider": evaluator.get("provider"),
        "fixture_only": evaluator.get("fixture_only"),
        "evaluator_scientific_claim_allowed": evaluator.get(
            "scientific_claim_allowed"
        ),
    }


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
    _validate_functionality_power_payload(payload, analysis)
    return {
        "schema_version": "1.0",
        "qualification_sha256": reference["sha256"],
        "qualification_payload": payload_text,
    }


def _validate_functionality_power_payload(
    payload: Any,
    analysis: Mapping[str, Any],
) -> None:
    required = {
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
    coordinate = payload.get("analysis_coordinate", {}) if isinstance(payload, dict) else {}
    assumptions = payload.get("assumptions", {}) if isinstance(payload, dict) else {}
    if (
        not isinstance(payload, dict)
        or set(payload) != required
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
        raise FactorialExperimentError(
            "factorial functionality power qualification is unsupported or incomplete"
        )


def _execute_intervention(
    inputs: Mapping[str, Any],
    protocol: Mapping[str, Any],
    task: Mapping[str, Any],
    realization: FactorialRealizationSpec,
) -> tuple[dict[FactorialCell, str], dict[FactorialCell, Any], bytes, dict[str, Any]]:
    prospective = inputs["config"]["schema_version"] == "1.1"
    request = {
        "request_kind": (
            "blind_factorial_complete_prompt_rewrite"
            if prospective
            else "blind_factorial_prompt_intervention"
        ),
        "source_prompt": task["prompt"],
        "source_prompt_tsg": task["prompt_tsg"] if prospective else None,
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
    if not prospective:
        request.pop("source_prompt_tsg")
        request.pop("factor_operations")
        request.pop("factor_ids")
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
    if prospective:
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
        _validate_variant_graphs(inputs, protocol, task, graphs)
    else:
        expected = {f"{cell.value}_text" for cell in FACTORIAL_CELL_ORDER}
        if set(value) != expected:
            raise FactorialExperimentError("factorial executor response schema drift")
        for cell in FACTORIAL_CELL_ORDER:
            text = value[f"{cell.value}_text"]
            if (
                not isinstance(text, str)
                or not text.strip()
                or text != text.strip()
                or len(text) > maximum
                or "\n" in text
                or "\r" in text
            ):
                raise FactorialExperimentError("factorial executor suffix format drift")
            prompts[cell] = task["prompt"] + "\n\n" + text
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


def _validate_variant_graphs(
    inputs: Mapping[str, Any],
    protocol: Mapping[str, Any],
    task: Mapping[str, Any],
    graphs: Mapping[FactorialCell, Any],
) -> None:
    """Check task/context/non-target projections and exact operation-aware states."""

    source = prompt_tsg_from_record(task["prompt_tsg"])
    pair = protocol["pair"]
    query = next(
        (
            item
            for item in inputs["catalog"]["queries"]
            if item["query_id"] == pair.pair_context_query_id
        ),
        None,
    )
    if query is None:
        raise FactorialExperimentError("factorial pair query is absent from the catalog")
    excluded = {"task.root", *pair.factors}

    def projection(graph: Any) -> tuple[tuple[str, ...], tuple[tuple[str, str, str], ...]]:
        semantics = {item.node_id: item.semantic_id for item in graph.nodes}
        nodes = tuple(
            sorted(
                item.semantic_id
                for item in graph.nodes
                if item.semantic_id not in excluded
            )
        )
        edges = tuple(
            sorted(
                (
                    semantics[item.source_id],
                    item.edge_type,
                    semantics[item.target_id],
                )
                for item in graph.edges
                if semantics[item.source_id] not in excluded
                and semantics[item.target_id] not in excluded
            )
        )
        return nodes, edges

    source_projection = projection(source)
    for cell in FACTORIAL_CELL_ORDER:
        graph = graphs[cell]
        context = query_context(
            graph,
            query=query,
            cwe=task["cwe"],
            task_family=task.get("task_family", task["archetype"]),
        )
        treatment_states = cell.target_states
        expected_states = tuple(
            QueryState.PRESENT
            if (treated and operation.value == "add")
            or (not treated and operation.value == "remove")
            else QueryState.ABSENT
            for treated, operation in zip(
                treatment_states, pair.operations, strict=True
            )
        )
        observed_states = tuple(feature_state(graph, factor) for factor in pair.factors)
        if (
            context.state is not QueryState.PRESENT
            or projection(graph) != source_projection
            or observed_states != expected_states
        ):
            raise FactorialExperimentError(
                "factorial variant Prompt TSG projection or target state drift"
            )


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
    raw = bailian_complete(request, evaluator, generation_prompt)
    value = _json_object(raw)
    code = value.get("code") if set(value) == {"code"} else None
    if not isinstance(code, str):
        raise FactorialExperimentError("generator response schema drift")
    generator_digest = hashlib.sha256(raw).hexdigest()
    provider_calls = [
        {
            "stage": "generation",
            "assignment_id": assignment_id,
            "pair_id": pair_id,
            "model_id": model_id,
            "generator_adapter_id": inputs["adapters"].generator.adapter_id,
            "request": request,
            "response_sha256": generator_digest,
            "response": raw.decode("utf-8"),
        }
    ]
    if not code.strip() or not python_syntax_valid(code):
        status = CodeStatus.NO_CODE if not code.strip() else CodeStatus.INVALID
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
            {
                "generation_model_id": model_id,
                "security_profile_id": pair.oracle_profile_id,
                "security_policy_sha256": pair.oracle_policy_sha256,
                "generation_request": request,
                "generation_response": raw.decode("utf-8"),
                "code": code,
                "security": None,
                "functional_request": None,
                "functional_response": None,
            },
            provider_calls,
        )
    security = evaluate_security_profile(code, pair.oracle_profile_id)
    contract = task["functional_contract"]
    functional_request = build_review_request(
        code,
        task["prompt"],
        requirements=contract["requirements"],
        environment_dependencies=contract["environment_dependencies"],
    )
    functional_raw = bailian_complete(
        functional_request,
        inputs["functional_evaluator"],
        inputs["functional_prompt"],
    )
    functional = validate_review_response(functional_raw, code)
    functional_digest = hashlib.sha256(functional_raw).hexdigest()
    provider_calls.append(
        {
            "stage": "functional",
            "assignment_id": assignment_id,
            "pair_id": pair_id,
            "model_id": model_id,
            "functional_evaluator_adapter_id": inputs[
                "adapters"
            ].functional_evaluator.adapter_id,
            "request": functional_request,
            "response_sha256": functional_digest,
            "response": functional_raw.decode("utf-8"),
        }
    )
    measurement = Measurement(
        assignment_id,
        CodeStatus.VALID,
        OracleStatus(security["security_label"]),
        FunctionalStatus(functional["status"]),
        generator_digest,
        content_hash(code),
        content_hash(security),
        functional_digest,
    )
    return (
        measurement,
        {
            "generation_model_id": model_id,
            "security_profile_id": pair.oracle_profile_id,
            "security_policy_sha256": pair.oracle_policy_sha256,
            "generation_request": request,
            "generation_response": raw.decode("utf-8"),
            "code": code,
            "security": security,
            "functional_request": functional_request,
            "functional_response": functional_raw.decode("utf-8"),
            "functional_validated": functional,
        },
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
        minimum_evaluability = min(
            item["point"]
            for item in evaluability["cells"].values()
            if item["point"] is not None
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
        if config["schema_version"] == "1.0":
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
        if config["schema_version"] == "1.0":
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
    if config["schema_version"] == "1.0":
        trace_spec = next(iter(trace_endpoints_by_pair.values()))
    trace_summary = _mechanism_trace_summary(measurement_records, trace_spec)
    trace_verification = verify_mechanism_trace_diagnostics(
        measurement_records, trace_summary, trace_spec
    )
    report = {
        "schema_version": config["schema_version"],
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
    if config["schema_version"] == "1.1":
        report.update(
            {
                "security_interaction_claim_ready_coordinates": [
                    item["coordinate_id"]
                    for item in primary_results
                    if item["gate"]["security_interaction_claim_ready"]
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


def _adapters(
    registry: Any,
    executor: Mapping[str, Any],
    validator: Mapping[str, Any],
    generation: Mapping[str, Any],
    oracle_profile_id: str,
    oracle_policy_sha256: str,
    functional_evaluator: Mapping[str, Any],
    functional_prompt: str,
) -> AdapterBundle:
    return AdapterBundle(
        AdapterSpec(AdapterKind.REPRESENTATION, "prompt-tsg-pair-catalog", "1", registry.prompt_tsg_catalog_sha256),
        AdapterSpec(AdapterKind.SELECTOR, "preregistered-pair-registry", "1", content_hash(registry)),
        AdapterSpec(AdapterKind.INTERVENTION_EXECUTOR, executor["candidate_id"], "1", content_hash(executor)),
        AdapterSpec(AdapterKind.INTERVENTION_VALIDATOR, validator["candidate_id"], "1", content_hash(validator)),
        AdapterSpec(AdapterKind.GENERATOR, generation["model_id"], "1", content_hash(generation)),
        AdapterSpec(AdapterKind.SECURITY_ORACLE, oracle_profile_id, "1", oracle_policy_sha256),
        AdapterSpec(
            AdapterKind.FUNCTIONAL_EVALUATOR,
            functional_evaluator["candidate_id"],
            "1",
            content_hash({"evaluator": functional_evaluator, "prompt": functional_prompt}),
        ),
    )


def _oracle_qualification(
    root: Path,
    section: Mapping[str, Any],
    pair: Any,
    *,
    prospective: bool,
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
    if prospective:
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
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise FactorialExperimentError(f"frozen file drift: {path}")


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise FactorialExperimentError("provider response is not valid JSON") from None
    if not isinstance(value, dict):
        raise FactorialExperimentError("provider response is not a JSON object")
    return value


def _read_exact_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise FactorialExperimentError(f"JSON input is invalid or duplicated: {path}") from None


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


__all__ = [
    "FactorialExperimentError",
    "freeze_factorial_experiment",
    "preflight_factorial_experiment",
    "run_factorial_experiment",
    "verify_factorial_freeze_bundle",
]
