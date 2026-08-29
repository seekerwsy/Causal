"""Semantic verifier for the active pre-outcome factorial freeze."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import (
    json_object,
    read_json_exact,
    verify_bundle,
)
from prompt_mechanism_study.factorial_protocol import (
    FactorialExperimentError,
    validate_factorial_analysis,
    validate_factorial_config,
    validate_factorial_functionality_power,
)
from prompt_mechanism_study.intervention import FACTORIAL_CELL_ORDER, FactorialCell
from prompt_mechanism_study.mechanisms import bind_pair, load_pair_registry
from prompt_mechanism_study.prompt_tsg import (
    QueryState,
    build_prompt_tsg,
    feature_state,
    load_catalog,
    prompt_tsg_from_record,
    prompt_tsg_record,
    query_context,
    validate_prompt_tsg,
)
from prompt_mechanism_study.qualification import (
    QualificationError,
    validate_functional_qualification,
)
from prompt_mechanism_study.records import canonical_value, content_hash, content_id
from prompt_mechanism_study.security_profiles import security_profile_producer_sha256


def verify_factorial_freeze_bundle(root: Path) -> dict[str, Any]:
    """Replay the frozen study without making provider calls."""

    verify_bundle(root)
    config = _read_json(root / "effective-config.json")
    study = _read_json(root / "study-freeze.json")
    task_inputs = _read_json(root / "factorial-measurement-inputs.json")
    variant_payload = _read_json(root / "factorial-variant-tsgs.json")
    execution = _read_json(root / "execution-order.json")
    calls = _read_json(root / "intervention-calls.json")
    if (
        not isinstance(config, Mapping)
        or config.get("schema_version") != "1.1"
        or not isinstance(study, Mapping)
        or not isinstance(task_inputs, Mapping)
        or set(task_inputs) != {"schema_version", "tasks"}
        or task_inputs.get("schema_version") != "1.1"
        or not isinstance(task_inputs.get("tasks"), list)
        or not isinstance(variant_payload, Mapping)
        or set(variant_payload) != {"schema_version", "variants"}
        or variant_payload.get("schema_version") != "1.0"
        or not isinstance(variant_payload.get("variants"), Mapping)
        or not isinstance(execution, Mapping)
        or set(execution) != {"schema_version", "assignment_ids"}
        or execution.get("schema_version") != "1.0"
        or not isinstance(calls, list)
    ):
        raise FactorialExperimentError("factorial freeze envelope is invalid")
    validate_factorial_config(config)
    validate_factorial_analysis(config)
    catalog = load_catalog(root / "factorial-prompt-tsg-catalog.json")
    registry = load_pair_registry(root / "factorial-pair-registry.json", catalog)
    pair_by_id = {item.pair_id: item for item in registry.pairs}
    tasks = {item["task_id"]: item for item in task_inputs["tasks"]}
    if len(tasks) != len(task_inputs["tasks"]):
        raise FactorialExperimentError("factorial freeze task inputs are duplicated")

    graphs = variant_payload["variants"]
    expected_variants: dict[str, tuple[str, str]] = {}
    for policy in study.get("policies", ()):
        pair_id = content_id("pair_", policy["pair"])
        if pair_id not in pair_by_id or canonical_value(pair_by_id[pair_id]) != policy["pair"]:
            raise FactorialExperimentError("factorial freeze pair leaves the registry")
        for bundle in policy["bundles"]:
            for variant in bundle["variants"]:
                prompt = variant["execution"]["prompt_text"]
                expected_variants[content_hash(prompt)] = (
                    prompt,
                    bundle["task_id"],
                )
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
            validate_factorial_variant_graphs(
                catalog,
                pair,
                tasks[bundle["task_id"]],
                cell_graphs,
            )

    _verify_oracle_qualifications(
        _read_json(root / "factorial-oracle-qualifications.json"),
        study,
        pair_by_id,
    )
    _verify_functionality_power(root, config, study)
    _verify_functional_qualification(
        config,
        study,
        _read_json(root / "factorial-functional-qualification.json"),
    )

    binding_rows = {
        (item["pair_id"], item["task_id"]): item for item in study.get("pair_bindings", ())
    }
    for (pair_id, task_id), raw_binding in binding_rows.items():
        task = tasks.get(task_id)
        pair = pair_by_id.get(pair_id)
        if task is None or pair is None:
            raise FactorialExperimentError("factorial freeze pair binding coordinate drift")
        graph = prompt_tsg_from_record(task["prompt_tsg"])
        validate_prompt_tsg(graph, prompt=task["prompt"], catalog=catalog)
        query = next(
            item for item in catalog["queries"] if item["query_id"] == pair.pair_context_query_id
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
        (
            content_id("pair_", policy["pair"]),
            bundle["task_id"],
            bundle["realization_id"],
        )
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
        executor = _json_object(executor_raw)
        validator = _json_object(validator_raw)
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
                raise FactorialExperimentError("factorial freeze executor-to-variant replay drift")
        if (
            set(validator) != {"a00", "a10", "a01", "a11", "cross_cell", "reason"}
            or any(
                type(flag) is not bool or not flag
                for name, section in validator.items()
                if name != "reason"
                for flag in section.values()
            )
            or any(
                item["validation"]["evidence_sha256"] != call["validator_response_sha256"]
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


def validate_factorial_variant_graphs(
    catalog: Mapping[str, Any],
    pair: Any,
    task: Mapping[str, Any],
    graphs: Mapping[FactorialCell, Any],
) -> None:
    """Check context, non-target projection, and exact treatment states."""

    source = prompt_tsg_from_record(task["prompt_tsg"])
    query = next(
        (item for item in catalog["queries"] if item["query_id"] == pair.pair_context_query_id),
        None,
    )
    if query is None:
        raise FactorialExperimentError("factorial pair query is absent from the catalog")
    excluded = {"task.root", *pair.factors}

    def projection(
        graph: Any,
    ) -> tuple[tuple[str, ...], tuple[tuple[str, str, str], ...]]:
        semantics = {item.node_id: item.semantic_id for item in graph.nodes}
        nodes = tuple(
            sorted(item.semantic_id for item in graph.nodes if item.semantic_id not in excluded)
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
        expected_states = tuple(
            QueryState.PRESENT
            if (treated and operation.value == "add")
            or (not treated and operation.value == "remove")
            else QueryState.ABSENT
            for treated, operation in zip(
                cell.target_states,
                pair.operations,
                strict=True,
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


def _verify_oracle_qualifications(
    artifact: Any,
    study: Mapping[str, Any],
    pair_by_id: Mapping[str, Any],
) -> None:
    if (
        not isinstance(artifact, dict)
        or set(artifact) != {"schema_version", "producer", "pairs"}
        or artifact["schema_version"] != "1.0"
    ):
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
        or [item.get("pair_id") for item in rows] != sorted(expected_pair_ids)
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
            or hashlib.sha256(policy_payload.encode("utf-8")).hexdigest() != row["policy_sha256"]
            or not isinstance(qualification_payload, str)
            or hashlib.sha256(qualification_payload.encode("utf-8")).hexdigest()
            != row["qualification_sha256"]
        ):
            raise FactorialExperimentError("factorial frozen Oracle identity drifts")
        policy = _json_object(policy_payload)
        qualification = _json_object(qualification_payload)
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
            raise FactorialExperimentError("factorial frozen Oracle qualification semantics drift")
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


def _verify_functionality_power(
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
    artifact = _read_json(path)
    if (
        not isinstance(artifact, dict)
        or set(artifact)
        != {
            "schema_version",
            "qualification_sha256",
            "qualification_payload",
        }
        or artifact["schema_version"] != "1.0"
    ):
        raise FactorialExperimentError("frozen functionality power qualification is invalid")
    payload_text = artifact["qualification_payload"]
    if (
        not isinstance(payload_text, str)
        or hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
        != artifact["qualification_sha256"]
        or artifact["qualification_sha256"]
        != analysis["functionality_power_qualification"]["sha256"]
        or plan.get("functionality_power_qualification_sha256") != artifact["qualification_sha256"]
    ):
        raise FactorialExperimentError("frozen functionality power qualification digest drifts")
    payload = _json_object(payload_text)
    planned_units = validate_factorial_functionality_power(payload, analysis)
    if any(
        len({bundle["task_unit_id"] for bundle in policy["bundles"]}) < planned_units
        for policy in study.get("policies", ())
    ):
        raise FactorialExperimentError(
            "frozen factorial support is smaller than the functionality power plan"
        )


def _verify_functional_qualification(
    config: Mapping[str, Any],
    study: Mapping[str, Any],
    sealed: Any,
) -> None:
    if not isinstance(sealed, Mapping):
        raise FactorialExperimentError("bundled functional qualification is invalid")
    identity = sealed.get("qualification_identity")
    if not isinstance(identity, Mapping):
        raise FactorialExperimentError("bundled functional qualification identity is invalid")
    section = config["functional_oracle"]
    evaluator = {
        "candidate_id": identity.get("candidate_id"),
        "model_id": identity.get("model_id"),
        "provider": identity.get("provider"),
        "fixture_only": identity.get("fixture_only"),
        "scientific_claim_allowed": identity.get("evaluator_scientific_claim_allowed"),
    }
    try:
        validated = validate_functional_qualification(
            section,
            evaluator,
            sealed,
            structural_smoke_allowed=(
                config.get("phase") == "development_canary"
                and config.get("scientific_claim_allowed") is False
            ),
            include_evaluator_metadata=True,
        )
    except QualificationError as error:
        raise FactorialExperimentError(str(error)) from error
    identity = validated["qualification_identity"]
    adapter_material = {
        "evaluator_config_sha256": identity["evaluator_config_sha256"],
        "prompt_sha256": identity["prompt_sha256"],
        "qualification_sha256": validated["qualification_sha256"],
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


def _read_json(path: Path) -> Any:
    try:
        return read_json_exact(path)
    except ValueError:
        raise FactorialExperimentError(f"JSON input is invalid or duplicated: {path}") from None


def _json_object(payload: str) -> dict[str, Any]:
    try:
        return json_object(payload)
    except ValueError:
        raise FactorialExperimentError(
            "factorial frozen provider response is invalid JSON"
        ) from None


__all__ = [
    "validate_factorial_variant_graphs",
    "verify_factorial_freeze_bundle",
]
