"""Portable freeze bundle for the observational interaction selector."""

from __future__ import annotations

import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.interaction_selector import (
    InteractionSelectorPlan,
    PairDiscoveryObservation,
    build_tsg_pair_universe,
    run_interaction_selector,
)
from prompt_mechanism_study.mechanisms import (
    FactorialCompatibility,
    MechanismRelationSpec,
    PairRelation,
    PairRelationEvidence,
    PairSpec,
    RelationEvidenceContract,
    load_pair_registry,
    pair_matches_relation_spec,
    validate_active_factorial_relation,
    validate_mechanism_relation_spec,
    validate_pair_factors,
    validate_pair_relation_evidence,
)
from prompt_mechanism_study.prioritization import SelectorKind, SlotStatus
from prompt_mechanism_study.prompt_tsg import (
    QueryState,
    catalog_sha256,
    feature_state,
    load_catalog,
    prompt_tsg_from_record,
    validate_prompt_tsg,
)
from prompt_mechanism_study.records import canonical_value, content_hash
from prompt_mechanism_study.representation import Operation
from prompt_mechanism_study.selector_experiment import load_selection_freeze_bundle


class InteractionSelectorExperimentError(ValueError):
    """The interaction-selector freeze does not replay exactly."""


INTERACTION_SELECTION_ARTIFACT_FILES = (
    "effective-config.json",
    "graph-support-effective-config.json",
    "graph-support-identity.json",
    "graph-support-selection.json",
    "pair-registry.json",
    "prompt-tsg-catalog.json",
    "prompt-tsg-evidence.json",
    "report.json",
    "selection-freeze.json",
)

_SELECTION_ARTIFACT_FILES = (
    "effective-config.json",
    "identity.json",
    "selection.json",
)


def freeze_interaction_selection_from_config(config_path: Path, output: Path) -> dict[str, Any]:
    """Run the existing selector from one small canonical JSON input."""

    config_file = config_path.resolve()
    config = _config(read_json(config_file))
    catalog_path = _resolve_source_path(
        config["prompt_tsg_catalog_path"], config_root=config_file.parent
    )
    registry_path = _resolve_source_path(
        config["pair_registry_path"], config_root=config_file.parent
    )
    prompt_tsg_evidence_path = _resolve_source_path(
        config["prompt_tsg_evidence_path"], config_root=config_file.parent
    )
    graph_factors, graph_support_files = _graph_support_from_source(
        config["graph_support_selection"], config_root=config_file.parent
    )
    (
        pairs,
        specs,
        evidence,
        rows,
        plan,
        catalog,
        _registry,
        registry_value,
        prompt_tsg_evidence,
    ) = _typed_inputs(
        config,
        catalog_path=catalog_path,
        registry_path=registry_path,
        prompt_tsg_evidence_path=prompt_tsg_evidence_path,
    )
    graph_factors = _relevant_graph_factors(graph_factors, pairs)
    universe = build_tsg_pair_universe(pairs, specs)
    frozen = run_interaction_selector(
        universe, rows, evidence, plan, graph_supported_factor_ids=graph_factors
    )
    report = _report(frozen)
    write_bundle(
        output,
        {
            "effective-config.json": config,
            **graph_support_files,
            "pair-registry.json": registry_value,
            "prompt-tsg-catalog.json": catalog,
            "prompt-tsg-evidence.json": prompt_tsg_evidence,
            "selection-freeze.json": canonical_value(frozen),
            "report.json": report,
        },
    )
    verified = verify_interaction_selection_bundle(output)
    return {**verified, **report}


def verify_interaction_selection_bundle(root: Path) -> dict[str, Any]:
    """Reconstruct all inputs and rerun gates, scores, ranks, and IDs."""

    manifest = verify_bundle(root)
    if set(manifest["files"]) != set(INTERACTION_SELECTION_ARTIFACT_FILES):
        raise InteractionSelectorExperimentError("interaction selection artifact set is not exact")
    config = _config(read_json(root / "effective-config.json"))
    graph_factors = _graph_support_from_embedded(root, config["graph_support_selection"])
    (
        pairs,
        specs,
        evidence,
        rows,
        plan,
        _catalog,
        registry,
        _registry_value,
        _prompt_tsg_evidence,
    ) = _typed_inputs(
        config,
        catalog_path=root / "prompt-tsg-catalog.json",
        registry_path=root / "pair-registry.json",
        prompt_tsg_evidence_path=root / "prompt-tsg-evidence.json",
    )
    graph_factors = _relevant_graph_factors(graph_factors, pairs)
    frozen = run_interaction_selector(
        build_tsg_pair_universe(pairs, specs), rows, evidence, plan,
        graph_supported_factor_ids=graph_factors,
    )
    if read_json(root / "selection-freeze.json") != canonical_value(frozen):
        raise InteractionSelectorExperimentError("stored interaction selection does not recompute")
    report = _report(frozen)
    if read_json(root / "report.json") != report:
        raise InteractionSelectorExperimentError("stored interaction selection report does not recompute")
    return {
        "status": "INTERACTION_SELECTION_BUNDLE_VERIFIED",
        "freeze_id": frozen.freeze_id,
        "selected_graph_pair_ids": list(frozen.selected_graph_pair_ids),
        "selected_pure_interaction_pair_ids": list(frozen.selected_pure_interaction_pair_ids),
        "selected_pair_ids": sorted(
            (*frozen.selected_graph_pair_ids, *frozen.selected_pure_interaction_pair_ids)
        ),
        "prompt_tsg_catalog_sha256": registry.prompt_tsg_catalog_sha256,
        "pair_registry_id": registry.registry_id,
        "bundle_sha256": bundle_digest(root),
    }


def _typed_inputs(
    config: Mapping[str, Any],
    *,
    catalog_path: Path,
    registry_path: Path,
    prompt_tsg_evidence_path: Path,
):
    catalog = load_catalog(catalog_path)
    if catalog_sha256(catalog) != config["prompt_tsg_catalog_sha256"]:
        raise InteractionSelectorExperimentError(
            "interaction selector Prompt TSG catalog digest drift"
        )
    registry_value = read_json(registry_path)
    if content_hash(registry_value) != config["pair_registry_sha256"]:
        raise InteractionSelectorExperimentError(
            "interaction selector pair registry digest drift"
        )
    registry = load_pair_registry(registry_path, catalog)
    prompt_tsg_evidence = read_json(prompt_tsg_evidence_path)
    if content_hash(prompt_tsg_evidence) != config["prompt_tsg_evidence_sha256"]:
        raise InteractionSelectorExperimentError(
            "interaction selector Prompt TSG evidence digest drift"
        )
    task_by_id, graph_by_id = _prompt_tsg_evidence(prompt_tsg_evidence, catalog)
    pairs = registry.pairs
    for pair in pairs:
        validate_pair_factors(
            pair, catalog, atomic_factor_ids=registry.atomic_factor_ids
        )
        validate_active_factorial_relation(pair.relation_type)
    specs = tuple(
        _relation_spec(_object(item, "relation spec"))
        for item in _list(config["relation_specs"], "relation specs")
    )
    for spec in specs:
        validate_mechanism_relation_spec(
            spec, catalog, atomic_factor_ids=registry.atomic_factor_ids
        )
        validate_active_factorial_relation(spec.relation_type)
    evidence = tuple(
        _evidence(_object(item, "relation evidence"))
        for item in _list(config["relation_evidence"], "relation evidence")
    )
    rows = tuple(
        _observation(_object(item, "discovery observation"))
        for item in _list(config["observations"], "observations")
    )
    _validate_discovery_evidence(rows, config["discovery_evidence"])
    plan = _plan(_object(config["plan"], "interaction selector plan"))
    _validate_relation_bindings(
        pairs,
        specs,
        evidence,
        rows,
        task_by_id=task_by_id,
        graph_by_id=graph_by_id,
    )
    return (
        pairs,
        specs,
        evidence,
        rows,
        plan,
        catalog,
        registry,
        registry_value,
        prompt_tsg_evidence,
    )


def _relation_spec(value: Mapping[str, Any]) -> MechanismRelationSpec:
    _require_exact_keys(
        value,
        {
            "relation_id",
            "factor_1_id",
            "factor_2_id",
            "relation_type",
            "factorial_compatibility",
            "context_query_id",
            "evidence_contract",
            "eligible_languages",
            "eligible_task_families",
            "eligible_cwes",
            "allowed_operation_pairs",
        },
        "relation spec",
    )
    contract = _object(value["evidence_contract"], "relation evidence contract")
    _require_exact_keys(
        contract,
        {"required_semantics", "required_relations"},
        "relation evidence contract",
    )
    return MechanismRelationSpec(
        value["relation_id"], value["factor_1_id"], value["factor_2_id"],
        PairRelation(value["relation_type"]),
        FactorialCompatibility(value["factorial_compatibility"]),
        value["context_query_id"],
        RelationEvidenceContract(tuple(contract["required_semantics"]), tuple(tuple(item) for item in contract["required_relations"])),
        tuple(value["eligible_languages"]), tuple(value["eligible_task_families"]),
        tuple(value["eligible_cwes"]),
        tuple((Operation(item[0]), Operation(item[1])) for item in value["allowed_operation_pairs"]),
    )


def _evidence(value: Mapping[str, Any]) -> PairRelationEvidence:
    _require_exact_keys(
        value,
        {
            "pair_id",
            "relation_spec_id",
            "relation_id",
            "task_id",
            "task_unit_id",
            "prompt_tsg_id",
            "evidence_contract_id",
            "state",
            "evidence_node_ids",
            "evidence_edge_ids",
            "outcomes_or_arms_used",
        },
        "relation evidence",
    )
    result = PairRelationEvidence(
        value["pair_id"], value["relation_spec_id"], value["relation_id"],
        value["task_id"], value["task_unit_id"], value["prompt_tsg_id"],
        value["evidence_contract_id"], QueryState(value["state"]),
        tuple(value["evidence_node_ids"]), tuple(value["evidence_edge_ids"]),
        value["outcomes_or_arms_used"],
    )
    if result.outcomes_or_arms_used:
        raise InteractionSelectorExperimentError(
            "interaction selector relation evidence is not outcome/arm blind"
        )
    return result


def _observation(value: Mapping[str, Any]) -> PairDiscoveryObservation:
    _require_exact_keys(
        value,
        {
            "pair_id",
            "relation_spec_id",
            "relation_evidence_id",
            "task_unit_id",
            "model_id",
            "source_lineage_id",
            "language",
            "task_archetype",
            "api_family",
            "context_query_id",
            "context_state",
            "factor_states",
            "factor_reliabilities",
            "covariates",
            "outcome",
        },
        "discovery observation",
    )
    return PairDiscoveryObservation(
        value["pair_id"], value["relation_spec_id"], value["relation_evidence_id"],
        value["task_unit_id"], value["model_id"], value["source_lineage_id"],
        value["language"], value["task_archetype"], value["api_family"],
        value["context_query_id"], QueryState(value["context_state"]),
        tuple((item[0], QueryState(item[1])) for item in value["factor_states"]),
        tuple(tuple(item) for item in value["factor_reliabilities"]),
        tuple(tuple(item) for item in value["covariates"]), value["outcome"],
    )


def _plan(value: Mapping[str, Any]) -> InteractionSelectorPlan:
    _require_exact_keys(
        value,
        {
            "model_id",
            "outcome_id",
            "covariate_names",
            "minimum_cell_task_units",
            "minimum_shared_lineages",
            "minimum_feature_reliability",
            "ridge_lambda",
            "cross_fit_folds",
            "bootstrap_draws",
            "bootstrap_seed",
            "top_l_per_lane",
        },
        "interaction selector plan",
    )
    return InteractionSelectorPlan(
        value["model_id"], value["outcome_id"], tuple(value["covariate_names"]),
        value["minimum_cell_task_units"], value["minimum_shared_lineages"],
        value["minimum_feature_reliability"], value["ridge_lambda"],
        value["cross_fit_folds"], value["bootstrap_draws"], value["bootstrap_seed"],
        value["top_l_per_lane"],
    )


def _report(frozen: Any) -> dict[str, Any]:
    graph = list(frozen.selected_graph_pair_ids)
    pure = list(frozen.selected_pure_interaction_pair_ids)
    return {
        "schema_version": "1.2",
        "status": "INTERACTION_SELECTION_FROZEN",
        "freeze_id": frozen.freeze_id,
        "universe_id": frozen.universe_id,
        "plan_id": frozen.plan_id,
        "selected_graph_pair_ids": graph,
        "selected_pure_interaction_pair_ids": pure,
        "selected_pair_ids": sorted((*graph, *pure)),
    }


def _config(value: Any) -> dict[str, Any]:
    config = _object(value, "interaction selector config")
    expected = {
        "schema_version",
        "prompt_tsg_catalog_path",
        "prompt_tsg_catalog_sha256",
        "prompt_tsg_evidence_path",
        "prompt_tsg_evidence_sha256",
        "pair_registry_path",
        "pair_registry_sha256",
        "relation_specs",
        "relation_evidence",
        "observations",
        "discovery_evidence",
        "plan",
        "graph_support_selection",
    }
    if set(config) != expected or config.get("schema_version") != "1.2":
        raise InteractionSelectorExperimentError("interaction selector config fields are not exact")
    for name in (
        "prompt_tsg_catalog_path",
        "prompt_tsg_evidence_path",
        "pair_registry_path",
    ):
        if not isinstance(config[name], str) or not config[name].strip():
            raise InteractionSelectorExperimentError(
                "interaction selector artifact path is invalid"
            )
    for name in (
        "prompt_tsg_catalog_sha256",
        "prompt_tsg_evidence_sha256",
        "pair_registry_sha256",
    ):
        _require_digest(config[name], name)
    support = config["graph_support_selection"]
    if support is not None:
        support = _object(support, "graph-support selection")
        _require_exact_keys(
            support,
            {"artifact_path", "artifact_bundle_sha256"},
            "graph-support selection",
        )
        if not isinstance(support["artifact_path"], str) or not support[
            "artifact_path"
        ].strip():
            raise InteractionSelectorExperimentError(
                "graph-support selection path is invalid"
            )
        _require_digest(
            support["artifact_bundle_sha256"],
            "graph-support selection bundle",
        )
    return config


def _validate_relation_bindings(
    pairs: tuple[PairSpec, ...],
    specs: tuple[MechanismRelationSpec, ...],
    evidence: tuple[PairRelationEvidence, ...],
    rows: tuple[PairDiscoveryObservation, ...],
    *,
    task_by_id: Mapping[str, Mapping[str, Any]],
    graph_by_id: Mapping[str, Any],
) -> None:
    pair_by_id = {item.pair_id: item for item in pairs}
    spec_by_id = {item.relation_spec_id: item for item in specs}
    evidence_by_id = {item.evidence_id: item for item in evidence}
    if len(spec_by_id) != len(specs) or len(evidence_by_id) != len(evidence):
        raise InteractionSelectorExperimentError(
            "interaction selector relation inputs are duplicated"
        )
    for item in evidence:
        pair = pair_by_id.get(item.pair_id)
        spec = spec_by_id.get(item.relation_spec_id)
        task = task_by_id.get(item.task_id)
        graph = graph_by_id.get(item.prompt_tsg_id)
        if (
            pair is None
            or spec is None
            or task is None
            or graph is None
            or not pair_matches_relation_spec(pair, spec)
            or item.relation_id != spec.relation_id
            or item.evidence_contract_id != spec.evidence_contract.contract_id
        ):
            raise InteractionSelectorExperimentError(
                "interaction selector relation evidence leaves the catalog-bound universe"
            )
        validate_pair_relation_evidence(item, task, graph, pair, spec)
    if {item.task_id for item in evidence} != set(task_by_id) or {
        item.prompt_tsg_id for item in evidence
    } != set(graph_by_id):
        raise InteractionSelectorExperimentError(
            "Prompt TSG evidence is not exactly used by relation evidence"
        )
    if {item.relation_evidence_id for item in rows} != set(evidence_by_id):
        raise InteractionSelectorExperimentError(
            "interaction selector observations do not exactly bind relation evidence"
        )
    for row in rows:
        item = evidence_by_id[row.relation_evidence_id]
        task = task_by_id[item.task_id]
        graph = graph_by_id[item.prompt_tsg_id]
        pair = pair_by_id[row.pair_id]
        expected_factor_states = tuple(
            (factor_id, feature_state(graph, factor_id))
            for factor_id in pair.factors
        )
        if (
            row.pair_id != item.pair_id
            or row.relation_spec_id != item.relation_spec_id
            or row.task_unit_id != item.task_unit_id
            or row.task_unit_id != task["task_unit_id"]
            or row.language != task["language"]
            or row.task_archetype != task["task_family"]
            or row.context_query_id != pair.pair_context_query_id
            or row.context_state is not item.state
            or row.factor_states != expected_factor_states
        ):
            raise InteractionSelectorExperimentError(
                "interaction selector observation drifts from its task-side evidence"
            )


def _prompt_tsg_evidence(
    value: Any, catalog: Mapping[str, Any]
) -> tuple[dict[str, Mapping[str, Any]], dict[str, Any]]:
    rows = _list(value, "Prompt TSG evidence")
    if not rows:
        raise InteractionSelectorExperimentError("Prompt TSG evidence cannot be empty")
    task_by_id: dict[str, Mapping[str, Any]] = {}
    graph_by_id: dict[str, Any] = {}
    for raw in rows:
        item = _object(raw, "Prompt TSG evidence item")
        _require_exact_keys(item, {"task", "graph"}, "Prompt TSG evidence item")
        task = _object(item["task"], "Prompt TSG task")
        _require_exact_keys(
            task,
            {"task_id", "task_unit_id", "prompt", "language", "task_family", "cwe"},
            "Prompt TSG task",
        )
        if any(
            not isinstance(task[name], str) or not task[name].strip()
            for name in ("task_id", "task_unit_id", "prompt", "language", "task_family", "cwe")
        ):
            raise InteractionSelectorExperimentError("Prompt TSG task values are invalid")
        graph = prompt_tsg_from_record(_object(item["graph"], "Prompt TSG graph"))
        validate_prompt_tsg(graph, prompt=task["prompt"], catalog=catalog)
        if graph.task_id != task["task_id"]:
            raise InteractionSelectorExperimentError("Prompt TSG graph does not bind its task")
        if task["task_id"] in task_by_id or graph.tsg_id in graph_by_id:
            raise InteractionSelectorExperimentError("Prompt TSG evidence identities are duplicated")
        task_by_id[task["task_id"]] = task
        graph_by_id[graph.tsg_id] = graph
    return task_by_id, graph_by_id


def _validate_discovery_evidence(
    observations: tuple[PairDiscoveryObservation, ...], value: Any
) -> None:
    rows = _list(value, "pair discovery evidence")
    expected_ids = sorted(item.observation_id for item in observations)
    if [item.get("observation_id") for item in rows if isinstance(item, dict)] != expected_ids:
        raise InteractionSelectorExperimentError(
            "pair discovery evidence order or support is not exact"
        )
    observation_by_id = {item.observation_id: item for item in observations}
    for raw in rows:
        item = _object(raw, "pair discovery evidence item")
        _require_exact_keys(
            item,
            {
                "observation_id",
                "producer_id",
                "raw_output",
                "raw_output_sha256",
                "confirm_outcomes_used",
            },
            "pair discovery evidence item",
        )
        observation = observation_by_id.get(item["observation_id"])
        if (
            observation is None
            or item["raw_output"] != canonical_value(observation)
            or item["raw_output_sha256"] != content_hash(item["raw_output"])
            or item["confirm_outcomes_used"] is not False
            or not isinstance(item["producer_id"], str)
            or not item["producer_id"].strip()
        ):
            raise InteractionSelectorExperimentError(
                "pair discovery evidence does not bind its natural observation"
            )


def _graph_support_from_source(
    value: Mapping[str, Any] | None, *, config_root: Path
) -> tuple[tuple[str, ...], dict[str, Any]]:
    if value is None:
        sentinel = {"status": "not_used"}
        return (), {
            "graph-support-effective-config.json": sentinel,
            "graph-support-identity.json": sentinel,
            "graph-support-selection.json": sentinel,
        }
    root = _resolve_source_path(value["artifact_path"], config_root=config_root)
    if bundle_digest(root) != value["artifact_bundle_sha256"]:
        raise InteractionSelectorExperimentError("graph-support selection bundle digest drift")
    selection = load_selection_freeze_bundle(root)
    factors = _graph_support_factors(selection)
    return factors, {
        f"graph-support-{name}": read_json(root / name)
        for name in _SELECTION_ARTIFACT_FILES
    }


def _graph_support_from_embedded(
    root: Path, value: Mapping[str, Any] | None
) -> tuple[str, ...]:
    names = tuple(f"graph-support-{name}" for name in _SELECTION_ARTIFACT_FILES)
    if value is None:
        if any(read_json(root / name) != {"status": "not_used"} for name in names):
            raise InteractionSelectorExperimentError(
                "unused graph-support artifacts are not exact sentinels"
            )
        return ()
    with tempfile.TemporaryDirectory(prefix="prompt-mechanism-selector-") as temporary:
        reconstructed = Path(temporary) / "selection"
        write_bundle(
            reconstructed,
            {
                name: read_json(root / f"graph-support-{name}")
                for name in _SELECTION_ARTIFACT_FILES
            },
        )
        if bundle_digest(reconstructed) != value["artifact_bundle_sha256"]:
            raise InteractionSelectorExperimentError(
                "embedded graph-support selection bundle digest drift"
            )
        selection = load_selection_freeze_bundle(reconstructed)
    return _graph_support_factors(selection)


def _graph_support_factors(selection: Any) -> tuple[str, ...]:
    if selection.plan.behavior_version != "shared-selector-suite-v2":
        raise InteractionSelectorExperimentError(
            "graph support requires the active prospective selector behavior"
        )
    fci_runs = tuple(run for run in selection.runs if run.kind is SelectorKind.FCI)
    if len(fci_runs) != 1:
        raise InteractionSelectorExperimentError("graph support requires exactly one FCI run")
    selected = {
        slot.candidate_id
        for ranking in fci_runs[0].rankings
        for slot in ranking.slots
        if slot.status is SlotStatus.FILLED
    }
    skeletons = dict(selection.universe.candidate_skeletons)
    if None in selected or not selected <= set(skeletons):
        raise InteractionSelectorExperimentError(
            "graph-support FCI slots leave the frozen candidate universe"
        )
    return tuple(
        sorted(
            {
                feature_id
                for candidate_id in selected
                for feature_id in skeletons[candidate_id].actionable_feature_ids
            }
        )
    )


def _relevant_graph_factors(
    factors: tuple[str, ...], pairs: tuple[PairSpec, ...]
) -> tuple[str, ...]:
    pair_factors = {factor_id for pair in pairs for factor_id in pair.factors}
    return tuple(sorted(set(factors) & pair_factors))


def _resolve_source_path(value: str, *, config_root: Path) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (config_root / path).resolve()


def _require_digest(value: Any, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise InteractionSelectorExperimentError(f"{name} must be a lowercase digest")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InteractionSelectorExperimentError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise InteractionSelectorExperimentError(f"{label} must be a list")
    return value


def _require_exact_keys(value: Mapping[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise InteractionSelectorExperimentError(f"{label} fields are not exact")


__all__ = [
    "INTERACTION_SELECTION_ARTIFACT_FILES",
    "InteractionSelectorExperimentError",
    "freeze_interaction_selection_from_config",
    "verify_interaction_selection_bundle",
]
