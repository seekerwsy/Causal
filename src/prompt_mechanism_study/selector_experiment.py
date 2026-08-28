"""Minimal artifact closure for the frozen selector study.

The public path is deliberately linear: freeze selection, freeze its bridge,
verify successor evidence and extract coordinates, evaluate, then independently
replay the stored result.  This module contains JSON reconstruction only; the
scientific calculations remain in :mod:`selector_inference` and
:mod:`selector_verify`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.prioritization import (
    BackgroundKnowledgeRule,
    BridgeRecord,
    BridgeStatus,
    CandidateUniverseManifest,
    DiscoveryObservation,
    ExpertRankingInput,
    FrozenFCIRelationScores,
    RankedCandidate,
    SelectionFreezeManifest,
    SelectorFailure,
    SelectorKind,
    SelectorRanking,
    SelectorRun,
    SelectorRunStatus,
    SelectorSensitivityAudit,
    SelectorSensitivityRanking,
    SelectorSlot,
    SelectorSuitePlan,
    SharedBridgeMap,
    SlotStatus,
    discovery_data_sha256,
    freeze_shared_bridge_map,
    run_selector_suite,
)
from prompt_mechanism_study.records import canonical_value, content_hash, content_id
from prompt_mechanism_study.representation import (
    CandidateSkeletonV2,
    ExpectedDirection,
    FrozenHypothesisV2,
    Operation,
    TargetSpecV2,
)
from prompt_mechanism_study.selector_inference import (
    ConfirmationCoordinate,
    ConfirmationStatus,
    SelectorInferencePlan,
    SelectorInferenceResult,
    SelectorMethodPoint,
    SelectorPairInterval,
    SelectorPairPoint,
    SelectorYieldPoint,
    SlotContribution,
    evaluate_selector_study,
)
from prompt_mechanism_study.selector_verify import verify_selector_result
from prompt_mechanism_study.successor_experiment import verify_successor_result_bundle


class SelectorExperimentError(ValueError):
    """A stored selector-study artifact failed closed."""


ACTIVE_SELECTOR_SCHEMA_VERSION = "2.0"
ACTIVE_SELECTOR_BEHAVIOR_VERSION = "shared-selector-suite-v2"
ARCHIVAL_SELECTOR_SCHEMA_VERSION = "1.0"
ARCHIVAL_SELECTOR_BEHAVIOR_VERSION = "shared-selector-suite-v1"


def freeze_selection_from_config(config_path: Path, output: Path) -> dict[str, Any]:
    """Freeze the active prospective selector protocol (schema 2.0 only)."""

    config = _object(read_json(config_path), "selector freeze config")
    selection = _selection_from_config(config, archival=False)
    return write_selection_freeze_bundle(output, selection, config)


def freeze_archival_selection_from_config(
    config_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Reproduce the frozen schema-1.0 selector protocol for archival audit."""

    config = _object(read_json(config_path), "archival selector freeze config")
    selection = _selection_from_config(config, archival=True)
    return write_archival_selection_freeze_bundle(output, selection, config)


def build_active_selector_evidence(
    universe: CandidateUniverseManifest,
    observations: Sequence[DiscoveryObservation],
    *,
    source_lineage_by_task_unit: Mapping[str, str] | None = None,
    producer_id: str = "frozen-natural-discovery-v1",
    minimum_positive_task_units: int = 2,
    minimum_negative_task_units: int = 2,
    minimum_shared_source_lineages: int = 1,
) -> tuple[CandidateUniverseManifest, dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    """Build the replayable support gate and standardized expert information budget."""

    if not isinstance(producer_id, str) or not producer_id.strip():
        raise SelectorExperimentError("discovery producer_id is invalid")
    lineage_map = dict(source_lineage_by_task_unit or {})
    evidence = []
    for observation in observations:
        lineage = lineage_map.get(observation.task_unit_id, "source-lineage.default")
        if not isinstance(lineage, str) or not lineage.strip():
            raise SelectorExperimentError("discovery source lineage is invalid")
        raw_output = canonical_value(observation)
        evidence.append(
            {
                "observation_id": observation.observation_id,
                "task_unit_id": observation.task_unit_id,
                "model_id": observation.model_id,
                "request_randomness_slot": observation.request_randomness_slot,
                "source_lineage_id": lineage,
                "producer_id": producer_id,
                "raw_output": raw_output,
                "raw_output_sha256": content_hash(raw_output),
                "confirm_outcomes_used": False,
            }
        )
    evidence.sort(key=lambda item: item["observation_id"])
    thresholds = {
        "minimum_positive_task_units": minimum_positive_task_units,
        "minimum_negative_task_units": minimum_negative_task_units,
        "minimum_shared_source_lineages": minimum_shared_source_lineages,
    }
    parsed = _discovery_evidence(tuple(observations), evidence)
    support = _support_audit(universe, tuple(observations), parsed, thresholds)
    supported = tuple(row["candidate_id"] for row in support["rows"] if row["eligible"])
    interim = replace(
        universe,
        supported_candidate_ids=supported,
        positivity_audit_sha256=content_hash(support),
    )
    information_budget = _information_budget(interim, tuple(observations), evidence)
    frozen = replace(interim, information_budget_sha256=content_hash(information_budget))
    return frozen, support, information_budget, evidence


def _validate_active_selector_evidence(
    universe: CandidateUniverseManifest,
    observations: tuple[DiscoveryObservation, ...],
    raw_support: Any,
    raw_information_budget: Any,
    raw_discovery_evidence: Any,
) -> dict[str, Any]:
    support = _object(raw_support, "selector support audit")
    _require_exact_keys(
        support,
        {
            "schema_version",
            "minimum_positive_task_units",
            "minimum_negative_task_units",
            "minimum_shared_source_lineages",
            "outcomes_or_confirm_data_used",
            "rows",
        },
        "selector support audit",
    )
    if support["schema_version"] != "1.0" or support["outcomes_or_confirm_data_used"] is not False:
        raise SelectorExperimentError("selector support audit is not outcome-blind")
    thresholds = {
        name: support[name]
        for name in (
            "minimum_positive_task_units",
            "minimum_negative_task_units",
            "minimum_shared_source_lineages",
        )
    }
    evidence = _discovery_evidence(observations, raw_discovery_evidence)
    expected_support = _support_audit(universe, observations, evidence, thresholds)
    if support != expected_support or content_hash(support) != universe.positivity_audit_sha256:
        raise SelectorExperimentError("selector support audit does not recompute")
    supported = tuple(row["candidate_id"] for row in support["rows"] if row["eligible"])
    if supported != universe.supported_candidate_ids:
        raise SelectorExperimentError("supported candidates do not derive from the frozen gate")
    information_budget = _object(raw_information_budget, "selector information budget")
    expected_budget = _information_budget(universe, observations, raw_discovery_evidence)
    if (
        information_budget != expected_budget
        or content_hash(information_budget) != universe.information_budget_sha256
    ):
        raise SelectorExperimentError("selector information budget does not recompute")
    return information_budget


def _discovery_evidence(
    observations: tuple[DiscoveryObservation, ...], value: Any
) -> dict[str, Mapping[str, Any]]:
    rows = _list(value, "selector discovery evidence")
    if [item.get("observation_id") for item in rows if isinstance(item, dict)] != sorted(
        item.observation_id for item in observations
    ):
        raise SelectorExperimentError("selector discovery evidence order is not canonical")
    observation_by_id = {item.observation_id: item for item in observations}
    evidence_by_id: dict[str, Mapping[str, Any]] = {}
    for raw in rows:
        item = _exact_object(
            raw,
            {
                "observation_id",
                "task_unit_id",
                "model_id",
                "request_randomness_slot",
                "source_lineage_id",
                "producer_id",
                "raw_output",
                "raw_output_sha256",
                "confirm_outcomes_used",
            },
            "selector discovery evidence item",
        )
        observation = observation_by_id.get(item["observation_id"])
        if (
            observation is None
            or item["observation_id"] in evidence_by_id
            or item["task_unit_id"] != observation.task_unit_id
            or item["model_id"] != observation.model_id
            or item["request_randomness_slot"] != observation.request_randomness_slot
            or item["raw_output"] != canonical_value(observation)
            or item["raw_output_sha256"] != content_hash(item["raw_output"])
            or item["confirm_outcomes_used"] is not False
            or not isinstance(item["source_lineage_id"], str)
            or not item["source_lineage_id"].strip()
            or not isinstance(item["producer_id"], str)
            or not item["producer_id"].strip()
        ):
            raise SelectorExperimentError("selector discovery evidence does not bind its observation")
        evidence_by_id[item["observation_id"]] = item
    if set(evidence_by_id) != set(observation_by_id):
        raise SelectorExperimentError("selector discovery evidence is not exactly closed")
    return evidence_by_id


def _support_audit(
    universe: CandidateUniverseManifest,
    observations: tuple[DiscoveryObservation, ...],
    evidence_by_id: Mapping[str, Mapping[str, Any]],
    thresholds: Mapping[str, Any],
) -> dict[str, Any]:
    for name, value in thresholds.items():
        if type(value) is not int or value <= 0:
            raise SelectorExperimentError(f"selector support threshold {name} is invalid")
    rows = []
    for candidate_id in universe.candidate_ids:
        state_by_task: dict[str, int] = {}
        lineage_by_task: dict[str, str] = {}
        for observation in observations:
            states = dict(observation.candidate_states)
            if candidate_id not in states:
                continue
            task_id = observation.task_unit_id
            state = int(states[candidate_id])
            lineage = evidence_by_id[observation.observation_id]["source_lineage_id"]
            if task_id in state_by_task and (
                state_by_task[task_id] != state or lineage_by_task[task_id] != lineage
            ):
                raise SelectorExperimentError(
                    "natural discovery state or lineage changes within a task unit"
                )
            state_by_task[task_id] = state
            lineage_by_task[task_id] = lineage
        positive = tuple(sorted(task for task, state in state_by_task.items() if state == 1))
        negative = tuple(sorted(task for task, state in state_by_task.items() if state == 0))
        positive_lineages = tuple(sorted({lineage_by_task[task] for task in positive}))
        negative_lineages = tuple(sorted({lineage_by_task[task] for task in negative}))
        shared = tuple(sorted(set(positive_lineages) & set(negative_lineages)))
        reasons = []
        if len(positive) < thresholds["minimum_positive_task_units"]:
            reasons.append("insufficient_positive_task_units")
        if len(negative) < thresholds["minimum_negative_task_units"]:
            reasons.append("insufficient_negative_task_units")
        if len(shared) < thresholds["minimum_shared_source_lineages"]:
            reasons.append("insufficient_source_lineage_overlap")
        rows.append(
            {
                "candidate_id": candidate_id,
                "positive_task_unit_ids": list(positive),
                "negative_task_unit_ids": list(negative),
                "positive_source_lineage_ids": list(positive_lineages),
                "negative_source_lineage_ids": list(negative_lineages),
                "shared_source_lineage_ids": list(shared),
                "eligible": not reasons,
                "reason_codes": sorted(reasons),
            }
        )
    return {
        "schema_version": "1.0",
        **dict(thresholds),
        "outcomes_or_confirm_data_used": False,
        "rows": rows,
    }


def _information_budget(
    universe: CandidateUniverseManifest,
    observations: tuple[DiscoveryObservation, ...],
    raw_discovery_evidence: Any,
) -> dict[str, Any]:
    skeletons = dict(universe.candidate_skeletons)
    cards = []
    mapping = []
    for index, candidate_id in enumerate(universe.supported_candidate_ids, start=1):
        skeleton = skeletons[candidate_id]
        task_values: dict[str, tuple[int, list[int]]] = {}
        for observation in observations:
            states = dict(observation.candidate_states)
            if candidate_id not in states:
                continue
            state = int(states[candidate_id])
            current = task_values.setdefault(observation.task_unit_id, (state, []))
            if current[0] != state:
                raise SelectorExperimentError("candidate state changes within a task unit")
            current[1].append(observation.outcome)
        by_state = {
            state: [sum(values) / len(values) for observed, values in task_values.values() if observed == state]
            for state in (0, 1)
        }
        blind_id = f"candidate-card-{index:04d}"
        mapping.append([blind_id, candidate_id])
        cards.append(
            {
                "blind_id": blind_id,
                "context_query_id": skeleton.context_query_id,
                "actionable_feature_ids": list(skeleton.actionable_feature_ids),
                "operation": skeleton.operation.value,
                "cwe": skeleton.cwe,
                "archetype": skeleton.archetype,
                "outcome_id": skeleton.outcome_id,
                "expected_direction": skeleton.expected_direction.value,
                "realization_policy_id": skeleton.realization_policy_id,
                "discovery_summary": {
                    "task_units": len(task_values),
                    "state_0_task_units": len(by_state[0]),
                    "state_1_task_units": len(by_state[1]),
                    "state_0_outcome_mean": (
                        sum(by_state[0]) / len(by_state[0]) if by_state[0] else None
                    ),
                    "state_1_outcome_mean": (
                        sum(by_state[1]) / len(by_state[1]) if by_state[1] else None
                    ),
                },
            }
        )
    return {
        "schema_version": "1.0",
        "confirm_outcomes_used": False,
        "discovery_evidence_sha256": content_hash(raw_discovery_evidence),
        "blind_mapping": mapping,
        "candidate_cards": cards,
    }


def _selection_from_config(
    config: Mapping[str, Any],
    *,
    archival: bool,
) -> SelectionFreezeManifest:
    expected = {
        "schema_version",
        "universe",
        "observations",
        "plan",
        "expert_input",
        "fci_relation_scores",
    }
    if not archival:
        expected |= {"support_audit", "information_budget", "discovery_evidence"}
    expected_schema, _expected_behavior = _selector_protocol(archival)
    if set(config) != expected or config.get("schema_version") != expected_schema:
        raise SelectorExperimentError("selector freeze config fields are not exact")
    universe = _universe(_object(config["universe"], "candidate universe"))
    observations = tuple(
        DiscoveryObservation(
            row["task_unit_id"], row["model_id"], row["family_id"],
            row["request_randomness_slot"], tuple(tuple(item) for item in row["candidate_states"]),
            tuple(tuple(item) for item in row["covariates"]), row["outcome"],
        )
        for row in (
            _exact_object(item, {"task_unit_id", "model_id", "family_id", "request_randomness_slot", "candidate_states", "covariates", "outcome"}, "discovery observation")
            for item in _list(config["observations"], "discovery observations")
        )
    )
    if discovery_data_sha256(observations) != universe.discovery_data_sha256:
        raise SelectorExperimentError("discovery observations do not match the universe digest")
    information_budget = None
    if not archival:
        information_budget = _validate_active_selector_evidence(
            universe,
            observations,
            config["support_audit"],
            config["information_budget"],
            config["discovery_evidence"],
        )
    plan = _suite_plan(_object(config["plan"], "selector suite plan"))
    _require_selector_protocol(plan, archival=archival)
    expert = None
    if config["expert_input"] is not None:
        item = _exact_object(config["expert_input"], {"universe_manifest_id", "model_id", "candidate_card_sha256", "ranked_candidate_ids", "identity_blinded", "confirm_outcomes_visible"}, "expert input")
        if not archival and item["candidate_card_sha256"] != content_hash(
            information_budget["candidate_cards"]
        ):
            raise SelectorExperimentError(
                "expert ranking does not bind the standardized candidate cards"
            )
        expert = ExpertRankingInput(item["universe_manifest_id"], item["model_id"], item["candidate_card_sha256"], tuple(item["ranked_candidate_ids"]), item["identity_blinded"], item["confirm_outcomes_visible"])
    fci = None
    if config["fci_relation_scores"] is not None:
        item = _exact_object(config["fci_relation_scores"], {"universe_manifest_id", "selector_plan_id", "evidence_sha256", "scores"}, "FCI relation scores")
        fci = FrozenFCIRelationScores(item["universe_manifest_id"], item["selector_plan_id"], item["evidence_sha256"], tuple(tuple(value) for value in item["scores"]))
    return run_selector_suite(universe, observations, plan, expert_input=expert, fci_relation_scores=fci)


def write_selection_freeze_bundle(
    output: Path,
    selection: SelectionFreezeManifest,
    effective_config: Mapping[str, Any],
) -> dict[str, Any]:
    """Write an active schema-2.0 five-selector freeze."""

    return _write_selection_freeze_bundle(
        output,
        selection,
        effective_config,
        archival=False,
    )


def write_archival_selection_freeze_bundle(
    output: Path,
    selection: SelectionFreezeManifest,
    effective_config: Mapping[str, Any],
) -> dict[str, Any]:
    """Write a clearly marked schema-1.0 archival selector freeze."""

    return _write_selection_freeze_bundle(
        output,
        selection,
        effective_config,
        archival=True,
    )


def _write_selection_freeze_bundle(
    output: Path,
    selection: SelectionFreezeManifest,
    effective_config: Mapping[str, Any],
    *,
    archival: bool,
) -> dict[str, Any]:
    schema_version, _behavior_version = _selector_protocol(archival)
    _require_selector_protocol(selection.plan, archival=archival)
    config = _object(effective_config, "selector effective config")
    if config.get("schema_version") != schema_version:
        raise SelectorExperimentError("selector effective config uses the wrong protocol")

    write_bundle(output, {
        "effective-config.json": effective_config,
        "identity.json": {
            "schema_version": schema_version,
            "selection_id": selection.selection_id,
        },
        "selection.json": canonical_value(selection),
    })
    loaded = _load_selection_freeze_bundle(output, archival=archival)
    status = "ARCHIVAL_SELECTION_FREEZE_VERIFIED" if archival else "SELECTION_FREEZE_VERIFIED"
    return {"status": status, "selection_id": loaded.selection_id,
            "bundle_sha256": bundle_digest(output)}


def load_selection_freeze_bundle(root: Path) -> SelectionFreezeManifest:
    """Load and replay an active schema-2.0 selector freeze."""

    return _load_selection_freeze_bundle(root, archival=False)


def load_archival_selection_freeze_bundle(root: Path) -> SelectionFreezeManifest:
    """Load and replay a schema-1.0 archival selector freeze."""

    return _load_selection_freeze_bundle(root, archival=True)


def _load_selection_freeze_bundle(
    root: Path,
    *,
    archival: bool,
) -> SelectionFreezeManifest:
    manifest = verify_bundle(root)
    _exact_files(manifest, {"effective-config.json", "identity.json", "selection.json"}, "selection freeze")
    selection = _selection(_object(read_json(root / "selection.json"), "selection"))
    _require_selector_protocol(selection.plan, archival=archival)
    replay = _selection_from_config(
        _object(read_json(root / "effective-config.json"), "selector freeze config"),
        archival=archival,
    )
    if replay != selection:
        raise SelectorExperimentError("selection freeze does not replay from its stored inputs")
    identity = _object(read_json(root / "identity.json"), "selection identity")
    expected_schema, _expected_behavior = _selector_protocol(archival)
    if set(identity) != {"schema_version", "selection_id"} or identity.get("schema_version") != expected_schema or identity.get("selection_id") != selection.selection_id:
        raise SelectorExperimentError("selection freeze identity does not recompute")
    return selection


def verify_selection_freeze_bundle(root: Path) -> dict[str, Any]:
    selection = load_selection_freeze_bundle(root)
    return {"status": "SELECTION_FREEZE_VERIFIED", "selection_id": selection.selection_id,
            "bundle_sha256": bundle_digest(root)}


def verify_archival_selection_freeze_bundle(root: Path) -> dict[str, Any]:
    selection = load_archival_selection_freeze_bundle(root)
    return {"status": "ARCHIVAL_SELECTION_FREEZE_VERIFIED", "selection_id": selection.selection_id,
            "bundle_sha256": bundle_digest(root)}


def write_bridge_freeze_bundle(
    output: Path,
    selection_bundle: Path,
    bridge: SharedBridgeMap,
) -> dict[str, Any]:
    """Freeze an active schema-2.0 predecessor-bound bridge."""

    return _write_bridge_freeze_bundle(
        output,
        selection_bundle,
        bridge,
        archival=False,
    )


def write_archival_bridge_freeze_bundle(
    output: Path,
    selection_bundle: Path,
    bridge: SharedBridgeMap,
) -> dict[str, Any]:
    """Freeze a schema-1.0 bridge only for archival reproduction."""

    return _write_bridge_freeze_bundle(
        output,
        selection_bundle,
        bridge,
        archival=True,
    )


def _write_bridge_freeze_bundle(
    output: Path,
    selection_bundle: Path,
    bridge: SharedBridgeMap,
    *,
    archival: bool,
) -> dict[str, Any]:
    selection = _load_selection_freeze_bundle(selection_bundle, archival=archival)
    schema_version, _behavior_version = _selector_protocol(archival)
    if not archival:
        _validate_active_bridge_contract(selection, bridge)

    if bridge.selection_id != selection.selection_id:
        raise SelectorExperimentError("bridge does not bind the frozen selection")
    write_bundle(output, {
        "bridge.json": canonical_value(bridge),
        "lineage.json": {
            "schema_version": schema_version,
            "stage": "bridge_before_confirmation",
            "selection_id": selection.selection_id,
            "selection_bundle_sha256": bundle_digest(selection_bundle),
        },
    })
    loaded = _load_bridge_freeze_bundle(
        output,
        selection_bundle,
        archival=archival,
    )
    status = "ARCHIVAL_BRIDGE_FREEZE_VERIFIED" if archival else "BRIDGE_FREEZE_VERIFIED"
    return {"status": status, "bridge_map_id": loaded.bridge_map_id,
            "bundle_sha256": bundle_digest(output)}


def freeze_bridge_from_config(
    selection_bundle: Path,
    config_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Freeze active schema-2.0 protocolization decisions."""

    return _freeze_bridge_from_config(
        selection_bundle,
        config_path,
        output,
        archival=False,
    )


def freeze_archival_bridge_from_config(
    selection_bundle: Path,
    config_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Freeze schema-1.0 protocolization decisions for archival audit."""

    return _freeze_bridge_from_config(
        selection_bundle,
        config_path,
        output,
        archival=True,
    )


def _freeze_bridge_from_config(
    selection_bundle: Path,
    config_path: Path,
    output: Path,
    *,
    archival: bool,
) -> dict[str, Any]:
    selection = _load_selection_freeze_bundle(selection_bundle, archival=archival)
    expected_schema, _expected_behavior = _selector_protocol(archival)

    config = _object(read_json(config_path), "bridge freeze config")
    if set(config) != {"schema_version", "records"} or config.get("schema_version") != expected_schema:
        raise SelectorExperimentError("bridge freeze config fields are not exact")
    raw_records = _list(config["records"], "bridge records")
    for raw in raw_records:
        _exact_object(raw, {"candidate_id", "status", "final_hypothesis_id", "reason_code", "final_hypothesis"}, "bridge record")
    records = tuple(
        BridgeRecord(
            row["candidate_id"],
            BridgeStatus(row["status"]),
            row.get("final_hypothesis_id"),
            row.get("reason_code"),
            _hypothesis(_object(row["final_hypothesis"], "bridge final hypothesis"))
            if row.get("final_hypothesis") is not None else None,
        )
        for row in map(_object_row, raw_records)
    )
    bridge = freeze_shared_bridge_map(selection, records)
    return _write_bridge_freeze_bundle(
        output,
        selection_bundle,
        bridge,
        archival=archival,
    )


def load_bridge_freeze_bundle(root: Path, selection_bundle: Path) -> SharedBridgeMap:
    """Load and independently revalidate an active schema-2.0 bridge."""

    return _load_bridge_freeze_bundle(root, selection_bundle, archival=False)


def load_archival_bridge_freeze_bundle(
    root: Path,
    selection_bundle: Path,
) -> SharedBridgeMap:
    """Load a schema-1.0 archival bridge."""

    return _load_bridge_freeze_bundle(root, selection_bundle, archival=True)


def _load_bridge_freeze_bundle(
    root: Path,
    selection_bundle: Path,
    *,
    archival: bool,
) -> SharedBridgeMap:
    manifest = verify_bundle(root)
    _exact_files(manifest, {"bridge.json", "lineage.json"}, "bridge freeze")
    selection = _load_selection_freeze_bundle(selection_bundle, archival=archival)
    bridge = _bridge(_object(read_json(root / "bridge.json"), "bridge"))
    lineage = _object(read_json(root / "lineage.json"), "bridge lineage")
    expected_schema, _expected_behavior = _selector_protocol(archival)
    expected = {
        "schema_version": expected_schema,
        "stage": "bridge_before_confirmation",
        "selection_id": selection.selection_id,
        "selection_bundle_sha256": bundle_digest(selection_bundle),
    }
    if lineage != expected or bridge.selection_id != selection.selection_id:
        raise SelectorExperimentError("bridge freeze lineage does not recompute")
    if tuple(record.candidate_id for record in bridge.records) != selection.selected_union_candidate_ids:
        raise SelectorExperimentError("bridge freeze does not close the selected union")
    if not archival:
        _validate_active_bridge_contract(selection, bridge)
    return bridge


def verify_bridge_freeze_bundle(root: Path, selection_bundle: Path) -> dict[str, Any]:
    bridge = load_bridge_freeze_bundle(root, selection_bundle)
    return {"status": "BRIDGE_FREEZE_VERIFIED", "bridge_map_id": bridge.bridge_map_id,
            "bundle_sha256": bundle_digest(root)}


def verify_archival_bridge_freeze_bundle(
    root: Path,
    selection_bundle: Path,
) -> dict[str, Any]:
    bridge = load_archival_bridge_freeze_bundle(root, selection_bundle)
    return {"status": "ARCHIVAL_BRIDGE_FREEZE_VERIFIED", "bridge_map_id": bridge.bridge_map_id,
            "bundle_sha256": bundle_digest(root)}


def confirmation_coordinates_from_successor_bundles(
    selection: SelectionFreezeManifest,
    bridge: SharedBridgeMap,
    successor_bundles: Sequence[Path],
) -> tuple[ConfirmationCoordinate, ...]:
    """Derive coordinates only from independently verified secure-yield evidence."""

    if not successor_bundles:
        raise SelectorExperimentError("at least one successor result bundle is required")
    successful = {record.final_hypothesis_id for record in bridge.records if record.status is BridgeStatus.SUCCESS}
    coordinates: list[ConfirmationCoordinate] = []
    frozen_hypotheses: set[str] = set()
    for root in successor_bundles:
        verify_successor_result_bundle(root)
        study = _object(read_json(root / "study-freeze.json"), "successor study")
        if (study.get("candidate_universe_manifest_id") != selection.universe.manifest_id
                or study.get("selection_freeze_manifest_id") != selection.selection_id):
            raise SelectorExperimentError("successor result does not bind the selector freeze")
        source_hypotheses = {
            content_id("frozen_hypothesis_v2_", _object(item, "successor hypothesis"))
            for item in _list(study.get("hypotheses"), "successor hypotheses")
        }
        if frozen_hypotheses & source_hypotheses:
            raise SelectorExperimentError("successor bundles contain invalid or duplicate frozen hypotheses")
        frozen_hypotheses.update(source_hypotheses)
        minimum = _object(study.get("analysis_plan"), "successor analysis plan").get("minimum_task_units")
        if type(minimum) is not int or minimum < 2:
            raise SelectorExperimentError("successor minimum task-unit support is invalid")
        inference = _object(_object(read_json(root / "analysis.json"), "successor analysis").get("inference"), "successor inference")
        for raw in _list(inference.get("estimates"), "successor estimates"):
            estimate = _object(raw, "successor estimate")
            if estimate.get("metric") != "secure_yield" or estimate.get("model_id") != selection.plan.model_id:
                continue
            hypothesis_id = estimate.get("hypothesis_id")
            if hypothesis_id not in successful:
                continue
            direction = {"increase": 1, "decrease": -1}.get(estimate.get("expected_direction"))
            if direction is None:
                raise SelectorExperimentError("successor expected direction is invalid")
            effects = []
            for raw_unit in _list(estimate.get("task_unit_contributions"), "task-unit contributions"):
                unit = _object(raw_unit, "task-unit contribution")
                values = _list(unit.get("contrast_values"), "task-unit contrasts")
                matches = [value for value in values if isinstance(value, list) and len(value) == 4 and value[0] == "target_minus_noop"]
                if len(matches) != 1 or type(matches[0][1]) not in {int, float}:
                    raise SelectorExperimentError("secure-yield Target-Noop contribution is unavailable")
                effects.append((unit.get("task_unit_id"), float(matches[0][1])))
            coordinates.append(ConfirmationCoordinate(
                hypothesis_id, estimate["model_id"], direction,
                tuple(sorted(effects)), minimum, True,
            ))
    frozen = tuple(sorted(coordinates, key=lambda item: item.coordinate_id))
    if len({item.coordinate_id for item in frozen}) != len(frozen):
        raise SelectorExperimentError("successor bundles contain duplicate confirmation coordinates")
    if frozen_hypotheses != successful:
        raise SelectorExperimentError("successor frozen hypotheses do not exactly equal successful bridges")
    if {item.final_hypothesis_id for item in frozen} != successful:
        raise SelectorExperimentError("verified successor evidence does not close every successful bridge")
    return frozen


def run_selector_experiment(
    selection_bundle: Path,
    bridge_bundle: Path,
    successor_bundles: Sequence[Path],
    plan: SelectorInferencePlan,
    output: Path,
) -> dict[str, Any]:
    selection = load_selection_freeze_bundle(selection_bundle)
    bridge = load_bridge_freeze_bundle(bridge_bundle, selection_bundle)
    coordinates = confirmation_coordinates_from_successor_bundles(selection, bridge, successor_bundles)
    result = evaluate_selector_study(selection, bridge, coordinates, plan)
    verification = verify_selector_result(selection, bridge, coordinates, plan, result)
    roots = tuple(Path(path).resolve() for path in successor_bundles)
    artifact_parent = Path(output).resolve().parent
    write_bundle(output, {
        "coordinates.json": canonical_value(coordinates),
        "lineage.json": {
            "schema_version": "1.0",
            "selection_bundle_path": _portable_path(selection_bundle, artifact_parent),
            "selection_bundle_sha256": bundle_digest(selection_bundle),
            "bridge_bundle_path": _portable_path(bridge_bundle, artifact_parent),
            "bridge_bundle_sha256": bundle_digest(bridge_bundle),
            "successor_bundles": [
                {"path": _portable_path(path, artifact_parent), "bundle_sha256": bundle_digest(path)} for path in roots
            ],
        },
        "plan.json": canonical_value(plan),
        "result.json": canonical_value(result),
        "verification.json": verification,
    })
    stored = verify_selector_experiment_bundle(output)
    return {**stored, "result_id": result.result_id}


def run_selector_experiment_from_config(
    selection_bundle: Path,
    bridge_bundle: Path,
    successor_bundles: Sequence[Path],
    plan_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Load one exact inference-plan JSON and run the frozen selector study."""

    value = _object(read_json(plan_path), "selector inference config")
    if set(value) != {"schema_version", "plan"} or value.get("schema_version") != "1.0":
        raise SelectorExperimentError("selector inference config fields are not exact")
    plan = _inference_plan(_object(value["plan"], "selector inference plan"))
    return run_selector_experiment(
        selection_bundle,
        bridge_bundle,
        successor_bundles,
        plan,
        output,
    )


def verify_selector_experiment_bundle(root: Path) -> dict[str, Any]:
    """Reconstruct all typed inputs and independently replay a stored result."""

    manifest = verify_bundle(root)
    _exact_files(manifest, {"coordinates.json", "lineage.json", "plan.json", "result.json", "verification.json"}, "selector result")
    lineage = _object(read_json(root / "lineage.json"), "selector lineage")
    _require_exact_keys(
        lineage,
        {
            "schema_version",
            "selection_bundle_path",
            "selection_bundle_sha256",
            "bridge_bundle_path",
            "bridge_bundle_sha256",
            "successor_bundles",
        },
        "selector lineage",
    )
    if lineage["schema_version"] != "1.0":
        raise SelectorExperimentError("selector result lineage schema is unsupported")
    selection_path = _stored_path(lineage["selection_bundle_path"], root.resolve().parent)
    bridge_path = _stored_path(lineage["bridge_bundle_path"], root.resolve().parent)
    selection = load_selection_freeze_bundle(selection_path)
    if bundle_digest(selection_path) != lineage.get("selection_bundle_sha256"):
        raise SelectorExperimentError("stored selection bundle was replaced")
    bridge = load_bridge_freeze_bundle(bridge_path, selection_path)
    if bundle_digest(bridge_path) != lineage.get("bridge_bundle_sha256"):
        raise SelectorExperimentError("stored bridge bundle was replaced")
    raw_sources = _list(lineage.get("successor_bundles"), "successor lineage")
    source_paths = []
    seen = set()
    for raw in raw_sources:
        item = _exact_object(
            raw,
            {"path", "bundle_sha256"},
            "successor lineage item",
        )
        path = _stored_path(item["path"], root.resolve().parent)
        digest = bundle_digest(path)
        if digest != item["bundle_sha256"] or digest in seen:
            raise SelectorExperimentError("stored successor bundle is missing, duplicated, or replaced")
        seen.add(digest)
        source_paths.append(path)
    derived = confirmation_coordinates_from_successor_bundles(selection, bridge, source_paths)
    stored_coordinates = tuple(_coordinate(_object(value, "coordinate")) for value in _list(read_json(root / "coordinates.json"), "coordinates"))
    if stored_coordinates != derived:
        raise SelectorExperimentError("stored confirmation coordinates do not rederive")
    plan = _inference_plan(_object(read_json(root / "plan.json"), "selector inference plan"))
    result = _result(_object(read_json(root / "result.json"), "selector result"))
    verified = verify_selector_result(selection, bridge, derived, plan, result)
    if read_json(root / "verification.json") != verified:
        raise SelectorExperimentError("stored selector verification was replaced")
    return {**verified, "status": "SELECTOR_RESULT_BUNDLE_VERIFIED", "bundle_sha256": bundle_digest(root)}


def run_representation_comparison_from_config(
    config_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Compare direct and context-conditioned universes as an end-to-end RQ2 track."""

    config_file = config_path.resolve()
    config = _representation_config(read_json(config_file))
    artifact_parent = output.resolve().parent
    lineage: dict[str, Any] = {"schema_version": "1.0", "tracks": {}}
    summaries = {}
    for role in ("direct", "direct_context"):
        item = config[role]
        source = _resolve_config_path(item["result_path"], config_file.parent)
        digest = bundle_digest(source)
        if digest != item["result_bundle_sha256"]:
            raise SelectorExperimentError("representation source result bundle drift")
        summaries[role] = _representation_summary(
            source,
            role=role,
            expected_adapter_id=item["representation_adapter_id"],
        )
        lineage["tracks"][role] = {
            "result_path": _portable_path(source, artifact_parent),
            "result_bundle_sha256": digest,
            "representation_adapter_id": item["representation_adapter_id"],
        }
    report = _representation_report(summaries)
    write_bundle(output, {"lineage.json": lineage, "report.json": report})
    verified = verify_representation_comparison_bundle(output)
    return {**verified, **report}


def verify_representation_comparison_bundle(root: Path) -> dict[str, Any]:
    """Replay both complete selector funnels and recompute the descriptive RQ2 comparison."""

    manifest = verify_bundle(root)
    _exact_files(manifest, {"lineage.json", "report.json"}, "representation comparison")
    lineage = _exact_object(
        read_json(root / "lineage.json"),
        {"schema_version", "tracks"},
        "representation comparison lineage",
    )
    if lineage["schema_version"] != "1.0":
        raise SelectorExperimentError("representation comparison schema is invalid")
    tracks = _object(lineage["tracks"], "representation tracks")
    _require_exact_keys(tracks, {"direct", "direct_context"}, "representation tracks")
    summaries = {}
    for role in ("direct", "direct_context"):
        item = _exact_object(
            tracks[role],
            {"result_path", "result_bundle_sha256", "representation_adapter_id"},
            "representation track lineage",
        )
        source = _stored_path(item["result_path"], root.resolve().parent)
        if bundle_digest(source) != item["result_bundle_sha256"]:
            raise SelectorExperimentError("stored representation source was replaced")
        summaries[role] = _representation_summary(
            source,
            role=role,
            expected_adapter_id=item["representation_adapter_id"],
        )
    report = _representation_report(summaries)
    if read_json(root / "report.json") != report:
        raise SelectorExperimentError("representation comparison report does not recompute")
    return {
        "status": "REPRESENTATION_COMPARISON_BUNDLE_VERIFIED",
        "bundle_sha256": bundle_digest(root),
    }


def _representation_config(value: Any) -> dict[str, Any]:
    config = _exact_object(
        value,
        {"schema_version", "direct", "direct_context"},
        "representation comparison config",
    )
    if config["schema_version"] != "1.0":
        raise SelectorExperimentError("representation comparison config schema is invalid")
    for role in ("direct", "direct_context"):
        item = _exact_object(
            config[role],
            {"result_path", "result_bundle_sha256", "representation_adapter_id"},
            "representation comparison source",
        )
        if any(not isinstance(item[name], str) or not item[name].strip() for name in (
            "result_path", "representation_adapter_id"
        )):
            raise SelectorExperimentError("representation comparison source is invalid")
        _require_digest(item["result_bundle_sha256"], "representation result bundle")
    if (
        config["direct"]["representation_adapter_id"]
        == config["direct_context"]["representation_adapter_id"]
    ):
        raise SelectorExperimentError("representation tracks must use different adapters")
    return config


def _representation_summary(
    result_root: Path,
    *,
    role: str,
    expected_adapter_id: str,
) -> dict[str, Any]:
    verify_selector_experiment_bundle(result_root)
    lineage = _object(read_json(result_root / "lineage.json"), "selector lineage")
    selection_path = _stored_path(
        lineage["selection_bundle_path"], result_root.resolve().parent
    )
    bridge_path = _stored_path(lineage["bridge_bundle_path"], result_root.resolve().parent)
    selection = load_selection_freeze_bundle(selection_path)
    bridge = load_bridge_freeze_bundle(bridge_path, selection_path)
    result = _result(_object(read_json(result_root / "result.json"), "selector result"))
    if selection.universe.representation_adapter_id != expected_adapter_id:
        raise SelectorExperimentError("representation adapter identity drift")
    successful = tuple(
        record for record in bridge.records if record.status is BridgeStatus.SUCCESS
    )
    confirmed = tuple(
        item.final_hypothesis_id for item in result.confirmation_statuses if item.confirmed
    )
    candidate_total = len(selection.universe.candidate_ids)
    supported_total = len(selection.universe.supported_candidate_ids)
    selected_total = len(selection.selected_union_candidate_ids)
    effects = [
        {
            "final_hypothesis_id": item.final_hypothesis_id,
            "model_id": item.model_id,
            "point": item.point,
            "adjusted_lower": item.adjusted_lower,
            "adjusted_upper": item.adjusted_upper,
            "confirmed": item.confirmed,
        }
        for item in result.confirmation_statuses
    ]
    strict_yield = [
        {
            "selector_id": item.selector_id,
            "model_id": item.model_id,
            "confirmed_yield_at_k": item.confirmed_yield,
        }
        for item in result.method_points
    ]
    return {
        "role": role,
        "representation_adapter_id": expected_adapter_id,
        "model_id": selection.plan.model_id,
        "outcome_id": selection.universe.outcome_id,
        "top_k": selection.universe.top_k,
        "candidate_total": candidate_total,
        "supported_candidate_total": supported_total,
        "candidate_coverage": supported_total / candidate_total if candidate_total else 0.0,
        "selected_union_total": selected_total,
        "protocolized_success_total": len(successful),
        "protocolization_rate": len(successful) / selected_total if selected_total else 0.0,
        "unique_confirmed_hypothesis_ids": sorted(set(confirmed)),
        "strict_confirmed_yield_at_k": strict_yield,
        "effect_distribution": effects,
    }


def _representation_report(summaries: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    direct = summaries["direct"]
    contextual = summaries["direct_context"]
    for field in ("model_id", "outcome_id", "top_k"):
        if direct[field] != contextual[field]:
            raise SelectorExperimentError(
                "representation tracks do not share the frozen comparison contract"
            )
    direct_yield = {
        (item["selector_id"], item["model_id"]): item["confirmed_yield_at_k"]
        for item in direct["strict_confirmed_yield_at_k"]
    }
    contextual_yield = {
        (item["selector_id"], item["model_id"]): item["confirmed_yield_at_k"]
        for item in contextual["strict_confirmed_yield_at_k"]
    }
    if set(direct_yield) != set(contextual_yield):
        raise SelectorExperimentError("representation tracks expose different selector summaries")
    return {
        "schema_version": "1.0",
        "status": "REPRESENTATION_COMPARISON_COMPLETE",
        "interpretation": "end_to_end_representation_comparison_not_pure_selector",
        "shared_contract": {
            "model_id": direct["model_id"],
            "outcome_id": direct["outcome_id"],
            "top_k": direct["top_k"],
        },
        "tracks": {"direct": direct, "direct_context": contextual},
        "differences_direct_context_minus_direct": {
            "candidate_coverage": contextual["candidate_coverage"]
            - direct["candidate_coverage"],
            "protocolization_rate": contextual["protocolization_rate"]
            - direct["protocolization_rate"],
            "unique_confirmed_hypotheses": len(
                contextual["unique_confirmed_hypothesis_ids"]
            )
            - len(direct["unique_confirmed_hypothesis_ids"]),
            "strict_confirmed_yield_at_k": [
                {
                    "selector_id": selector_id,
                    "model_id": model_id,
                    "difference": contextual_yield[(selector_id, model_id)]
                    - direct_yield[(selector_id, model_id)],
                }
                for selector_id, model_id in sorted(direct_yield)
            ],
        },
    }


def _resolve_config_path(value: str, parent: Path) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (parent / path).resolve()


def _selection(value: Mapping[str, Any]) -> SelectionFreezeManifest:
    _require_exact_keys(
        value,
        {
            "universe",
            "plan",
            "runs",
            "selected_union_candidate_ids",
            "gate_failure_reason",
            "sensitivity_audit",
            "fci_background_knowledge_audit_json",
        },
        "selection",
    )
    universe = _object(value["universe"], "candidate universe")
    plan = _object(value["plan"], "selector suite plan")
    runs = tuple(_selector_run(_object(item, "selector run")) for item in _list(value["runs"], "selector runs"))
    sensitivity = None
    if value["sensitivity_audit"] is not None:
        item = _object(value["sensitivity_audit"], "selector sensitivity audit")
        _require_exact_keys(
            item,
            {
                "fixed_reference_observation_sha256",
                "two_level_seeds",
                "common_request_randomness_slots",
                "rankings",
                "top_k_stability",
                "multi_slot_task_means",
            },
            "selector sensitivity audit",
        )
        rankings = tuple(
            SelectorSensitivityRanking(
                row["analysis"],
                row["replicate"],
                row["selector_id"],
                row["ranking_label"],
                tuple(row["ordered_candidate_ids"]),
            )
            for row in (
                _exact_object(
                    raw,
                    {
                        "analysis",
                        "replicate",
                        "selector_id",
                        "ranking_label",
                        "ordered_candidate_ids",
                    },
                    "selector sensitivity ranking",
                )
                for raw in _list(item["rankings"], "selector sensitivity rankings")
            )
        )
        sensitivity = SelectorSensitivityAudit(
            item["fixed_reference_observation_sha256"], tuple(item["two_level_seeds"]),
            tuple(item["common_request_randomness_slots"]),
            rankings,
            tuple(tuple(row) for row in item["top_k_stability"]),
            tuple((row[0], tuple(tuple(value) for value in row[1]), row[2]) for row in item["multi_slot_task_means"]),
        )
    return SelectionFreezeManifest(
        _universe(universe), _suite_plan(plan),
        runs, tuple(value["selected_union_candidate_ids"]), value["gate_failure_reason"],
        sensitivity, value["fci_background_knowledge_audit_json"],
    )


def _universe(value: Mapping[str, Any]) -> CandidateUniverseManifest:
    _require_exact_keys(value, {"source_universe_id", "candidate_ids", "supported_candidate_ids", "realization_policy_ids", "candidate_family_ids", "discovery_data_sha256", "positivity_audit_sha256", "information_budget_sha256", "outcome_id", "top_k", "representation_adapter_id", "candidate_skeletons"}, "candidate universe")
    skeletons = []
    for candidate_id, raw in value["candidate_skeletons"]:
        item = _exact_object(raw, {"candidate_key", "context_query_id", "actionable_feature_ids", "operation", "cwe", "archetype", "outcome_id", "expected_direction", "realization_policy_id"}, "candidate skeleton")
        skeletons.append((candidate_id, CandidateSkeletonV2(
            item["candidate_key"], item["context_query_id"], tuple(item["actionable_feature_ids"]),
            Operation(item["operation"]), item["cwe"], item["archetype"], item["outcome_id"],
            ExpectedDirection(item["expected_direction"]), item["realization_policy_id"],
        )))
    return CandidateUniverseManifest(value["source_universe_id"], tuple(value["candidate_ids"]), tuple(value["supported_candidate_ids"]), tuple(tuple(item) for item in value["realization_policy_ids"]), tuple(tuple(item) for item in value["candidate_family_ids"]), value["discovery_data_sha256"], value["positivity_audit_sha256"], value["information_budget_sha256"], value["outcome_id"], value["top_k"], value["representation_adapter_id"], tuple(skeletons))


def _suite_plan(value: Mapping[str, Any]) -> SelectorSuitePlan:
    _require_exact_keys(value, {"model_id", "ridge_lambda", "prediction_folds", "random_seeds", "fci_alpha", "fci_backend_version", "fci_ci_test", "fci_bootstrap_draws", "fci_depth", "fci_max_path_length", "behavior_version", "fci_background_knowledge", "fci_wrong_bk_perturbation"}, "selector suite plan")
    def rules(name):
        return tuple(
            BackgroundKnowledgeRule(item["rule_id"], item["scope_family_id"], item["bk_family_id"], item["provenance_class"], item["forbidden_from"], item["forbidden_to"])
            for item in (
                _exact_object(raw, {"rule_id", "scope_family_id", "bk_family_id", "provenance_class", "forbidden_from", "forbidden_to"}, "BK rule")
                for raw in value[name]
            )
        )
    return SelectorSuitePlan(value["model_id"], value["ridge_lambda"], value["prediction_folds"], tuple(value["random_seeds"]), value["fci_alpha"], value["fci_backend_version"], value["fci_ci_test"], value["fci_bootstrap_draws"], value["fci_depth"], value["fci_max_path_length"], value["behavior_version"], rules("fci_background_knowledge"), rules("fci_wrong_bk_perturbation"))


def _selector_run(value: Mapping[str, Any]) -> SelectorRun:
    _require_exact_keys(
        value,
        {
            "kind",
            "selector_id",
            "model_id",
            "universe_manifest_id",
            "discovery_data_sha256",
            "plan_id",
            "status",
            "rankings",
            "failures",
        },
        "selector run",
    )
    rankings = []
    for raw in _list(value["rankings"], "selector rankings"):
        item = _exact_object(
            raw,
            {"label", "seed", "scores", "slots", "evidence_sha256"},
            "selector ranking",
        )
        scores = tuple(
            RankedCandidate(row["candidate_id"], row["score"], row["rank"])
            for row in (
                _exact_object(
                    score,
                    {"candidate_id", "score", "rank"},
                    "ranked candidate",
                )
                for score in _list(item["scores"], "ranked candidates")
            )
        )
        slots = tuple(
            SelectorSlot(
                row["rank"],
                SlotStatus(row["status"]),
                row["candidate_id"],
                row["reason_code"],
            )
            for row in (
                _exact_object(
                    slot,
                    {"rank", "status", "candidate_id", "reason_code"},
                    "selector slot",
                )
                for slot in _list(item["slots"], "selector slots")
            )
        )
        rankings.append(SelectorRanking(item["label"], item["seed"], scores, slots, item["evidence_sha256"]))
    failures = tuple(
        SelectorFailure(row["reason_code"], row["detail"], row["candidate_id"])
        for row in (
            _exact_object(
                failure,
                {"reason_code", "detail", "candidate_id"},
                "selector failure",
            )
            for failure in _list(value["failures"], "selector failures")
        )
    )
    return SelectorRun(SelectorKind(value["kind"]), value["selector_id"], value["model_id"], value["universe_manifest_id"], value["discovery_data_sha256"], value["plan_id"], SelectorRunStatus(value["status"]), tuple(rankings), failures)


def _bridge(value: Mapping[str, Any]) -> SharedBridgeMap:
    _require_exact_keys(value, {"selection_id", "records"}, "bridge")
    records = tuple(
        BridgeRecord(
            row["candidate_id"],
            BridgeStatus(row["status"]),
            row["final_hypothesis_id"],
            row["reason_code"],
            _hypothesis(_object(row["final_hypothesis"], "bridge final hypothesis"))
            if row["final_hypothesis"] is not None
            else None,
        )
        for row in (
            _exact_object(
                raw,
                {
                    "candidate_id",
                    "status",
                    "final_hypothesis_id",
                    "reason_code",
                    "final_hypothesis",
                },
                "bridge record",
            )
            for raw in _list(value["records"], "bridge records")
        )
    )
    return SharedBridgeMap(value["selection_id"], records)


def _hypothesis(value: Mapping[str, Any]) -> FrozenHypothesisV2:
    _require_exact_keys(value, {"skeleton", "target_spec"}, "bridge final hypothesis")
    skeleton_raw = _object(value["skeleton"], "bridge candidate skeleton")
    target = _object(value["target_spec"], "bridge target spec")
    _require_exact_keys(
        skeleton_raw,
        {
            "candidate_key",
            "context_query_id",
            "actionable_feature_ids",
            "operation",
            "cwe",
            "archetype",
            "outcome_id",
            "expected_direction",
            "realization_policy_id",
        },
        "bridge candidate skeleton",
    )
    _require_exact_keys(
        target,
        {
            "candidate_skeleton_id",
            "context_query_id",
            "actionable_feature_id",
            "operation",
            "context_query_catalog_sha256",
            "feature_catalog_sha256",
            "allowed_delta_policy_sha256",
        },
        "bridge target spec",
    )
    skeleton = CandidateSkeletonV2(
        skeleton_raw["candidate_key"], skeleton_raw["context_query_id"], tuple(skeleton_raw["actionable_feature_ids"]),
        Operation(skeleton_raw["operation"]), skeleton_raw["cwe"], skeleton_raw["archetype"], skeleton_raw["outcome_id"],
        ExpectedDirection(skeleton_raw["expected_direction"]), skeleton_raw["realization_policy_id"],
    )
    return FrozenHypothesisV2(skeleton, TargetSpecV2(
        target["candidate_skeleton_id"], target["context_query_id"], target["actionable_feature_id"],
        Operation(target["operation"]), target["context_query_catalog_sha256"], target["feature_catalog_sha256"],
        target["allowed_delta_policy_sha256"],
    ))


def _coordinate(value: Mapping[str, Any]) -> ConfirmationCoordinate:
    _require_exact_keys(
        value,
        {
            "final_hypothesis_id",
            "model_id",
            "expected_direction",
            "task_unit_effects",
            "minimum_task_units",
            "provenance_complete",
        },
        "confirmation coordinate",
    )
    return ConfirmationCoordinate(value["final_hypothesis_id"], value["model_id"], value["expected_direction"], tuple((item[0], item[1]) for item in value["task_unit_effects"]), value["minimum_task_units"], value["provenance_complete"])


def _inference_plan(value: Mapping[str, Any]) -> SelectorInferencePlan:
    _require_exact_keys(
        value,
        {
            "bootstrap_seed",
            "inner_draws",
            "outer_draws",
            "alpha",
            "minimum_valid_fraction",
            "selector_pairs",
        },
        "selector inference plan",
    )
    return SelectorInferencePlan(value["bootstrap_seed"], value["inner_draws"], value["outer_draws"], value["alpha"], value["minimum_valid_fraction"], tuple(tuple(item) for item in value["selector_pairs"]))


def _result(value: Mapping[str, Any]) -> SelectorInferenceResult:
    _require_exact_keys(
        value,
        {
            "plan_id",
            "selection_id",
            "bridge_map_id",
            "confirmation_input_sha256",
            "primary_critical_value",
            "primary_valid_draws",
            "primary_invalid_draws",
            "confirmation_statuses",
            "yield_points",
            "method_points",
            "pair_points",
            "selector_pair_critical_value",
            "pair_intervals",
            "valid_outer_draws",
            "invalid_outer_draws",
            "outer_pair_draws_sha256",
            "pair_inference_status",
        },
        "selector result",
    )
    statuses = tuple(
        ConfirmationStatus(
            row["final_hypothesis_id"],
            row["model_id"],
            row["point"],
            row["standard_error"],
            row["adjusted_lower"],
            row["adjusted_upper"],
            row["oriented_adjusted_lower"],
            row["task_units"],
            row["provenance_complete"],
            row["confirmed"],
        )
        for row in (
            _exact_object(
                raw,
                {
                    "final_hypothesis_id",
                    "model_id",
                    "point",
                    "standard_error",
                    "adjusted_lower",
                    "adjusted_upper",
                    "oriented_adjusted_lower",
                    "task_units",
                    "provenance_complete",
                    "confirmed",
                },
                "confirmation status",
            )
            for raw in _list(value["confirmation_statuses"], "confirmation statuses")
        )
    )
    yields = []
    for item in (
        _exact_object(
            raw,
            {
                "selector_id",
                "ranking_id",
                "model_id",
                "budget_k",
                "confirmed_slots",
                "confirmed_yield",
                "slot_contributions",
            },
            "selector yield point",
        )
        for raw in _list(value["yield_points"], "selector yield points")
    ):
        contributions = tuple(
            SlotContribution(
                row["selector_id"],
                row["ranking_id"],
                row["rank"],
                SlotStatus(row["slot_status"]),
                row["candidate_id"],
                row["final_hypothesis_id"],
                row["confirmed_contribution"],
                row["reason_code"],
            )
            for row in (
                _exact_object(
                    raw,
                    {
                        "selector_id",
                        "ranking_id",
                        "rank",
                        "slot_status",
                        "candidate_id",
                        "final_hypothesis_id",
                        "confirmed_contribution",
                        "reason_code",
                    },
                    "selector slot contribution",
                )
                for raw in _list(item["slot_contributions"], "selector slot contributions")
            )
        )
        yields.append(SelectorYieldPoint(item["selector_id"], item["ranking_id"], item["model_id"], item["budget_k"], item["confirmed_slots"], item["confirmed_yield"], contributions))
    method_points = tuple(
        SelectorMethodPoint(
            row["selector_id"],
            row["model_id"],
            row["ranking_count"],
            row["confirmed_yield"],
        )
        for row in (
            _exact_object(
                raw,
                {"selector_id", "model_id", "ranking_count", "confirmed_yield"},
                "selector method point",
            )
            for raw in _list(value["method_points"], "selector method points")
        )
    )
    pair_points = tuple(
        SelectorPairPoint(
            row["pair_id"],
            row["left_selector_id"],
            row["right_selector_id"],
            row["difference"],
        )
        for row in (
            _exact_object(
                raw,
                {"pair_id", "left_selector_id", "right_selector_id", "difference"},
                "selector pair point",
            )
            for raw in _list(value["pair_points"], "selector pair points")
        )
    )
    pair_intervals = tuple(
        SelectorPairInterval(
            row["pair_id"],
            row["standard_error"],
            row["lower"],
            row["upper"],
        )
        for row in (
            _exact_object(
                raw,
                {"pair_id", "standard_error", "lower", "upper"},
                "selector pair interval",
            )
            for raw in _list(value["pair_intervals"], "selector pair intervals")
        )
    )
    return SelectorInferenceResult(
        value["plan_id"], value["selection_id"], value["bridge_map_id"], value["confirmation_input_sha256"], value["primary_critical_value"], value["primary_valid_draws"], value["primary_invalid_draws"], statuses, tuple(yields),
        method_points, pair_points, value["selector_pair_critical_value"], pair_intervals, value["valid_outer_draws"], value["invalid_outer_draws"], value["outer_pair_draws_sha256"], value["pair_inference_status"],
    )


def _selector_protocol(archival: bool) -> tuple[str, str]:
    if archival:
        return ARCHIVAL_SELECTOR_SCHEMA_VERSION, ARCHIVAL_SELECTOR_BEHAVIOR_VERSION
    return ACTIVE_SELECTOR_SCHEMA_VERSION, ACTIVE_SELECTOR_BEHAVIOR_VERSION


def _require_selector_protocol(
    plan: SelectorSuitePlan,
    *,
    archival: bool,
) -> None:
    _schema_version, expected_behavior = _selector_protocol(archival)
    if plan.behavior_version != expected_behavior:
        boundary = "archival" if archival else "active"
        raise SelectorExperimentError(
            f"{boundary} selector requires behavior_version {expected_behavior}"
        )


def _validate_active_bridge_contract(
    selection: SelectionFreezeManifest,
    bridge: SharedBridgeMap,
) -> None:
    """Rebind every v2 success to its exact frozen predecessor skeleton."""

    _require_selector_protocol(selection.plan, archival=False)
    skeleton_by_candidate = dict(selection.universe.candidate_skeletons)
    if set(skeleton_by_candidate) != set(selection.universe.candidate_ids):
        raise SelectorExperimentError("candidate skeleton table is not closed")
    for record in bridge.records:
        if record.candidate_id not in skeleton_by_candidate:
            raise SelectorExperimentError("bridge references an unknown candidate")
        if record.status is not BridgeStatus.SUCCESS:
            continue
        hypothesis = record.final_hypothesis
        predecessor = skeleton_by_candidate[record.candidate_id]
        if hypothesis is None or hypothesis.skeleton != predecessor:
            raise SelectorExperimentError(
                "prospective bridge final hypothesis does not preserve its predecessor skeleton"
            )
        target = hypothesis.target_spec
        if (
            target.candidate_skeleton_id != predecessor.candidate_skeleton_id
            or target.context_query_id != predecessor.context_query_id
            or target.actionable_feature_id != predecessor.actionable_feature_id
            or target.operation is not predecessor.operation
            or record.final_hypothesis_id != hypothesis.hypothesis_id
        ):
            raise SelectorExperimentError(
                "prospective bridge target or hypothesis identity drifts from its predecessor"
            )
    try:
        replay = freeze_shared_bridge_map(selection, bridge.records)
    except (TypeError, ValueError) as error:
        raise SelectorExperimentError(
            "prospective bridge contract does not independently replay"
        ) from error
    if replay != bridge:
        raise SelectorExperimentError("prospective bridge identity does not independently replay")


def _exact_files(manifest: Mapping[str, Any], names: set[str], label: str) -> None:
    if set(manifest.get("files", {})) != names:
        raise SelectorExperimentError(f"{label} artifact set is not exact")


def _portable_path(value: Path, artifact_parent: Path) -> str:
    path = Path(value).resolve()
    try:
        relative = path.relative_to(artifact_parent.resolve())
    except ValueError:
        raise SelectorExperimentError(
            "selector artifact inputs must remain beneath the result parent for portable replay"
        ) from None
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise SelectorExperimentError("selector artifact input path is not portable")
    return relative.as_posix()


def _stored_path(value: Any, artifact_parent: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise SelectorExperimentError("stored artifact path is invalid")
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise SelectorExperimentError("stored artifact path must be a confined relative path")
    path = (artifact_parent / relative).resolve()
    try:
        path.relative_to(artifact_parent.resolve())
    except ValueError:
        raise SelectorExperimentError("stored artifact path escapes its portable parent") from None
    return path


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SelectorExperimentError(f"{label} must be an object")
    return value


def _object_row(value: Any) -> dict[str, Any]:
    return _object(value, "stored row")


def _exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    item = _object(value, label)
    _require_exact_keys(item, keys, label)
    return item


def _require_exact_keys(value: Mapping[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise SelectorExperimentError(f"{label} fields are not exact")


def _require_digest(value: Any, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SelectorExperimentError(f"{label} digest is invalid")


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SelectorExperimentError(f"{label} must be a list")
    return value


__all__ = [
    "ACTIVE_SELECTOR_BEHAVIOR_VERSION",
    "ACTIVE_SELECTOR_SCHEMA_VERSION",
    "ARCHIVAL_SELECTOR_BEHAVIOR_VERSION",
    "ARCHIVAL_SELECTOR_SCHEMA_VERSION",
    "SelectorExperimentError",
    "build_active_selector_evidence",
    "confirmation_coordinates_from_successor_bundles",
    "freeze_archival_bridge_from_config",
    "freeze_archival_selection_from_config",
    "freeze_bridge_from_config",
    "freeze_selection_from_config",
    "load_archival_bridge_freeze_bundle",
    "load_archival_selection_freeze_bundle",
    "load_bridge_freeze_bundle",
    "load_selection_freeze_bundle",
    "run_representation_comparison_from_config",
    "run_selector_experiment",
    "verify_archival_bridge_freeze_bundle",
    "verify_archival_selection_freeze_bundle",
    "verify_bridge_freeze_bundle",
    "verify_representation_comparison_bundle",
    "verify_selection_freeze_bundle",
    "verify_selector_experiment_bundle",
    "write_archival_bridge_freeze_bundle",
    "write_archival_selection_freeze_bundle",
    "write_bridge_freeze_bundle",
    "write_selection_freeze_bundle",
]
