"""Outcome-blind selection and bridge freezing for the selector study."""

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
from prompt_mechanism_study.records import canonical_value, content_hash
from prompt_mechanism_study.representation import (
    CandidateSkeletonV2,
    ExpectedDirection,
    FrozenHypothesisV2,
    Operation,
    TargetSpecV2,
)


class SelectorExperimentError(ValueError):
    """A stored selector-study artifact failed closed."""


ACTIVE_SELECTOR_SCHEMA_VERSION = "2.0"
ACTIVE_SELECTOR_BEHAVIOR_VERSION = "shared-selector-suite-v2"


def freeze_selection_from_config(config_path: Path, output: Path) -> dict[str, Any]:
    """Freeze the active prospective selector protocol (schema 2.0 only)."""

    config = _object(read_json(config_path), "selector freeze config")
    selection = _selection_from_config(config)
    return write_selection_freeze_bundle(output, selection, config)


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


def _selection_from_config(config: Mapping[str, Any]) -> SelectionFreezeManifest:
    expected = {
        "schema_version",
        "universe",
        "observations",
        "plan",
        "expert_input",
        "fci_relation_scores",
    }
    expected |= {"support_audit", "information_budget", "discovery_evidence"}
    if (
        set(config) != expected
        or config.get("schema_version") != ACTIVE_SELECTOR_SCHEMA_VERSION
    ):
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
    information_budget = _validate_active_selector_evidence(
        universe,
        observations,
        config["support_audit"],
        config["information_budget"],
        config["discovery_evidence"],
    )
    plan = _suite_plan(_object(config["plan"], "selector suite plan"))
    _require_selector_protocol(plan)
    expert = None
    if config["expert_input"] is not None:
        item = _exact_object(config["expert_input"], {"universe_manifest_id", "model_id", "candidate_card_sha256", "ranked_candidate_ids", "identity_blinded", "confirm_outcomes_visible"}, "expert input")
        if item["candidate_card_sha256"] != content_hash(
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

    _require_selector_protocol(selection.plan)
    config = _object(effective_config, "selector effective config")
    if config.get("schema_version") != ACTIVE_SELECTOR_SCHEMA_VERSION:
        raise SelectorExperimentError("selector effective config uses the wrong protocol")

    write_bundle(output, {
        "effective-config.json": effective_config,
        "identity.json": {
            "schema_version": ACTIVE_SELECTOR_SCHEMA_VERSION,
            "selection_id": selection.selection_id,
        },
        "selection.json": canonical_value(selection),
    })
    loaded = load_selection_freeze_bundle(output)
    return {"status": "SELECTION_FREEZE_VERIFIED", "selection_id": loaded.selection_id,
            "bundle_sha256": bundle_digest(output)}


def load_selection_freeze_bundle(root: Path) -> SelectionFreezeManifest:
    """Load and replay an active schema-2.0 selector freeze."""

    manifest = verify_bundle(root)
    _exact_files(manifest, {"effective-config.json", "identity.json", "selection.json"}, "selection freeze")
    selection = selection_from_record(
        _object(read_json(root / "selection.json"), "selection")
    )
    _require_selector_protocol(selection.plan)
    replay = _selection_from_config(
        _object(read_json(root / "effective-config.json"), "selector freeze config"),
    )
    if replay != selection:
        raise SelectorExperimentError("selection freeze does not replay from its stored inputs")
    identity = _object(read_json(root / "identity.json"), "selection identity")
    if set(identity) != {"schema_version", "selection_id"} or identity.get("schema_version") != ACTIVE_SELECTOR_SCHEMA_VERSION or identity.get("selection_id") != selection.selection_id:
        raise SelectorExperimentError("selection freeze identity does not recompute")
    return selection


def verify_selection_freeze_bundle(root: Path) -> dict[str, Any]:
    selection = load_selection_freeze_bundle(root)
    return {"status": "SELECTION_FREEZE_VERIFIED", "selection_id": selection.selection_id,
            "bundle_sha256": bundle_digest(root)}


def write_bridge_freeze_bundle(
    output: Path,
    selection_bundle: Path,
    bridge: SharedBridgeMap,
) -> dict[str, Any]:
    """Freeze an active schema-2.0 predecessor-bound bridge."""

    selection = load_selection_freeze_bundle(selection_bundle)
    _validate_active_bridge_contract(selection, bridge)

    if bridge.selection_id != selection.selection_id:
        raise SelectorExperimentError("bridge does not bind the frozen selection")
    write_bundle(output, {
        "bridge.json": canonical_value(bridge),
        "lineage.json": {
            "schema_version": ACTIVE_SELECTOR_SCHEMA_VERSION,
            "stage": "bridge_before_confirmation",
            "selection_id": selection.selection_id,
            "selection_bundle_sha256": bundle_digest(selection_bundle),
        },
    })
    loaded = load_bridge_freeze_bundle(output, selection_bundle)
    return {"status": "BRIDGE_FREEZE_VERIFIED", "bridge_map_id": loaded.bridge_map_id,
            "bundle_sha256": bundle_digest(output)}


def freeze_bridge_from_config(
    selection_bundle: Path,
    config_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Freeze active schema-2.0 protocolization decisions."""

    selection = load_selection_freeze_bundle(selection_bundle)

    config = _object(read_json(config_path), "bridge freeze config")
    if set(config) != {"schema_version", "records"} or config.get("schema_version") != ACTIVE_SELECTOR_SCHEMA_VERSION:
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
    return write_bridge_freeze_bundle(output, selection_bundle, bridge)


def load_bridge_freeze_bundle(root: Path, selection_bundle: Path) -> SharedBridgeMap:
    """Load and independently revalidate an active schema-2.0 bridge."""

    manifest = verify_bundle(root)
    _exact_files(manifest, {"bridge.json", "lineage.json"}, "bridge freeze")
    selection = load_selection_freeze_bundle(selection_bundle)
    bridge = bridge_from_record(_object(read_json(root / "bridge.json"), "bridge"))
    lineage = _object(read_json(root / "lineage.json"), "bridge lineage")
    expected = {
        "schema_version": ACTIVE_SELECTOR_SCHEMA_VERSION,
        "stage": "bridge_before_confirmation",
        "selection_id": selection.selection_id,
        "selection_bundle_sha256": bundle_digest(selection_bundle),
    }
    if lineage != expected or bridge.selection_id != selection.selection_id:
        raise SelectorExperimentError("bridge freeze lineage does not recompute")
    if tuple(record.candidate_id for record in bridge.records) != selection.selected_union_candidate_ids:
        raise SelectorExperimentError("bridge freeze does not close the selected union")
    _validate_active_bridge_contract(selection, bridge)
    return bridge


def verify_bridge_freeze_bundle(root: Path, selection_bundle: Path) -> dict[str, Any]:
    bridge = load_bridge_freeze_bundle(root, selection_bundle)
    return {"status": "BRIDGE_FREEZE_VERIFIED", "bridge_map_id": bridge.bridge_map_id,
            "bundle_sha256": bundle_digest(root)}


def selection_from_record(value: Mapping[str, Any]) -> SelectionFreezeManifest:
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


def bridge_from_record(value: Mapping[str, Any]) -> SharedBridgeMap:
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


def _require_selector_protocol(plan: SelectorSuitePlan) -> None:
    if plan.behavior_version != ACTIVE_SELECTOR_BEHAVIOR_VERSION:
        raise SelectorExperimentError(
            "active selector requires behavior_version "
            f"{ACTIVE_SELECTOR_BEHAVIOR_VERSION}"
        )


def _validate_active_bridge_contract(
    selection: SelectionFreezeManifest,
    bridge: SharedBridgeMap,
) -> None:
    """Rebind every v2 success to its exact frozen predecessor skeleton."""

    _require_selector_protocol(selection.plan)
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


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SelectorExperimentError(f"{label} must be a list")
    return value


__all__ = [
    "ACTIVE_SELECTOR_BEHAVIOR_VERSION",
    "ACTIVE_SELECTOR_SCHEMA_VERSION",
    "SelectorExperimentError",
    "bridge_from_record",
    "build_active_selector_evidence",
    "freeze_bridge_from_config",
    "freeze_selection_from_config",
    "load_bridge_freeze_bundle",
    "load_selection_freeze_bundle",
    "selection_from_record",
    "verify_bridge_freeze_bundle",
    "verify_selection_freeze_bundle",
    "write_bridge_freeze_bundle",
    "write_selection_freeze_bundle",
]
