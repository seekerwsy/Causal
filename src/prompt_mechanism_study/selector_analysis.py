"""Post-outcome confirmation and representation analysis for the selector study.

Selection and bridge freezing remain outcome-blind in ``selector_experiment``;
this module is the only layer that consumes verified successor outcomes.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.inference import (
    AssignedArmITTRecord,
    ConfirmatoryEffectStatus,
    EvidenceLevel,
    SharedEvidenceRecord,
    TargetRandomizationPlan,
    TargetSelectorYieldResult,
    TargetTaskBundle,
)
from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    ConfirmationDispatchManifest,
    FixedSlotLedger,
    SelectionFreezeManifest,
    SharedConfirmationUnion,
    SharedBridgeMap,
    PolicyTrack,
    SlotStatus,
)
from prompt_mechanism_study.records import canonical_value, content_hash, content_id
from prompt_mechanism_study.representation import DataRoleManifest
from prompt_mechanism_study.selector_experiment import (
    SelectorExperimentError,
    load_bridge_freeze_bundle,
    load_selection_freeze_bundle,
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
from prompt_mechanism_study.selector_verify import (
    load_and_verify_target_result_bundle,
    target_result_package_index,
    verify_selector_result,
    verify_target_result_components,
    verify_target_shared_evidence,
)
from prompt_mechanism_study.study_design import (
    ConfirmationFreeze,
    DiscoveryDesignFreeze,
    FormalBudgetPreflight,
    FormalReportAuthorization,
    RQ1BudgetQualification,
    StudyFreezeIndex,
)
from prompt_mechanism_study.successor_verify import verify_successor_result_bundle


def build_target_rq_tables(
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    authorization: FormalReportAuthorization | None = None,
) -> dict[str, Any]:
    """Build claim-gated RQ tables from the one independently verified v3 record."""

    if type(evidence) is not SharedEvidenceRecord or type(yields) is not TargetSelectorYieldResult:
        raise TypeError("target RQ tables require shared evidence and fixed-slot yields")
    verification = verify_target_shared_evidence(evidence, yields)
    if verification.get("status") != "TARGET_SHARED_EVIDENCE_VERIFIED":
        raise SelectorExperimentError("target shared evidence did not verify")
    slots_by_selector: dict[tuple[PolicyTrack, str, str], list[Any]] = {}
    for slot in yields.slots:
        slots_by_selector.setdefault(
            (slot.track, slot.model_id, slot.selector_id), []
        ).append(slot)
    selector_rows = []
    for selector in sorted(
        yields.selectors,
        key=lambda item: (item.track.value, item.model_id, item.selector_id),
    ):
        key = (selector.track, selector.model_id, selector.selector_id)
        slots = sorted(slots_by_selector.get(key, []), key=lambda item: item.rank)
        if len(slots) != selector.top_k:
            raise SelectorExperimentError("target selector table lost a fixed K slot")
        status_counts = Counter(
            (
                slot.effect_status.value
                if slot.effect_status is not None
                else (
                    "SELECTOR_EMPTY_OR_FAILURE"
                    if slot.slot_status is not SlotStatus.FILLED
                    else "BRIDGE_OR_PROTOCOLIZATION_FAILURE"
                )
            )
            for slot in slots
        )
        selector_rows.append(
            {
                "track": selector.track.value,
                "model_id": selector.model_id,
                "selector_id": selector.selector_id,
                "top_k": selector.top_k,
                "meaningful_slots": selector.meaningful_slots,
                "meaningful_yield_at_k": selector.meaningful_yield_at_k,
                "positive_meaningful_slots": status_counts[
                    ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL.value
                ],
                "negative_meaningful_slots": status_counts[
                    ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL.value
                ],
                "practically_null_slots": status_counts[
                    ConfirmatoryEffectStatus.PRACTICALLY_NULL.value
                ],
                "inconclusive_slots": status_counts[
                    ConfirmatoryEffectStatus.INCONCLUSIVE.value
                ],
                "non_evaluable_slots": status_counts[
                    ConfirmatoryEffectStatus.NON_EVALUABLE.value
                ],
                "selector_empty_or_failure_slots": status_counts[
                    "SELECTOR_EMPTY_OR_FAILURE"
                ],
                "bridge_or_protocolization_failure_slots": status_counts[
                    "BRIDGE_OR_PROTOCOLIZATION_FAILURE"
                ],
            }
        )
    selector_by_key = {
        (row["track"], row["model_id"], row["selector_id"]): row
        for row in selector_rows
    }
    rq2_rows = []
    for track, full_id, ablation_id in (
        (PolicyTrack.ATOMIC, "atomic_full", "atomic_rd_only"),
        (PolicyTrack.PAIR, "pair_full", "pair_no_relation"),
    ):
        models = sorted(
            {
                model_id
                for row_track, model_id, selector_id in selector_by_key
                if row_track == track.value and selector_id in {full_id, ablation_id}
            }
        )
        for model_id in models:
            full = selector_by_key.get((track.value, model_id, full_id))
            ablation = selector_by_key.get((track.value, model_id, ablation_id))
            if full is None or ablation is None or full["top_k"] != ablation["top_k"]:
                raise SelectorExperimentError(
                    "RQ2 requires both sole-difference variants with the same K"
                )
            rq2_rows.append(
                {
                    "track": track.value,
                    "model_id": model_id,
                    "full_selector_id": full_id,
                    "ablation_selector_id": ablation_id,
                    "top_k": full["top_k"],
                    "full_meaningful_yield_at_k": full["meaningful_yield_at_k"],
                    "ablation_meaningful_yield_at_k": ablation[
                        "meaningful_yield_at_k"
                    ],
                    "full_minus_ablation_yield_at_k": (
                        full["meaningful_yield_at_k"]
                        - ablation["meaningful_yield_at_k"]
                    ),
                    "comparison_semantics": (
                        "descriptive_fixed_discovery_split_no_rank_pairing"
                    ),
                }
            )
    family_rows = []
    effect_rows = []
    for family in evidence.families:
        family_rows.append(
            {
                "track": family.track.value,
                "family_status": family.status.value,
                "simultaneous_critical_value": family.simultaneous_critical_value,
                "valid_bootstrap_draws": family.valid_bootstrap_draws,
                "invalid_bootstrap_draws": family.invalid_bootstrap_draws,
                "unique_effects": len(family.estimates),
            }
        )
        for estimate in family.estimates:
            effect_rows.append(
                {
                    "track": estimate.track.value,
                    "candidate_record_id": estimate.candidate_record_id,
                    "effect_coordinate_id": estimate.effect_coordinate_id,
                    "policy_key": estimate.policy_key,
                    "model_id": estimate.model_id,
                    "estimand": (
                        "assigned_arm_task_unit_target_minus_noop_itt"
                        if estimate.track is PolicyTrack.ATOMIC
                        else "assigned_cell_task_unit_risk_difference_interaction_itt"
                    ),
                    "primary_endpoint": "oracle_evaluable_secure_code_yield",
                    "point": estimate.point,
                    "standard_error": estimate.standard_error,
                    "simultaneous_lower": estimate.simultaneous_lower,
                    "simultaneous_upper": estimate.simultaneous_upper,
                    "latent_lower": estimate.latent_lower,
                    "latent_upper": estimate.latent_upper,
                    "practical_margin": estimate.practical_margin,
                    "effect_status": estimate.status.value,
                    "reasons": list(estimate.reasons),
                    "task_units": estimate.task_units,
                    "assignments": estimate.assignments,
                    "arms": [
                        {
                            "arm": arm.arm.value,
                            "assignments": arm.assignments,
                            "secure_yield": arm.secure_yield,
                            "code_validity": arm.code_validity,
                            "oracle_evaluability": arm.oracle_evaluability,
                            "functionality_yield": arm.functionality_yield,
                            "joint_success_yield": arm.joint_success_yield,
                            "oracle_unknown_valid_assignments": (
                                arm.oracle_unknown_valid_assignments
                            ),
                            "terminal_assignments": arm.terminal_assignments,
                        }
                        for arm in estimate.arm_summaries
                    ],
                }
            )
    claim_allowed = authorization is not None
    if authorization is not None:
        if type(authorization) is not FormalReportAuthorization:
            raise TypeError("target RQ authorization must be a formal receipt")
        if (
            authorization.protocol_id
            != evidence.ledger.dispatch.union.ledger.protocol_id
            or authorization.shared_evidence_record.artifact_id
            != evidence.shared_evidence_record_id
            or authorization.shared_evidence_record.sha256 != content_hash(evidence)
            or authorization.target_selector_yield_result.artifact_id
            != yields.target_selector_yield_result_id
            or authorization.target_selector_yield_result.sha256
            != content_hash(yields)
            or authorization.evidence_ledger.artifact_id
            != evidence.ledger.evidence_ledger_id
            or authorization.evidence_ledger.sha256 != content_hash(evidence.ledger)
            or authorization.evidence_level != evidence.evidence_level.value
            or authorization.scientific_claim_allowed is not True
        ):
            raise SelectorExperimentError(
                "formal report authorization drifted from target evidence"
            )
        report_status = "FORMAL_REPORT_AUTHORIZED"
    else:
        report_status = (
            "EXECUTED_EVIDENCE_AWAITING_FORMAL_REPORT_AUTHORIZATION"
            if evidence.evidence_level
            in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED}
            else "NON_CLAIM_TEST_ARTIFACT"
        )
    report: dict[str, Any] = {
        "schema_version": "3.0",
        "protocol_id": evidence.ledger.dispatch.union.ledger.protocol_id,
        "shared_evidence_record_id": evidence.shared_evidence_record_id,
        "target_selector_yield_result_id": yields.target_selector_yield_result_id,
        "evidence_level": evidence.evidence_level.value,
        "report_status": report_status,
        "scientific_claim_allowed": claim_allowed,
        "formal_report_authorization_id": (
            None
            if authorization is None
            else authorization.formal_report_authorization_id
        ),
        "endpoint_order": [item.value for item in evidence.plan.metrics],
        "rq1_selector_rows": selector_rows,
        "rq2_full_minus_ablation_rows": rq2_rows,
        "primary_family_rows": family_rows,
        "unique_effect_rows": sorted(
            effect_rows,
            key=lambda row: (row["track"], row["candidate_record_id"]),
        ),
        "independent_verification": verification,
    }
    report["target_rq_tables_id"] = content_id("target_rq_tables_", report)
    return report


def write_target_result_bundle(
    output: Path,
    *,
    manifest: DataRoleManifest,
    budget: RQ1BudgetQualification,
    discovery: DiscoveryDesignFreeze,
    ledger: FixedSlotLedger,
    union: SharedConfirmationUnion,
    dispatch: ConfirmationDispatchManifest,
    randomization_plan: TargetRandomizationPlan,
    task_bundles: Sequence[TargetTaskBundle],
    assignments: Sequence[AssignedArmITTRecord],
    preflight: FormalBudgetPreflight,
    confirmation: ConfirmationFreeze,
    index: StudyFreezeIndex,
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    authorization: FormalReportAuthorization | None = None,
) -> dict[str, object]:
    """Write the one exact target-v3 reviewer package and verify its stored bytes."""

    frozen_assignments = tuple(
        sorted(assignments, key=lambda item: item.assignment_id)
    )
    frozen_task_bundles = tuple(
        sorted(
            task_bundles,
            key=lambda item: (item.policy_key, item.task_unit_id, item.task_instance_id),
        )
    )
    report = build_target_rq_tables(evidence, yields, authorization)
    verification = verify_target_result_components(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=frozen_task_bundles,
        assignments=frozen_assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
        evidence=evidence,
        yields=yields,
        report=report,
        authorization=authorization,
    )
    package_index = target_result_package_index(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=frozen_task_bundles,
        assignments=frozen_assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
        evidence=evidence,
        yields=yields,
        report=report,
        verification=verification,
        authorization=authorization,
    )
    write_bundle(
        output,
        {
            "package_index.json": package_index,
            "data_role_manifest.json": manifest,
            "rq1_budget_qualification.json": budget,
            "discovery_design_freeze.json": discovery,
            "fixed_slot_ledger.json": ledger,
            "shared_confirmation_union.json": union,
            "confirmation_dispatch_manifest.json": dispatch,
            "target_randomization_plan.json": randomization_plan,
            "confirmation_task_bundles.json": frozen_task_bundles,
            "assignments.json": frozen_assignments,
            "formal_budget_preflight.json": preflight,
            "confirmation_freeze.json": confirmation,
            "study_freeze_index.json": index,
            "shared_evidence_record.json": evidence,
            "target_selector_yield_result.json": yields,
            "formal_report_authorization.json": authorization,
            "rq_tables.json": report,
            "verification.json": verification,
        },
    )
    return load_and_verify_target_result_bundle(output)


def confirmation_coordinates_from_successor_bundles(
    selection: SelectionFreezeManifest,
    bridge: SharedBridgeMap,
    successor_bundles: Sequence[Path],
) -> tuple[ConfirmationCoordinate, ...]:
    """Derive coordinates only from independently verified secure-yield evidence."""

    if not successor_bundles:
        raise SelectorExperimentError("at least one successor result bundle is required")
    successful = {
        record.final_hypothesis_id
        for record in bridge.records
        if record.status is BridgeStatus.SUCCESS
    }
    coordinates: list[ConfirmationCoordinate] = []
    frozen_hypotheses: set[str] = set()
    for root in successor_bundles:
        verify_successor_result_bundle(root)
        study = _object(read_json(root / "study-freeze.json"), "successor study")
        if (
            study.get("candidate_universe_manifest_id") != selection.universe.manifest_id
            or study.get("selection_freeze_manifest_id") != selection.selection_id
        ):
            raise SelectorExperimentError("successor result does not bind the selector freeze")
        source_hypotheses = {
            content_id("frozen_hypothesis_v2_", _object(item, "successor hypothesis"))
            for item in _list(study.get("hypotheses"), "successor hypotheses")
        }
        if frozen_hypotheses & source_hypotheses:
            raise SelectorExperimentError(
                "successor bundles contain invalid or duplicate frozen hypotheses"
            )
        frozen_hypotheses.update(source_hypotheses)
        minimum = _object(study.get("analysis_plan"), "successor analysis plan").get(
            "minimum_task_units"
        )
        if type(minimum) is not int or minimum < 2:
            raise SelectorExperimentError("successor minimum task-unit support is invalid")
        inference = _object(
            _object(read_json(root / "analysis.json"), "successor analysis").get("inference"),
            "successor inference",
        )
        for raw in _list(inference.get("estimates"), "successor estimates"):
            estimate = _object(raw, "successor estimate")
            if (
                estimate.get("metric") != "secure_yield"
                or estimate.get("model_id") != selection.plan.model_id
            ):
                continue
            hypothesis_id = estimate.get("hypothesis_id")
            if hypothesis_id not in successful:
                continue
            direction = {"increase": 1, "decrease": -1}.get(estimate.get("expected_direction"))
            if direction is None:
                raise SelectorExperimentError("successor expected direction is invalid")
            effects = []
            for raw_unit in _list(
                estimate.get("task_unit_contributions"), "task-unit contributions"
            ):
                unit = _object(raw_unit, "task-unit contribution")
                values = _list(unit.get("contrast_values"), "task-unit contrasts")
                matches = [
                    value
                    for value in values
                    if isinstance(value, list)
                    and len(value) == 4
                    and value[0] == "target_minus_noop"
                ]
                if len(matches) != 1 or type(matches[0][1]) not in {int, float}:
                    raise SelectorExperimentError(
                        "secure-yield Target-Noop contribution is unavailable"
                    )
                effects.append((unit.get("task_unit_id"), float(matches[0][1])))
            coordinates.append(
                ConfirmationCoordinate(
                    hypothesis_id,
                    estimate["model_id"],
                    direction,
                    tuple(sorted(effects)),
                    minimum,
                    True,
                )
            )
    frozen = tuple(sorted(coordinates, key=lambda item: item.coordinate_id))
    if len({item.coordinate_id for item in frozen}) != len(frozen):
        raise SelectorExperimentError(
            "successor bundles contain duplicate confirmation coordinates"
        )
    if frozen_hypotheses != successful:
        raise SelectorExperimentError(
            "successor frozen hypotheses do not exactly equal successful bridges"
        )
    if {item.final_hypothesis_id for item in frozen} != successful:
        raise SelectorExperimentError(
            "verified successor evidence does not close every successful bridge"
        )
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
    coordinates = confirmation_coordinates_from_successor_bundles(
        selection, bridge, successor_bundles
    )
    result = evaluate_selector_study(selection, bridge, coordinates, plan)
    verification = verify_selector_result(selection, bridge, coordinates, plan, result)
    roots = tuple(Path(path).resolve() for path in successor_bundles)
    artifact_parent = Path(output).resolve().parent
    write_bundle(
        output,
        {
            "coordinates.json": canonical_value(coordinates),
            "lineage.json": {
                "schema_version": "1.0",
                "selection_bundle_path": _portable_path(selection_bundle, artifact_parent),
                "selection_bundle_sha256": bundle_digest(selection_bundle),
                "bridge_bundle_path": _portable_path(bridge_bundle, artifact_parent),
                "bridge_bundle_sha256": bundle_digest(bridge_bundle),
                "successor_bundles": [
                    {
                        "path": _portable_path(path, artifact_parent),
                        "bundle_sha256": bundle_digest(path),
                    }
                    for path in roots
                ],
            },
            "plan.json": canonical_value(plan),
            "result.json": canonical_value(result),
            "verification.json": verification,
        },
    )
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
    _exact_files(
        manifest,
        {"coordinates.json", "lineage.json", "plan.json", "result.json", "verification.json"},
        "selector result",
    )
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
            raise SelectorExperimentError(
                "stored successor bundle is missing, duplicated, or replaced"
            )
        seen.add(digest)
        source_paths.append(path)
    derived = confirmation_coordinates_from_successor_bundles(selection, bridge, source_paths)
    stored_coordinates = tuple(
        _coordinate(_object(value, "coordinate"))
        for value in _list(read_json(root / "coordinates.json"), "coordinates")
    )
    if stored_coordinates != derived:
        raise SelectorExperimentError("stored confirmation coordinates do not rederive")
    plan = _inference_plan(_object(read_json(root / "plan.json"), "selector inference plan"))
    result = _result(_object(read_json(root / "result.json"), "selector result"))
    verified = verify_selector_result(selection, bridge, derived, plan, result)
    if read_json(root / "verification.json") != verified:
        raise SelectorExperimentError("stored selector verification was replaced")
    return {
        **verified,
        "status": "SELECTOR_RESULT_BUNDLE_VERIFIED",
        "bundle_sha256": bundle_digest(root),
    }


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
        if any(
            not isinstance(item[name], str) or not item[name].strip()
            for name in ("result_path", "representation_adapter_id")
        ):
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
    selection_path = _stored_path(lineage["selection_bundle_path"], result_root.resolve().parent)
    bridge_path = _stored_path(lineage["bridge_bundle_path"], result_root.resolve().parent)
    selection = load_selection_freeze_bundle(selection_path)
    bridge = load_bridge_freeze_bundle(bridge_path, selection_path)
    result = _result(_object(read_json(result_root / "result.json"), "selector result"))
    if selection.universe.representation_adapter_id != expected_adapter_id:
        raise SelectorExperimentError("representation adapter identity drift")
    successful = tuple(record for record in bridge.records if record.status is BridgeStatus.SUCCESS)
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
            "candidate_coverage": contextual["candidate_coverage"] - direct["candidate_coverage"],
            "protocolization_rate": contextual["protocolization_rate"]
            - direct["protocolization_rate"],
            "unique_confirmed_hypotheses": len(contextual["unique_confirmed_hypothesis_ids"])
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
    return ConfirmationCoordinate(
        value["final_hypothesis_id"],
        value["model_id"],
        value["expected_direction"],
        tuple((item[0], item[1]) for item in value["task_unit_effects"]),
        value["minimum_task_units"],
        value["provenance_complete"],
    )


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
    return SelectorInferencePlan(
        value["bootstrap_seed"],
        value["inner_draws"],
        value["outer_draws"],
        value["alpha"],
        value["minimum_valid_fraction"],
        tuple(tuple(item) for item in value["selector_pairs"]),
    )


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
        yields.append(
            SelectorYieldPoint(
                item["selector_id"],
                item["ranking_id"],
                item["model_id"],
                item["budget_k"],
                item["confirmed_slots"],
                item["confirmed_yield"],
                contributions,
            )
        )
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
        value["plan_id"],
        value["selection_id"],
        value["bridge_map_id"],
        value["confirmation_input_sha256"],
        value["primary_critical_value"],
        value["primary_valid_draws"],
        value["primary_invalid_draws"],
        statuses,
        tuple(yields),
        method_points,
        pair_points,
        value["selector_pair_critical_value"],
        pair_intervals,
        value["valid_outer_draws"],
        value["invalid_outer_draws"],
        value["outer_pair_draws_sha256"],
        value["pair_inference_status"],
    )


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
    "build_target_rq_tables",
    "confirmation_coordinates_from_successor_bundles",
    "run_representation_comparison_from_config",
    "run_selector_experiment",
    "run_selector_experiment_from_config",
    "verify_representation_comparison_bundle",
    "verify_selector_experiment_bundle",
    "write_target_result_bundle",
]
