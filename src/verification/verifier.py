"""Replay direct experiment inputs, raw measurements, assignment and statistical results."""
from pathlib import Path
from prompt_mechanism_study.artifact_io import file_sha256, read_json_exact, verify_bundle
from prompt_mechanism_study.experiment.inference import EvidenceLevel, SharedEvidenceRecord, TargetSelectorYieldResult
from prompt_mechanism_study.records import content_id
from prompt_mechanism_study.experiment.study_design import StudyConfig, ConfirmationInputs
from prompt_mechanism_study.tsg.representation import DataRole, validate_data_role_firewall
from prompt_mechanism_study.verification.design import verify_target_randomization, _verify_discovery_population
from prompt_mechanism_study.verification.effects import verify_target_shared_evidence
from prompt_mechanism_study.verification.integrity import _decode_target_file
from prompt_mechanism_study.verification.reporting import _check_target_rq_tables, _replay_execution_measurements

TARGET_RESULT_PACKAGE_FILES = frozenset({
    "study_config.json", "confirmation_inputs.json", "measurement_records.json",
    "shared_evidence_record.json", "target_selector_yield_result.json", "rq_tables.json",
})


def verify_confirmation_inputs(study, confirmation, assignments):
    """Check prospective membership and independently replay assignment before measurement."""
    manifest = study.manifest
    validate_data_role_firewall(manifest, {b.data_id: b.role for b in manifest.bindings})
    if study.protocol_status != "SPECIFIED_DRAFT":
        raise ValueError("formal execution is unavailable under SPECIFIED_DRAFT")
    if confirmation.study_id != study.study_id or not _verify_discovery_population(study.population_lineage, manifest):
        raise ValueError("study input/population binding differs")
    dispatch = confirmation.dispatch
    ledger = dispatch.ledger
    expected = {(model, selector) for model in study.model_ids for selector in study.selector_ids}
    universe = study.discovery_inputs["universe"]
    if (universe["discovery_population_sha256"] != manifest.discovery_population_sha256
        or universe["top_k"] != study.top_k
        or any(source.universe_id != content_id("atomic_candidate_universe_", universe) for source in ledger.sources)):
        raise ValueError("candidate universe differs from the frozen source population")
    if (ledger.protocol_id != manifest.protocol_id
        or {(s.model_id, s.selector_id) for s in ledger.sources} != expected
        or any(k != study.top_k for _, k in ledger.top_k_by_track)
        or confirmation.randomization_plan.atomic_total_block_slots != study.atomic_total_block_slots):
        raise ValueError("selection differs from the prospective study configuration")
    if len(assignments) > study.generation_call_limit:
        raise ValueError("actual assignments exceed generation call limit")
    permitted = {t.task_unit_id for b in manifest.bindings if b.role is DataRole.CONFIRMATION for t in b.task_units}
    if any(b.task_unit_id not in permitted for b in confirmation.task_bundles):
        raise ValueError("task is outside the confirmation population")
    return verify_target_randomization(dispatch, confirmation.randomization_plan, confirmation.task_bundles, assignments)


def load_and_verify_target_result_bundle(root: Path) -> dict[str, object]:
    """Verify stored bytes, replay raw measurements, and independently rebuild every RQ row."""
    root = Path(root)
    stored = verify_bundle(root)
    if set(stored.get("files", {})) != TARGET_RESULT_PACKAGE_FILES:
        raise ValueError("result package file set differs")
    study = _decode_target_file(root / "study_config.json", StudyConfig)
    confirmation = _decode_target_file(root / "confirmation_inputs.json", ConfirmationInputs)
    evidence = _decode_target_file(root / "shared_evidence_record.json", SharedEvidenceRecord)
    yields = _decode_target_file(root / "target_selector_yield_result.json", TargetSelectorYieldResult)
    report = read_json_exact(root / "rq_tables.json")
    raw = read_json_exact(root / "measurement_records.json")
    if evidence.evidence_level in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED}:
        raise ValueError("formal execution is unavailable under SPECIFIED_DRAFT")
    if evidence.ledger.dispatch != confirmation.dispatch or evidence.plan != study.inference_plan:
        raise ValueError("evidence differs from prospective inputs")
    verify_confirmation_inputs(study, confirmation, evidence.ledger.assignments)
    measurement = _replay_execution_measurements(evidence, confirmation.measurement_contract, raw)
    verify_target_shared_evidence(evidence, yields)
    tables = _check_target_rq_tables(evidence, yields, report)
    return dict(status="TARGET_RESULT_BUNDLE_VERIFIED", package_status=report["report_status"],
        scientific_claim_allowed=False, evidence_level=evidence.evidence_level.value,
        assignment_count=len(evidence.ledger.assignments),
        task_unit_count=len({a.task_unit_id for a in evidence.ledger.assignments}),
        study_id=study.study_id, target_rq_tables_id=tables["target_rq_tables_id"],
        measurement_verification_status=measurement["status"],
        result_bundle_sha256=file_sha256(root / "manifest.json"))
