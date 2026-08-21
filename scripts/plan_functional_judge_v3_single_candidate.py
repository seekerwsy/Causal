"""Build a closed, zero-call v3 single-candidate fresh-holdout plan.

This is intentionally separate from the paired v1/v2/v3 calibration planner.
It reuses that planner's frozen-input loaders, but the resulting authority
permits exactly one v3 candidate with a 2-case exposed-tune pilot followed by
22 remaining cases.  It never reads a provider credential.
"""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

sys.dont_write_bytecode = True

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
for _source_root in (_REPOSITORY_ROOT / "src", _REPOSITORY_ROOT):
    if str(_source_root) not in sys.path:
        sys.path.insert(0, str(_source_root))

from scripts import analyze_functional_judge_calibration as paired_analyzer
from scripts import freeze_functional_judge_calibration_campaign as full_campaign
from scripts import plan_functional_judge_calibration as paired_planner

from secaware.exploratory.artifact_integrity import (
    verify_closed_manifest,
    write_closed_manifest_atomic,
)
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.pipeline.artifact import canonical_sha256

_ANALYSIS_KIND = "single_candidate_absolute_holdout"
_CANDIDATE_ID = "qwen35flash-requirement-aggregate-v3"
_PROTOCOL_VERSION = "v3"
_EXPECTED_PROMPT_SHA256 = "5aecb580cba8b241da4108aca61465781de5d7e7fbd2662072a84b28eac2eecf"
_EXPECTED_EVALUATOR_CONFIG_SHA256 = (
    "fe7434f9ef2c1d84ef00901de8234ed424eec42a57257fa5a9a6d59aa5338125"
)
_EXPECTED_VALIDATION_CASES_SHA256 = (
    "4ee3353cc601b96be79a879fcedb6f36cffcfc56b0737d4db12e1f4bb3787195"
)
_EXPECTED_CALIBRATION_SPEC_SHA256 = (
    "e6d9b9fecb219250dd5a1bce6c30135954b10ada9efdef05b83c5f2ef42cb56a"
)
_EXPECTED_HOLDOUT_SOURCE_POLICY_SHA256 = (
    "7a41f4132df96fd675d7a3bcd3af73cebfe131fc3313cd35c94d9d78d233a3a8"
)
_EXPECTED_CASE_SOURCE_BINDINGS_SHA256 = (
    "f43ef37a72689833fa89425aa3c746c89a6a474099c7f481353534182b240f3e"
)

_PLAN_FILES = {
    "calibration-case-metadata.jsonl",
    "cases.jsonl",
    "command.json",
    "contracts.jsonl",
    "environment.json",
    "pilot-cases.jsonl",
    "plan.json",
    "remaining-cases.jsonl",
}
_EVALUATION_DESIGN = {
    "analysis_kind": _ANALYSIS_KIND,
    "candidate_role": "new_candidate",
    "candidate_protocol_version": _PROTOCOL_VERSION,
    "expected_candidates": 1,
    "expected_slices": 2,
    "expected_single_pass_attempts": 24,
    "expected_total_functional_judge_provider_attempts": 24,
    "historical_comparison_allowed": False,
    "historical_trace_reuse_allowed": False,
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= frozenset("0123456789abcdef")


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError(f"expected JSON object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if type(value) is not dict:
            raise ValueError(f"expected JSON objects: {path}")
        rows.append(value)
    return rows


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def _select_pilot_cases(tune_cases: list[dict[str, object]]) -> list[dict[str, object]]:
    pilot: list[dict[str, object]] = []
    for expected in ("fail", "pass"):
        matches = sorted(
            (row for row in tune_cases if row.get("expected_status") == expected),
            key=lambda row: str(row.get("case_id")),
        )
        if matches:
            pilot.append(matches[0])
    if len(pilot) < 2:
        pilot = sorted(tune_cases, key=lambda row: str(row.get("case_id")))[:2]
    return pilot


def _expected_authority_hashes() -> dict[str, str]:
    expected = {
        "system_prompt": _EXPECTED_PROMPT_SHA256,
        "evaluator_config": _EXPECTED_EVALUATOR_CONFIG_SHA256,
        "validation_cases": _EXPECTED_VALIDATION_CASES_SHA256,
        "calibration_spec": _EXPECTED_CALIBRATION_SPEC_SHA256,
        "holdout_source_policy": _EXPECTED_HOLDOUT_SOURCE_POLICY_SHA256,
        "case_source_bindings": _EXPECTED_CASE_SOURCE_BINDINGS_SHA256,
    }
    if not all(_is_sha256(value) for value in expected.values()):
        raise ValueError("fresh-holdout production authorities are not finalized")
    return expected


def _validate_holdout_authorities(
    *,
    spec_path: Path,
    validation_path: Path,
    policy_path: Path,
    bindings_path: Path,
    prompt_path: Path,
    evaluator_config_path: Path,
) -> dict[str, object]:
    paths = {
        "system_prompt": prompt_path.resolve(),
        "evaluator_config": evaluator_config_path.resolve(),
        "validation_cases": validation_path.resolve(),
        "calibration_spec": spec_path.resolve(),
        "holdout_source_policy": policy_path.resolve(),
        "case_source_bindings": bindings_path.resolve(),
    }
    if any(not path.is_file() for path in paths.values()):
        raise ValueError("fresh-holdout authority file is unavailable")
    expected = _expected_authority_hashes()
    actual = {name: _sha256_file(path) for name, path in paths.items()}
    if actual != expected:
        raise ValueError("fresh-holdout authority digest failed validation")

    evaluator = full_campaign._load_evaluator(
        paths["evaluator_config"],
        role="new_candidate",
        protocol="v3",
    )
    if (
        evaluator.candidate_id != _CANDIDATE_ID
        or evaluator.model_id != "qwen3.5-flash-2026-02-23"
        or evaluator.max_attempts != 1
        or evaluator.source_sha256 != expected["evaluator_config"]
    ):
        raise ValueError("v3 evaluator identity failed validation")

    policy = _read_json(paths["holdout_source_policy"])
    bindings = _read_jsonl(paths["case_source_bindings"])
    validation = _read_jsonl(paths["validation_cases"])
    if len(bindings) != 16 or len(validation) != 16:
        raise ValueError("fresh-holdout provenance cardinality failed validation")
    active = policy.get("active_validation")
    cutoff = policy.get("candidate_cutoff")
    contamination = policy.get("contamination_audit")
    derivation = policy.get("derivation")
    incidents = policy.get("operational_incidents")
    if not all(type(value) is dict for value in (active, cutoff, contamination, derivation)):
        raise ValueError("fresh-holdout policy schema failed validation")
    if (
        set(policy)
        != {
            "active_validation",
            "candidate_cutoff",
            "contamination_audit",
            "derivation",
            "official_artifact_replacement_allowed",
            "operational_incidents",
            "purpose",
            "schema_version",
            "scientific_claim_allowed",
            "source_authorities",
            "source_basis_catalog",
            "status",
        }
        or policy.get("schema_version") != "1.0"
        or policy.get("status") != "FRESH_HOLDOUT_FROZEN_NO_PROVIDER_CALLS"
        or policy.get("scientific_claim_allowed") is not False
        or policy.get("official_artifact_replacement_allowed") is not False
        or active
        != {
            "case_source_bindings_path": (
                "data/functional-judge/blind-calibration-v4/case-source-bindings.jsonl"
            ),
            "case_source_bindings_sha256": expected["case_source_bindings"],
            "cases": 16,
            "expected_fail": 8,
            "expected_pass": 8,
            "families": [
                "gtf_fasta_append",
                "pdf_bag_of_words",
                "slurm_exit_code",
                "sqlite_metadata",
            ],
            "per_family_expected_fail": 2,
            "per_family_expected_pass": 2,
            "validation_cases_path": (
                "data/functional-judge/blind-calibration-v4/validation-cases.jsonl"
            ),
            "validation_cases_sha256": expected["validation_cases"],
        }
        or cutoff.get("candidate_id") != _CANDIDATE_ID
        or cutoff.get("candidate_prompt_sha256_before_holdout_creation")
        != expected["system_prompt"]
        or cutoff.get("candidate_config_sha256_before_holdout_creation")
        != expected["evaluator_config"]
        or cutoff.get("provider_calls_on_fresh_holdout_before_freeze") != 0
        or contamination.get("model_output_dependent_case_selection") is not False
        or contamination.get("exposed_tune", {}).get("cases") != 8
        or contamination.get("historical_validation")
        != {
            "cases": 16,
            "downgraded_role": (
                "exposed_historical_regression_only_not_fresh_validation_not_ranking"
            ),
            "path": "data/functional-judge/blind-calibration-v3/validation-cases.jsonl",
            "sha256": "8e62c17753dd09c352a89571429aec5ecd4dc2b41280cdaeb8d3835fa9a8dca6",
        }
        or derivation.get("llm_output_conditioned_case_selection") is not False
        or derivation.get("runtime_test_reauthored_per_task") is not False
        or derivation.get("selection_policy_id")
        != "four_family_two_pass_two_fail_contract_adapter_projection_v1"
        or type(incidents) is not list
        or len(incidents) != 1
        or type(incidents[0]) is not dict
        or incidents[0].get("status") != "resolved_no_outcome_contamination"
        or incidents[0].get("remote_or_provider_call_made") is not False
        or incidents[0].get("unchanged_frozen_hashes")
        != {
            "case_source_bindings_sha256": expected["case_source_bindings"],
            "calibration_spec_sha256": expected["calibration_spec"],
            "validation_cases_sha256": expected["validation_cases"],
        }
    ):
        raise ValueError("fresh-holdout policy closure failed validation")

    _spec, family_specs = paired_planner._load_spec(paths["calibration_spec"])
    validation_by_id = {row.get("case_id"): row for row in validation}
    bindings_by_id = {row.get("case_id"): row for row in bindings}
    basis_ids = {
        row.get("basis_id") for row in policy.get("source_basis_catalog", []) if type(row) is dict
    }
    binding_keys = {
        "case_id",
        "code_sha256",
        "derivation_rule_id",
        "expected_status",
        "family",
        "functional_contract_id",
        "functional_requirement_ids",
        "gold_requirement_verdicts",
        "schema_version",
        "selection_rank",
        "source_basis_ids",
        "task_id",
    }
    if (
        len(validation_by_id) != 16
        or len(bindings_by_id) != 16
        or set(validation_by_id) != set(bindings_by_id)
        or {row.get("selection_rank") for row in bindings} != set(range(1, 17))
        or None in basis_ids
    ):
        raise ValueError("fresh-holdout case binding identity failed validation")
    for case_id, case in validation_by_id.items():
        binding = bindings_by_id[case_id]
        family = family_specs.get(str(case.get("family")))
        verdicts = binding.get("gold_requirement_verdicts")
        source_basis_ids = binding.get("source_basis_ids")
        if (
            set(binding) != binding_keys
            or binding.get("schema_version") != "1.0"
            or binding.get("derivation_rule_id") != "adapter_contract_projection_v1"
            or family is None
            or binding.get("task_id") != case.get("task_id")
            or binding.get("family") != case.get("family")
            or binding.get("expected_status") != case.get("expected_status")
            or binding.get("code_sha256")
            != hashlib.sha256(str(case.get("code_text")).encode("utf-8")).hexdigest()
            or binding.get("functional_contract_id") != family["functional_contract_id"]
            or binding.get("functional_requirement_ids") != family["functional_requirement_ids"]
            or type(verdicts) is not dict
            or list(verdicts) != family["functional_requirement_ids"]
            or any(value not in {"met", "not_met"} for value in verdicts.values())
            or ("fail" if "not_met" in verdicts.values() else "pass") != case.get("expected_status")
            or type(source_basis_ids) is not list
            or not source_basis_ids
            or any(value not in basis_ids for value in source_basis_ids)
        ):
            raise ValueError("fresh-holdout case binding closure failed validation")
    return {
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": actual,
        "policy": policy,
        "bindings": bindings,
    }


def _plan_artifacts(
    *,
    spec_path: Path,
    delivery_path: Path,
    tune_overlay_dir: Path,
    validation_path: Path,
    contracts_path: Path | None,
) -> tuple[
    dict[str, object],
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
    str,
    str,
]:
    spec, family_specs = paired_planner._load_spec(spec_path)
    paired_planner._validate_delivery(delivery_path, spec)
    tune_rows, overlay_manifest, evidence_manifest, contracts = paired_planner._load_tune_rows(
        tune_overlay_dir,
        spec,
        family_specs,
    )
    authoritative_contracts = tune_overlay_dir / "frozen-functional-contracts.jsonl"
    if contracts_path is not None and contracts_path.resolve() != authoritative_contracts.resolve():
        raise ValueError("contracts must be the tune overlay frozen functional contracts")
    if _sha256_file(validation_path) != spec["validation_cases_sha256"]:
        raise ValueError("validation fixture artifact digest mismatch")
    validation_rows = paired_planner._load_validation_rows(validation_path, spec, family_specs)

    provider_cases: list[dict[str, object]] = []
    metadata: list[dict[str, object]] = []
    tune_seed_by_assignment = {
        assignment_id: 94_001 + index
        for index, assignment_id in enumerate(sorted(row["assignment_id"] for row in tune_rows))
    }
    overlay_root = tune_overlay_dir.resolve()
    for row in tune_rows:
        seed_id = tune_seed_by_assignment[row["assignment_id"]]
        code_path = paired_planner._resolve_posix_file(overlay_root, row["code_path"], label="code")
        code_bytes = code_path.read_bytes()
        if hashlib.sha256(code_bytes).hexdigest() != row["code_sha256"]:
            raise ValueError("tune code changed after overlay verification")
        code_text = code_bytes.decode("utf-8")
        provider_cases.append(
            {
                "case_id": row["case_id"],
                "task_id": row["task_id"],
                "seed_id": seed_id,
                "code_text": code_text,
                "expected_status": row["expected_status"],
            }
        )
        metadata.append(
            {
                "schema_version": "1.0",
                "case_id": row["case_id"],
                "task_id": row["task_id"],
                "seed_id": seed_id,
                "split": "tune",
                "family": row["family"],
                "equivalence_group": row["equivalence_group"],
                "paired_group_id": row["paired_group_id"],
                "expected_status": row["expected_status"],
                "code_sha256": row["code_sha256"],
                "source_kind": "d_dev_verified_live_artifact",
                "source_id": row["assignment_id"],
                "source_role": row["arm_role"],
                "source_path": row["source_artifact_path"],
                "source_sha256": row["source_artifact_sha256"],
                "source_root_manifest_sha256": row["source_root_manifest_sha256"],
                "gold_method": "Y_F^E",
                "gold_evidence_path": row["measurement_path"],
                "gold_evidence_sha256": row["measurement_sha256"],
            }
        )

    validation_sha256 = _sha256_file(validation_path)
    for row in validation_rows:
        code_sha256 = hashlib.sha256(row["code_text"].encode("utf-8")).hexdigest()
        provider_cases.append(
            {
                "case_id": row["case_id"],
                "task_id": row["task_id"],
                "seed_id": row["seed_id"],
                "code_text": row["code_text"],
                "expected_status": row["expected_status"],
            }
        )
        metadata.append(
            {
                "schema_version": "1.0",
                "case_id": row["case_id"],
                "task_id": row["task_id"],
                "seed_id": row["seed_id"],
                "split": "validation",
                "family": row["family"],
                "equivalence_group": row["equivalence_group"],
                "paired_group_id": None,
                "expected_status": row["expected_status"],
                "code_sha256": code_sha256,
                "source_kind": "frozen_fresh_validation_fixture_v1",
                "source_id": row["case_id"],
                "source_role": row["fixture_role"],
                "source_path": validation_path.name,
                "source_sha256": validation_sha256,
                "source_root_manifest_sha256": None,
                "gold_method": "frozen_clear_semantic_fixture_v1",
                "gold_evidence_path": validation_path.name,
                "gold_evidence_sha256": validation_sha256,
            }
        )
    provider_cases.sort(key=lambda row: row["case_id"])
    metadata.sort(key=lambda row: row["case_id"])
    if (
        len(provider_cases) != 24
        or len({row["case_id"] for row in provider_cases}) != 24
        or {row["case_id"] for row in provider_cases} != {row["case_id"] for row in metadata}
    ):
        raise ValueError("single-candidate case closure failed validation")

    tune_cases = [
        case
        for case in provider_cases
        if next(row for row in metadata if row["case_id"] == case["case_id"])["split"] == "tune"
    ]
    pilot = _select_pilot_cases(tune_cases)
    pilot_ids = {row["case_id"] for row in pilot}
    remaining = [row for row in provider_cases if row["case_id"] not in pilot_ids]
    if (
        len(pilot) != 2
        or len(remaining) != 22
        or any(
            next(item for item in metadata if item["case_id"] == row["case_id"])["split"] != "tune"
            for row in pilot
        )
    ):
        raise ValueError("single-candidate pilot partition failed validation")
    return (
        spec,
        provider_cases,
        metadata,
        contracts,
        pilot,
        overlay_manifest,
        evidence_manifest,
    )


def _load_closed_plan(
    plan_dir: Path,
    *,
    calibration_spec_path: Path,
    expected_plan_id: str,
    expected_root_manifest_sha256: str,
) -> tuple[
    dict[str, object],
    dict[str, dict[str, object]],
    dict[str, TaskFunctionalContractRecord],
]:
    root = plan_dir.resolve()
    manifest_path = root / "artifact-manifest.json"
    if (
        not _is_sha256(expected_root_manifest_sha256)
        or _sha256_file(manifest_path) != expected_root_manifest_sha256
        or type(expected_plan_id) is not str
        or not expected_plan_id.startswith("functional_judge_v3_single_candidate_plan_")
    ):
        raise ValueError("single-candidate plan authority failed validation")
    manifest = verify_closed_manifest(manifest_path, label="v3 single-candidate plan")
    if {str(row["path"]) for row in manifest["files"]} != _PLAN_FILES:
        raise ValueError("single-candidate plan file closure failed validation")

    spec_path = calibration_spec_path.resolve()
    spec, family_specs = paired_planner._load_spec(spec_path)
    plan = _read_json(root / "plan.json")
    cases = _read_jsonl(root / "cases.jsonl")
    pilot_cases = _read_jsonl(root / "pilot-cases.jsonl")
    remaining_cases = _read_jsonl(root / "remaining-cases.jsonl")
    metadata_rows = _read_jsonl(root / "calibration-case-metadata.jsonl")
    contract_rows = _read_jsonl(root / "contracts.jsonl")
    plan_content = {key: value for key, value in plan.items() if key != "plan_id"}
    if (
        plan.get("status") != "FUNCTIONAL_JUDGE_V3_SINGLE_CANDIDATE_PLAN_COMPLETE"
        or plan.get("claim") is not False
        or plan.get("scientific_claim_allowed") is not False
        or plan.get("plan_id") != expected_plan_id
        or plan.get("plan_id")
        != "functional_judge_v3_single_candidate_plan_" + canonical_sha256(plan_content)
        or plan.get("calibration_id") != spec["calibration_id"]
        or plan.get("calibration_spec_sha256") != _sha256_file(spec_path)
        or plan.get("candidate_roles") != spec["candidate_roles"]
        or plan.get("evaluation_design") != _EVALUATION_DESIGN
        or plan.get("validation_cases_sha256") != spec["validation_cases_sha256"]
        or plan.get("provider_cases_sha256") != canonical_sha256(cases)
        or plan.get("case_metadata_sha256") != canonical_sha256(metadata_rows)
        or plan.get("contracts_sha256") != canonical_sha256(contract_rows)
        or plan.get("fresh_holdout_authorities", {}).get("sha256") != _expected_authority_hashes()
        or plan.get("case_counts")
        != {
            "total": 24,
            "tune": 8,
            "validation": 16,
            "families": 4,
            "pilot": 2,
            "remaining": 22,
        }
        or len(cases) != 24
        or len(pilot_cases) != 2
        or len(remaining_cases) != 22
        or len(metadata_rows) != 24
    ):
        raise ValueError("single-candidate plan failed validation")

    pilot_ids = {row.get("case_id") for row in pilot_cases}
    remaining_ids = {row.get("case_id") for row in remaining_cases}
    all_ids = {row.get("case_id") for row in cases}
    metadata_by_id = {row.get("case_id"): row for row in metadata_rows}
    if (
        pilot_ids != set(plan.get("pilot_case_ids", []))
        or pilot_ids & remaining_ids
        or pilot_ids | remaining_ids != all_ids
        or any(metadata_by_id.get(case_id, {}).get("split") != "tune" for case_id in pilot_ids)
    ):
        raise ValueError("single-candidate pilot/remaining partition failed validation")

    frozen_contracts: dict[str, TaskFunctionalContractRecord] = {}
    family_specs_by_task = {str(row["task_id"]): row for row in family_specs.values()}
    try:
        for raw in contract_rows:
            contract = TaskFunctionalContractRecord.model_validate(raw)
            family_spec = family_specs_by_task.get(contract.task_id)
            if (
                family_spec is None
                or contract.task_id in frozen_contracts
                or contract.model_dump(mode="json") != raw
                or contract.contract_id != family_spec["functional_contract_id"]
                or canonical_sha256(raw) != family_spec["functional_contract_record_sha256"]
                or [item.requirement_id for item in contract.requirements]
                != family_spec["functional_requirement_ids"]
            ):
                raise ValueError
            frozen_contracts[contract.task_id] = contract
    except Exception:  # noqa: BLE001 - normalize strict model validation failures
        raise ValueError("single-candidate frozen contracts failed validation") from None

    case_by_id: dict[str, dict[str, object]] = {}
    for row in cases:
        case_id = row.get("case_id")
        if (
            frozenset(row) != paired_analyzer._PROVIDER_CASE_KEYS
            or type(case_id) is not str
            or not case_id
            or case_id in case_by_id
            or type(row.get("task_id")) is not str
            or type(row.get("seed_id")) is not int
            or type(row.get("code_text")) is not str
            or row.get("expected_status") not in {"pass", "fail"}
        ):
            raise ValueError("single-candidate provider case failed validation")
        case_by_id[case_id] = row

    metadata: dict[str, dict[str, object]] = {}
    split_counts: Counter[str] = Counter()
    tune_pair_counts: Counter[str] = Counter()
    for row in metadata_rows:
        case_id = row.get("case_id")
        provider_case = case_by_id.get(case_id) if type(case_id) is str else None
        if (
            frozenset(row) != paired_analyzer._METADATA_KEYS
            or row.get("schema_version") != "1.0"
            or provider_case is None
            or case_id in metadata
            or row.get("split") not in {"tune", "validation"}
            or row.get("task_id") != provider_case["task_id"]
            or row.get("seed_id") != provider_case["seed_id"]
            or row.get("expected_status") != provider_case["expected_status"]
            or row.get("code_sha256")
            != hashlib.sha256(provider_case["code_text"].encode("utf-8")).hexdigest()
        ):
            raise ValueError("single-candidate metadata failed validation")
        if row["split"] == "tune":
            paired_group = row.get("paired_group_id")
            if (
                row.get("source_role") not in {"target_patch", "noop_rewrite"}
                or type(paired_group) is not str
                or not paired_group.startswith("functional_pair_")
                or row.get("equivalence_group") is not None
            ):
                raise ValueError("single-candidate tune metadata failed validation")
            tune_pair_counts[paired_group] += 1
        elif row.get("paired_group_id") is not None:
            raise ValueError("single-candidate validation metadata failed validation")
        split_counts[row["split"]] += 1
        metadata[case_id] = row
    if (
        set(metadata) != set(case_by_id)
        or split_counts != {"tune": 8, "validation": 16}
        or sorted(tune_pair_counts.values()) != [2, 2, 2, 2]
        or {row["task_id"] for row in metadata.values()} != set(frozen_contracts)
    ):
        raise ValueError("single-candidate case join failed validation")

    thresholds = plan.get("thresholds")
    if (
        type(thresholds) is not dict
        or frozenset(thresholds) != paired_analyzer._THRESHOLD_KEYS
        or thresholds != spec["thresholds"]
        or thresholds.get("tune_cases") != 8
        or thresholds.get("tune_min_correct") != 8
        or thresholds.get("tune_max_false_pass") != 0
        or thresholds.get("tune_max_equivalence_inconsistency") != 0
        or thresholds.get("tune_role") != "engineering_regression_gate_not_ranking"
        or thresholds.get("validation_cases") != 16
        or thresholds.get("validation_min_correct") != 15
        or thresholds.get("validation_max_false_pass") != 0
        or thresholds.get("validation_max_equivalence_inconsistency") != 0
        or thresholds.get("validation_max_invalid") != 0
    ):
        raise ValueError("single-candidate thresholds failed validation")
    return plan, metadata, frozen_contracts


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--source-final-delivery", type=Path, required=True)
    parser.add_argument("--tune-overlay-dir", type=Path, required=True)
    parser.add_argument("--validation-cases", type=Path, required=True)
    parser.add_argument("--holdout-source-policy", type=Path, required=True)
    parser.add_argument("--case-source-bindings", type=Path, required=True)
    parser.add_argument("--v3-system-prompt", type=Path, required=True)
    parser.add_argument("--v3-evaluator-config", type=Path, required=True)
    parser.add_argument("--contracts", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _build_plan(
    args: argparse.Namespace,
    *,
    raw_argv: list[str],
    command_argv: list[str] | None = None,
) -> dict[str, object]:
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError("refusing to overwrite an existing single-candidate plan")
    if command_argv is None:
        command_argv = [sys.executable, str(Path(__file__).resolve()), *raw_argv]
    if any(type(value) is not str or not value for value in command_argv):
        raise ValueError("recorded plan command failed validation")

    spec_path = args.spec.resolve()
    delivery_path = args.source_final_delivery.resolve()
    validation_path = args.validation_cases.resolve()
    tune_overlay_dir = args.tune_overlay_dir.resolve()
    holdout = _validate_holdout_authorities(
        spec_path=spec_path,
        validation_path=validation_path,
        policy_path=args.holdout_source_policy,
        bindings_path=args.case_source_bindings,
        prompt_path=args.v3_system_prompt,
        evaluator_config_path=args.v3_evaluator_config,
    )
    (
        spec,
        cases,
        metadata,
        contracts,
        pilot,
        overlay_manifest,
        evidence_manifest,
    ) = _plan_artifacts(
        spec_path=spec_path,
        delivery_path=delivery_path,
        tune_overlay_dir=tune_overlay_dir,
        validation_path=validation_path,
        contracts_path=args.contracts,
    )
    pilot_ids = {row["case_id"] for row in pilot}
    remaining = [row for row in cases if row["case_id"] not in pilot_ids]
    plan_core: dict[str, object] = {
        "schema_version": "1.0",
        "status": "FUNCTIONAL_JUDGE_V3_SINGLE_CANDIDATE_PLAN_COMPLETE",
        "claim": False,
        "scientific_claim_allowed": False,
        "calibration_id": spec["calibration_id"],
        "calibration_spec_sha256": _sha256_file(spec_path),
        "candidate_roles": spec["candidate_roles"],
        "evaluation_design": _EVALUATION_DESIGN,
        "purpose": spec["purpose"],
        "case_counts": {
            "total": 24,
            "tune": 8,
            "validation": 16,
            "families": 4,
            "pilot": 2,
            "remaining": 22,
        },
        "new_calls": {
            "functional_judge_provider_attempts": 0,
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
            "planner_provider_attempts": 0,
        },
        "source_final_delivery_sha256": spec["source_final_delivery_sha256"],
        "source_live_root_manifest_sha256": spec["source_live_root_manifest_sha256"],
        "source_live_root_provenance_sha256": spec["source_live_root_provenance_sha256"],
        "executable_source_spec_id": spec["executable_source_spec_id"],
        "executable_source_spec_sha256": spec["executable_source_spec_sha256"],
        "frozen_functional_contracts_sha256": spec["frozen_functional_contracts_sha256"],
        "functional_contract_set_sha256": spec["functional_contract_set_sha256"],
        "tune_overlay_root_manifest_sha256": overlay_manifest,
        "tune_overlay_evidence_manifest_sha256": evidence_manifest,
        "validation_cases_sha256": _sha256_file(validation_path),
        "provider_cases_sha256": canonical_sha256(cases),
        "case_metadata_sha256": canonical_sha256(metadata),
        "contracts_sha256": canonical_sha256(contracts),
        "pilot_case_ids": sorted(pilot_ids),
        "thresholds": spec["thresholds"],
        "fresh_holdout_authorities": {
            "paths": holdout["paths"],
            "sha256": holdout["sha256"],
            "validation_cases": 16,
            "exposed_tune_cases": 8,
            "prior_trace_reuse_allowed": False,
        },
    }
    plan = {
        **plan_core,
        "plan_id": "functional_judge_v3_single_candidate_plan_" + canonical_sha256(plan_core),
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    _write_jsonl(output_dir / "cases.jsonl", cases)
    _write_jsonl(output_dir / "pilot-cases.jsonl", pilot)
    _write_jsonl(output_dir / "remaining-cases.jsonl", remaining)
    _write_jsonl(output_dir / "calibration-case-metadata.jsonl", metadata)
    _write_jsonl(output_dir / "contracts.jsonl", contracts)
    _write_json(output_dir / "plan.json", plan)
    _write_json(
        output_dir / "environment.json",
        {
            "schema_version": "1.0",
            "captured_at_utc": _utc_now(),
            "working_directory": str(Path.cwd().resolve()),
            "python_executable": sys.executable,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "credential_value_read": False,
        },
    )
    _write_json(
        output_dir / "command.json",
        {
            "schema_version": "1.0",
            "argv": command_argv,
            "secret_in_argv": False,
            "provider_attempts": 0,
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
        },
    )
    write_closed_manifest_atomic(output_dir, label="v3 single-candidate plan")
    return plan


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        plan = _build_plan(_parse_args(raw_argv), raw_argv=raw_argv)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:  # noqa: BLE001 - publish only sanitized failure type
        raise SystemExit(f"v3 single-candidate planning failed: {type(error).__name__}") from None
    print(plan["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
