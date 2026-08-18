"""Zero-provider planning adapter for the bounded randomized exploratory Gate C canary."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.config import AppConfig, load_config, write_resolved_config
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.generation.request_planner import plan_confirmation_requests
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.oracle.policy import load_policy_bundle
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.experiments import (
    ArmRole,
    AssignmentRecord,
    ExperimentalUnit,
    PromptVariantRecord,
)
from secaware.schema.records import PromptRecord

_SCHEMA_VERSION = "1.0"
_ARMS = (
    ArmRole.TARGET_PATCH,
    ArmRole.NOOP_REWRITE,
    ArmRole.LENGTH_MATCHED_PLACEBO,
    ArmRole.GENERIC_SECURITY_REMINDER,
)
_ORACLE_UNKNOWN_MODE = "preserve_unknown_coverage"
_ORACLE_PROFILE_MODE = "profile_scoped_decision"
_GATE_B_EXACT_MAPPING = "exact_variant_id_v1"
_GATE_B_SEMANTIC_MAPPING = "task_arm_target_feature_v1"
_GATE_B_REVALIDATION_SCHEMA = "revalidation_v1"
_GATE_B_DIRECT_SCHEMA = "direct_exploratory_v1"
_TASK_SELECTION_BOUNDED_CANARY = "explicit_bounded_canary"
_TASK_SELECTION_ALL_GATE_B = "all_gate_b_tasks"


def _gate_b_artifact_schema(config: dict[str, Any]) -> str:
    value = config.get("gate_b_artifact_schema", _GATE_B_REVALIDATION_SCHEMA)
    if value not in {_GATE_B_REVALIDATION_SCHEMA, _GATE_B_DIRECT_SCHEMA}:
        raise ValueError("Gate C Gate B artifact schema failed validation")
    return str(value)


def _gate_b_mapping_policy(config: dict[str, Any]) -> str:
    value = config.get("gate_b_variant_mapping_policy", _GATE_B_EXACT_MAPPING)
    if value not in {_GATE_B_EXACT_MAPPING, _GATE_B_SEMANTIC_MAPPING}:
        raise ValueError("Gate C Gate A/B mapping policy failed validation")
    return str(value)


def _oracle_decision_mode(config: dict[str, Any]) -> str:
    profile_mode = config.get("oracle_decision_policy")
    legacy_mode = config.get("oracle_zero_finding_policy")
    if profile_mode is None and legacy_mode == _ORACLE_UNKNOWN_MODE:
        return _ORACLE_UNKNOWN_MODE
    if profile_mode == _ORACLE_PROFILE_MODE and legacy_mode is None:
        return _ORACLE_PROFILE_MODE
    raise ValueError("Gate C Oracle decision policy failed validation")


def _selected_task_ids(config: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    policy = config.get("task_selection_policy", _TASK_SELECTION_BOUNDED_CANARY)
    raw = config.get("selected_task_ids")
    if (
        policy not in {_TASK_SELECTION_BOUNDED_CANARY, _TASK_SELECTION_ALL_GATE_B}
        or type(raw) is not list
        or any(type(item) is not str or not item for item in raw)
    ):
        raise ValueError("Gate C task selection failed validation")
    selected = tuple(raw)
    valid_size = (
        2 <= len(selected) <= 5 if policy == _TASK_SELECTION_BOUNDED_CANARY else len(selected) == 51
    )
    if not valid_size or len(set(selected)) != len(selected):
        raise ValueError("Gate C task selection failed validation")
    return str(policy), selected


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("Gate C configuration failed validation")
    return value


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value) + b"\n")


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def _id(prefix: str, value: object) -> str:
    return prefix + canonical_sha256(value)


def _verify_closed_manifest(root: Path) -> None:
    manifest = _read_json(root / "artifact-manifest.json")
    entries = manifest.get("files")
    if manifest.get("schema_version") != _SCHEMA_VERSION or type(entries) is not list:
        raise ValueError("Gate C upstream manifest failed validation")
    expected: set[str] = set()
    for item in entries:
        if type(item) is not dict or type(item.get("path")) is not str:
            raise ValueError("Gate C upstream manifest failed validation")
        relative = Path(str(item["path"]))
        normalized = relative.as_posix()
        path = (root / relative).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError:
            raise ValueError("Gate C upstream manifest failed validation") from None
        if (
            relative.is_absolute()
            or normalized != item["path"]
            or normalized in expected
            or not path.is_file()
            or sha256_file(path) != item.get("sha256")
        ):
            raise ValueError("Gate C upstream manifest failed validation")
        expected.add(normalized)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "artifact-manifest.json"
    }
    if expected != actual:
        raise ValueError("Gate C upstream manifest closure failed validation")


def _validations(
    gate_b_dir: Path,
    *,
    identity_field: str = "variant_id",
    pattern: str = "*.json",
) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for path in sorted((gate_b_dir / "validation").glob(pattern)):
        item = _read_json(path)
        variant_id = item.get(identity_field)
        if type(variant_id) is not str or variant_id in records:
            raise ValueError("Gate C Gate B validation identity failed validation")
        records[variant_id] = item
    return records


def _direct_gate_b_records(
    gate_b_dir: Path,
    *,
    source_by_task: dict[str, PromptRecord],
) -> tuple[
    tuple[PromptRecord, ...],
    tuple[dict[str, Any], ...],
    tuple[dict[str, Any], ...],
    dict[str, dict[str, Any]],
]:
    _verify_closed_manifest(gate_b_dir)
    direct = tuple(read_jsonl(gate_b_dir / "llm-variants.jsonl", required=True, allow_empty=False))
    direct_by_variant: dict[str, dict[str, Any]] = {}
    for item in direct:
        variant_id = item.get("gate_a_variant_id")
        if type(variant_id) is not str or not variant_id or variant_id in direct_by_variant:
            raise ValueError("Gate C direct Gate B variant identity failed validation")
        direct_by_variant[variant_id] = item

    pairs: dict[str, tuple[Path, Path, dict[str, Any], dict[str, Any]]] = {}
    for request_path in sorted((gate_b_dir / "raw" / "intervention").glob("*.request.json")):
        response_path = request_path.with_name(
            request_path.name.removesuffix(".request.json") + ".response.json"
        )
        if not response_path.is_file():
            raise ValueError("Gate C direct Gate B intervention pair failed validation")
        request = _read_json(request_path)
        response = _read_json(response_path)
        variant_id = request.get("exploratory_variant_id")
        if type(variant_id) is not str or not variant_id or variant_id in pairs:
            raise ValueError("Gate C direct Gate B intervention pair failed validation")
        pairs[variant_id] = (request_path, response_path, request, response)
    if set(pairs) != set(direct_by_variant):
        raise ValueError("Gate C direct Gate B intervention coverage failed validation")

    validations = _validations(
        gate_b_dir,
        identity_field="gate_a_variant_id",
        pattern="record-*.json",
    )
    if set(validations) != set(direct_by_variant) or any(
        item.get("status") != "PASSED" for item in validations.values()
    ):
        raise ValueError("Gate C direct Gate B validation coverage failed validation")

    prompts: list[PromptRecord] = []
    provenance: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for variant_id, item in sorted(direct_by_variant.items()):
        task_id = str(item.get("task_id", ""))
        source = source_by_task.get(task_id)
        request_path, response_path, request, response = pairs[variant_id]
        candidate_text = _direct_candidate_text(
            source=source,
            variant=item,
            request=request,
            response=response,
        )
        if (
            source is None
            or candidate_text != item.get("prompt")
            or source.prompt_id != item.get("source_prompt_id")
            or source.prompt_sha256 != item.get("source_prompt_sha256")
            or request.get("source_prompt", {}).get("content") != source.prompt
            or request.get("source_prompt", {}).get("content_sha256") != source.prompt_sha256
            or request.get("arm_role") != item.get("arm_role")
            or request.get("exploratory_variant_id") != variant_id
            or hashlib.sha256(candidate_text.encode("utf-8")).hexdigest()
            != item.get("prompt_sha256")
        ):
            raise ValueError("Gate C direct Gate B Prompt provenance failed validation")
        prompt = PromptRecord.model_validate(
            {
                "prompt_id": item["blind_prompt_id"],
                "task_id": task_id,
                "split": "confirm",
                "language": source.language,
                "task_family": source.task_family,
                "cwe": source.cwe,
                "prompt": candidate_text,
                "prompt_role": "neutral_baseline",
                "counterpart_prompt_id": None,
            }
        )
        prompts.append(prompt)
        provenance.append(
            {
                **item,
                "variant_id": variant_id,
                "prompt_id": prompt.prompt_id,
                "intervention_request_sha256": sha256_file(request_path),
                "intervention_response_sha256": sha256_file(response_path),
            }
        )
        records.append(
            {
                "kind": "variant",
                "variant_id": variant_id,
                "proposal_id": item["proposal_id"],
                "graph_sha256": item["graph_sha256"],
            }
        )
    return tuple(prompts), tuple(provenance), tuple(records), validations


def _direct_candidate_text(
    *,
    source: PromptRecord | None,
    variant: Mapping[str, object],
    request: Mapping[str, object],
    response: Mapping[str, object],
) -> str | None:
    """Authenticate old full-candidate and new append-suffix Gate B envelopes."""

    output_mode = variant.get("intervention_output_mode", "full_candidate_text_v1")
    if output_mode == "full_candidate_text_v1":
        if frozenset(response) != {"candidate_text"}:
            return None
        candidate_text = response.get("candidate_text")
        return candidate_text if type(candidate_text) is str else None
    if output_mode != "append_suffix_v1" or source is None:
        return None
    if request.get("intervention_output_mode") != "append_suffix_v1" or frozenset(response) != {
        "append_suffix"
    }:
        return None
    suffix = response.get("append_suffix")
    if type(suffix) is not str or not suffix.strip() or suffix.startswith(source.prompt):
        return None
    return source.prompt + suffix


def _build_standard_records(
    *,
    gate_a_assignments: tuple[dict[str, Any], ...],
    gate_b_prompts: tuple[PromptRecord, ...],
    gate_b_provenance: tuple[dict[str, Any], ...],
    gate_b_records: tuple[dict[str, Any], ...],
    gate_b_validations: dict[str, dict[str, Any]],
    source_by_task: dict[str, PromptRecord],
    selected_task_ids: tuple[str, ...],
    model_id: str,
    randomization_plan_sha256: str,
    extractor_policy_sha256: str,
    gate_b_mapping_policy: str,
    target_feature_by_candidate: dict[str, str],
) -> tuple[
    tuple[AssignmentRecord, ...], tuple[PromptVariantRecord, ...], tuple[dict[str, object], ...]
]:
    expected_assignments = len(selected_task_ids) * len(_ARMS)
    prompt_by_id = {item.prompt_id: item for item in gate_b_prompts}
    provenance_by_variant = {str(item["variant_id"]): item for item in gate_b_provenance}
    provenance_by_coordinate: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in gate_b_provenance:
        coordinate = (
            str(item.get("task_id")),
            str(item.get("arm_role")),
            str(item.get("target_feature_id")),
        )
        if coordinate in provenance_by_coordinate:
            raise ValueError("Gate C Gate B semantic coordinate is not unique")
        provenance_by_coordinate[coordinate] = item
    record_by_variant = {
        str(item["variant_id"]): item for item in gate_b_records if item.get("kind") == "variant"
    }
    selected = tuple(
        item for item in gate_a_assignments if item.get("task_id") in selected_task_ids
    )
    if (
        len(selected) != expected_assignments
        or len({str(item["assignment_id"]) for item in selected}) != expected_assignments
    ):
        raise ValueError("Gate C inherited assignment coverage failed validation")
    variants: list[PromptVariantRecord] = []
    assignments: list[AssignmentRecord] = []
    mappings: list[dict[str, object]] = []
    coordinate_by_task: dict[str, dict[str, str]] = {}
    for inherited in selected:
        task_id = str(inherited["task_id"])
        gate_a_variant_id = str(inherited["variant_id"])
        candidate_id = str(inherited["candidate_id"])
        target_feature_id = target_feature_by_candidate.get(candidate_id)
        if target_feature_id is None:
            raise ValueError("Gate C Gate A candidate mapping failed validation")
        if gate_b_mapping_policy == _GATE_B_EXACT_MAPPING:
            provenance = provenance_by_variant.get(gate_a_variant_id)
        elif gate_b_mapping_policy == _GATE_B_SEMANTIC_MAPPING:
            provenance = provenance_by_coordinate.get(
                (task_id, str(inherited.get("arm_role")), target_feature_id)
            )
        else:  # pragma: no cover - validated by the public planner
            raise ValueError("Gate C Gate A/B mapping policy failed validation")
        exploratory_variant_id = "" if provenance is None else str(provenance.get("variant_id", ""))
        validation = gate_b_validations.get(exploratory_variant_id)
        record = record_by_variant.get(exploratory_variant_id)
        if (
            provenance is None
            or validation is None
            or record is None
            or validation.get("status") != "PASSED"
            or inherited.get("model_id") != model_id
            or provenance.get("task_id") != task_id
            or provenance.get("arm_role") != inherited.get("arm_role")
            or provenance.get("target_feature_id") != target_feature_id
        ):
            raise ValueError("Gate C Gate A/B mapping failed validation")
        prompt = prompt_by_id.get(str(provenance["prompt_id"]))
        source = source_by_task.get(task_id)
        if (
            prompt is None
            or source is None
            or prompt.prompt_sha256 != provenance.get("prompt_sha256")
        ):
            raise ValueError("Gate C variant Prompt provenance failed validation")
        coordinates = coordinate_by_task.setdefault(
            task_id,
            {
                "hypothesis_id": _id("hypothesis_", {"gate_c": "v1", "candidate_id": candidate_id}),
                "target_spec_id": _id(
                    "target_",
                    {
                        "gate_c": "v1",
                        "candidate_id": candidate_id,
                        "target_feature_id": provenance["target_feature_id"],
                    },
                ),
                "target_instance_id": _id(
                    "target_instance_",
                    {"gate_c": "v1", "task_id": task_id, "candidate_id": candidate_id},
                ),
                "arm_protocol_id": _id(
                    "arm_protocol_",
                    {
                        "gate_c": "v1",
                        "candidate_id": candidate_id,
                        "arm_roles": [item.value for item in _ARMS],
                    },
                ),
            },
        )
        coordinates["protocol_instance_id"] = _id(
            "protocol_instance_",
            {
                "gate_c": "v1",
                "task_id": task_id,
                "arm_protocol_id": coordinates["arm_protocol_id"],
            },
        )
        role = ArmRole(str(inherited["arm_role"]))
        length_match_id = (
            _id("length_match_", validation) if role is ArmRole.LENGTH_MATCHED_PLACEBO else None
        )
        standard_variant = PromptVariantRecord.from_content(
            task_id=task_id,
            source_prompt_id=source.prompt_id,
            language=prompt.language,
            variant_prompt_id=prompt.prompt_id,
            hypothesis_id=coordinates["hypothesis_id"],
            target_spec_id=coordinates["target_spec_id"],
            target_instance_id=coordinates["target_instance_id"],
            arm_protocol_id=coordinates["arm_protocol_id"],
            protocol_instance_id=coordinates["protocol_instance_id"],
            arm_role=role,
            prompt_sha256=prompt.prompt_sha256,
            prompt_text=prompt.prompt,
            proposal_id=str(record["proposal_id"]),
            graph_id="graph_" + str(record["graph_sha256"]),
            delta_id=_id("delta_", validation),
            executor_policy_sha256=canonical_sha256(
                {
                    "request_sha256": provenance["intervention_request_sha256"],
                    "response_sha256": provenance["intervention_response_sha256"],
                }
            ),
            extractor_policy_sha256=extractor_policy_sha256,
            length_match_id=length_match_id,
        )
        unit = ExperimentalUnit(
            task_id=task_id,
            hypothesis_id=coordinates["hypothesis_id"],
            target_spec_id=coordinates["target_spec_id"],
            model_id=model_id,
            seed_slot=int(inherited["seed_slot"]),
        )
        assignment = AssignmentRecord.from_content(
            block_id=AssignmentRecord.block_id_from_key(
                task_id,
                coordinates["hypothesis_id"],
                coordinates["target_spec_id"],
                coordinates["arm_protocol_id"],
                model_id,
            ),
            experimental_unit=unit,
            target_spec_id=coordinates["target_spec_id"],
            target_instance_id=coordinates["target_instance_id"],
            arm_protocol_id=coordinates["arm_protocol_id"],
            protocol_instance_id=coordinates["protocol_instance_id"],
            variant_id=standard_variant.variant_id,
            arm_role=role,
            seed_id=int(inherited["seed_id"]),
            rng_version="sha256-rejection-fisher-yates-v1",
            randomization_plan_sha256=randomization_plan_sha256,
        )
        variants.append(standard_variant)
        assignments.append(assignment)
        mappings.append(
            {
                "schema_version": _SCHEMA_VERSION,
                "task_id": task_id,
                "arm_role": role.value,
                "gate_a_assignment_id": inherited["assignment_id"],
                "gate_a_variant_id": gate_a_variant_id,
                "gate_b_variant_id": exploratory_variant_id,
                "assignment_id": assignment.assignment_id,
                "variant_id": standard_variant.variant_id,
                "seed_slot": unit.seed_slot,
                "seed_id": assignment.seed_id,
            }
        )
    if (
        len(assignments) != expected_assignments
        or len(variants) != expected_assignments
        or len({item.assignment_id for item in assignments}) != expected_assignments
        or len({item.variant_id for item in variants}) != expected_assignments
        or any(
            {item.arm_role for item in assignments if item.experimental_unit.task_id == task_id}
            != set(_ARMS)
            for task_id in selected_task_ids
        )
    ):
        raise ValueError("Gate C standard assignment block failed validation")
    return (
        tuple(
            sorted(
                assignments,
                key=lambda item: (item.experimental_unit.task_id, item.experimental_unit.seed_slot),
            )
        ),
        tuple(sorted(variants, key=lambda item: (item.task_id, item.arm_role.value))),
        tuple(sorted(mappings, key=lambda item: (str(item["task_id"]), int(item["seed_slot"])))),
    )


def plan_gate_c_canary(
    *,
    repo_root: Path,
    gate_c_config_path: Path,
    app_config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    config = _read_json(gate_c_config_path.resolve())
    app_config: AppConfig = load_config(app_config_path.resolve(), run_dir=output_dir)
    _write_json(output_dir / "effective-gate-c-config.json", config)
    write_resolved_config(app_config, output_dir / "effective-app-config.yaml")
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    oracle_decision_mode = _oracle_decision_mode(config)
    gate_b_mapping_policy = _gate_b_mapping_policy(config)
    gate_b_artifact_schema = _gate_b_artifact_schema(config)
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("inherit_gate_a_seed_slots") is not True
        or config.get("require_gate_b_pass") is not True
        or config.get("scientific_claim_allowed") is not False
        or config.get("scale_up_allowed") is not False
        or app_config.generation.provider != "openai_compatible"
        or app_config.generation.openai_compatible is None
        or len(app_config.generation.models) != 1
        or app_config.generation.openai_compatible.max_attempts != 1
        or not app_config.functional_judge.enabled
        or app_config.functional_judge.mode != "single_pass"
        or app_config.functional_judge.llm is None
        or app_config.functional_judge.llm.max_attempts != 1
    ):
        raise ValueError("Gate C policy failed validation")
    task_selection_policy, selected_task_ids = _selected_task_ids(config)
    expected_assignments = len(selected_task_ids) * len(_ARMS)
    if any(
        config.get(key) != expected_assignments
        for key in (
            "expected_assignments",
            "expected_generation_requests",
            "maximum_generation_provider_attempts",
            "maximum_functional_judge_provider_attempts",
        )
    ) or config.get("expected_blocks") != len(selected_task_ids):
        raise ValueError("Gate C configured assignment coverage failed validation")
    gate_a_dir = (repo_root / str(config["gate_a_dir"])).resolve()
    gate_b_dir = (repo_root / str(config["gate_b_dir"])).resolve()
    contracts_path = (repo_root / str(config["functional_contracts_path"])).resolve()
    for path in (gate_a_dir, gate_b_dir, contracts_path):
        path.relative_to(repo_root)
    gate_a_report = _read_json(gate_a_dir / "report.json")
    gate_b_report = _read_json(gate_b_dir / "report.json")
    expected_gate_b_status = (
        "GATE_B_PASSED"
        if gate_b_artifact_schema == _GATE_B_DIRECT_SCHEMA
        else "GATE_B_REEXTRACTION_PASSED"
    )
    if (
        gate_a_report.get("status") != "GATE_A_PASSED"
        or gate_b_report.get("status") != expected_gate_b_status
    ):
        raise ValueError("Gate C upstream gate dependency failed validation")
    gate_a_assignments = tuple(
        read_jsonl(gate_a_dir / "assignments.jsonl", required=True, allow_empty=False)
    )
    gate_a_candidates = tuple(
        read_jsonl(gate_a_dir / "candidates.jsonl", required=True, allow_empty=False)
    )
    sources = tuple(
        read_jsonl(
            gate_b_dir / "source-prompts.jsonl",
            PromptRecord,
            required=True,
            allow_empty=False,
        )
    )
    source_by_task = {item.task_id: item for item in sources}
    if len(source_by_task) != len(sources):
        raise ValueError("Gate C source Prompt identity failed validation")
    if any(task_id not in source_by_task for task_id in selected_task_ids) or (
        task_selection_policy == _TASK_SELECTION_ALL_GATE_B
        and (
            set(selected_task_ids) != set(source_by_task)
            or len({item.cwe for item in sources}) != 5
        )
    ):
        raise ValueError("Gate C task selection failed validation")
    if gate_b_artifact_schema == _GATE_B_DIRECT_SCHEMA:
        prompts, provenance, records, validations = _direct_gate_b_records(
            gate_b_dir,
            source_by_task=source_by_task,
        )
        gate_b_variants_path = gate_b_dir / "llm-variants.jsonl"
    else:
        prompts = tuple(
            read_jsonl(
                gate_b_dir / "variant-prompts.jsonl",
                PromptRecord,
                required=True,
                allow_empty=False,
            )
        )
        provenance = tuple(
            read_jsonl(
                gate_b_dir / "frozen-variant-provenance.jsonl",
                required=True,
                allow_empty=False,
            )
        )
        records = tuple(read_jsonl(gate_b_dir / "records.jsonl", required=True, allow_empty=False))
        validations = _validations(gate_b_dir)
        gate_b_variants_path = gate_b_dir / "variant-prompts.jsonl"
    target_feature_by_candidate: dict[str, str] = {}
    for item in gate_a_candidates:
        candidate_id = item.get("candidate_id")
        target_feature_id = item.get("target_feature_id")
        if (
            type(candidate_id) is not str
            or not candidate_id
            or type(target_feature_id) is not str
            or not target_feature_id
            or candidate_id in target_feature_by_candidate
        ):
            raise ValueError("Gate C Gate A candidate mapping failed validation")
        target_feature_by_candidate[candidate_id] = target_feature_id
    all_contracts = tuple(
        read_jsonl(
            contracts_path,
            TaskFunctionalContractRecord,
            required=True,
            allow_empty=False,
        )
    )
    all_contract_by_task = {item.task_id: item for item in all_contracts}
    if len(all_contract_by_task) != len(all_contracts) or any(
        task_id not in all_contract_by_task for task_id in selected_task_ids
    ):
        raise ValueError("Gate C functional contract identity failed validation")
    contracts = tuple(all_contract_by_task[task_id] for task_id in selected_task_ids)
    contract_by_task = {item.task_id: item for item in contracts}
    if set(contract_by_task) != set(selected_task_ids) or any(
        contract_by_task[task_id].source_prompt_sha256 != source_by_task[task_id].prompt_sha256
        for task_id in selected_task_ids
    ):
        raise ValueError("Gate C functional contract coverage failed validation")
    model_id = app_config.generation.models[0]
    assignments, variants, mappings = _build_standard_records(
        gate_a_assignments=gate_a_assignments,
        gate_b_prompts=prompts,
        gate_b_provenance=provenance,
        gate_b_records=records,
        gate_b_validations=validations,
        source_by_task=source_by_task,
        selected_task_ids=selected_task_ids,
        model_id=model_id,
        randomization_plan_sha256=sha256_file(gate_a_dir / "assignments.jsonl"),
        extractor_policy_sha256=str(gate_b_report["policy_digests"]["extractor_policy_sha256"]),
        gate_b_mapping_policy=gate_b_mapping_policy,
        target_feature_by_candidate=target_feature_by_candidate,
    )
    requests = tuple(plan_confirmation_requests(assignments, variants, app_config.generation))
    if (
        len(assignments) != config.get("expected_assignments")
        or len({item.block_id for item in assignments}) != config.get("expected_blocks")
        or len(requests) != config.get("expected_generation_requests")
        or len(requests) > config.get("maximum_generation_provider_attempts")
        or len(requests) > config.get("maximum_functional_judge_provider_attempts")
        or len({item.request_id for item in requests}) != len(requests)
    ):
        raise ValueError("Gate C provider budget failed validation")
    policy = load_policy_bundle((repo_root / app_config.oracle.policy_lock_path).resolve())
    profile_by_id = {item.profile_id: item for item in policy.coverage_profiles}
    coverage_rows: list[dict[str, object]] = []
    for task_id in selected_task_ids:
        source = source_by_task[task_id]
        profile = profile_by_id.get(str(source.oracle_profile_id))
        if (
            profile is None
            or profile.cwe != source.cwe
            or source.task_family not in profile.task_families
        ):
            raise ValueError("Gate C Oracle profile scope failed validation")
        coverage_rows.append(
            {
                "schema_version": _SCHEMA_VERSION,
                "task_id": task_id,
                "prompt_id": source.prompt_id,
                "oracle_profile_id": profile.profile_id,
                "cwe": profile.cwe,
                "zero_finding_supported": profile.zero_finding_supported,
                "zero_finding_interpretation": (
                    _ORACLE_PROFILE_MODE
                    if oracle_decision_mode == _ORACLE_PROFILE_MODE
                    else "secure"
                    if profile.zero_finding_supported
                    else "unknown_coverage"
                ),
                "decision_backend": profile.decision_backend,
                "analyzer_rule_ids": list(profile.analyzer_rule_ids),
            }
        )
    if oracle_decision_mode == _ORACLE_UNKNOWN_MODE:
        if any(item["zero_finding_interpretation"] != "unknown_coverage" for item in coverage_rows):
            raise ValueError("Gate C zero-finding policy failed validation")
    elif any(
        item["zero_finding_interpretation"] != _ORACLE_PROFILE_MODE
        or item["zero_finding_supported"] is not True
        or item["decision_backend"] != "python_ast_mechanism_v1"
        for item in coverage_rows
    ):
        raise ValueError("Gate C profile-scoped Oracle policy failed validation")
    write_jsonl(output_dir / "assignments.jsonl", assignments)
    write_jsonl(output_dir / "prompt-variants.jsonl", variants)
    write_jsonl(output_dir / "generation-requests.jsonl", requests)
    write_jsonl(output_dir / "gate-a-b-mapping.jsonl", mappings)
    write_jsonl(output_dir / "task-functional-contracts.jsonl", contracts)
    write_jsonl(output_dir / "oracle-coverage.jsonl", coverage_rows)
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "gate_c_id": config["gate_c_id"],
        "status": "GATE_C_PLAN_COMPLETE",
        "provider_calls_allowed": False,
        "oracle_execution_allowed": False,
        "oracle_decision_policy": oracle_decision_mode,
        "gate_b_variant_mapping_policy": gate_b_mapping_policy,
        "gate_b_artifact_schema": gate_b_artifact_schema,
        "task_selection_policy": task_selection_policy,
        "scientific_claim_allowed": False,
        "scale_up_allowed": False,
        "counts": {
            "independent_tasks": len(selected_task_ids),
            "blocks": len({item.block_id for item in assignments}),
            "assignments": len(assignments),
            "prompt_variants": len(variants),
            "generation_requests": len(requests),
            "maximum_generation_provider_attempts": int(
                config["maximum_generation_provider_attempts"]
            ),
            "maximum_functional_judge_provider_attempts": int(
                config["maximum_functional_judge_provider_attempts"]
            ),
            "functional_contracts": len(contracts),
            "oracle_profiles": len(coverage_rows),
            "zero_finding_unknown_profiles": sum(
                item["zero_finding_interpretation"] == "unknown_coverage" for item in coverage_rows
            ),
            "profile_scoped_decision_profiles": sum(
                item["zero_finding_interpretation"] == _ORACLE_PROFILE_MODE
                for item in coverage_rows
            ),
            "errors": 0,
            "pending_generation": len(requests),
        },
        "models": {
            "code_generator": model_id,
            "functional_judge": app_config.functional_judge.llm.model_id,
        },
        "input_digests": {
            "gate_c_config_sha256": sha256_file(gate_c_config_path),
            "app_config_sha256": sha256_file(app_config_path),
            "gate_a_assignments_sha256": sha256_file(gate_a_dir / "assignments.jsonl"),
            "gate_b_report_sha256": sha256_file(gate_b_dir / "report.json"),
            "gate_b_variants_sha256": sha256_file(gate_b_variants_path),
            "functional_contracts_sha256": sha256_file(contracts_path),
            "oracle_policy_sha256": policy.combined_sha256,
        },
    }
    _write_json(output_dir / "report.json", report)
    files = sorted(path for path in output_dir.rglob("*") if path.is_file())
    _write_json(
        output_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {
                    "path": path.relative_to(output_dir).as_posix(),
                    "sha256": sha256_file(path),
                }
                for path in files
            ],
        },
    )
    return report


__all__ = ["plan_gate_c_canary"]
