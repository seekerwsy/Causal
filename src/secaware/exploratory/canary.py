"""Zero-provider Gate A for randomized exploratory Prompt-feature variation."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.config import TSGConfig
from secaware.extractors.deterministic_catalog import DeterministicCatalogExtractor
from secaware.extractors.factory import extraction_policy
from secaware.intervention.arm_catalog import materialize_safety_arm_specs
from secaware.intervention.executors import DETERMINISTIC_INTERVENTION_POLICY_SHA256
from secaware.intervention.variant_validation import blind_variant_prompt_record_from_text
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.randomness import RNG_VERSION, DeterministicRNG
from secaware.schema.experiments import ArmRole
from secaware.schema.features import (
    FeatureFamily,
    FeatureOperation,
    FeatureState,
    PromptExtractorBackend,
)
from secaware.schema.records import PromptRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
    prompt_feature_spec,
)
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.queries import feature_state_vector

_SCHEMA_VERSION = "1.0"
_RENDERER_ID = "exploratory-deterministic-catalog-adapter-v1"
_ARMS = (
    ArmRole.TARGET_PATCH,
    ArmRole.NOOP_REWRITE,
    ArmRole.LENGTH_MATCHED_PLACEBO,
    ArmRole.GENERIC_SECURITY_REMINDER,
)
_SAFETY_SENTINELS = (
    "safety.prohibited_unsafe_request",
    "safety.vulnerability_disclosure",
    "safety.expected_outcome_leakage",
)


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
        raise ValueError("exploratory canary configuration failed validation")
    return value


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _id(prefix: str, payload: object) -> str:
    return prefix + canonical_sha256(payload)


def _renderer_policy_sha256(config: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "renderer_id": _RENDERER_ID,
            "base_confirmation_renderer_sha256": DETERMINISTIC_INTERVENTION_POLICY_SHA256,
            "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
            "renderer_config": config,
        }
    )


def _matched_clause(feature_id: str, reference_bytes: int) -> str:
    spec = prompt_feature_spec(feature_id)
    if (
        feature_id != "presentation.length_matched_placebo"
        or not spec.intervenable
        or not spec.intervention_clauses
        or type(reference_bytes) is not int
        or reference_bytes <= 0
    ):
        raise ValueError("exploratory canary renderer failed validation")
    tolerance = max(4, math.ceil(reference_bytes * 0.05))
    selected = min(
        enumerate(spec.intervention_clauses),
        key=lambda item: (abs(len(item[1].encode("utf-8")) - reference_bytes), item[0]),
    )[1]
    if abs(len(selected.encode("utf-8")) - reference_bytes) > tolerance:
        raise ValueError("exploratory canary renderer failed validation")
    return selected


def _render_text(source: str, target_feature_id: str, role: ArmRole) -> str:
    target_clause = prompt_feature_spec(target_feature_id).intervention_clauses
    if len(target_clause) != 1:
        raise ValueError("exploratory canary renderer failed validation")
    if role is ArmRole.TARGET_PATCH:
        return source + target_clause[0]
    if role is ArmRole.NOOP_REWRITE:
        return source + "\n"
    if role is ArmRole.LENGTH_MATCHED_PLACEBO:
        return source + _matched_clause(
            "presentation.length_matched_placebo",
            len(target_clause[0].encode("utf-8")),
        )
    if role is ArmRole.GENERIC_SECURITY_REMINDER:
        clauses = prompt_feature_spec("safety.generic_security_reminder").intervention_clauses
        if len(clauses) != 1:
            raise ValueError("exploratory canary renderer failed validation")
        return source + clauses[0]
    raise ValueError("exploratory canary renderer failed validation")


def _state_map(graph_record: object) -> dict[str, FeatureState]:
    graph = record_to_multidigraph(graph_record)
    return dict(feature_state_vector(graph))


def _validate_delta(
    source_states: dict[str, FeatureState],
    variant_states: dict[str, FeatureState],
    *,
    target_feature_id: str,
    role: ArmRole,
    arm: object,
) -> tuple[tuple[str, ...], bool]:
    allowed = {
        transition.feature_id: (transition.from_states, transition.to_states)
        for transition in arm.allowed_delta.allowed_transitions
    }
    changed = tuple(
        sorted(
            feature_id
            for feature_id in source_states
            if source_states[feature_id] is not variant_states[feature_id]
        )
    )
    for feature_id in changed:
        transition = allowed.get(feature_id)
        if transition is None or transition != (
            (source_states[feature_id],),
            (variant_states[feature_id],),
        ):
            raise ValueError("exploratory canary AllowedDelta failed validation")
    if any(variant_states[item] is not FeatureState.ABSENT for item in _SAFETY_SENTINELS):
        raise ValueError("exploratory canary security neutrality failed validation")
    expected_changed = {
        ArmRole.NOOP_REWRITE: (),
        ArmRole.LENGTH_MATCHED_PLACEBO: ("presentation.length_matched_placebo",),
        ArmRole.GENERIC_SECURITY_REMINDER: ("safety.generic_security_reminder",),
    }.get(role)
    if role is ArmRole.TARGET_PATCH:
        if changed not in {(), (target_feature_id,)}:
            raise ValueError("exploratory canary realized feature delta failed validation")
        target_recognized = variant_states[target_feature_id] is FeatureState.PRESENT
    elif expected_changed is None or changed != expected_changed:
        raise ValueError("exploratory canary realized feature delta failed validation")
    else:
        target_recognized = False
    if role is not ArmRole.TARGET_PATCH and (
        variant_states[target_feature_id] is not FeatureState.ABSENT
    ):
        raise ValueError("exploratory canary target feature state failed validation")
    return changed, target_recognized


def _selection_maps_for_split(
    selection: dict[str, Any],
    *,
    selected_split: str,
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    if selected_split not in {"discover", "confirm"}:
        raise ValueError("exploratory canary selected split failed validation")
    tasks = selection.get("tasks")
    if type(tasks) is not list or not tasks:
        raise ValueError("exploratory canary selection failed validation")
    discover: dict[str, dict[str, Any]] = {}
    confirm_ids: set[str] = set()
    discover_clusters: set[str] = set()
    confirm_clusters: set[str] = set()
    for task in tasks:
        if type(task) is not dict:
            raise ValueError("exploratory canary selection failed validation")
        task_id = task.get("task_id", task.get("task_cluster_id"))
        cluster_id = task.get("task_cluster_id")
        split = task.get("split")
        if (
            type(task_id) is not str
            or not task_id
            or type(cluster_id) is not str
            or not cluster_id
            or split not in {"discover", "confirm"}
        ):
            raise ValueError("exploratory canary selection failed validation")
        if split == "discover":
            if task_id in discover or cluster_id in discover_clusters:
                raise ValueError("exploratory canary selection failed validation")
            discover[task_id] = task
            discover_clusters.add(cluster_id)
        else:
            if task_id in confirm_ids or cluster_id in confirm_clusters:
                raise ValueError("exploratory canary selection failed validation")
            confirm_ids.add(task_id)
            confirm_clusters.add(cluster_id)
    if not discover or set(discover) & confirm_ids or discover_clusters & confirm_clusters:
        raise ValueError("exploratory canary split isolation failed validation")
    if selected_split == "discover":
        return discover, confirm_ids
    confirm = {str(task["task_id"]): task for task in tasks if task.get("split") == "confirm"}
    return confirm, set(discover)


def _selection_maps(selection: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Preserve the original discovery-selection helper for existing callers."""

    return _selection_maps_for_split(selection, selected_split="discover")


def _candidate_for_task(
    task: dict[str, Any],
    candidate_config: list[dict[str, Any]],
    *,
    selection_sha256: str,
) -> dict[str, Any]:
    matches = [item for item in candidate_config if item.get("cwe") == task.get("cwe")]
    if len(matches) != 1:
        raise ValueError("exploratory canary candidate scope failed validation")
    item = matches[0]
    feature_id = item.get("target_feature_id")
    operation = item.get("operation")
    if type(feature_id) is not str or operation != FeatureOperation.ADD.value:
        raise ValueError("exploratory canary candidate failed validation")
    spec = prompt_feature_spec(feature_id)
    if (
        spec.feature_family is not FeatureFamily.SAFETY_CONTROL
        or task.get("cwe") not in spec.applicable_cwes
        or task.get("task_family") not in spec.applicable_task_families
        or FeatureOperation.ADD not in spec.operations
    ):
        raise ValueError("exploratory canary candidate applicability failed validation")
    content = {
        "schema_version": _SCHEMA_VERSION,
        "selection_sha256": selection_sha256,
        "scope_id": f"scope.cwe_{str(task['cwe']).removeprefix('CWE-')}",
        "cwe": task["cwe"],
        "task_family": task["task_family"],
        "feature_family": spec.feature_family.value,
        "target_feature_id": feature_id,
        "operation": FeatureOperation.ADD.value,
        "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        "status": "preregistered_engineering_candidate",
    }
    return {"candidate_id": _id("exploratory_candidate_", content), **content}


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def build_randomized_exploratory_canary(
    *,
    repo_root: Path,
    config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Build and validate the zero-provider exploratory-discovery canary artifacts."""

    repo_root = repo_root.resolve()
    config_path = config_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    config = _read_json(config_path)
    _write_json(output_dir / "effective-config.json", config)
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    try:
        if (
            config.get("schema_version") != _SCHEMA_VERSION
            or config.get("gate") != "zero_provider_contract"
            or config.get("allowed_source_split") not in {"discover", "confirm"}
            or config.get("allow_outcome_generation") is not False
            or config.get("rng_version") != RNG_VERSION
        ):
            raise ValueError("exploratory canary policy failed validation")
        selection_path = (repo_root / str(config["selection_path"])).resolve()
        prompts_path = (repo_root / str(config["prompts_path"])).resolve()
        selection_path.relative_to(repo_root)
        prompts_path.relative_to(repo_root)
        selection = _read_json(selection_path)
        selected_split = str(config["allowed_source_split"])
        selected_tasks, forbidden_task_ids = _selection_maps_for_split(
            selection,
            selected_split=selected_split,
        )
        expected_count_key = (
            "expected_discover_tasks" if selected_split == "discover" else "expected_confirm_tasks"
        )
        if len(selected_tasks) != int(config.get(expected_count_key, -1)):
            raise ValueError("exploratory canary task count failed validation")
        prompts = tuple(read_jsonl(prompts_path, PromptRecord, required=True, allow_empty=False))
        source_by_task = {
            item.task_id: item
            for item in prompts
            if item.split == selected_split and item.prompt_role.value == "neutral_baseline"
        }
        if set(source_by_task) != set(selected_tasks) or set(source_by_task) & forbidden_task_ids:
            raise ValueError("exploratory canary Prompt split failed validation")
        selection_sha256 = sha256_file(selection_path)
        input_prompts_sha256 = sha256_file(prompts_path)
        candidate_config = config.get("candidates")
        selected_cwes = {str(item["cwe"]) for item in selected_tasks.values()}
        if (
            type(candidate_config) is not list
            or len(candidate_config) != len(selected_cwes)
            or {str(item.get("cwe")) for item in candidate_config if type(item) is dict}
            != selected_cwes
        ):
            raise ValueError("exploratory canary candidate budget failed validation")
        candidates_by_cwe: dict[str, dict[str, Any]] = {}
        for task in selected_tasks.values():
            candidate = _candidate_for_task(
                task,
                candidate_config,
                selection_sha256=selection_sha256,
            )
            existing = candidates_by_cwe.setdefault(candidate["cwe"], candidate)
            if existing != candidate:
                raise ValueError("exploratory canary candidate closure failed validation")
        model_id = config.get("model_id")
        seed_ids = config.get("seed_ids")
        if (
            type(model_id) is not str
            or type(seed_ids) is not list
            or len(seed_ids) != len(_ARMS)
            or any(type(item) is not int for item in seed_ids)
            or len(set(seed_ids)) != len(seed_ids)
        ):
            raise ValueError("exploratory canary assignment coordinates failed validation")
        configured_arms = tuple(ArmRole(item) for item in config.get("arm_roles", ()))
        if configured_arms != _ARMS:
            raise ValueError("exploratory canary arm protocol failed validation")
        renderer_config = config.get("renderer")
        if type(renderer_config) is not dict or renderer_config.get("id") != _RENDERER_ID:
            raise ValueError("exploratory canary renderer policy failed validation")
        renderer_policy_sha256 = _renderer_policy_sha256(renderer_config)
        policy = extraction_policy(
            TSGConfig(prompt_extractor=PromptExtractorBackend.DETERMINISTIC_CATALOG_V1)
        )
        extractor = DeterministicCatalogExtractor()
        candidates = tuple(sorted(candidates_by_cwe.values(), key=lambda item: item["cwe"]))
        source_prompts: list[PromptRecord] = []
        proposals: list[object] = []
        graphs: list[object] = []
        variants: list[dict[str, Any]] = []
        variant_by_key: dict[tuple[str, str], dict[str, Any]] = {}
        state_rows: list[dict[str, object]] = []
        for task_id in sorted(selected_tasks):
            task = selected_tasks[task_id]
            source = source_by_task[task_id]
            source_prompts.append(source)
            candidate = candidates_by_cwe[str(task["cwe"])]
            target_feature_id = str(candidate["target_feature_id"])
            arm_specs = materialize_safety_arm_specs(
                target_feature_id,
                FeatureOperation.ADD,
            )
            arm_by_role = {item.role: item for item in arm_specs}
            if tuple(item.role for item in arm_specs) != _ARMS:
                raise ValueError("exploratory canary reused arm order failed validation")
            source_proposal = extractor.extract(source, policy)
            source_graph = build_prompt_tsg(source_proposal, source)
            source_states = _state_map(source_graph)
            if source_states[target_feature_id] is not FeatureState.ABSENT:
                raise ValueError("exploratory canary source target state failed validation")
            for role in _ARMS:
                text = _render_text(source.prompt, target_feature_id, role)
                blind_prompt = blind_variant_prompt_record_from_text(source, text, policy)
                proposal = extractor.extract(blind_prompt, policy)
                graph_record = build_prompt_tsg(proposal, blind_prompt)
                variant_states = _state_map(graph_record)
                changed, target_recognized = _validate_delta(
                    source_states,
                    variant_states,
                    target_feature_id=target_feature_id,
                    role=role,
                    arm=arm_by_role[role],
                )
                content = {
                    "schema_version": _SCHEMA_VERSION,
                    "candidate_id": candidate["candidate_id"],
                    "task_id": task_id,
                    "source_prompt_id": source.prompt_id,
                    "source_prompt_sha256": source.prompt_sha256,
                    "cwe": source.cwe,
                    "task_family": source.task_family,
                    "target_feature_id": target_feature_id,
                    "operation": FeatureOperation.ADD.value,
                    "arm_role": role.value,
                    "renderer_id": _RENDERER_ID,
                    "renderer_policy_sha256": renderer_policy_sha256,
                    "prompt": text,
                    "prompt_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    "blind_prompt_id": blind_prompt.prompt_id,
                    "blind_extractor_policy_sha256": policy.policy_sha256,
                    "allowed_delta": arm_by_role[role].allowed_delta.model_dump(mode="json"),
                    "realized_changed_feature_ids": list(changed),
                    "deterministic_target_recognized": target_recognized,
                    "outcome_generation_allowed": False,
                }
                variant = {
                    "variant_id": _id(
                        "exploratory_variant_",
                        {key: value for key, value in content.items() if key != "prompt"},
                    ),
                    **content,
                }
                key = (task_id, role.value)
                if key in variant_by_key:
                    raise ValueError("exploratory canary variant uniqueness failed validation")
                variant_by_key[key] = variant
                variants.append(variant)
                proposals.append(proposal)
                graphs.append(graph_record)
                state_rows.append(
                    {
                        "variant_id": variant["variant_id"],
                        "task_id": task_id,
                        "cwe": source.cwe,
                        "arm_role": role.value,
                        "target_feature_id": target_feature_id,
                        "target_feature_state": variant_states[target_feature_id].value,
                        "intended_target_feature_state": (
                            FeatureState.PRESENT.value
                            if role is ArmRole.TARGET_PATCH
                            else FeatureState.ABSENT.value
                        ),
                        "deterministic_target_recognized": target_recognized,
                        "feature_states": {
                            item.feature_id: variant_states[item.feature_id].value
                            for item in PROMPT_FEATURE_CATALOG
                        },
                    }
                )
        expected_variants = len(selected_tasks) * len(_ARMS)
        if len(variants) != expected_variants or len(variant_by_key) != expected_variants:
            raise ValueError("exploratory canary variant coverage failed validation")
        assignments: list[dict[str, object]] = []
        global_seed = config.get("global_seed")
        if type(global_seed) is not int:
            raise ValueError("exploratory canary global seed failed validation")
        for task_id in sorted(selected_tasks):
            candidate = candidates_by_cwe[str(selected_tasks[task_id]["cwe"])]
            seed_material = {
                "schema_version": _SCHEMA_VERSION,
                "rng_version": RNG_VERSION,
                "global_seed": global_seed,
                "task_id": task_id,
                "candidate_id": candidate["candidate_id"],
                "model_id": model_id,
            }
            permutation = DeterministicRNG(_canonical(seed_material)).shuffle(_ARMS)
            block_content = {
                "task_id": task_id,
                "candidate_id": candidate["candidate_id"],
                "model_id": model_id,
                "rng_version": RNG_VERSION,
            }
            block_id = _id("exploratory_block_", block_content)
            for seed_slot, (seed_id, role) in enumerate(zip(seed_ids, permutation, strict=True)):
                variant = variant_by_key[(task_id, role.value)]
                content = {
                    "schema_version": _SCHEMA_VERSION,
                    "block_id": block_id,
                    "task_id": task_id,
                    "candidate_id": candidate["candidate_id"],
                    "model_id": model_id,
                    "seed_slot": seed_slot,
                    "seed_id": seed_id,
                    "arm_role": role.value,
                    "context_variable_id": "c.exploratory_arm",
                    "context_value": role.value,
                    "variant_id": variant["variant_id"],
                    "rng_version": RNG_VERSION,
                    "seed_material_sha256": canonical_sha256(seed_material),
                    "outcome_generation_allowed": False,
                }
                assignments.append(
                    {"assignment_id": _id("exploratory_assignment_", content), **content}
                )
        block_counts = Counter(item["block_id"] for item in assignments)
        if set(block_counts.values()) != {len(_ARMS)}:
            raise ValueError("exploratory canary block balance failed validation")
        for block_id in block_counts:
            roles = {item["arm_role"] for item in assignments if item["block_id"] == block_id}
            if roles != {item.value for item in _ARMS}:
                raise ValueError("exploratory canary arm balance failed validation")
        write_jsonl(output_dir / "source-prompts.jsonl", source_prompts)
        write_jsonl(output_dir / "candidates.jsonl", candidates)
        write_jsonl(
            output_dir / "variants.jsonl",
            sorted(variants, key=lambda item: (item["task_id"], item["arm_role"])),
        )
        write_jsonl(
            output_dir / "assignments.jsonl",
            sorted(assignments, key=lambda item: (item["block_id"], item["seed_slot"])),
        )
        write_jsonl(
            output_dir / "deterministic-extraction-proposals.jsonl",
            sorted(proposals, key=lambda item: item.prompt_id),
        )
        write_jsonl(
            output_dir / "deterministic-prompt-tsg.jsonl",
            sorted(graphs, key=lambda item: item.prompt_id),
        )
        write_jsonl(
            output_dir / "feature-states.jsonl",
            sorted(state_rows, key=lambda item: (item["task_id"], item["arm_role"])),
        )
        feature_distribution: dict[str, dict[str, int]] = {}
        for row in state_rows:
            key = f"{row['cwe']}:{row['target_feature_id']}"
            local = feature_distribution.setdefault(key, {state.value: 0 for state in FeatureState})
            local[str(row["target_feature_state"])] += 1
        deterministic_target_recognized = sum(
            bool(row["deterministic_target_recognized"])
            for row in state_rows
            if row["arm_role"] == ArmRole.TARGET_PATCH.value
        )
        report: dict[str, object] = {
            "schema_version": _SCHEMA_VERSION,
            "canary_id": config.get("canary_id"),
            "status": "GATE_A_PASSED",
            "gate": "zero_provider_contract",
            "scientific_claim_allowed": False,
            "outcome_generation_allowed": False,
            "counts": {
                "independent_tasks": len(selected_tasks),
                (
                    "confirm_task_ids_excluded"
                    if selected_split == "discover"
                    else "discover_task_ids_excluded"
                ): len(forbidden_task_ids),
                "candidates": len(candidates),
                "variants": len(variants),
                "blocks": len(block_counts),
                "assignments": len(assignments),
                "extraction_proposals": len(proposals),
                "prompt_tsgs": len(graphs),
                "deterministic_target_recognized": deterministic_target_recognized,
                "deterministic_target_expected": len(selected_tasks),
                "errors": 0,
                "pending": 0,
            },
            "input_digests": {
                "config_sha256": sha256_file(config_path),
                "selection_sha256": selection_sha256,
                "prompts_sha256": input_prompts_sha256,
                "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
                "renderer_policy_sha256": renderer_policy_sha256,
                "extractor_policy_sha256": policy.policy_sha256,
            },
            "feature_distribution": feature_distribution,
            "deterministic_extractor_gate_role": "diagnostic_only",
            "next_gate": "blind_llm_intervention_and_extraction",
        }
        _write_json(output_dir / "report.json", report)
        artifact_names = tuple(sorted(path.name for path in output_dir.iterdir() if path.is_file()))
        artifact_manifest = {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {"path": name, "sha256": sha256_file(output_dir / name)} for name in artifact_names
            ],
        }
        _write_json(output_dir / "artifact-manifest.json", artifact_manifest)
        return report
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:
        _write_json(
            output_dir / "failure.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "status": "GATE_A_FAILED",
                "error_type": type(error).__name__,
                "message": str(error),
            },
        )
        raise


__all__ = ["build_randomized_exploratory_canary"]
