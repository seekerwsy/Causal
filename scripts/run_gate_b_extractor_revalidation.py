"""Plan or run bounded Gate B re-extraction over frozen intervention texts."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import sys
from typing import Any

from secaware.config import load_config, write_resolved_config
from secaware.exploratory.gate_b import (
    PLACEBO_LENGTH_POLICY_VERSION,
    _parse_response,
    _validate_llm_delta,
    validate_length_matched_placebo,
)
from secaware.extractors.factory import extraction_policy, structured_policy_for_config
from secaware.extractors.llm_facts import (
    LLM_FACTS_CRITERIA_PROJECTION_VERSION,
    LLM_FACTS_SYSTEM_TEMPLATE,
    facts_request_payload,
    parse_facts_response,
)
from secaware.intervention.variant_validation import blind_variant_prompt_record_from_text
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.llm.structured_transport import (
    OpenAICompatibleStructuredTransport,
    canonical_request_bytes,
)
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.experiments import AllowedDeltaRecord, ArmRole
from secaware.schema.features import FeatureState
from secaware.schema.records import PromptRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.queries import feature_state_vector


_SCHEMA_VERSION = "1.0"
_FORBIDDEN_REQUEST_KEYS = frozenset(
    {"experiment_arm", "generated_code", "oracle", "outcome", "expected_result"}
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
        raise ValueError("Gate B extractor revalidation input failed validation")
    return value


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value) + b"\n")


def _validate_prior_failure(
    failure: dict[str, Any],
    expected_failure_message: object,
) -> None:
    if (
        type(expected_failure_message) is not str
        or not expected_failure_message
        or failure.get("status") != "GATE_B_FAILED"
        or expected_failure_message not in str(failure.get("message"))
    ):
        raise ValueError("Gate B failed-attempt provenance failed validation")


def _load_env_file(path: Path) -> None:
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip()


def _artifact_stem(label: str) -> str:
    if len(label) <= 72 and all(character.isalnum() or character in "-_" for character in label):
        return label
    return "record-" + hashlib.sha256(label.encode("utf-8")).hexdigest()[:32]


def _recursive_keys(value: object) -> set[str]:
    if type(value) is dict:
        result = set(value)
        for item in value.values():
            result.update(_recursive_keys(item))
        return result
    if type(value) is list:
        result: set[str] = set()
        for item in value:
            result.update(_recursive_keys(item))
        return result
    return set()


def _state_map(graph_record: object) -> dict[str, FeatureState]:
    return dict(feature_state_vector(record_to_multidigraph(graph_record)))


def _intervention_pairs(root: Path) -> dict[str, tuple[Path, Path, dict[str, Any]]]:
    channel = root / "raw" / "intervention"
    result: dict[str, tuple[Path, Path, dict[str, Any]]] = {}
    for request_path in sorted(channel.glob("*.request.json")):
        response_path = request_path.with_name(
            request_path.name.removesuffix(".request.json") + ".response.json"
        )
        if not response_path.is_file():
            raise ValueError("Gate B intervention request/response pair is incomplete")
        payload = _read_json(request_path)
        variant_id = payload.get("exploratory_variant_id")
        if type(variant_id) is not str or not variant_id or variant_id in result:
            raise ValueError("Gate B intervention variant mapping failed validation")
        result[variant_id] = (request_path, response_path, payload)
    return result


def run_revalidation(
    *,
    repo_root: Path,
    revalidation_config_path: Path,
    app_config_path: Path,
    output_dir: Path,
    allow_provider: bool,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    config = _read_json(revalidation_config_path.resolve())
    app_config = load_config(app_config_path.resolve(), run_dir=output_dir)
    _write_json(output_dir / "effective-revalidation-config.json", config)
    write_resolved_config(app_config, output_dir / "effective-app-config.yaml")
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(
        output_dir / "environment.json",
        {
            "captured_at_utc": datetime.now(UTC).isoformat(),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": sys.version,
            "working_directory": os.getcwd(),
        },
    )
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("semantic_retry_allowed") is not False
        or config.get("allow_outcome_generation") is not False
        or config.get("scientific_claim_allowed") is not False
        or app_config.tsg.prompt_extractor.value != "llm_facts_v1"
        or app_config.tsg.llm is None
    ):
        raise ValueError("Gate B extractor revalidation policy failed validation")

    gate_a_dir = (repo_root / str(config["gate_a_dir"])).resolve()
    attempt_dir = (repo_root / str(config["intervention_attempt_dir"])).resolve()
    placebo_repair_dir = (repo_root / str(config["placebo_repair_dir"])).resolve()
    gate_a_dir.relative_to(repo_root)
    attempt_dir.relative_to(repo_root)
    placebo_repair_dir.relative_to(repo_root)
    failure = _read_json(attempt_dir / "failure.json")
    expected_failure_message = config.get(
        "expected_prior_failure_message",
        "TARGET_VARIATION_VIOLATION",
    )
    _validate_prior_failure(failure, expected_failure_message)
    selected_task_ids = tuple(config.get("selected_task_ids", ()))
    if not selected_task_ids or len(selected_task_ids) != len(set(selected_task_ids)):
        raise ValueError("Gate B revalidation task selection failed validation")

    sources = tuple(
        read_jsonl(
            gate_a_dir / "source-prompts.jsonl",
            PromptRecord,
            required=True,
            allow_empty=False,
        )
    )
    source_by_task = {source.task_id: source for source in sources}
    if any(task_id not in source_by_task for task_id in selected_task_ids):
        raise ValueError("Gate B revalidation source coverage failed validation")
    selected_sources = tuple(source_by_task[task_id] for task_id in selected_task_ids)
    variants = tuple(
        sorted(
            (
                item
                for item in read_jsonl(
                    gate_a_dir / "variants.jsonl", required=True, allow_empty=False
                )
                if item.get("task_id") in selected_task_ids
            ),
            key=lambda item: (str(item["task_id"]), str(item["arm_role"])),
        )
    )
    if (
        len(selected_sources) != config.get("expected_source_prompts")
        or len(variants) != config.get("expected_variant_prompts")
        or len(variants) != len(selected_sources) * 4
    ):
        raise ValueError("Gate B revalidation Prompt coverage failed validation")

    pairs = _intervention_pairs(attempt_dir)
    variant_ids = {str(item["variant_id"]) for item in variants}
    if set(pairs) != variant_ids:
        raise ValueError("Gate B intervention response coverage failed validation")
    placebo_variant_ids = {
        str(item["variant_id"])
        for item in variants
        if item.get("arm_role") == ArmRole.LENGTH_MATCHED_PLACEBO.value
    }
    replacement_pairs = _intervention_pairs(placebo_repair_dir)
    if set(replacement_pairs) != placebo_variant_ids:
        raise ValueError("Gate B placebo replacement coverage failed validation")
    repair_report = _read_json(placebo_repair_dir / "report.json")
    if repair_report.get("status") != "PLACEBO_REPAIR_PASSED":
        raise ValueError("Gate B placebo repair dependency failed validation")
    pairs.update(replacement_pairs)

    extractor_policy = extraction_policy(app_config.tsg)
    structured_policy = structured_policy_for_config(app_config.tsg)
    intervention_limit = app_config.intervention.llm
    if intervention_limit is None:
        raise ValueError("Gate B intervention config failed validation")
    frozen_variants: list[dict[str, object]] = []
    variant_entries: list[tuple[PromptRecord, dict[str, object]]] = []
    intervention_pair_digests: dict[str, dict[str, str]] = {}
    suffix_by_task_role: dict[tuple[str, ArmRole], str] = {}
    for item in variants:
        variant_id = str(item["variant_id"])
        source = source_by_task[str(item["task_id"])]
        request_path, response_path, saved_request = pairs[variant_id]
        if (
            saved_request.get("arm_role") != item.get("arm_role")
            or saved_request.get("operation") != item.get("operation")
            or saved_request.get("source_prompt", {}).get("content") != source.prompt
            or saved_request.get("source_prompt", {}).get("content_sha256") != source.prompt_sha256
        ):
            raise ValueError("Gate B intervention request provenance failed validation")
        raw = response_path.read_bytes()
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        text = _parse_response(raw, intervention_limit.max_response_bytes)
        if not text.startswith(source.prompt):
            raise ValueError("Gate B frozen variant source prefix failed validation")
        prompt = blind_variant_prompt_record_from_text(source, text, extractor_policy)
        suffix = text[len(source.prompt) :]
        suffix_by_task_role[(source.task_id, ArmRole(str(item["arm_role"])))] = suffix
        meta = {
            "variant_id": variant_id,
            "task_id": source.task_id,
            "arm_role": str(item["arm_role"]),
            "target_feature_id": str(item["target_feature_id"]),
            "allowed_delta": item["allowed_delta"],
            "intervention_request_sha256": sha256_file(request_path),
            "intervention_response_sha256": sha256_file(response_path),
            "append_only_suffix_length": len(suffix),
            "append_only_suffix_sha256": hashlib.sha256(suffix.encode("utf-8")).hexdigest(),
        }
        variant_entries.append((prompt, meta))
        frozen_variants.append(
            {
                "schema_version": _SCHEMA_VERSION,
                "prompt_id": prompt.prompt_id,
                "prompt_sha256": prompt.prompt_sha256,
                **meta,
            }
        )
        intervention_pair_digests[variant_id] = {
            "request_sha256": sha256_file(request_path),
            "response_sha256": sha256_file(response_path),
        }

    placebo_length_validations: list[dict[str, object]] = []
    for source in selected_sources:
        validation = {
            **validate_length_matched_placebo(
                target_suffix=suffix_by_task_role[(source.task_id, ArmRole.TARGET_PATCH)],
                noop_suffix=suffix_by_task_role[(source.task_id, ArmRole.NOOP_REWRITE)],
                placebo_suffix=suffix_by_task_role[
                    (source.task_id, ArmRole.LENGTH_MATCHED_PLACEBO)
                ],
            ),
            "task_id": source.task_id,
        }
        placebo_length_validations.append(validation)
    if any(item["status"] != "PASSED" for item in placebo_length_validations):
        raise ValueError("Gate B replacement placebo length failed validation")

    prompt_entries: list[tuple[str, str, PromptRecord, dict[str, object] | None]] = [
        ("source", f"source:{prompt.prompt_id}", prompt, None) for prompt in selected_sources
    ] + [
        ("variant", f"variant:{meta['variant_id']}", prompt, meta)
        for prompt, meta in variant_entries
    ]
    entry_keys = [entry_key for _kind, entry_key, _prompt, _meta in prompt_entries]
    if len(prompt_entries) != config.get("provider_call_budget") or len(entry_keys) != len(
        set(entry_keys)
    ):
        raise ValueError("Gate B revalidation provider budget failed validation")

    records: list[dict[str, object]] = []
    proposals: list[object] = []
    graphs: list[object] = []
    state_by_entry: dict[str, dict[str, FeatureState]] = {}
    provider_attempts = 0
    provider_responses = 0
    transport = None
    if allow_provider:
        llm = app_config.tsg.llm
        transport = OpenAICompatibleStructuredTransport(
            base_url=llm.base_url,
            api_key_env=llm.api_key_env,
            system_template=LLM_FACTS_SYSTEM_TEMPLATE,
        )

    written_request_paths: set[Path] = set()
    for kind, entry_key, prompt, meta in prompt_entries:
        request_payload = facts_request_payload(prompt, extractor_policy)
        if (
            request_payload.get("criteria_projection_version")
            != LLM_FACTS_CRITERIA_PROJECTION_VERSION
            or _recursive_keys(request_payload) & _FORBIDDEN_REQUEST_KEYS
            or any("semantic_criteria" not in item for item in request_payload["allowed_features"])
        ):
            raise ValueError("Gate B extractor request audit failed validation")
        request = canonical_request_bytes(request_payload)
        stem = _artifact_stem(entry_key)
        request_root = output_dir / (
            "raw/extractor" if allow_provider else "planned-requests/extractor"
        )
        request_root.mkdir(parents=True, exist_ok=True)
        request_path = request_root / f"{stem}.request.json"
        if request_path in written_request_paths or request_path.exists():
            raise ValueError("Gate B extractor request artifact identity collision")
        request_path.write_bytes(request + b"\n")
        written_request_paths.add(request_path)
        base_record: dict[str, object] = {
            "schema_version": _SCHEMA_VERSION,
            "kind": kind,
            "entry_key": entry_key,
            "prompt_id": prompt.prompt_id,
            "task_id": prompt.task_id,
            "prompt_sha256": prompt.prompt_sha256,
            "request_sha256": hashlib.sha256(request).hexdigest(),
            "variant_id": None if meta is None else meta["variant_id"],
            "arm_role": None if meta is None else meta["arm_role"],
        }
        if not allow_provider:
            records.append({**base_record, "status": "PLANNED"})
            continue
        provider_attempts += 1
        try:
            if transport is None:  # pragma: no cover - guarded by allow_provider
                raise RuntimeError("missing extractor transport")
            raw = transport.complete(request, structured_policy)
            provider_responses += 1
            (request_root / f"{stem}.response.json").write_bytes(raw + b"\n")
            proposal = parse_facts_response(raw, prompt, extractor_policy)
            graph = build_prompt_tsg(proposal, prompt)
            proposals.append(proposal)
            graphs.append(graph)
            state_by_entry[entry_key] = _state_map(graph)
            records.append(
                {
                    **base_record,
                    "status": "EXTRACTED",
                    "proposal_id": proposal.proposal_id,
                    "graph_sha256": graph.graph_sha256,
                }
            )
        except Exception as error:
            failure_record = {
                **base_record,
                "status": "ERROR",
                "error_type": type(error).__name__,
                "message": str(error),
            }
            _write_json(request_root / f"{stem}.failure.json", failure_record)
            records.append(failure_record)

    validations: list[dict[str, object]] = []
    if len(written_request_paths) != len(prompt_entries):
        raise ValueError("Gate B extractor request artifact coverage failed validation")
    unique_request_bytes = len({str(item["request_sha256"]) for item in records})
    if unique_request_bytes != len(prompt_entries):
        raise ValueError("Gate B extractor request byte uniqueness failed validation")

    if allow_provider:
        for prompt, meta in variant_entries:
            source = source_by_task[str(meta["task_id"])]
            source_states = state_by_entry.get(f"source:{source.prompt_id}")
            variant_states = state_by_entry.get(f"variant:{meta['variant_id']}")
            if source_states is None or variant_states is None:
                validation: dict[str, object] = {
                    "schema_version": _SCHEMA_VERSION,
                    "status": "ERROR",
                    "failure_codes": ["EXTRACTION_UNAVAILABLE"],
                    "variant_id": meta["variant_id"],
                    "task_id": meta["task_id"],
                    "arm_role": meta["arm_role"],
                }
            else:
                validation = {
                    **_validate_llm_delta(
                        source_states,
                        variant_states,
                        role=ArmRole(str(meta["arm_role"])),
                        target_feature_id=str(meta["target_feature_id"]),
                        allowed_delta=AllowedDeltaRecord.model_validate(meta["allowed_delta"]),
                    ),
                    "variant_id": meta["variant_id"],
                    "task_id": meta["task_id"],
                    "arm_role": meta["arm_role"],
                }
            validations.append(validation)
            _write_json(
                output_dir / "validation" / f"{_artifact_stem(str(meta['variant_id']))}.json",
                validation,
            )

    write_jsonl(output_dir / "source-prompts.jsonl", selected_sources)
    write_jsonl(output_dir / "variant-prompts.jsonl", [item[0] for item in variant_entries])
    write_jsonl(output_dir / "frozen-variant-provenance.jsonl", frozen_variants)
    write_jsonl(output_dir / "placebo-length-validations.jsonl", placebo_length_validations)
    write_jsonl(output_dir / "records.jsonl", records)
    write_jsonl(output_dir / "extraction-proposals.jsonl", proposals)
    write_jsonl(output_dir / "prompt-tsg.jsonl", graphs)
    validation_failures = sum(item.get("status") != "PASSED" for item in validations)
    errors = sum(item["status"] == "ERROR" for item in records)
    status = "PLAN_COMPLETE"
    if allow_provider:
        status = (
            "GATE_B_REEXTRACTION_PASSED"
            if errors == 0 and validation_failures == 0 and len(validations) == len(variants)
            else "GATE_B_REEXTRACTION_FAILED"
        )
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "revalidation_id": config["revalidation_id"],
        "status": status,
        "scientific_claim_allowed": False,
        "outcome_generation_allowed": False,
        "provider_calls_allowed": allow_provider,
        "counts": {
            "independent_tasks": len(selected_sources),
            "source_prompts": len(selected_sources),
            "variant_prompts": len(variant_entries),
            "unique_request_bytes": unique_request_bytes,
            "planned_provider_calls": len(prompt_entries),
            "provider_attempts": provider_attempts,
            "provider_responses": provider_responses,
            "extracted": sum(item["status"] == "EXTRACTED" for item in records),
            "validated_variants": sum(item.get("status") == "PASSED" for item in validations),
            "validation_failures": validation_failures,
            "errors": errors,
            "pending": sum(item["status"] == "PLANNED" for item in records),
        },
        "policy_digests": {
            "extractor_policy_sha256": extractor_policy.policy_sha256,
            "criteria_projection_version": LLM_FACTS_CRITERIA_PROJECTION_VERSION,
            "placebo_length_policy_version": PLACEBO_LENGTH_POLICY_VERSION,
        },
        "input_digests": {
            "revalidation_config_sha256": sha256_file(revalidation_config_path),
            "app_config_sha256": sha256_file(app_config_path),
            "gate_a_report_sha256": sha256_file(gate_a_dir / "report.json"),
            "gate_a_sources_sha256": sha256_file(gate_a_dir / "source-prompts.jsonl"),
            "gate_a_variants_sha256": sha256_file(gate_a_dir / "variants.jsonl"),
            "failed_attempt_sha256": sha256_file(attempt_dir / "failure.json"),
            "intervention_pairs_sha256": canonical_sha256(intervention_pair_digests),
            "placebo_repair_report_sha256": sha256_file(placebo_repair_dir / "report.json"),
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--revalidation-config", type=Path, required=True)
    parser.add_argument("--app-config", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--allow-provider", action="store_true")
    args = parser.parse_args()
    _load_env_file(args.env_file)
    report = run_revalidation(
        repo_root=args.repo_root,
        revalidation_config_path=args.revalidation_config,
        app_config_path=args.app_config,
        output_dir=args.output_dir,
        allow_provider=args.allow_provider,
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
