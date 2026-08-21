"""Plan or run the bounded repair of invalid Gate B placebo variants."""

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
    _INTERVENTION_SYSTEM_TEMPLATE,
    _intervention_payload,
    _parse_response,
    validate_length_matched_placebo,
)
from secaware.intervention.executors import (
    INTERVENTION_EXECUTOR_OUTPUT_SCHEMA_SHA256,
    intervention_executor_policy_sha256,
)
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.llm.structured_transport import (
    OpenAICompatibleStructuredTransport,
    StructuredLLMPolicy,
    canonical_request_bytes,
)
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.experiments import AllowedDeltaRecord, ArmRole
from secaware.schema.records import PromptRecord


_SCHEMA_VERSION = "1.0"
_REQUEST_POLICY_VERSION = "gate-b-placebo-repair-request-v1"
_SYSTEM_TEMPLATE_VERSION = "gate-b-placebo-repair-executor-v1"
_SYSTEM_TEMPLATE = (
    _INTERVENTION_SYSTEM_TEMPLATE
    + "\n\nFor this repair request, candidate_text must preserve source_prompt.content exactly "
    "as its prefix and append exactly one natural, presentation-only sentence. The appended suffix "
    "must be non-empty, must satisfy placebo_length_contract, and must differ from the supplied "
    "no-op suffix. Do not mention security, safety, vulnerabilities, attacks, validation, escaping, "
    "authorization, or any target mechanism. Do not add, remove, or reinterpret task behavior."
)


def _repair_system_template(reviewed_suffix: str | None) -> str:
    if reviewed_suffix is None:
        return _SYSTEM_TEMPLATE
    return (
        _SYSTEM_TEMPLATE
        + "\n\nFor this reviewed-clause repair, append exactly required_exact_suffix after the "
        "unchanged source prefix. Copy it character-for-character; do not shorten, paraphrase, or "
        "replace it."
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
        raise ValueError("Gate B placebo repair input failed validation")
    return value


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value) + b"\n")


def _load_env_file(path: Path) -> None:
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip()


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def _artifact_stem(label: str) -> str:
    return "record-" + hashlib.sha256(label.encode("utf-8")).hexdigest()[:32]


def _saved_interventions(root: Path) -> dict[str, tuple[dict[str, Any], bytes, Path, Path]]:
    result: dict[str, tuple[dict[str, Any], bytes, Path, Path]] = {}
    for request_path in sorted((root / "raw" / "intervention").glob("*.request.json")):
        response_path = request_path.with_name(
            request_path.name.removesuffix(".request.json") + ".response.json"
        )
        if not response_path.is_file():
            raise ValueError("Gate B saved intervention pair failed validation")
        request = _read_json(request_path)
        variant_id = request.get("exploratory_variant_id")
        if type(variant_id) is not str or not variant_id or variant_id in result:
            raise ValueError("Gate B saved intervention identity failed validation")
        raw = response_path.read_bytes()
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        result[variant_id] = (request, raw, request_path, response_path)
    return result


def run_repair(
    *,
    repo_root: Path,
    repair_config_path: Path,
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
    config = _read_json(repair_config_path.resolve())
    app_config = load_config(app_config_path.resolve(), run_dir=output_dir)
    _write_json(output_dir / "effective-repair-config.json", config)
    write_resolved_config(app_config, output_dir / "effective-app-config.yaml")
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("placebo_length_policy_version") != PLACEBO_LENGTH_POLICY_VERSION
        or config.get("semantic_retry_allowed") is not False
        or config.get("allow_outcome_generation") is not False
        or config.get("scientific_claim_allowed") is not False
        or app_config.intervention.llm is None
    ):
        raise ValueError("Gate B placebo repair policy failed validation")
    reviewed_suffix = config.get("reviewed_placebo_suffix")
    if reviewed_suffix is not None and (
        type(reviewed_suffix) is not str
        or not reviewed_suffix.startswith(" ")
        or reviewed_suffix != reviewed_suffix.rstrip()
    ):
        raise ValueError("Gate B reviewed placebo suffix failed validation")
    request_policy_version = (
        "gate-b-placebo-reviewed-clause-request-v2"
        if reviewed_suffix is not None
        else _REQUEST_POLICY_VERSION
    )
    system_template_version = (
        "gate-b-placebo-reviewed-clause-executor-v2"
        if reviewed_suffix is not None
        else _SYSTEM_TEMPLATE_VERSION
    )
    system_template = _repair_system_template(reviewed_suffix)

    gate_a_dir = (repo_root / str(config["gate_a_dir"])).resolve()
    prior_dir = (repo_root / str(config["prior_attempt_dir"])).resolve()
    gate_a_dir.relative_to(repo_root)
    prior_dir.relative_to(repo_root)
    selected_task_ids = tuple(config.get("selected_task_ids", ()))
    if not selected_task_ids or len(selected_task_ids) != len(set(selected_task_ids)):
        raise ValueError("Gate B placebo task selection failed validation")
    sources = tuple(
        read_jsonl(
            gate_a_dir / "source-prompts.jsonl",
            PromptRecord,
            required=True,
            allow_empty=False,
        )
    )
    source_by_task = {source.task_id: source for source in sources}
    variants = tuple(
        item
        for item in read_jsonl(gate_a_dir / "variants.jsonl", required=True, allow_empty=False)
        if item.get("task_id") in selected_task_ids
    )
    by_task_role = {
        (str(item["task_id"]), ArmRole(str(item["arm_role"]))): item for item in variants
    }
    if len(by_task_role) != len(selected_task_ids) * 4:
        raise ValueError("Gate B placebo arm coverage failed validation")
    saved = _saved_interventions(prior_dir)
    intervention = app_config.intervention.llm
    structured_policy = StructuredLLMPolicy(
        endpoint_sha256=hashlib.sha256(intervention.base_url.encode("utf-8")).hexdigest(),
        model_id=intervention.model_id,
        system_template_sha256=hashlib.sha256(system_template.encode("utf-8")).hexdigest(),
        output_schema_sha256=INTERVENTION_EXECUTOR_OUTPUT_SCHEMA_SHA256,
        temperature=intervention.temperature,
        top_p=intervention.top_p,
        seed=intervention.seed,
        timeout_seconds=intervention.timeout_seconds,
        max_attempts=intervention.max_attempts,
        max_response_bytes=intervention.max_response_bytes,
        enable_thinking=intervention.enable_thinking,
    )
    executor_policy_sha256 = intervention_executor_policy_sha256(structured_policy)
    transport = None
    if allow_provider:
        transport = OpenAICompatibleStructuredTransport(
            base_url=intervention.base_url,
            api_key_env=intervention.api_key_env,
            system_template=system_template,
        )

    records: list[dict[str, object]] = []
    repaired: list[dict[str, object]] = []
    provider_attempts = 0
    provider_responses = 0
    source_pair_digests: dict[str, object] = {}
    for task_id in selected_task_ids:
        source = source_by_task.get(task_id)
        if source is None:
            raise ValueError("Gate B placebo source coverage failed validation")
        target = by_task_role[(task_id, ArmRole.TARGET_PATCH)]
        noop = by_task_role[(task_id, ArmRole.NOOP_REWRITE)]
        placebo = by_task_role[(task_id, ArmRole.LENGTH_MATCHED_PLACEBO)]
        target_saved = saved[str(target["variant_id"])]
        noop_saved = saved[str(noop["variant_id"])]
        target_text = _parse_response(target_saved[1], intervention.max_response_bytes)
        noop_text = _parse_response(noop_saved[1], intervention.max_response_bytes)
        if not target_text.startswith(source.prompt) or not noop_text.startswith(source.prompt):
            raise ValueError("Gate B placebo source-prefix dependency failed validation")
        target_suffix = target_text[len(source.prompt) :]
        noop_suffix = noop_text[len(source.prompt) :]
        bounds = validate_length_matched_placebo(
            target_suffix=target_suffix,
            noop_suffix=noop_suffix,
            placebo_suffix="p" * len(target_suffix),
        )
        if reviewed_suffix is not None:
            reviewed_validation = validate_length_matched_placebo(
                target_suffix=target_suffix,
                noop_suffix=noop_suffix,
                placebo_suffix=reviewed_suffix,
            )
            if reviewed_validation["status"] != "PASSED":
                raise ValueError("reviewed placebo suffix length failed validation")
        request = _intervention_payload(
            source,
            placebo,
            AllowedDeltaRecord.model_validate(placebo["allowed_delta"]),
        )
        request = {
            **request,
            "request_kind": "bounded_length_matched_placebo_repair",
            "request_policy_version": request_policy_version,
            "arm_objective": (
                "Append exactly one natural presentation-only sentence. Preserve all task and "
                "safety semantics. The appended suffix length must satisfy placebo_length_contract."
            ),
            "placebo_length_contract": {
                "policy_version": PLACEBO_LENGTH_POLICY_VERSION,
                "length_unit": "unicode_characters",
                "target_suffix_length": bounds["target_suffix_length"],
                "minimum_placebo_length": bounds["minimum_placebo_length"],
                "maximum_placebo_length": bounds["maximum_placebo_length"],
                "must_be_nonempty": True,
                "must_differ_from_noop": True,
                "noop_suffix_sha256": hashlib.sha256(noop_suffix.encode("utf-8")).hexdigest(),
                "required_exact_suffix": reviewed_suffix,
            },
        }
        request_bytes = canonical_request_bytes(request)
        variant_id = str(placebo["variant_id"])
        stem = _artifact_stem(variant_id)
        channel = output_dir / ("raw/intervention" if allow_provider else "planned-requests/intervention")
        channel.mkdir(parents=True, exist_ok=True)
        (channel / f"{stem}.request.json").write_bytes(request_bytes + b"\n")
        base_record: dict[str, object] = {
            "schema_version": _SCHEMA_VERSION,
            "task_id": task_id,
            "variant_id": variant_id,
            "arm_role": ArmRole.LENGTH_MATCHED_PLACEBO.value,
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "target_suffix_length": bounds["target_suffix_length"],
            "minimum_placebo_length": bounds["minimum_placebo_length"],
            "maximum_placebo_length": bounds["maximum_placebo_length"],
        }
        source_pair_digests[task_id] = {
            "target_request_sha256": sha256_file(target_saved[2]),
            "target_response_sha256": sha256_file(target_saved[3]),
            "noop_request_sha256": sha256_file(noop_saved[2]),
            "noop_response_sha256": sha256_file(noop_saved[3]),
        }
        if not allow_provider:
            records.append({**base_record, "status": "PLANNED"})
            continue
        provider_attempts += 1
        try:
            if transport is None:  # pragma: no cover - guarded by allow_provider
                raise RuntimeError("missing placebo repair transport")
            raw = transport.complete(request_bytes, structured_policy)
            provider_responses += 1
            (channel / f"{stem}.response.json").write_bytes(raw + b"\n")
            text = _parse_response(raw, intervention.max_response_bytes)
            if not text.startswith(source.prompt):
                raise ValueError("Gate B repaired placebo source prefix failed validation")
            suffix = text[len(source.prompt) :]
            validation = validate_length_matched_placebo(
                target_suffix=target_suffix,
                noop_suffix=noop_suffix,
                placebo_suffix=suffix,
            )
            if reviewed_suffix is not None and suffix != reviewed_suffix:
                validation = {
                    **validation,
                    "status": "FAILED",
                    "failure_codes": [
                        *validation["failure_codes"],
                        "PLACEBO_REVIEWED_CLAUSE_MISMATCH",
                    ],
                }
            validation = {
                **validation,
                "task_id": task_id,
                "variant_id": variant_id,
                "source_prefix_preserved": True,
                "placebo_suffix_sha256": hashlib.sha256(suffix.encode("utf-8")).hexdigest(),
            }
            _write_json(output_dir / "validation" / f"{stem}.json", validation)
            status = "PASSED" if validation["status"] == "PASSED" else "FAILED"
            records.append({**base_record, "status": status, "validation": validation})
            repaired.append(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "task_id": task_id,
                    "variant_id": variant_id,
                    "arm_role": ArmRole.LENGTH_MATCHED_PLACEBO.value,
                    "prompt": text,
                    "prompt_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    "executor_policy_sha256": executor_policy_sha256,
                    "request_policy_sha256": canonical_sha256(
                        {
                            "request_policy_version": request_policy_version,
                            "system_template_version": system_template_version,
                            "placebo_length_policy_version": PLACEBO_LENGTH_POLICY_VERSION,
                            "reviewed_placebo_suffix_sha256": (
                                hashlib.sha256(reviewed_suffix.encode("utf-8")).hexdigest()
                                if reviewed_suffix is not None
                                else None
                            ),
                            "executor_policy_sha256": executor_policy_sha256,
                        }
                    ),
                }
            )
        except Exception as error:
            failure_record = {
                **base_record,
                "status": "ERROR",
                "error_type": type(error).__name__,
                "message": str(error),
            }
            _write_json(channel / f"{stem}.failure.json", failure_record)
            records.append(failure_record)

    if len(records) != config.get("expected_placebo_variants") or len(records) != config.get(
        "provider_call_budget"
    ):
        raise ValueError("Gate B placebo repair budget failed validation")
    write_jsonl(output_dir / "records.jsonl", records)
    write_jsonl(output_dir / "repaired-variants.jsonl", repaired)
    errors = sum(item["status"] == "ERROR" for item in records)
    failures = sum(item["status"] == "FAILED" for item in records)
    status = "PLAN_COMPLETE"
    if allow_provider:
        status = (
            "PLACEBO_REPAIR_PASSED"
            if errors == 0 and failures == 0 and len(repaired) == len(records)
            else "PLACEBO_REPAIR_FAILED"
        )
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "repair_id": config["repair_id"],
        "status": status,
        "scientific_claim_allowed": False,
        "outcome_generation_allowed": False,
        "provider_calls_allowed": allow_provider,
        "counts": {
            "placebo_variants": len(records),
            "planned_provider_calls": len(records),
            "provider_attempts": provider_attempts,
            "provider_responses": provider_responses,
            "passed": sum(item["status"] == "PASSED" for item in records),
            "failures": failures,
            "errors": errors,
            "pending": sum(item["status"] == "PLANNED" for item in records),
        },
        "policy_digests": {
            "executor_policy_sha256": executor_policy_sha256,
            "placebo_length_policy_version": PLACEBO_LENGTH_POLICY_VERSION,
            "reviewed_placebo_suffix_sha256": (
                hashlib.sha256(reviewed_suffix.encode("utf-8")).hexdigest()
                if reviewed_suffix is not None
                else None
            ),
        },
        "input_digests": {
            "repair_config_sha256": sha256_file(repair_config_path),
            "app_config_sha256": sha256_file(app_config_path),
            "gate_a_variants_sha256": sha256_file(gate_a_dir / "variants.jsonl"),
            "prior_failure_sha256": sha256_file(prior_dir / "failure.json"),
            "source_pair_digests_sha256": canonical_sha256(source_pair_digests),
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
    parser.add_argument("--repair-config", type=Path, required=True)
    parser.add_argument("--app-config", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--allow-provider", action="store_true")
    args = parser.parse_args()
    _load_env_file(args.env_file)
    report = run_repair(
        repo_root=args.repo_root,
        repair_config_path=args.repair_config,
        app_config_path=args.app_config,
        output_dir=args.output_dir,
        allow_provider=args.allow_provider,
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
