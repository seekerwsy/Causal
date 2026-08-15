"""Run a bounded, non-scientific Prompt extractor strategy calibration."""

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

from secaware.config import TSGConfig, load_config, write_resolved_config
from secaware.extractors.base import ExtractionPolicy
from secaware.extractors.deterministic_catalog import DeterministicCatalogExtractor
from secaware.extractors.factory import extraction_policy
from secaware.extractors.llm_direct_graph import (
    LLM_DIRECT_GRAPH_OUTPUT_SCHEMA_SHA256,
    direct_graph_request_payload,
    parse_direct_graph_response,
)
from secaware.extractors.llm_facts import (
    LLM_FACTS_OUTPUT_SCHEMA_SHA256,
    facts_request_payload,
    parse_facts_response,
)
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.llm.structured_transport import (
    OpenAICompatibleStructuredTransport,
    StructuredLLMPolicy,
    canonical_request_bytes,
)
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.features import FeatureState, PromptExtractorBackend
from secaware.schema.prompt_extraction import MAX_RAW_RESPONSE_CHARS
from secaware.schema.records import PromptRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG_SHA256,
    prompt_feature_spec,
)
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.queries import feature_state_vector


_SCHEMA_VERSION = "1.0"
_LLM_STRATEGIES = (
    "llm_facts_criteria_v2",
    "llm_direct_graph_criteria_v2",
)
_DETERMINISTIC_STRATEGY = "deterministic_catalog_v1"


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
        raise ValueError("extractor calibration input failed validation")
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


def _semantic_criteria(feature_id: str) -> dict[str, object]:
    spec = prompt_feature_spec(feature_id)
    return {
        "positive_indicators": list(spec.deterministic_terms),
        "reviewed_requirement_clauses": [
            item.strip() for item in spec.intervention_clauses
        ],
        "state_rule": (
            "present only when prompt_text explicitly requests this feature or a "
            "semantically equivalent requirement"
        ),
    }


def _facts_criteria_request(prompt: PromptRecord, policy: ExtractionPolicy) -> dict[str, object]:
    payload = facts_request_payload(prompt, policy)
    allowed = []
    for item in payload["allowed_features"]:
        projected = dict(item)
        projected["semantic_criteria"] = _semantic_criteria(str(item["feature_id"]))
        allowed.append(projected)
    return {**payload, "criteria_projection_version": "feature-spec-criteria-v1", "allowed_features": allowed}


def _direct_criteria_request(
    prompt: PromptRecord,
    policy: ExtractionPolicy,
) -> dict[str, object]:
    payload = direct_graph_request_payload(prompt, policy)
    templates = []
    for item in payload["allowed_node_templates"]:
        projected = dict(item)
        projected["semantic_criteria"] = _semantic_criteria(str(item["feature_id"]))
        templates.append(projected)
    return {
        **payload,
        "criteria_projection_version": "feature-spec-criteria-v1",
        "allowed_node_templates": templates,
    }


def _structured_policy(llm: object, template: str, output_schema_sha256: str) -> StructuredLLMPolicy:
    return StructuredLLMPolicy(
        endpoint_sha256=hashlib.sha256(llm.base_url.encode("utf-8")).hexdigest(),
        model_id=llm.model_id,
        system_template_sha256=hashlib.sha256(template.encode("utf-8")).hexdigest(),
        output_schema_sha256=output_schema_sha256,
        temperature=llm.temperature,
        top_p=llm.top_p,
        seed=llm.seed,
        timeout_seconds=llm.timeout_seconds,
        max_attempts=llm.max_attempts,
        max_response_bytes=llm.max_response_bytes,
        enable_thinking=llm.enable_thinking,
    )


def _experimental_policy(
    backend: PromptExtractorBackend,
    strategy: str,
    structured: StructuredLLMPolicy,
) -> ExtractionPolicy:
    digest = canonical_sha256(
        {
            "backend": backend.value,
            "strategy": strategy,
            "criteria_projection_version": "feature-spec-criteria-v1",
            "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
            "max_response_chars": MAX_RAW_RESPONSE_CHARS,
            "structured_policy": {
                name: getattr(structured, name)
                for name in StructuredLLMPolicy.__dataclass_fields__
            },
        }
    )
    return ExtractionPolicy(
        backend=backend,
        policy_sha256=digest,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        max_response_chars=MAX_RAW_RESPONSE_CHARS,
    )


def _state_map(graph: object) -> dict[str, str]:
    return {
        feature_id: state.value
        for feature_id, state in feature_state_vector(record_to_multidigraph(graph))
    }


def _evaluate(
    strategy: str,
    prompt: PromptRecord,
    expected: dict[str, str],
    proposal: object,
    graph: object,
) -> dict[str, object]:
    states = _state_map(graph)
    observed = {feature_id: states[feature_id] for feature_id in sorted(expected)}
    mismatches = [
        {
            "feature_id": feature_id,
            "expected": expected[feature_id],
            "observed": observed[feature_id],
        }
        for feature_id in sorted(expected)
        if observed[feature_id] != expected[feature_id]
    ]
    return {
        "schema_version": _SCHEMA_VERSION,
        "strategy": strategy,
        "prompt_id": prompt.prompt_id,
        "status": "PASSED" if not mismatches else "MISMATCH",
        "proposal_id": proposal.proposal_id,
        "graph_sha256": graph.graph_sha256,
        "expected_states": expected,
        "observed_states": observed,
        "mismatches": mismatches,
    }


def _error_record(strategy: str, prompt: PromptRecord, error: Exception) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "strategy": strategy,
        "prompt_id": prompt.prompt_id,
        "status": "ERROR",
        "error_type": type(error).__name__,
        "message": str(error),
    }


def _strategy_summary(records: list[dict[str, object]], strategy: str) -> dict[str, object]:
    selected = [item for item in records if item["strategy"] == strategy]
    mismatches = sum(len(item.get("mismatches", [])) for item in selected)
    decisions = sum(len(item.get("expected_states", {})) for item in selected)
    return {
        "strategy": strategy,
        "cases": len(selected),
        "passed": sum(item["status"] == "PASSED" for item in selected),
        "mismatched": sum(item["status"] == "MISMATCH" for item in selected),
        "errors": sum(item["status"] == "ERROR" for item in selected),
        "correct_feature_decisions": decisions - mismatches,
        "total_feature_decisions": decisions,
    }


def run_calibration(
    *,
    repo_root: Path,
    calibration_config_path: Path,
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
    calibration = _read_json(calibration_config_path.resolve())
    app_config = load_config(app_config_path.resolve(), run_dir=output_dir)
    _write_json(output_dir / "effective-calibration-config.json", calibration)
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
        calibration.get("schema_version") != _SCHEMA_VERSION
        or calibration.get("scientific_claim_allowed") is not False
        or calibration.get("semantic_retry_allowed") is not False
        or calibration.get("one_call_per_llm_strategy_prompt") is not True
    ):
        raise ValueError("extractor calibration policy failed validation")
    strategies = tuple(calibration.get("strategies", ()))
    expected_strategies = (*_LLM_STRATEGIES, _DETERMINISTIC_STRATEGY)
    if strategies != expected_strategies:
        raise ValueError("extractor calibration strategies failed validation")
    prompts_path = (repo_root / str(calibration["prompts_path"])).resolve()
    expected_path = (repo_root / str(calibration["expected_states_path"])).resolve()
    prompts_path.relative_to(repo_root)
    expected_path.relative_to(repo_root)
    prompts = tuple(
        read_jsonl(
            prompts_path,
            PromptRecord,
            required=True,
            allow_empty=False,
            stage="extractor-strategy-calibration",
        )
    )
    expected_rows = [json.loads(line) for line in expected_path.read_text(encoding="utf-8").splitlines() if line]
    expected = {str(item["prompt_id"]): dict(item["expected_states"]) for item in expected_rows}
    if set(expected) != {item.prompt_id for item in prompts}:
        raise ValueError("extractor calibration expected states failed validation")
    planned_calls = len(prompts) * len(_LLM_STRATEGIES)
    if planned_calls != calibration.get("provider_call_budget"):
        raise ValueError("extractor calibration call budget failed validation")

    llm = app_config.tsg.llm
    if llm is None or llm.max_attempts != 1 or llm.temperature != 0.0:
        raise ValueError("extractor calibration LLM coordinates failed validation")
    template_root = repo_root / "src" / "secaware" / "extractors" / "prompts"
    templates = {
        "llm_facts_criteria_v2": (
            template_root / "llm_facts_criteria_v2_calibration.txt"
        ).read_text(encoding="utf-8"),
        "llm_direct_graph_criteria_v2": (
            template_root / "llm_direct_graph_criteria_v2_calibration.txt"
        ).read_text(encoding="utf-8"),
    }
    structured = {
        "llm_facts_criteria_v2": _structured_policy(
            llm,
            templates["llm_facts_criteria_v2"],
            LLM_FACTS_OUTPUT_SCHEMA_SHA256,
        ),
        "llm_direct_graph_criteria_v2": _structured_policy(
            llm,
            templates["llm_direct_graph_criteria_v2"],
            LLM_DIRECT_GRAPH_OUTPUT_SCHEMA_SHA256,
        ),
    }
    policies = {
        "llm_facts_criteria_v2": _experimental_policy(
            PromptExtractorBackend.LLM_FACTS_V1,
            "llm_facts_criteria_v2",
            structured["llm_facts_criteria_v2"],
        ),
        "llm_direct_graph_criteria_v2": _experimental_policy(
            PromptExtractorBackend.LLM_DIRECT_GRAPH_V1,
            "llm_direct_graph_criteria_v2",
            structured["llm_direct_graph_criteria_v2"],
        ),
    }
    deterministic_config = TSGConfig(
        prompt_extractor=PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
        llm=None,
    )
    deterministic_policy = extraction_policy(deterministic_config)
    deterministic = DeterministicCatalogExtractor()
    records: list[dict[str, object]] = []
    proposals: list[object] = []
    graphs: list[object] = []
    provider_attempts = 0
    provider_responses = 0

    for prompt in prompts:
        try:
            proposal = deterministic.extract(prompt, deterministic_policy)
            graph = build_prompt_tsg(proposal, prompt)
            records.append(
                _evaluate(
                    _DETERMINISTIC_STRATEGY,
                    prompt,
                    expected[prompt.prompt_id],
                    proposal,
                    graph,
                )
            )
            proposals.append(proposal)
            graphs.append(graph)
        except Exception as error:
            records.append(_error_record(_DETERMINISTIC_STRATEGY, prompt, error))

    if allow_provider:
        for strategy in _LLM_STRATEGIES:
            transport = OpenAICompatibleStructuredTransport(
                base_url=llm.base_url,
                api_key_env=llm.api_key_env,
                system_template=templates[strategy],
            )
            for prompt in prompts:
                strategy_root = output_dir / "raw" / strategy
                strategy_root.mkdir(parents=True, exist_ok=True)
                request_payload = (
                    _facts_criteria_request(prompt, policies[strategy])
                    if strategy == "llm_facts_criteria_v2"
                    else _direct_criteria_request(prompt, policies[strategy])
                )
                request = canonical_request_bytes(request_payload)
                (strategy_root / f"{prompt.prompt_id}.request.json").write_bytes(request + b"\n")
                provider_attempts += 1
                try:
                    raw = transport.complete(request, structured[strategy])
                    provider_responses += 1
                    (strategy_root / f"{prompt.prompt_id}.response.json").write_bytes(raw + b"\n")
                    proposal = (
                        parse_facts_response(raw, prompt, policies[strategy])
                        if strategy == "llm_facts_criteria_v2"
                        else parse_direct_graph_response(raw, prompt, policies[strategy])
                    )
                    graph = build_prompt_tsg(proposal, prompt)
                    records.append(
                        _evaluate(
                            strategy,
                            prompt,
                            expected[prompt.prompt_id],
                            proposal,
                            graph,
                        )
                    )
                    proposals.append(proposal)
                    graphs.append(graph)
                except Exception as error:
                    failure = _error_record(strategy, prompt, error)
                    _write_json(strategy_root / f"{prompt.prompt_id}.failure.json", failure)
                    records.append(failure)
    else:
        for strategy in _LLM_STRATEGIES:
            for prompt in prompts:
                strategy_root = output_dir / "planned-requests" / strategy
                strategy_root.mkdir(parents=True, exist_ok=True)
                request_payload = (
                    _facts_criteria_request(prompt, policies[strategy])
                    if strategy == "llm_facts_criteria_v2"
                    else _direct_criteria_request(prompt, policies[strategy])
                )
                request = canonical_request_bytes(request_payload)
                (strategy_root / f"{prompt.prompt_id}.request.json").write_bytes(
                    request + b"\n"
                )
                records.append(
                    {
                        "schema_version": _SCHEMA_VERSION,
                        "strategy": strategy,
                        "prompt_id": prompt.prompt_id,
                        "status": "PLANNED",
                        "request_sha256": hashlib.sha256(request).hexdigest(),
                    }
                )

    write_jsonl(output_dir / "records.jsonl", records)
    write_jsonl(output_dir / "proposals.jsonl", proposals)
    write_jsonl(output_dir / "prompt-tsg.jsonl", graphs)
    summaries = [_strategy_summary(records, strategy) for strategy in strategies]
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "calibration_id": calibration["calibration_id"],
        "status": "CALIBRATION_COMPLETE" if allow_provider else "PLAN_COMPLETE",
        "scientific_claim_allowed": False,
        "provider_calls_allowed": allow_provider,
        "counts": {
            "prompts": len(prompts),
            "strategies": len(strategies),
            "planned_provider_calls": planned_calls,
            "provider_attempts": provider_attempts,
            "provider_responses": provider_responses,
            "errors": sum(item["status"] == "ERROR" for item in records),
            "pending": sum(item["status"] == "PLANNED" for item in records),
        },
        "strategy_summaries": summaries,
        "policy_digests": {
            strategy: policies[strategy].policy_sha256 for strategy in _LLM_STRATEGIES
        }
        | {_DETERMINISTIC_STRATEGY: deterministic_policy.policy_sha256},
        "input_digests": {
            "calibration_config_sha256": sha256_file(calibration_config_path),
            "app_config_sha256": sha256_file(app_config_path),
            "prompts_sha256": sha256_file(prompts_path),
            "expected_states_sha256": sha256_file(expected_path),
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
    parser.add_argument("--calibration-config", type=Path, required=True)
    parser.add_argument("--app-config", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--allow-provider", action="store_true")
    args = parser.parse_args()
    _load_env_file(args.env_file)
    report = run_calibration(
        repo_root=args.repo_root,
        calibration_config_path=args.calibration_config,
        app_config_path=args.app_config,
        output_dir=args.output_dir,
        allow_provider=args.allow_provider,
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
