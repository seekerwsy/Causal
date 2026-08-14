"""Capture and diagnose one LLM facts response outside the atomic production stage."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.config import load_config
from secaware.extractors.factory import extraction_policy, structured_policy_for_config
from secaware.extractors.llm_facts import (
    LLM_FACTS_SYSTEM_TEMPLATE,
    catalog_prompt_view,
    facts_request_payload,
    parse_facts_response,
)
from secaware.io.jsonl import read_jsonl
from secaware.llm.structured_transport import (
    OpenAICompatibleStructuredTransport,
    canonical_request_bytes,
)
from secaware.schema.records import PromptRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG
from secaware.tsg.proposal_validator import feature_is_applicable


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _mechanical_diagnostics(raw: bytes, prompt: PromptRecord) -> dict[str, object]:
    applicable_ids = {
        item.feature_id for item in PROMPT_FEATURE_CATALOG if feature_is_applicable(item, prompt)
    }
    result: dict[str, object] = {
        "utf8_valid": False,
        "json_valid": False,
        "envelope_valid": False,
        "facts_is_list": False,
        "expected_model_fact_count": len(applicable_ids),
        "derived_not_applicable_fact_count": len(PROMPT_FEATURE_CATALOG) - len(applicable_ids),
    }
    try:
        text = raw.decode("utf-8", errors="strict")
        result["utf8_valid"] = True
        payload = json.loads(text)
        result["json_valid"] = True
    except Exception:
        return result
    if type(payload) is not dict:
        return result
    result["top_level_keys"] = sorted(str(key) for key in payload)
    result["envelope_valid"] = set(payload) == {"facts"}
    facts = payload.get("facts")
    if type(facts) is not list:
        return result
    result["facts_is_list"] = True
    result["actual_fact_count"] = len(facts)
    expected_ids = applicable_ids
    actual_ids = [item.get("feature_id") for item in facts if type(item) is dict]
    result["missing_feature_ids"] = sorted(expected_ids - set(actual_ids))
    result["unknown_feature_ids"] = sorted(
        str(item) for item in set(actual_ids) - expected_ids
    )
    result["duplicate_feature_ids"] = sorted(
        str(item) for item in set(actual_ids) if actual_ids.count(item) > 1
    )
    exact_key_failures: list[object] = []
    semantic_role_failures: list[object] = []
    state_failures: list[object] = []
    evidence_presence_failures: list[object] = []
    evidence_key_failures: list[object] = []
    evidence_bounds_failures: list[object] = []
    evidence_text_failures: list[object] = []
    derived_evidence_digest_count = 0
    expected_fact_keys = {
        "feature_id",
        "state",
        "semantic_role",
        "evidence",
        "relation_feature_ids",
    }
    for index, fact in enumerate(facts):
        if type(fact) is not dict:
            exact_key_failures.append(index)
            continue
        feature_id = fact.get("feature_id", f"index:{index}")
        if set(fact) != expected_fact_keys:
            exact_key_failures.append(feature_id)
        if fact.get("semantic_role") != "feature_state":
            semantic_role_failures.append(feature_id)
        state = fact.get("state")
        if state not in {"present", "absent"}:
            state_failures.append(feature_id)
        evidence = fact.get("evidence")
        if type(evidence) is not list or (state == "present") != bool(evidence):
            evidence_presence_failures.append(feature_id)
            continue
        for span in evidence:
            if type(span) is not dict:
                evidence_bounds_failures.append(feature_id)
                continue
            if set(span) != {"text"}:
                evidence_key_failures.append(feature_id)
                continue
            text = span.get("text")
            if (
                type(text) is not str
                or not text
                or len(text) > 4096
            ):
                evidence_bounds_failures.append(feature_id)
                continue
            if prompt.prompt.count(text) != 1:
                evidence_text_failures.append(feature_id)
            hashlib.sha256(text.encode("utf-8")).hexdigest()
            derived_evidence_digest_count += 1
    result.update(
        {
            "exact_key_failures": exact_key_failures,
            "semantic_role_failures": semantic_role_failures,
            "state_failures": state_failures,
            "evidence_presence_failures": evidence_presence_failures,
            "evidence_key_failures": evidence_key_failures,
            "evidence_bounds_failures": evidence_bounds_failures,
            "evidence_text_failures": evidence_text_failures,
            "derived_evidence_digest_count": derived_evidence_digest_count,
        }
    )
    return result


def diagnose(
    *,
    config_path: Path,
    prompts_path: Path,
    output_dir: Path,
    prompt_id: str | None = None,
) -> dict[str, object]:
    if output_dir.exists():
        raise FileExistsError(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    config = load_config(config_path)
    prompts = read_jsonl(
        prompts_path,
        PromptRecord,
        required=True,
        allow_empty=False,
        stage="diagnose-llm-facts-response",
    )
    prompt = next(
        (item for item in prompts if prompt_id is None or item.prompt_id == prompt_id),
        None,
    )
    if type(prompt) is not PromptRecord:
        raise ValueError("diagnostic prompt failed validation")
    policy = extraction_policy(config.tsg)
    structured = structured_policy_for_config(config.tsg)
    llm = config.tsg.llm
    if llm is None:
        raise ValueError("diagnostic LLM config is unavailable")
    request = canonical_request_bytes(facts_request_payload(prompt, policy))
    _write_json(
        output_dir / "command.json",
        {
            "argv": list(sys.argv),
            "working_directory": os.getcwd(),
            "credential_source": f"environment:{llm.api_key_env}",
            "credential_persisted": False,
        },
    )
    _write_json(
        output_dir / "environment.json",
        {
            "captured_at_utc": datetime.now(UTC).isoformat(),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": sys.version,
            "python_executable": sys.executable,
        },
    )
    _write_json(
        output_dir / "policy.json",
        {
            "extractor_policy_sha256": policy.policy_sha256,
            "structured_policy": {
                field: getattr(structured, field)
                for field in structured.__dataclass_fields__
            },
            "catalog_feature_count": len(catalog_prompt_view()),
        },
    )
    (output_dir / "request.json").write_bytes(request + b"\n")
    transport = OpenAICompatibleStructuredTransport(
        base_url=llm.base_url,
        api_key_env=llm.api_key_env,
        system_template=LLM_FACTS_SYSTEM_TEMPLATE,
    )
    raw = transport.complete(request, structured)
    (output_dir / "raw-response.json").write_bytes(raw + b"\n")
    mechanical = _mechanical_diagnostics(raw, prompt)
    _write_json(output_dir / "mechanical-diagnostics.json", mechanical)
    proposal_valid = False
    tsg_valid = False
    try:
        proposal = parse_facts_response(raw, prompt, policy)
        proposal_valid = True
        build_prompt_tsg(proposal, prompt)
        tsg_valid = True
    except Exception:
        pass
    report = {
        "schema_version": "1.0",
        "status": "VALID" if tsg_valid else "INVALID",
        "prompt_id": prompt.prompt_id,
        "prompt_sha256": prompt.prompt_sha256,
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "response_sha256": hashlib.sha256(raw).hexdigest(),
        "response_bytes": len(raw),
        "proposal_valid": proposal_valid,
        "tsg_valid": tsg_valid,
        "mechanical_diagnostics_sha256": hashlib.sha256(
            (output_dir / "mechanical-diagnostics.json").read_bytes()
        ).hexdigest(),
    }
    _write_json(output_dir / "report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--prompts", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--prompt-id")
    args = parser.parse_args()
    report = diagnose(
        config_path=args.config,
        prompts_path=args.prompts,
        output_dir=args.output_dir,
        prompt_id=args.prompt_id,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
