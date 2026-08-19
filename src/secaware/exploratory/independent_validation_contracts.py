"""Freeze source Prompts and functional contracts before independent validation."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.functional_judge.schema import (
    FunctionalAuditDecisionRecord,
    FunctionalAuditStatus,
    FunctionalJudgeability,
    FunctionalRequirementRecord,
    TaskFunctionalContractRecord,
)
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.records import PromptRecord

_SCHEMA_VERSION = "1.0"
_REQUIRED_CWES = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")
_TASK_FAMILY = {
    "CWE-78": "command_execution",
    "CWE-89": "database_query",
    "CWE-502": "data_deserialization",
    "CWE-328": "security_digest",
    "CWE-338": "security_randomness",
}
_CONTRACT_LABEL_LEAKAGE = re.compile(
    r"(?i)(?:\bCWE-\d+\b|\bvulnerabilit(?:y|ies)\b|\binjection\b|"
    r"\btarget[_ -]?patch\b|\bsecure(?:d|ly)?\b|\binsecure\b|\bcausal\b)"
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=lambda item: item.model_dump(mode="json"),
    ).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("independent functional contract JSON failed validation")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if type(value) is not dict:
            raise ValueError("independent functional contract JSONL failed validation")
        result.append(value)
    return result


def _write_json(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(_canonical(value) + b"\n")


def _write_jsonl(path: Path, values: list[object]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for value in values:
            handle.write(_canonical(value).decode("utf-8") + "\n")


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def _repo_input(repo_root: Path, record: object) -> Path:
    if type(record) is not dict or set(record) != {"path", "sha256"}:
        raise ValueError("independent functional contract input failed validation")
    relative = record.get("path")
    digest = record.get("sha256")
    if type(relative) is not str or type(digest) is not str or len(digest) != 64:
        raise ValueError("independent functional contract input failed validation")
    path = (repo_root / relative).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        raise ValueError("independent functional contract input escaped repository") from None
    if not path.is_file() or sha256_file(path) != digest:
        raise ValueError("independent functional contract input digest failed validation")
    return path


def _manifest(root: Path) -> dict[str, object]:
    files = sorted(
        path for path in root.rglob("*") if path.is_file() and path.name != "artifact-manifest.json"
    )
    return {
        "schema_version": _SCHEMA_VERSION,
        "files": [
            {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)}
            for path in files
        ],
    }


def _requirement_records(
    values: object, *, source_prompt: str
) -> tuple[FunctionalRequirementRecord, ...]:
    if type(values) is not list or not values or len(values) > 16:
        raise ValueError("independent functional requirements failed validation")
    records = tuple(
        sorted(
            (FunctionalRequirementRecord.model_validate(value) for value in values),
            key=lambda item: item.requirement_id,
        )
    )
    if (
        len({item.requirement_id for item in records}) != len(records)
        or any(item.prompt_evidence_quote not in source_prompt for item in records)
        or any(_CONTRACT_LABEL_LEAKAGE.search(item.criterion) for item in records)
    ):
        raise ValueError("independent functional requirement provenance failed validation")
    return records


def _prompt_id(prompt_sha256: str) -> str:
    return "independent-source-" + prompt_sha256[:24]


def _packet(
    *, cluster: dict[str, Any], source: dict[str, Any], source_prompt_id: str
) -> dict[str, object]:
    content = {
        "schema_version": _SCHEMA_VERSION,
        "packet_version": "independent-validation-functional-contract-v1",
        "task_id": cluster["semantic_cluster_id"],
        "source_prompt_id": source_prompt_id,
        "source_prompt_sha256": cluster["source_prompt_sha256"],
        "language": cluster["language"],
        "prompt": source["prompt"],
        "blindness": {
            "intervention_arm_withheld": True,
            "generated_code_withheld": True,
            "mechanism_state_withheld": True,
            "security_outcome_withheld": True,
            "generator_identity_withheld": True,
        },
    }
    return {
        **content,
        "packet_id": "functional_audit_packet_" + canonical_sha256(content),
    }


def _freeze_one(
    *,
    cluster: dict[str, Any],
    source: dict[str, Any],
    audit: dict[str, Any],
) -> tuple[
    PromptRecord,
    dict[str, object],
    FunctionalAuditDecisionRecord,
    TaskFunctionalContractRecord,
]:
    prompt = source.get("prompt")
    digest = cluster.get("source_prompt_sha256")
    if (
        type(prompt) is not str
        or not prompt.strip()
        or type(digest) is not str
        or hashlib.sha256(prompt.encode("utf-8")).hexdigest() != digest
        or cluster.get("cwe") not in _REQUIRED_CWES
        or cluster.get("language") not in {"python", "java", "go", "c"}
    ):
        raise ValueError("independent source Prompt failed validation")
    source_prompt_id = _prompt_id(digest)
    prompt_record = PromptRecord.model_validate(
        {
            "prompt_id": source_prompt_id,
            "task_id": cluster["semantic_cluster_id"],
            "split": "confirm",
            "language": cluster["language"],
            "task_family": _TASK_FAMILY[cluster["cwe"]],
            "cwe": cluster["cwe"],
            "prompt": prompt,
            "prompt_role": "neutral_baseline",
            "counterpart_prompt_id": None,
        }
    )
    requirements = _requirement_records(audit.get("requirements"), source_prompt=prompt)
    raw_dependencies = audit.get("environment_dependencies", [])
    if type(raw_dependencies) is not list or any(
        type(item) is not str or not item.strip() for item in raw_dependencies
    ):
        raise ValueError("independent functional dependencies failed validation")
    dependencies = tuple(sorted(set(raw_dependencies)))
    judgeability = FunctionalJudgeability(str(audit.get("judgeability")))
    if judgeability is FunctionalJudgeability.UNJUDGEABLE:
        raise ValueError("independent functional contract cannot be unjudgeable")
    packet = _packet(cluster=cluster, source=source, source_prompt_id=source_prompt_id)
    evidence_quotes = tuple(dict.fromkeys(item.prompt_evidence_quote for item in requirements))
    decision = FunctionalAuditDecisionRecord.from_content(
        packet_id=packet["packet_id"],
        task_id=cluster["semantic_cluster_id"],
        source_prompt_id=source_prompt_id,
        source_prompt_sha256=digest,
        pass_id="A",
        language=cluster["language"],
        judgeability=judgeability,
        requirements=requirements,
        environment_dependencies=dependencies,
        confidence="HIGH",
        evidence_quotes=evidence_quotes,
        rationale=(
            "The source Prompt states finite observable interface, behavior, input/output, or "
            "error-handling requirements; only those task requirements are retained."
        ),
        rubric_version="functional-contract-audit-v1",
        auditor_kind="CODEX",
        auditor_id="codex-primary",
    )
    evidence_sha256 = canonical_sha256(decision.model_dump(mode="json"))
    contract = TaskFunctionalContractRecord.from_content(
        task_id=cluster["semantic_cluster_id"],
        source_prompt_id=source_prompt_id,
        source_prompt_sha256=digest,
        language=cluster["language"],
        judgeability=judgeability,
        requirements=requirements,
        environment_dependencies=dependencies,
        audit_pass_ids=("A",),
        audit_status=FunctionalAuditStatus.RESOLVED,
        auditor_kind="CODEX",
        audit_evidence_sha256=evidence_sha256,
    )
    return prompt_record, packet, decision, contract


def freeze_independent_validation_contracts(
    *,
    repo_root: Path,
    config_path: Path,
    restricted_dir: Path,
    public_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Create one immutable restricted bundle plus a non-redistributive public receipt."""

    if restricted_dir.exists() or public_dir.exists():
        raise FileExistsError(restricted_dir if restricted_dir.exists() else public_dir)
    config = _read_json(config_path)
    inputs = config.get("inputs")
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("freeze_id") != "five_cwe_independent_validation_contracts_v1"
        or config.get("expected_tasks") != 55
        or config.get("expected_prior_tasks") != 40
        or config.get("expected_supplemental_tasks") != 15
        or config.get("required_cwes") != list(_REQUIRED_CWES)
        or config.get("provider_calls_allowed") is not False
        or config.get("outcomes_allowed") is not False
        or config.get("raw_prompt_redistribution_allowed") is not False
        or type(inputs) is not dict
        or set(inputs)
        != {
            "final_pool",
            "prior_candidate_packets",
            "prior_reconciled_decisions",
            "supplemental_prompts",
            "supplemental_requirements",
        }
    ):
        raise ValueError("independent functional contract config failed validation")
    paths = {name: _repo_input(repo_root, value) for name, value in inputs.items()}
    clusters = _read_jsonl(paths["final_pool"])
    prior_packets = _read_jsonl(paths["prior_candidate_packets"])
    prior_decisions = _read_jsonl(paths["prior_reconciled_decisions"])
    supplemental_prompts = _read_jsonl(paths["supplemental_prompts"])
    supplemental_requirements = _read_jsonl(paths["supplemental_requirements"])
    if len(clusters) != 55 or len({row.get("semantic_cluster_id") for row in clusters}) != 55:
        raise ValueError("independent functional contract pool failed validation")

    packet_by_record = {row.get("record_id"): row for row in prior_packets}
    decision_by_record = {row.get("record_id"): row for row in prior_decisions}
    supplemental_by_cluster = {row.get("semantic_cluster_id"): row for row in supplemental_prompts}
    requirements_by_record = {row.get("source_record_id"): row for row in supplemental_requirements}
    if (
        None in packet_by_record
        or None in decision_by_record
        or None in supplemental_by_cluster
        or None in requirements_by_record
        or len(supplemental_by_cluster) != 15
        or len(requirements_by_record) != 15
    ):
        raise ValueError("independent functional contract indexes failed validation")

    prompts: list[PromptRecord] = []
    packets: list[dict[str, object]] = []
    decisions: list[FunctionalAuditDecisionRecord] = []
    contracts: list[TaskFunctionalContractRecord] = []
    origins: list[str] = []
    for cluster in sorted(clusters, key=lambda row: str(row["semantic_cluster_id"])):
        if cluster.get("pool_origin") == "prior_external_public_sources":
            record_id = cluster.get("representative_record_id")
            source = packet_by_record.get(record_id)
            prior = decision_by_record.get(record_id)
            if source is None or prior is None or type(prior.get("audit")) is not dict:
                raise ValueError("independent prior functional provenance failed validation")
            audit = prior["audit"]
            origins.append("prior_reused")
        elif cluster.get("pool_origin") == "codesec_eval_seceval_plus_restricted_source":
            source = supplemental_by_cluster.get(cluster.get("semantic_cluster_id"))
            if source is None:
                raise ValueError("independent supplemental Prompt failed validation")
            audit = requirements_by_record.get(source.get("source_record_id"))
            if audit is None:
                raise ValueError("independent supplemental requirements failed validation")
            origins.append("supplemental_codex")
        else:
            raise ValueError("independent functional contract origin failed validation")
        prompt, packet, decision, contract = _freeze_one(
            cluster=cluster, source=source, audit=audit
        )
        prompts.append(prompt)
        packets.append(packet)
        decisions.append(decision)
        contracts.append(contract)

    if (
        Counter(origins) != Counter({"prior_reused": 40, "supplemental_codex": 15})
        or {item.task_id for item in contracts}
        != {str(row["semantic_cluster_id"]) for row in clusters}
        or len({item.prompt_id for item in prompts}) != 55
        or len({item.contract_id for item in contracts}) != 55
    ):
        raise ValueError("independent functional contract coverage failed validation")

    restricted_dir.mkdir(parents=True, exist_ok=False)
    public_dir.mkdir(parents=True, exist_ok=False)
    _write_json(restricted_dir / "effective-config.json", config)
    _write_json(restricted_dir / "environment.json", _environment())
    _write_json(
        restricted_dir / "command.json",
        {"schema_version": _SCHEMA_VERSION, "argv": list(command_argv)},
    )
    _write_jsonl(restricted_dir / "source-prompts.jsonl", list(prompts))
    _write_jsonl(restricted_dir / "audit-packets.jsonl", packets)
    _write_jsonl(restricted_dir / "audit-decisions.jsonl", list(decisions))
    _write_jsonl(restricted_dir / "task-functional-contracts.jsonl", list(contracts))
    restricted_report = {
        "schema_version": _SCHEMA_VERSION,
        "status": "INDEPENDENT_VALIDATION_CONTRACTS_FROZEN",
        "scientific_claim_allowed": False,
        "provider_calls": 0,
        "outcomes_consumed": 0,
        "counts": {
            "tasks": 55,
            "prompts": 55,
            "contracts": 55,
            "audit_decisions": 55,
            "prior_requirements_reused": sum(
                len(item.requirements)
                for item, origin in zip(contracts, origins)
                if origin == "prior_reused"
            ),
            "supplemental_requirements": sum(
                len(item.requirements)
                for item, origin in zip(contracts, origins)
                if origin == "supplemental_codex"
            ),
            "failed": 0,
            "pending": 0,
        },
        "by_cwe": dict(sorted(Counter(item.cwe for item in prompts).items())),
        "by_language": dict(sorted(Counter(item.language for item in prompts).items())),
        "prompt_bundle_sha256": sha256_file(restricted_dir / "source-prompts.jsonl"),
        "contract_bundle_sha256": sha256_file(restricted_dir / "task-functional-contracts.jsonl"),
    }
    _write_json(restricted_dir / "report.json", restricted_report)
    _write_json(restricted_dir / "artifact-manifest.json", _manifest(restricted_dir))

    public_records = [
        {
            "schema_version": _SCHEMA_VERSION,
            "task_id": prompt.task_id,
            "source_id": cluster["source_id"],
            "cwe": prompt.cwe,
            "language": prompt.language,
            "source_prompt_sha256": contract.source_prompt_sha256,
            "contract_id": contract.contract_id,
            "judgeability": contract.judgeability.value,
            "requirement_count": len(contract.requirements),
            "requirements_sha256": canonical_sha256(
                [item.model_dump(mode="json") for item in contract.requirements]
            ),
        }
        for cluster, prompt, contract in zip(
            sorted(clusters, key=lambda row: str(row["semantic_cluster_id"])),
            prompts,
            contracts,
        )
    ]
    _write_json(public_dir / "effective-config.json", config)
    _write_json(
        public_dir / "command.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "argv": list(command_argv),
            "provider_calls": 0,
            "outcomes_consumed": 0,
        },
    )
    _write_jsonl(public_dir / "contract-receipts.jsonl", public_records)
    public_report = {
        **restricted_report,
        "raw_prompts_in_public_artifact": 0,
        "raw_requirements_in_public_artifact": 0,
        "restricted_report_sha256": sha256_file(restricted_dir / "report.json"),
        "next_action": "freeze_four_arm_runtime_and_analysis_manifest",
    }
    _write_json(public_dir / "report.json", public_report)
    _write_json(public_dir / "artifact-manifest.json", _manifest(public_dir))
    return public_report


__all__ = ["freeze_independent_validation_contracts"]
