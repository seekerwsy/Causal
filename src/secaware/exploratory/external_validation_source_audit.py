"""Outcome-blind audit of public sources for independent causal validation."""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.dataset_audit.fingerprints import (
    exact_prompt_sha256,
    normalized_prompt_sha256,
)
from secaware.dataset_audit.neutrality import classify_neutrality
from secaware.pipeline.artifact import sha256_file

_SCHEMA_VERSION = "1.0"
_TARGET_CWES = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")
_LLMSECEVAL_CWES = {
    "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')": "CWE-78",
    "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')": "CWE-89",
    "Deserialization of Untrusted Data": "CWE-502",
}
_SECCODE_LANG_FILES = {
    "cpp": "datasets/benchmark/cpp/c.json",
    "go": "datasets/benchmark/go/go.json",
    "java": "datasets/benchmark/java/java.json",
    "nodejs": "datasets/benchmark/nodejs/nodejs.json",
    "python": "datasets/benchmark/python/python.json",
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        row = json.loads(line)
        if type(row) is not dict:
            raise ValueError("external source JSONL row failed validation")
        rows.append(row)
    return rows


def _write_json(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(_canonical(value) + b"\n")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(_canonical(row).decode("utf-8") + "\n")


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
        raise ValueError("external source repository input failed validation")
    relative = record.get("path")
    digest = record.get("sha256")
    if type(relative) is not str or type(digest) is not str or len(digest) != 64:
        raise ValueError("external source repository input failed validation")
    path = (repo_root / relative).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        raise ValueError("external source repository input escaped repository") from None
    if not path.is_file() or sha256_file(path) != digest:
        raise ValueError("external source repository input digest failed validation")
    return path


def _validate_config(repo_root: Path, config_path: Path) -> tuple[dict[str, Any], dict[str, Path]]:
    config = _read_json(config_path)
    if type(config) is not dict:
        raise ValueError("external source configuration failed validation")
    inputs = config.get("repository_inputs")
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("audit_id") != "five_cwe_external_validation_source_audit_v1"
        or config.get("target_cwes") != list(_TARGET_CWES)
        or config.get("minimum_validation_tasks") != 50
        or config.get("provider_calls_allowed") is not False
        or config.get("outcomes_allowed") is not False
        or type(inputs) is not dict
        or set(inputs) != {"method_development_selection", "repository_record_audit"}
    ):
        raise ValueError("external source configuration failed validation")
    return config, {name: _repo_input(repo_root, value) for name, value in inputs.items()}


def _task(
    *,
    source_id: str,
    source_record_id: str,
    cwe: str | None,
    language: str,
    prompt: str,
    source_path: str,
    functional_contract: str,
    ancestry_risk: str,
    benchmark_variant: str,
) -> dict[str, object]:
    neutrality = classify_neutrality(prompt)
    return {
        "schema_version": _SCHEMA_VERSION,
        "source_id": source_id,
        "source_record_id": source_record_id,
        "source_path": source_path,
        "benchmark_variant": benchmark_variant,
        "cwe": cwe,
        "language": language,
        "prompt": prompt,
        "exact_prompt_sha256": exact_prompt_sha256(prompt),
        "normalized_prompt_sha256": normalized_prompt_sha256(prompt),
        "neutrality_prescreen": neutrality.state.value,
        "neutrality_rule_version": neutrality.rule_version,
        "functional_contract": functional_contract,
        "source_ancestry_risk": ancestry_risk,
    }


def _codeguard_tasks(root: Path) -> list[dict[str, object]]:
    base = root / "data" / "base"
    if not (root / "README.md").is_file() or not base.is_dir():
        raise ValueError("CodeGuard+ source root failed validation")
    rows: list[dict[str, object]] = []
    for cwe_dir in sorted(base.glob("cwe-*")):
        for scenario in sorted(path for path in cwe_dir.iterdir() if path.is_dir()):
            info = _read_json(scenario / "info.json")
            if type(info) is not dict:
                raise ValueError("CodeGuard+ info record failed validation")
            language_token = info.get("language")
            language = {"py": "python", "c": "c", "cpp": "cpp"}.get(language_token)
            if language is None:
                raise ValueError("CodeGuard+ language failed validation")
            context_paths = (scenario / f"file_context.{language_token}", scenario / f"func_context.{language_token}")
            if not all(path.is_file() for path in context_paths):
                raise ValueError("CodeGuard+ context files failed validation")
            prompt = "".join(path.read_text(encoding="utf-8") for path in context_paths)
            raw_cwe = str(info.get("cwe", ""))
            try:
                cwe = f"CWE-{int(raw_cwe.removeprefix('CWE-'))}"
            except ValueError as error:
                raise ValueError("CodeGuard+ CWE failed validation") from error
            functional = root / "unit_test" / cwe_dir.name / scenario.name / "functional.py"
            rows.append(
                _task(
                    source_id="codeguard_plus",
                    source_record_id=f"{cwe_dir.name}/{scenario.name}",
                    cwe=cwe,
                    language=language,
                    prompt=prompt,
                    source_path=f"data/base/{cwe_dir.name}/{scenario.name}",
                    functional_contract=("executable_test" if functional.is_file() else "missing_test"),
                    ancestry_risk="copilot_securityeval_codeql_ancestry",
                    benchmark_variant="base_context",
                )
            )
    return rows


def _llmseceval_tasks(root: Path) -> list[dict[str, object]]:
    dataset = root / "Dataset" / "LLMSecEval-Prompts_dataset.json"
    raw = _read_json(dataset)
    if type(raw) is not list or len(raw) != 150:
        raise ValueError("LLMSecEval dataset failed validation")
    rows: list[dict[str, object]] = []
    for record in raw:
        if type(record) is not dict:
            raise ValueError("LLMSecEval record failed validation")
        prompt = record.get("LLM-generated NL Prompt")
        prompt_id = record.get("Prompt ID")
        language = record.get("Language")
        if not all(type(value) is str and value for value in (prompt, prompt_id, language)):
            raise ValueError("LLMSecEval record fields failed validation")
        rows.append(
            _task(
                source_id="llmseceval",
                source_record_id=prompt_id,
                cwe=_LLMSECEVAL_CWES.get(str(record.get("CWE Name"))),
                language=language.lower(),
                prompt=prompt,
                source_path="Dataset/LLMSecEval-Prompts_dataset.json",
                functional_contract="absent",
                ancestry_risk="pearce_copilot_scenario_ancestry",
                benchmark_variant="llm_generated_nl_prompt",
            )
        )
    return rows


def _seccode_cwe(name: str) -> str | None:
    if name.startswith("CommandInjection"):
        return "CWE-78"
    if name.startswith(("SQLInjection", "JDBCInjection")):
        return "CWE-89"
    if name.startswith("Deserialization"):
        return "CWE-502"
    if name.startswith("WeakHash"):
        return "CWE-328"
    if name.startswith("WeakRandomness"):
        return "CWE-338"
    return None


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(repo), *args),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _seccode_tasks(root: Path, *, expected_revision: str) -> list[dict[str, object]]:
    revision = _git(root, "rev-parse", "HEAD")
    if revision != expected_revision or "v2.2.0" not in _git(root, "tag", "--points-at", "HEAD").splitlines():
        raise ValueError("SecCodeBench revision failed validation")
    rows: list[dict[str, object]] = []
    for language, relative in sorted(_SECCODE_LANG_FILES.items()):
        raw = json.loads(_git(root, "show", f"HEAD:{relative}"))
        if type(raw) is not dict:
            raise ValueError("SecCodeBench language manifest failed validation")
        for name, record in sorted(raw.items()):
            if type(record) is not dict:
                raise ValueError("SecCodeBench task record failed validation")
            prompt_relative = f"datasets/benchmark/{'cpp' if language == 'cpp' else language}/prompts/{record['prompt']}.{record['locale']}"
            prompt = _git(root, "show", f"HEAD:{prompt_relative}")
            rows.append(
                _task(
                    source_id="seccodebench_v2_2_0",
                    source_record_id=name,
                    cwe=_seccode_cwe(name),
                    language=language,
                    prompt=prompt,
                    source_path=prompt_relative,
                    functional_contract=(
                        "executable_project_test"
                        if record.get("FuncTester") == "UnitTester"
                        else "unknown"
                    ),
                    ancestry_risk="independent_industrial_source",
                    benchmark_variant="gen",
                )
            )
    return rows


def _annotate_overlap(
    rows: list[dict[str, object]],
    *,
    method_hashes: set[str],
    asset_rows: list[dict[str, Any]],
) -> list[dict[str, object]]:
    exact_assets: dict[str, list[dict[str, Any]]] = {}
    normalized_assets: dict[str, list[dict[str, Any]]] = {}
    for asset in asset_rows:
        exact_assets.setdefault(str(asset.get("exact_prompt_sha256")), []).append(asset)
        normalized_assets.setdefault(str(asset.get("normalized_prompt_sha256")), []).append(asset)
    annotated: list[dict[str, object]] = []
    for row in rows:
        exact = str(row["exact_prompt_sha256"])
        normalized = str(row["normalized_prompt_sha256"])
        exact_matches = exact_assets.get(exact, [])
        normalized_matches = normalized_assets.get(normalized, [])
        asset_sources = sorted(
            {
                str(match.get("coordinate", {}).get("source_id"))
                for match in (*exact_matches, *normalized_matches)
            }
        )
        target = row.get("cwe") in _TARGET_CWES
        neutrality = row["neutrality_prescreen"]
        method_overlap = exact in method_hashes
        if method_overlap:
            review_status = "excluded_method_development_exact_overlap"
        elif not target:
            review_status = "outside_frozen_cwe_scope"
        elif neutrality == "OBVIOUS_CONFLICT":
            review_status = "excluded_neutrality_conflict"
        else:
            review_status = "blinded_task_review_required"
        annotated.append(
            {
                **row,
                "method_development_exact_overlap": method_overlap,
                "repository_asset_exact_overlap": bool(exact_matches),
                "repository_asset_normalized_overlap": bool(normalized_matches),
                "repository_asset_source_ids": asset_sources,
                "semantic_overlap_status": (
                    "known_repository_asset_overlap"
                    if exact_matches or normalized_matches
                    else (
                        "ancestry_review_required"
                        if row["source_ancestry_risk"]
                        != "independent_industrial_source"
                        else "no_known_overlap_review_still_required"
                    )
                ),
                "validation_stratum": (
                    "python_primary_candidate"
                    if row["language"] == "python"
                    else "multilanguage_transportability_candidate"
                ),
                "review_status": review_status,
            }
        )
    return annotated


def audit_external_validation_sources(
    *,
    repo_root: Path,
    config_path: Path,
    run_dir: Path,
    codeguard_root: Path,
    codeguard_archive: Path,
    llmseceval_root: Path,
    llmseceval_archive: Path,
    seccode_root: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Inventory public task sources without consuming generated outcomes."""

    if run_dir.exists():
        raise FileExistsError(run_dir)
    config, repo_inputs = _validate_config(repo_root, config_path)
    source_config = config.get("sources")
    if type(source_config) is not dict or set(source_config) != {
        "codeguard_plus",
        "llmseceval",
        "seccodebench_v2_2_0",
    }:
        raise ValueError("external source receipts failed validation")
    for source_id, archive in (
        ("codeguard_plus", codeguard_archive),
        ("llmseceval", llmseceval_archive),
    ):
        expected = source_config[source_id].get("archive_sha256")
        if not archive.is_file() or sha256_file(archive) != expected:
            raise ValueError(f"{source_id} archive digest failed validation")

    selection = _read_json(repo_inputs["method_development_selection"])
    if type(selection) is not dict or type(selection.get("tasks")) is not list:
        raise ValueError("method-development selection failed validation")
    method_hashes = {str(row.get("source_prompt_sha256")) for row in selection["tasks"]}
    if len(method_hashes) != 93:
        raise ValueError("method-development prompt population failed validation")
    asset_rows = _read_jsonl(repo_inputs["repository_record_audit"])

    source_rows = {
        "codeguard_plus": _codeguard_tasks(codeguard_root.resolve()),
        "llmseceval": _llmseceval_tasks(llmseceval_root.resolve()),
        "seccodebench_v2_2_0": _seccode_tasks(
            seccode_root.resolve(),
            expected_revision=source_config["seccodebench_v2_2_0"]["revision"],
        ),
    }
    all_rows = _annotate_overlap(
        [row for source_id in sorted(source_rows) for row in source_rows[source_id]],
        method_hashes=method_hashes,
        asset_rows=asset_rows,
    )
    target_rows = [row for row in all_rows if row.get("cwe") in _TARGET_CWES]
    review_rows = [row for row in target_rows if row["review_status"] == "blinded_task_review_required"]
    present_cwes = sorted({str(row["cwe"]) for row in review_rows})
    missing_cwes = [cwe for cwe in _TARGET_CWES if cwe not in present_cwes]

    by_source: dict[str, object] = {}
    for source_id in sorted(source_rows):
        rows = [row for row in all_rows if row["source_id"] == source_id]
        target = [row for row in rows if row.get("cwe") in _TARGET_CWES]
        by_source[source_id] = {
            "raw_tasks": len(rows),
            "five_cwe_tasks": len(target),
            "five_cwe_by_cwe": dict(sorted(Counter(str(row["cwe"]) for row in target).items())),
            "five_cwe_by_language": dict(
                sorted(Counter(str(row["language"]) for row in target).items())
            ),
            "candidate_neutral": sum(
                row["neutrality_prescreen"] == "CANDIDATE_NEUTRAL" for row in target
            ),
            "executable_functional_contract": sum(
                str(row["functional_contract"]).startswith("executable") for row in target
            ),
            "method_development_exact_overlap": sum(
                bool(row["method_development_exact_overlap"]) for row in target
            ),
            "repository_asset_exact_overlap": sum(
                bool(row["repository_asset_exact_overlap"]) for row in target
            ),
            "blinded_task_review_required": sum(
                row["review_status"] == "blinded_task_review_required" for row in target
            ),
        }

    run_dir.mkdir(parents=True, exist_ok=False)
    _write_json(run_dir / "effective-config.json", config)
    _write_json(run_dir / "environment.json", _environment())
    _write_json(
        run_dir / "command.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "argv": command_argv,
            "provider_calls": 0,
            "outcomes_consumed": 0,
        },
    )
    _write_json(
        run_dir / "input-provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "config_sha256": sha256_file(config_path),
            "repository_inputs": {
                name: {"path": str(path.relative_to(repo_root)), "sha256": sha256_file(path)}
                for name, path in sorted(repo_inputs.items())
            },
            "external_sources": {
                "codeguard_plus": {
                    "root": str(codeguard_root.resolve()),
                    "archive": str(codeguard_archive.resolve()),
                    "archive_sha256": sha256_file(codeguard_archive),
                },
                "llmseceval": {
                    "root": str(llmseceval_root.resolve()),
                    "archive": str(llmseceval_archive.resolve()),
                    "archive_sha256": sha256_file(llmseceval_archive),
                },
                "seccodebench_v2_2_0": {
                    "root": str(seccode_root.resolve()),
                    "revision": _git(seccode_root.resolve(), "rev-parse", "HEAD"),
                },
            },
        },
    )
    _write_jsonl(run_dir / "source-tasks.jsonl", all_rows)
    _write_jsonl(run_dir / "five-cwe-review-queue.jsonl", review_rows)
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "EXTERNAL_SOURCE_BLINDED_REVIEW_REQUIRED",
        "scientific_claim_allowed": False,
        "provider_calls": 0,
        "outcomes_consumed": 0,
        "sources": by_source,
        "combined": {
            "raw_tasks": len(all_rows),
            "five_cwe_tasks": len(target_rows),
            "python_five_cwe_tasks": sum(row["language"] == "python" for row in target_rows),
            "blinded_task_review_required": len(review_rows),
            "review_queue_by_cwe": dict(
                sorted(Counter(str(row["cwe"]) for row in review_rows).items())
            ),
            "review_queue_with_executable_contract": sum(
                str(row["functional_contract"]).startswith("executable") for row in review_rows
            ),
            "review_queue_repository_asset_overlap": sum(
                bool(row["repository_asset_exact_overlap"]) for row in review_rows
            ),
            "minimum_validation_tasks": config["minimum_validation_tasks"],
        },
        "missing_cwes_before_blinded_review": missing_cwes,
        "next_action": "complete_outcome_blind_task_eligibility_and_semantic_deduplication",
    }
    _write_json(run_dir / "report.json", report)
    files = [path for path in run_dir.rglob("*") if path.is_file()]
    _write_json(
        run_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {"path": path.relative_to(run_dir).as_posix(), "sha256": sha256_file(path)}
                for path in sorted(files)
            ],
        },
    )
    return report


__all__ = ["audit_external_validation_sources"]
