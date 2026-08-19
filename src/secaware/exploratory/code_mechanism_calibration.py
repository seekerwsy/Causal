"""Immutable calibration runner for multilingual code-mechanism facts."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import sys
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.exploratory.code_mechanism_facts import (
    CODE_MECHANISM_FACTS_OUTPUT_SCHEMA_SHA256,
    CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE,
    CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE_SHA256,
    LLMCodeMechanismFactsExtractor,
    code_mechanism_request_payload,
    parse_code_mechanism_response,
)
from secaware.llm.structured_transport import (
    OpenAICompatibleStructuredTransport,
    StructuredJSONTransport,
    StructuredLLMPolicy,
    canonical_request_bytes,
)
from secaware.pipeline.artifact import sha256_file

_SCHEMA_VERSION = "1.0"
_CWES = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")
_LANGUAGES = ("python", "java", "go", "c")
_EXPECTED_STATES = ("proved_safe", "proved_unsafe")


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
            raise ValueError("code mechanism calibration JSONL failed validation")
        rows.append(row)
    return rows


def _write_json(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(_canonical(value) + b"\n")


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
        raise ValueError("code mechanism calibration input failed validation")
    path_value = record.get("path")
    digest = record.get("sha256")
    if type(path_value) is not str or type(digest) is not str or len(digest) != 64:
        raise ValueError("code mechanism calibration input failed validation")
    path = (repo_root / path_value).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        raise ValueError("code mechanism calibration input escaped repository") from None
    if not path.is_file() or sha256_file(path) != digest:
        raise ValueError("code mechanism calibration input digest failed validation")
    return path


def _policy(config: dict[str, Any]) -> StructuredLLMPolicy:
    llm = config.get("llm")
    if type(llm) is not dict:
        raise ValueError("code mechanism calibration LLM config failed validation")
    base_url = llm.get("base_url")
    if (
        type(base_url) is not str
        or llm.get("provider") != "openai_compatible"
        or llm.get("system_template_sha256") != CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE_SHA256
        or llm.get("output_schema_sha256") != CODE_MECHANISM_FACTS_OUTPUT_SCHEMA_SHA256
    ):
        raise ValueError("code mechanism calibration LLM config failed validation")
    return StructuredLLMPolicy(
        endpoint_sha256=hashlib.sha256(base_url.encode("utf-8")).hexdigest(),
        model_id=llm["model_id"],
        system_template_sha256=llm["system_template_sha256"],
        output_schema_sha256=llm["output_schema_sha256"],
        temperature=float(llm["temperature"]),
        top_p=float(llm["top_p"]),
        seed=llm["seed"],
        timeout_seconds=float(llm["timeout_seconds"]),
        max_attempts=llm["max_attempts"],
        max_response_bytes=llm["max_response_bytes"],
        enable_thinking=llm["enable_thinking"],
    )


def _validate_case(row: dict[str, Any]) -> None:
    required = {"calibration_id", "code", "cwe", "expected_state", "language"}
    if (
        set(row) != required
        or type(row.get("calibration_id")) is not str
        or not row["calibration_id"]
        or type(row.get("code")) is not str
        or not row["code"].strip()
        or row.get("cwe") not in _CWES
        or row.get("language") not in _LANGUAGES
        or row.get("expected_state") not in _EXPECTED_STATES
    ):
        raise ValueError("code mechanism calibration case failed validation")


def run_code_mechanism_calibration(
    *,
    repo_root: Path,
    config_path: Path,
    run_dir: Path,
    command_argv: tuple[str, ...],
    transport: StructuredJSONTransport | None = None,
) -> dict[str, object]:
    """Run one frozen calibration selection and retain every request and response."""

    if run_dir.exists():
        raise FileExistsError(run_dir)
    config = _read_json(config_path)
    if type(config) is not dict:
        raise ValueError("code mechanism calibration config failed validation")
    selection = config.get("selected_calibration_ids")
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("calibration_kind") != "multilingual_code_mechanism_facts_v1"
        or type(selection) is not list
        or not selection
        or any(type(item) is not str or not item for item in selection)
        or len(selection) != len(set(selection))
        or config.get("expected_calls") != len(selection)
        or type(config.get("minimum_accuracy")) not in {int, float}
        or not 0.0 <= float(config["minimum_accuracy"]) <= 1.0
        or type(config.get("maximum_error_fraction")) not in {int, float}
        or not 0.0 <= float(config["maximum_error_fraction"]) <= 1.0
        or config.get("arms_allowed") is not False
        or config.get("outcomes_allowed") is not False
        or config.get("provider_calls_allowed") is not True
    ):
        raise ValueError("code mechanism calibration config failed validation")
    corpus_path = _repo_input(repo_root, config.get("corpus"))
    corpus = _read_jsonl(corpus_path)
    for row in corpus:
        _validate_case(row)
    by_id = {str(row["calibration_id"]): row for row in corpus}
    if len(by_id) != len(corpus) or any(item not in by_id for item in selection):
        raise ValueError("code mechanism calibration selection failed validation")
    selected = [by_id[item] for item in selection]
    policy = _policy(config)
    llm = config["llm"]
    selected_transport = transport
    if selected_transport is None:
        selected_transport = OpenAICompatibleStructuredTransport(
            base_url=llm["base_url"],
            api_key_env=llm["api_key_env"],
            system_template=CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE,
        )
    extractor = LLMCodeMechanismFactsExtractor(selected_transport, policy)

    run_dir.mkdir(parents=True, exist_ok=False)
    _write_json(run_dir / "effective-config.json", config)
    _write_json(run_dir / "environment.json", _environment())
    _write_json(
        run_dir / "command.json",
        {"schema_version": _SCHEMA_VERSION, "argv": list(command_argv)},
    )
    requests_path = run_dir / "requests.jsonl"
    responses_path = run_dir / "responses.jsonl"
    measurements_path = run_dir / "measurements.jsonl"
    errors_path = run_dir / "errors.jsonl"
    progress_path = run_dir / "progress.jsonl"
    completed = 0
    correct = 0
    errors = 0
    measurements: list[dict[str, object]] = []
    with (
        requests_path.open("x", encoding="utf-8", newline="\n") as request_handle,
        responses_path.open("x", encoding="utf-8", newline="\n") as response_handle,
        measurements_path.open("x", encoding="utf-8", newline="\n") as measurement_handle,
        errors_path.open("x", encoding="utf-8", newline="\n") as error_handle,
        progress_path.open("x", encoding="utf-8", newline="\n") as progress_handle,
    ):
        for index, row in enumerate(selected, start=1):
            request = code_mechanism_request_payload(
                code=row["code"], target_cwe=row["cwe"], language=row["language"]
            )
            request_bytes = canonical_request_bytes(request)
            request_record = {
                "calibration_id": row["calibration_id"],
                "request": request,
                "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            }
            request_handle.write(_canonical(request_record).decode("utf-8") + "\n")
            request_handle.flush()
            raw = b""
            try:
                raw = selected_transport.complete(request_bytes, policy)
                response_record = {
                    "calibration_id": row["calibration_id"],
                    "raw_response": raw.decode("utf-8"),
                    "response_sha256": hashlib.sha256(raw).hexdigest(),
                }
                response_handle.write(_canonical(response_record).decode("utf-8") + "\n")
                response_handle.flush()
                measurement = parse_code_mechanism_response(
                    raw,
                    code=row["code"],
                    target_cwe=row["cwe"],
                    language=row["language"],
                    policy=policy,
                )
                is_correct = measurement.mechanism_state == row["expected_state"]
                record = {
                    "calibration_id": row["calibration_id"],
                    "expected_state": row["expected_state"],
                    "correct": is_correct,
                    "measurement": asdict(measurement),
                }
                measurement_handle.write(_canonical(record).decode("utf-8") + "\n")
                measurement_handle.flush()
                measurements.append(record)
                completed += 1
                correct += int(is_correct)
            except Exception as error:  # noqa: BLE001 - every failed case is retained and audited
                errors += 1
                error_record = {
                    "calibration_id": row["calibration_id"],
                    "error_type": type(error).__name__,
                    "message": str(error),
                    "raw_response_sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                }
                error_handle.write(_canonical(error_record).decode("utf-8") + "\n")
                error_handle.flush()
            progress = {
                "completed": completed,
                "correct": correct,
                "errors": errors,
                "pending": len(selected) - index,
            }
            progress_handle.write(_canonical(progress).decode("utf-8") + "\n")
            progress_handle.flush()

    accuracy = correct / len(selected)
    error_fraction = errors / len(selected)
    passed = (
        completed + errors == len(selected)
        and accuracy >= float(config["minimum_accuracy"])
        and error_fraction <= float(config["maximum_error_fraction"])
    )
    by_language = Counter(
        f"{by_id[str(item['calibration_id'])]['language']}:{'correct' if item['correct'] else 'wrong'}"
        for item in measurements
    )
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "CODE_MECHANISM_CALIBRATION_PASS" if passed else "CODE_MECHANISM_CALIBRATION_FAIL",
        "scientific_claim_allowed": False,
        "counts": {
            "selected": len(selected),
            "provider_calls": len(selected),
            "completed": completed,
            "correct": correct,
            "errors": errors,
            "pending": 0,
        },
        "accuracy": accuracy,
        "error_fraction": error_fraction,
        "by_language_result": dict(sorted(by_language.items())),
        "policy_sha256": extractor.policy_sha256,
        "corpus_sha256": sha256_file(corpus_path),
        "next_action": config["next_action_on_pass"] if passed else "review_calibration_failures",
    }
    _write_json(run_dir / "report.json", report)
    files = [path for path in run_dir.iterdir() if path.is_file()]
    _write_json(
        run_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {"path": path.name, "sha256": sha256_file(path)} for path in sorted(files)
            ],
        },
    )
    return report


__all__ = ["run_code_mechanism_calibration"]
