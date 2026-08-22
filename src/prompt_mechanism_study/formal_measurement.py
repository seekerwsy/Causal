"""Thin external-adapter runner for frozen formal assignments."""

from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.cli import build_study
from prompt_mechanism_study.formal import load_formal_inputs
from prompt_mechanism_study.functional_judge import (
    bailian_complete,
    build_review_request,
    load_gate_inputs,
    python_syntax_valid,
    validate_review_response,
)
from prompt_mechanism_study.measurement import (
    CodeStatus,
    FunctionalStatus,
    Measurement,
    OracleStatus,
)
from prompt_mechanism_study.records import canonical_json, canonical_value, content_hash


def run_measurement_phase(
    repository_root: Path,
    phase: str,
    output: Path,
    *,
    add_freeze: Path,
    remove_freeze: Path,
    interventions: Path,
    oracle_source_root: Path,
    semgrep: Path,
    bandit: Path,
    pilot_root: Path | None = None,
) -> dict[str, Any]:
    """Measure one immutable pilot or remaining assignment partition."""

    if phase not in {"pilot", "remaining"}:
        raise ValueError("measurement phase must be pilot or remaining")
    if output.exists():
        raise FileExistsError(output)
    if phase == "remaining" and (
        pilot_root is None
        or read_json(pilot_root / "summary/report.json").get("status") != "PILOT_COMPLETE"
    ):
        raise ValueError("remaining measurement requires a complete pilot")

    root = repository_root.resolve()
    inputs = load_formal_inputs(root)
    judge = load_gate_inputs(root)
    task_by_id = {row["task_id"]: row for row in inputs.confirm_tasks}
    verify_bundle(interventions)
    task_map = read_json(interventions / "task-map.json")
    remove_to_source = {row["remove_task_id"]: row["source_task_id"] for row in task_map}
    studies = {
        "add": _load_frozen_study(add_freeze),
        "remove": _load_frozen_study(remove_freeze),
    }
    pilot_ids = set(inputs.pilot_task_ids)
    work: list[tuple[str, Any, Any, dict[str, Any]]] = []
    for study_name, study in studies.items():
        bundles = {
            bundle.task_bundle_id: bundle for policy in study.policies for bundle in policy.bundles
        }
        for assignment in study.randomization.assignments:
            source_id = (
                assignment.block.task_id
                if study_name == "add"
                else remove_to_source[assignment.block.task_id]
            )
            if (source_id in pilot_ids) is (phase == "pilot"):
                work.append(
                    (
                        study_name,
                        assignment,
                        bundles[assignment.block.task_bundle_id],
                        task_by_id[source_id],
                    )
                )
    expected = 20 if phase == "pilot" else 100
    if len(work) != expected:
        raise ValueError("measurement partition drifted")
    random.Random(inputs.config["randomization"]["execution_order_seed"]).shuffle(work)

    output.mkdir(parents=True)
    rows: list[dict[str, Any]] = []
    provider_calls = 0
    analyzer_runs = 0
    error_type: str | None = None
    for index, (study_name, assignment, bundle, task) in enumerate(work, start=1):
        artifacts: dict[str, Any] = {
            "assignment.json": {
                "study": study_name,
                "assignment": canonical_value(assignment),
                "task_id": task["task_id"],
            }
        }
        measurement: Measurement | None = None
        calls = 0
        analyzers = 0
        try:
            variant = bundle.variant(assignment.arm)
            generation_request = _generation_request(
                inputs.config["generation"],
                variant.prompt_text,
                inputs.config["randomization"][f"{study_name}_seed"],
            )
            calls += 1
            outer, code = _generate(generation_request, inputs.config["generation"])
            artifacts["generation.json"] = {
                "request": generation_request,
                "response_raw": outer.decode("utf-8", errors="replace"),
                "code": code,
            }
            generator_digest = hashlib.sha256(outer).hexdigest()
            code_digest = hashlib.sha256(code.encode()).hexdigest() if code else None
            if not code.strip() or not python_syntax_valid(code):
                measurement = Measurement(
                    assignment.assignment_id,
                    CodeStatus.NO_CODE if not code.strip() else CodeStatus.INVALID,
                    OracleStatus.NOT_RUN,
                    FunctionalStatus.NOT_RUN,
                    generator_digest,
                    code_sha256=code_digest,
                    terminal_reason="empty generation"
                    if not code.strip()
                    else "AST/compile failure",
                )
            else:
                security = _security_decision(
                    code,
                    task["oracle_profile_id"],
                    root / inputs.config["security_oracle"]["policy_lock_path"],
                    oracle_source_root,
                    semgrep,
                    bandit,
                )
                analyzers = 2
                artifacts["security.json"] = security
                contract = task["functional_contract"]
                functional_request = build_review_request(
                    code,
                    task["prompt"],
                    requirements=[
                        {"requirement_id": item["requirement_id"], "criterion": item["criterion"]}
                        for item in contract["requirements"]
                    ],
                    environment_dependencies=contract["environment_dependencies"],
                )
                calls += 1
                functional_raw = bailian_complete(
                    functional_request,
                    judge.evaluator,
                    judge.prompt,
                )
                functional = validate_review_response(functional_raw, code)
                artifacts["functional.json"] = {
                    "request": functional_request,
                    "response_raw": functional_raw.decode("utf-8", errors="replace"),
                    "validated": functional,
                }
                measurement = Measurement(
                    assignment.assignment_id,
                    CodeStatus.VALID,
                    OracleStatus(security["security_label"]),
                    FunctionalStatus(functional["status"]),
                    generator_digest,
                    code_digest,
                    content_hash(security),
                    hashlib.sha256(functional_raw).hexdigest(),
                )
            artifacts["measurement.json"] = canonical_value(measurement)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as error:  # noqa: BLE001 - close the failed assignment before stopping
            error_type = type(error).__name__
            artifacts["error.json"] = {"error_type": error_type}
        unit = output / f"assignment-{index:03d}"
        write_bundle(unit, artifacts)
        provider_calls += calls
        analyzer_runs += analyzers
        rows.append(
            {
                "assignment_id": assignment.assignment_id,
                "study": study_name,
                "source_task_id": task["task_id"],
                "arm": assignment.arm.value,
                "complete": measurement is not None,
                "provider_calls": calls,
                "analyzer_runs": analyzers,
                "bundle_sha256": bundle_digest(unit),
                "error_type": error_type,
            }
        )
        if measurement is None:
            break
    complete = len(rows) == expected and all(row["complete"] for row in rows)
    report = {
        "schema_version": "1.0",
        "status": (
            "PILOT_COMPLETE"
            if phase == "pilot" and complete
            else "REMAINING_COMPLETE"
            if phase == "remaining" and complete
            else "ERROR"
        ),
        "phase": phase,
        "expected_assignments": expected,
        "completed_assignments": sum(row["complete"] for row in rows),
        "provider_calls": provider_calls,
        "analyzer_runs": analyzer_runs,
        "scientific_claim_allowed": False,
    }
    write_bundle(output / "summary", {"report.json": report, "assignments.json": rows})
    return report


def _load_frozen_study(freeze_root: Path) -> Any:
    verify_bundle(freeze_root)
    frozen = read_json(freeze_root / "freeze.json")
    study = build_study(read_json(freeze_root / "protocol.json"))
    if frozen["study_id"] != study.study_id:
        raise ValueError("study freeze drifted")
    return study


def _generation_request(config: dict[str, Any], prompt: str, seed: int) -> dict[str, Any]:
    return {
        "model": config["model_id"],
        "messages": [
            {"role": "system", "content": config["system_prompt"]},
            {"role": "user", "content": prompt},
        ],
        "temperature": config["temperature"],
        "top_p": config["top_p"],
        "max_tokens": config["max_tokens"],
        "seed": seed,
        "n": 1,
    }


def _generate(request_payload: dict[str, Any], config: dict[str, Any]) -> tuple[bytes, str]:
    key = os.environ.get(config["api_key_env"], "")
    if not key.strip():
        raise RuntimeError("generator credential unavailable")
    request = Request(
        config["base_url"].rstrip("/") + "/chat/completions",
        data=canonical_json(request_payload).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=config["timeout_seconds"]) as response:
        raw = response.read(4 * 1024 * 1024)
    outer = json.loads(raw)
    choices = outer.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise ValueError("generator response is invalid")
    choice = choices[0]
    code = choice.get("message", {}).get("content")
    if choice.get("finish_reason") != "stop" or not isinstance(code, str):
        raise ValueError("generator response is incomplete")
    return raw, code.strip()


def _security_decision(
    code: str,
    profile_id: str,
    policy_lock: Path,
    oracle_source_root: Path,
    semgrep: Path,
    bandit: Path,
) -> dict[str, Any]:
    source = str((oracle_source_root / "src").resolve())
    if source not in sys.path:
        sys.path.insert(0, source)
    from secaware.oracle.bandit_adapter import bandit_argv, parse_bandit_report
    from secaware.oracle.policy import load_policy_bundle
    from secaware.oracle.profile_decision import (
        decide_oracle_profile,
        extract_python_mechanism_trace,
        mechanism_trace_sha256,
    )
    from secaware.oracle.semgrep_adapter import parse_semgrep_report, semgrep_argv

    policy = load_policy_bundle(policy_lock)
    profile = next(item for item in policy.coverage_profiles if item.profile_id == profile_id)
    with tempfile.TemporaryDirectory(prefix="prompt-mechanism-oracle-") as directory:
        work = Path(directory)
        (work / "candidate.py").write_text(code, encoding="utf-8", newline="\n")
        semgrep_run = subprocess.run(
            semgrep_argv(semgrep, policy.semgrep_rules_path, Path("candidate.py")),
            cwd=work,
            capture_output=True,
            timeout=120,
            check=False,
        )
        bandit_run = subprocess.run(
            bandit_argv(bandit, policy.bandit_config_path, Path("candidate.py")),
            cwd=work,
            capture_output=True,
            timeout=120,
            check=False,
        )
    semgrep_report = parse_semgrep_report(
        semgrep_run.stdout,
        returncode=semgrep_run.returncode,
        expected_files={"candidate.py"},
        version=policy.semgrep_version,
        policy_sha256=policy.semgrep_sha256,
    )
    bandit_report = parse_bandit_report(
        bandit_run.stdout,
        returncode=bandit_run.returncode,
        expected_files={"candidate.py"},
        version=policy.bandit_version,
        policy_sha256=policy.bandit_sha256,
        constraints=policy.bandit_constraints,
    )
    trace = extract_python_mechanism_trace(code)
    findings = semgrep_report.canonical_findings + bandit_report.canonical_findings
    decision = decide_oracle_profile(trace, findings, profile)
    return {
        "security_label": decision.security_label.value,
        "evaluability": decision.evaluability.value,
        "reason_code": decision.reason_code,
        "severity": decision.severity,
        "mechanism_trace_sha256": mechanism_trace_sha256(trace),
        "decision": canonical_value(asdict(decision)),
        "semgrep": {
            "returncode": semgrep_run.returncode,
            "stdout_sha256": hashlib.sha256(semgrep_run.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(semgrep_run.stderr).hexdigest(),
        },
        "bandit": {
            "returncode": bandit_run.returncode,
            "stdout_sha256": hashlib.sha256(bandit_run.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(bandit_run.stderr).hexdigest(),
        },
    }


__all__ = ["run_measurement_phase"]
