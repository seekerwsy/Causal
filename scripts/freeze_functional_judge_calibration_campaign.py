"""Freeze a zero-provider-call receipt before functional-Judge calibration runs."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import platform
import re
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

# This must be set before any project module is imported.  A deployment receipt
# must not rely on its caller remembering ``-B``: importing the validation code
# must leave an immutable archive byte-for-byte unchanged.
sys.dont_write_bytecode = True

# ``python scripts/<name>.py`` normally places only ``scripts/`` on sys.path.
# Add both src-layout roots before importing project modules so an immutable
# git-archive deployment does not rely on an editable installation.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
for _source_root in (_REPOSITORY_ROOT / "src", _REPOSITORY_ROOT):
    if str(_source_root) not in sys.path:
        sys.path.insert(0, str(_source_root))

analyzer = importlib.import_module("scripts.analyze_functional_judge_calibration")
planner = importlib.import_module("scripts.plan_functional_judge_calibration")
canary = importlib.import_module("scripts.validate_bailian_functional_judge")
artifact_integrity_module = importlib.import_module("secaware.exploratory.artifact_integrity")
pipeline_artifact_module = importlib.import_module("secaware.pipeline.artifact")
config_module = importlib.import_module("secaware.config")
functional_judge_factory_module = importlib.import_module("secaware.functional_judge.factory")
functional_judge_module = importlib.import_module("secaware.functional_judge.judge")
functional_judge_schema_module = importlib.import_module("secaware.functional_judge.schema")
verify_closed_manifest = artifact_integrity_module.verify_closed_manifest
write_closed_manifest_atomic = artifact_integrity_module.write_closed_manifest_atomic
write_json_atomic_exclusive = artifact_integrity_module.write_json_atomic_exclusive
canonical_sha256 = pipeline_artifact_module.canonical_sha256

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROVIDER_ATTEMPT_SCOPE = "included_closed_run_trace_records"
_DEPLOYMENT_REQUIRED_EXCLUSIONS = frozenset({"DEPLOYMENT_FILES.sha256", "DEPLOYMENT_MANIFEST.json"})
_DEPLOYMENT_OPTIONAL_EXCLUSIONS = frozenset({".env"})
_PHASE_SPECS = (
    ("baseline_pilot", "baseline", "pilot", 2),
    ("baseline_remaining", "baseline", "remaining", 22),
    ("new_candidate_pilot", "new_candidate", "pilot", 2),
    ("new_candidate_remaining", "new_candidate", "remaining", 22),
)
_PREFLIGHT_FILES = {
    "canary_cases.jsonl",
    "commands.jsonl",
    "config.json",
    "environment.json",
    "events.jsonl",
    "planned-evaluations.jsonl",
    "report.json",
}
_PREFLIGHT_CONFIG_KEYS = frozenset(
    {
        "api_key_env",
        "base_url",
        "candidate_id",
        "candidate_role",
        "enable_thinking",
        "endpoint_sha256",
        "evaluator_config_sha256",
        "evaluator_policy_sha256",
        "execution_performed",
        "judge_mode",
        "max_attempts",
        "max_response_bytes",
        "measurement_method",
        "model_id",
        "output_schema_sha256",
        "pass_seeds",
        "protocol_version",
        "provider",
        "provider_usage_capture",
        "region",
        "response_format",
        "schema_version",
        "system_template_sha256",
        "temperature",
        "timeout_seconds",
        "top_p",
        "validation_only_raw_exchange_capture",
    }
)
_PREFLIGHT_REPORT_KEYS = frozenset(
    {
        "candidate_id",
        "completed_at_utc",
        "credential_present",
        "evaluator_policy_sha256",
        "execution_performed",
        "live_ready",
        "measurement_method",
        "new_calls",
        "planned_evaluations_sha256",
        "protocol_version",
        "provider_attempt_scope",
        "provider_attempts",
        "schema_version",
        "started_at_utc",
        "status",
        "validated_case_count",
    }
)
_PREFLIGHT_ENVIRONMENT_KEYS = frozenset(
    {
        "captured_at_utc",
        "credential",
        "output_directory",
        "package_versions",
        "platform",
        "python_executable",
        "python_version",
        "schema_version",
        "working_directory",
    }
)
_PREFLIGHT_PACKAGE_VERSION_KEYS = frozenset({"openai", "pydantic", "secaware"})


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"JSON artifact failed validation: {path.name}") from error
    if type(value) is not dict:
        raise ValueError(f"expected a JSON object: {path.name}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError(f"JSONL artifact failed validation: {path.name}") from error
    rows: list[dict[str, object]] = []
    for line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"JSONL artifact failed validation: {path.name}") from error
        if type(value) is not dict:
            raise ValueError(f"expected JSON objects: {path.name}")
        rows.append(value)
    return rows


def _resolved_relative_file(root: Path, raw: object, *, label: str) -> Path:
    if type(raw) is not str or not raw or "\\" in raw:
        raise ValueError(f"{label} path failed validation")
    relative = PurePosixPath(raw)
    if (
        relative.is_absolute()
        or relative.as_posix() != raw
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError(f"{label} path failed validation")
    resolved = (root / Path(*relative.parts)).resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError(f"{label} path escaped its root") from None
    if not resolved.is_file():
        raise ValueError(f"{label} file is unavailable")
    return resolved


def _execution_code_paths() -> list[Path]:
    paths = [Path(__file__).resolve()]
    for name, module in sorted(sys.modules.items()):
        if not (name == "secaware" or name.startswith(("secaware.", "scripts."))):
            continue
        raw = getattr(module, "__file__", None)
        if raw is None:
            continue
        if type(raw) is not str:
            raise ValueError("execution module origin failed validation")
        paths.append(Path(raw).resolve())
    return sorted(set(paths), key=lambda path: path.as_posix())


def _validated_execution_origins(
    root: Path,
    listed: dict[str, str],
) -> list[dict[str, object]]:
    module_origins: list[dict[str, object]] = []
    for path in _execution_code_paths():
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            raise ValueError("execution module escaped the frozen deployment") from None
        digest = _sha256_file(path)
        if listed.get(relative) != digest:
            raise ValueError("execution module is not covered by the deployment ledger")
        module_origins.append({"path": str(path), "relative_path": relative, "sha256": digest})
    return module_origins


def _verify_deployment(
    manifest_path: Path,
    deployed_commit: str,
) -> tuple[dict[str, object], Path, dict[str, str]]:
    manifest_path = manifest_path.resolve()
    root = manifest_path.parent.resolve()
    if (
        manifest_path.name != "DEPLOYMENT_MANIFEST.json"
        or _COMMIT.fullmatch(deployed_commit) is None
        or root != _REPOSITORY_ROOT.resolve()
    ):
        raise ValueError("deployment authority failed validation")
    deployment = _read_json(manifest_path)
    deployment_files = deployment.get("deployment_files")
    if (
        deployment.get("schema_version") != "1.0"
        or deployment.get("deployed_commit") != deployed_commit
        or type(deployment.get("deployment_id")) is not str
        or not str(deployment["deployment_id"]).strip()
        or deployment.get("scientific_claim_allowed") is not False
        or type(deployment_files) is not dict
        or set(deployment_files) != {"exclusions", "listed_files", "path", "sha256"}
    ):
        raise ValueError("deployment manifest failed validation")

    exclusions = deployment_files.get("exclusions")
    ledger_raw = deployment_files.get("path")
    if (
        type(exclusions) is not list
        or any(type(item) is not str for item in exclusions)
        or exclusions != sorted(set(exclusions))
        or not _DEPLOYMENT_REQUIRED_EXCLUSIONS.issubset(set(exclusions))
        or not set(exclusions).issubset(
            _DEPLOYMENT_REQUIRED_EXCLUSIONS | _DEPLOYMENT_OPTIONAL_EXCLUSIONS
        )
        or ledger_raw not in exclusions
        or type(deployment_files.get("listed_files")) is not int
        or deployment_files["listed_files"] < 1
        or _SHA256.fullmatch(str(deployment_files.get("sha256"))) is None
    ):
        raise ValueError("deployment file closure summary failed validation")
    for exclusion in exclusions:
        relative = PurePosixPath(exclusion)
        if (
            not exclusion
            or "\\" in exclusion
            or relative.is_absolute()
            or relative.as_posix() != exclusion
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("deployment exclusion path failed validation")

    ledger_path = _resolved_relative_file(root, ledger_raw, label="deployment ledger")
    if _sha256_file(ledger_path) != deployment_files["sha256"]:
        raise ValueError("deployment ledger digest failed validation")
    listed: dict[str, str] = {}
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        try:
            digest, raw_path = line.split("  ", 1)
        except ValueError:
            raise ValueError("deployment ledger row failed validation") from None
        if _SHA256.fullmatch(digest) is None or raw_path in listed:
            raise ValueError("deployment ledger row failed validation")
        path = _resolved_relative_file(root, raw_path, label="deployment ledger entry")
        if path.relative_to(root).as_posix() != raw_path or _sha256_file(path) != digest:
            raise ValueError("deployment ledger entry digest failed validation")
        listed[raw_path] = digest
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.relative_to(root).as_posix() not in set(exclusions)
    }
    if (
        actual != set(listed)
        or len(listed) != deployment_files["listed_files"]
        or manifest_path.relative_to(root).as_posix() not in exclusions
    ):
        raise ValueError("deployment ledger exact closure failed validation")
    module_origins = _validated_execution_origins(root, listed)
    evidence = {
        "path": str(manifest_path),
        "sha256": _sha256_file(manifest_path),
        "deployment_id": deployment["deployment_id"],
        "deployed_commit": deployed_commit,
        "files_manifest_path": str(ledger_path),
        "files_manifest_sha256": deployment_files["sha256"],
        "listed_files": len(listed),
        "execution_module_origins": module_origins,
    }
    return evidence, root, listed


def _require_deployment_file(
    path: Path,
    *,
    deployment_root: Path,
    deployment_files: dict[str, str],
    label: str,
) -> None:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(deployment_root).as_posix()
    except ValueError:
        raise ValueError(f"{label} escaped the frozen deployment") from None
    if deployment_files.get(relative) != _sha256_file(resolved):
        raise ValueError(f"{label} is not covered by the deployment ledger")


def _load_evaluator(path: Path, *, role: str, protocol: str):
    resolved = path.resolve()
    try:
        evaluator = canary._load_evaluator_config(resolved)
    except SystemExit as error:
        raise ValueError("evaluator config failed validation") from error
    if (
        evaluator.candidate_role != role
        or evaluator.protocol_version != protocol
        or evaluator.mode != "single_pass"
        or evaluator.max_attempts != 1
        or evaluator.source_sha256 != _sha256_file(resolved)
    ):
        raise ValueError("evaluator role or single-attempt policy failed validation")
    return evaluator


def _evaluator_shared_coordinates(evaluator) -> dict[str, object]:
    return {
        "provider": evaluator.provider,
        "region": "cn-beijing",
        "model_id": evaluator.model_id,
        "base_url": evaluator.base_url,
        "endpoint_sha256": hashlib.sha256(evaluator.base_url.encode("utf-8")).hexdigest(),
        "api_key_env": evaluator.api_key_env,
        "timeout_seconds": evaluator.timeout_seconds,
        "max_attempts": evaluator.max_attempts,
        "max_response_bytes": evaluator.max_response_bytes,
        "temperature": evaluator.temperature,
        "top_p": evaluator.top_p,
        "pass_seeds": [evaluator.seed],
        "enable_thinking": evaluator.enable_thinking,
        "judge_mode": evaluator.mode,
        "response_format": {"type": "json_object"},
    }


def _expected_preflight_cases(
    provider_cases: list[dict[str, object]],
    contract_rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    by_task = {row.get("task_id"): row for row in contract_rows}
    if len(by_task) != len(contract_rows):
        raise ValueError("plan contract identity failed validation")
    expected: list[dict[str, object]] = []
    for row in provider_cases:
        contract = by_task.get(row.get("task_id"))
        if contract is None:
            raise ValueError("preflight case has no frozen contract")
        expected.append({**row, "contract": contract})
    return expected


def _expected_planned_evaluations(
    provider_cases: list[dict[str, object]],
    contract_rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    by_task = {row.get("task_id"): row for row in contract_rows}
    expected: list[dict[str, object]] = []
    for row in provider_cases:
        task_id = row.get("task_id")
        seed_id = row.get("seed_id")
        contract = by_task.get(task_id)
        if type(task_id) is not str or type(seed_id) is not int or contract is None:
            raise ValueError("planned evaluation coordinate failed validation")
        assignment, _variant = canary._assignment_and_variant(task_id, seed_id)
        expected.append(
            {
                "case_id": row["case_id"],
                "task_id": task_id,
                "assignment_id": assignment.assignment_id,
                "contract_id": contract["contract_id"],
                "code_sha256": hashlib.sha256(str(row["code_text"]).encode("utf-8")).hexdigest(),
                "expected_status": row["expected_status"],
            }
        )
    return expected


def _validate_preflight_command(
    argv: object,
    *,
    environment: dict[str, object],
    command_working_directory: object,
    root: Path,
    cases_path: Path,
    contracts_path: Path,
    evaluator_config_path: Path,
) -> None:
    environment_cwd = environment.get("working_directory")
    if (
        type(command_working_directory) is not str
        or type(environment_cwd) is not str
        or not Path(command_working_directory).is_absolute()
        or not Path(environment_cwd).is_absolute()
        or str(Path(command_working_directory).resolve()) != command_working_directory
        or str(Path(environment_cwd).resolve()) != environment_cwd
        or command_working_directory != environment_cwd
    ):
        raise ValueError("preflight command working directory failed validation")
    recorded_cwd = Path(command_working_directory)

    def resolve_argument(raw: str) -> Path:
        path = Path(raw)
        return path.resolve() if path.is_absolute() else (recorded_cwd / path).resolve()

    if (
        type(argv) is not list
        or len(argv) != 11
        or any(type(item) is not str or not item for item in argv)
        or type(environment.get("python_executable")) is not str
        or resolve_argument(argv[0]) != Path(str(environment["python_executable"])).resolve()
        or resolve_argument(argv[1]) != Path(str(canary.__file__)).resolve()
    ):
        raise ValueError("preflight command origin failed validation")
    options: dict[str, str] = {}
    preflight_count = 0
    index = 2
    while index < len(argv):
        flag = argv[index]
        if flag == "--preflight":
            preflight_count += 1
            index += 1
            continue
        if flag not in {
            "--output-dir",
            "--cases-path",
            "--contracts-path",
            "--evaluator-config",
        } or index + 1 >= len(argv):
            raise ValueError("preflight command option failed validation")
        if flag in options or argv[index + 1].startswith("--"):
            raise ValueError("preflight command option failed validation")
        options[flag] = argv[index + 1]
        index += 2
    expected = {
        "--output-dir": root,
        "--cases-path": cases_path.resolve(),
        "--contracts-path": contracts_path.resolve(),
        "--evaluator-config": evaluator_config_path.resolve(),
    }
    if (
        preflight_count != 1
        or set(options) != set(expected)
        or any(resolve_argument(options[flag]) != path for flag, path in expected.items())
    ):
        raise ValueError("preflight command binding failed validation")


def _verify_preflight(
    root: Path,
    *,
    evaluator,
    provider_cases: list[dict[str, object]],
    contract_rows: list[dict[str, object]],
    cases_path: Path,
    contracts_path: Path,
    evaluator_config_path: Path,
    expected_count: int,
    phase: str,
) -> dict[str, object]:
    root = root.resolve()
    manifest_path = root / "artifact-manifest.json"
    manifest = verify_closed_manifest(manifest_path, label=f"{phase} functional Judge preflight")
    if {str(item["path"]) for item in manifest["files"]} != _PREFLIGHT_FILES:
        raise ValueError(f"{phase} preflight file closure failed validation")
    config = _read_json(root / "config.json")
    report = _read_json(root / "report.json")
    environment = _read_json(root / "environment.json")
    cases = _read_jsonl(root / "canary_cases.jsonl")
    planned = _read_jsonl(root / "planned-evaluations.jsonl")
    commands = _read_jsonl(root / "commands.jsonl")
    events = _read_jsonl(root / "events.jsonl")
    expected_cases = _expected_preflight_cases(provider_cases, contract_rows)
    expected_planned = _expected_planned_evaluations(provider_cases, contract_rows)
    shared_coordinates = analyzer._validated_evaluator_coordinates(config)
    expected_coordinates = _evaluator_shared_coordinates(evaluator)
    expected_method = canary._measurement_method(evaluator.protocol_version)
    if (
        len(provider_cases) != expected_count
        or cases != expected_cases
        or planned != expected_planned
        or frozenset(config) != _PREFLIGHT_CONFIG_KEYS
        or config.get("schema_version") != "1.0"
        or config.get("candidate_id") != evaluator.candidate_id
        or config.get("candidate_role") != evaluator.candidate_role
        or config.get("provider") != evaluator.provider
        or config.get("model_id") != evaluator.model_id
        or config.get("base_url") != evaluator.base_url
        or config.get("api_key_env") != evaluator.api_key_env
        or config.get("timeout_seconds") != evaluator.timeout_seconds
        or config.get("max_attempts") != 1
        or config.get("max_response_bytes") != evaluator.max_response_bytes
        or config.get("temperature") != evaluator.temperature
        or config.get("top_p") != evaluator.top_p
        or config.get("pass_seeds") != [evaluator.seed]
        or config.get("enable_thinking") != evaluator.enable_thinking
        or config.get("protocol_version") != evaluator.protocol_version
        or config.get("judge_mode") != "single_pass"
        or config.get("measurement_method") != expected_method
        or config.get("execution_performed") is not False
        or config.get("evaluator_config_sha256") != evaluator.source_sha256
        or config.get("provider_usage_capture") != "unavailable_in_structured_transport_v1"
        or shared_coordinates != expected_coordinates
    ):
        raise ValueError(f"{phase} preflight config or policy failed validation")

    credential = environment.get("credential")
    package_versions = environment.get("package_versions")
    if (
        frozenset(environment) != _PREFLIGHT_ENVIRONMENT_KEYS
        or environment.get("schema_version") != "1.0"
        or type(environment.get("captured_at_utc")) is not str
        or not str(environment["captured_at_utc"])
        or environment.get("output_directory") != str(root)
        or type(environment.get("python_executable")) is not str
        or not str(environment["python_executable"])
        or type(environment.get("python_version")) is not str
        or not str(environment["python_version"])
        or type(environment.get("platform")) is not str
        or not str(environment["platform"])
        or type(package_versions) is not dict
        or frozenset(package_versions) != _PREFLIGHT_PACKAGE_VERSION_KEYS
        or any(
            value is not None and (type(value) is not str or not value)
            for value in package_versions.values()
        )
        or type(credential) is not dict
        or set(credential) != {"environment_variable", "present", "value_recorded"}
        or credential.get("environment_variable") != evaluator.api_key_env
        or type(credential.get("present")) is not bool
        or credential.get("value_recorded") is not False
        or len(commands) != 1
        or set(commands[0]) != {"argv", "secret_in_argv", "started_at_utc", "working_directory"}
        or commands[0].get("secret_in_argv") is not False
        or type(commands[0].get("argv")) is not list
        or not commands[0]["argv"]
        or len(events) != 2
        or set(events[0]) != {"at_utc", "case_count", "event"}
        or events[0].get("event") != "preflight_started"
        or events[0].get("case_count") != expected_count
        or set(events[1]) != {"at_utc", "event", "live_ready", "provider_attempts", "status"}
        or events[1].get("event") != "preflight_completed"
        or events[1].get("status") != "FUNCTIONAL_JUDGE_PREFLIGHT_COMPLETE"
        or events[1].get("provider_attempts") != 0
        or type(events[1].get("live_ready")) is not bool
        or events[1].get("live_ready") != credential["present"]
    ):
        raise ValueError(f"{phase} preflight zero-call environment failed validation")
    _validate_preflight_command(
        commands[0]["argv"],
        environment=environment,
        command_working_directory=commands[0]["working_directory"],
        root=root,
        cases_path=cases_path,
        contracts_path=contracts_path,
        evaluator_config_path=evaluator_config_path,
    )

    if (
        frozenset(report) != _PREFLIGHT_REPORT_KEYS
        or report.get("schema_version") != "1.0"
        or report.get("status") != "FUNCTIONAL_JUDGE_PREFLIGHT_COMPLETE"
        or report.get("validated_case_count") != expected_count
        or report.get("candidate_id") != evaluator.candidate_id
        or report.get("evaluator_policy_sha256") != config["evaluator_policy_sha256"]
        or report.get("protocol_version") != evaluator.protocol_version
        or report.get("measurement_method") != expected_method
        or report.get("execution_performed") is not False
        or report.get("credential_present") != credential["present"]
        or report.get("live_ready") != credential["present"]
        or report.get("provider_attempts") != 0
        or report.get("provider_attempt_scope") != _PROVIDER_ATTEMPT_SCOPE
        or report.get("new_calls")
        != {
            "functional_judge_provider_attempts": 0,
            "generation_provider_attempts": 0,
            "oracle_executions": 0,
        }
        or report.get("planned_evaluations_sha256") != canonical_sha256(planned)
    ):
        raise ValueError(f"{phase} preflight report or provider budget failed validation")
    return {
        "path": str(root),
        "root_manifest_sha256": _sha256_file(manifest_path),
        "candidate_id": evaluator.candidate_id,
        "candidate_role": evaluator.candidate_role,
        "protocol_version": evaluator.protocol_version,
        "phase": phase,
        "case_count": expected_count,
        "provider_cases_sha256": canonical_sha256(provider_cases),
        "run_case_inputs_sha256": canonical_sha256(cases),
        "planned_evaluations_sha256": canonical_sha256(planned),
        "evaluator_config_sha256": evaluator.source_sha256,
        "evaluator_policy_sha256": config["evaluator_policy_sha256"],
        "shared_evaluator_coordinates_sha256": canonical_sha256(shared_coordinates),
        "provider_attempts": 0,
        "provider_attempt_scope": _PROVIDER_ATTEMPT_SCOPE,
    }


def _strict_absent_outputs(paths: dict[str, Path]) -> dict[str, Path]:
    resolved = {name: path.resolve() for name, path in paths.items()}
    if len(set(resolved.values())) != len(resolved):
        raise ValueError("future campaign output paths must be distinct")
    values = list(resolved.values())
    for index, left in enumerate(values):
        for right in values[index + 1 :]:
            if left in right.parents or right in left.parents:
                raise ValueError("future campaign output paths cannot contain one another")
    existing = [name for name, path in resolved.items() if path.exists()]
    if existing:
        raise ValueError("future campaign output path already exists")
    return resolved


def _reject_authority_output_overlap(
    outputs: dict[str, Path],
    authority_roots: dict[str, Path],
) -> None:
    for output in outputs.values():
        resolved_output = output.resolve()
        for authority in authority_roots.values():
            resolved_authority = authority.resolve()
            if (
                resolved_output == resolved_authority
                or resolved_output in resolved_authority.parents
                or resolved_authority in resolved_output.parents
            ):
                raise ValueError("campaign output overlaps a frozen authority root")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate and freeze the four-stage functional-Judge calibration campaign "
            "without making provider, generation, or Oracle calls."
        )
    )
    parser.add_argument("--deployment-manifest", type=Path, required=True)
    parser.add_argument("--deployed-commit", required=True)
    parser.add_argument("--source-final-delivery", type=Path, required=True)
    parser.add_argument("--sidecar-dir", type=Path, required=True)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--calibration-spec", type=Path, required=True)
    parser.add_argument("--baseline-evaluator-config", type=Path, required=True)
    parser.add_argument("--new-candidate-evaluator-config", type=Path, required=True)
    for stage, _role, _phase, _count in _PHASE_SPECS:
        parser.add_argument(f"--{stage.replace('_', '-')}-preflight-dir", type=Path, required=True)
        parser.add_argument(f"--{stage.replace('_', '-')}-output-dir", type=Path, required=True)
    parser.add_argument("--analysis-output-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _freeze_campaign(
    args: argparse.Namespace,
    *,
    raw_argv: list[str],
    command_argv: list[str] | None = None,
    command_argv_source: str = "programmatic_explicit_argv",
) -> dict[str, object]:
    if command_argv is None:
        command_argv = [sys.executable, str(Path(__file__).resolve()), *raw_argv]
    if (
        type(command_argv) is not list
        or not command_argv
        or any(type(value) is not str or not value for value in command_argv)
    ):
        raise ValueError("recorded command argv must be a non-empty list of strings")
    if command_argv_source not in {"programmatic_explicit_argv", "sys.orig_argv"}:
        raise ValueError("unsupported command argv source")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError("refusing to overwrite an existing campaign receipt")
    deployment, deployment_root, deployment_files = _verify_deployment(
        args.deployment_manifest,
        args.deployed_commit,
    )
    spec_path = args.calibration_spec.resolve()
    delivery_path = args.source_final_delivery.resolve()
    sidecar_dir = args.sidecar_dir.resolve()
    plan_dir = args.plan_dir.resolve()
    baseline_path = args.baseline_evaluator_config.resolve()
    new_path = args.new_candidate_evaluator_config.resolve()
    for path, label in (
        (spec_path, "calibration spec"),
        (baseline_path, "baseline evaluator config"),
        (new_path, "new-candidate evaluator config"),
    ):
        _require_deployment_file(
            path,
            deployment_root=deployment_root,
            deployment_files=deployment_files,
            label=label,
        )
    spec, family_specs = planner._load_spec(spec_path)
    planner._validate_delivery(delivery_path, spec)
    sidecar_rows, sidecar_manifest_sha256, sidecar_evidence_sha256, sidecar_contracts = (
        planner._load_tune_rows(sidecar_dir, spec, family_specs)
    )
    sidecar_report = _read_json(sidecar_dir / "report.json")
    plan_manifest_path = plan_dir / "artifact-manifest.json"
    verify_closed_manifest(plan_manifest_path, label="functional Judge calibration plan authority")
    plan_manifest_sha256 = _sha256_file(plan_manifest_path)
    plan_identity = _read_json(plan_dir / "plan.json")
    expected_plan_id = plan_identity.get("plan_id")
    if type(expected_plan_id) is not str:
        raise ValueError("calibration plan identity failed validation")
    plan, _metadata, _frozen_contracts = analyzer._load_plan(
        plan_dir,
        calibration_spec_path=spec_path,
        expected_plan_id=expected_plan_id,
        expected_root_manifest_sha256=plan_manifest_sha256,
    )
    contract_rows = _read_jsonl(plan_dir / "contracts.jsonl")
    if (
        plan.get("case_counts")
        != {
            "total": 24,
            "tune": 8,
            "validation": 16,
            "families": 4,
            "pilot": 2,
            "remaining": 22,
        }
        or plan.get("tune_overlay_root_manifest_sha256") != sidecar_manifest_sha256
        or plan.get("tune_overlay_evidence_manifest_sha256") != sidecar_evidence_sha256
        or contract_rows != sidecar_contracts
        or len(sidecar_rows) != 8
        or sidecar_report.get("status") != "EXECUTABLE_FUNCTIONAL_SENSITIVITY_COMPLETE"
        or sidecar_report.get("sandbox_limitations") != []
        or sidecar_report.get("functional_contract_set_sha256")
        != spec["functional_contract_set_sha256"]
        or sidecar_report.get("counts", {}).get("tasks") != 4
        or sidecar_report.get("counts", {}).get("assignments") != 8
        or sidecar_report.get("counts", {}).get("provider_calls") != 0
        or sidecar_report.get("counts", {}).get("security_oracle_calls") != 0
        or plan.get("source_live_root_manifest_sha256") != spec["source_live_root_manifest_sha256"]
        or plan.get("source_live_root_provenance_sha256")
        != spec["source_live_root_provenance_sha256"]
    ):
        raise ValueError("sidecar, plan, contract, or old-live binding failed validation")

    baseline = _load_evaluator(baseline_path, role="baseline", protocol="v1")
    new_candidate = _load_evaluator(new_path, role="new_candidate", protocol="v2")
    baseline_shared = _evaluator_shared_coordinates(baseline)
    new_shared = _evaluator_shared_coordinates(new_candidate)
    if (
        baseline.candidate_id == new_candidate.candidate_id
        or baseline.model_id != new_candidate.model_id
        or baseline_shared != new_shared
        or baseline.max_attempts != 1
        or new_candidate.max_attempts != 1
    ):
        raise ValueError("candidate same-model shared-coordinate policy failed validation")

    pilot_cases = _read_jsonl(plan_dir / "pilot-cases.jsonl")
    remaining_cases = _read_jsonl(plan_dir / "remaining-cases.jsonl")
    cases_by_phase = {"pilot": pilot_cases, "remaining": remaining_cases}
    evaluators = {"baseline": baseline, "new_candidate": new_candidate}
    preflights: dict[str, dict[str, object]] = {}
    for stage, role, phase, expected_count in _PHASE_SPECS:
        preflight_root = getattr(args, f"{stage}_preflight_dir")
        cases_path = plan_dir / f"{phase}-cases.jsonl"
        evaluator_path = baseline_path if role == "baseline" else new_path
        preflights[stage] = _verify_preflight(
            preflight_root,
            evaluator=evaluators[role],
            provider_cases=cases_by_phase[phase],
            contract_rows=contract_rows,
            cases_path=cases_path,
            contracts_path=plan_dir / "contracts.jsonl",
            evaluator_config_path=evaluator_path,
            expected_count=expected_count,
            phase=stage,
        )
    if (
        len({preflights[stage]["evaluator_policy_sha256"] for stage in preflights}) != 2
        or preflights["baseline_pilot"]["evaluator_policy_sha256"]
        != preflights["baseline_remaining"]["evaluator_policy_sha256"]
        or preflights["new_candidate_pilot"]["evaluator_policy_sha256"]
        != preflights["new_candidate_remaining"]["evaluator_policy_sha256"]
        or len({preflights[stage]["shared_evaluator_coordinates_sha256"] for stage in preflights})
        != 1
    ):
        raise ValueError("preflight candidate policy closure failed validation")

    future_paths = {stage: getattr(args, f"{stage}_output_dir") for stage, *_rest in _PHASE_SPECS}
    future_paths["analysis"] = args.analysis_output_dir
    future = _strict_absent_outputs(future_paths)
    if output_dir in future.values() or any(
        output_dir in path.parents or path in output_dir.parents for path in future.values()
    ):
        raise ValueError("campaign receipt and future output paths overlap")
    authority_roots = {
        "deployment": deployment_root,
        "sidecar": sidecar_dir,
        "plan": plan_dir,
        **{
            f"preflight_{stage}": getattr(args, f"{stage}_preflight_dir").resolve()
            for stage, _role, _phase, _count in _PHASE_SPECS
        },
    }
    _reject_authority_output_overlap(
        {"receipt": output_dir, **future},
        authority_roots,
    )

    stages: list[dict[str, object]] = []
    for stage, role, phase, expected_count in _PHASE_SPECS:
        cases_path = plan_dir / f"{phase}-cases.jsonl"
        evaluator_path = baseline_path if role == "baseline" else new_path
        stages.append(
            {
                "stage": stage,
                "candidate_role": role,
                "candidate_id": evaluators[role].candidate_id,
                "protocol_version": evaluators[role].protocol_version,
                "phase": phase,
                "case_count": expected_count,
                "cases_path": str(cases_path),
                "cases_file_sha256": _sha256_file(cases_path),
                "contracts_path": str(plan_dir / "contracts.jsonl"),
                "contracts_file_sha256": _sha256_file(plan_dir / "contracts.jsonl"),
                "evaluator_config_path": str(evaluator_path),
                "evaluator_config_sha256": evaluators[role].source_sha256,
                "max_attempts_per_case": 1,
                "expected_provider_trace_attempts": expected_count,
                "provider_attempt_scope": _PROVIDER_ATTEMPT_SCOPE,
                "preflight": preflights[stage],
                "future_output_path": str(future[stage]),
                "future_output_absent": True,
            }
        )

    # Re-evaluate after every validator has run so any project module loaded
    # lazily during validation is also byte-bound to the deployment ledger.
    deployment["execution_module_origins"] = _validated_execution_origins(
        deployment_root,
        deployment_files,
    )
    receipt_core: dict[str, object] = {
        "schema_version": "1.0",
        "status": "FUNCTIONAL_JUDGE_CALIBRATION_CAMPAIGN_FROZEN",
        "role": "pre_provider_call_engineering_campaign_receipt",
        "claim": False,
        "scientific_claim_allowed": False,
        "official_artifact_replacement_allowed": False,
        "security_oracle_replacement_allowed": False,
        "purpose": (
            "Freeze the exact v1-versus-v2 four-stage functional-Judge engineering "
            "calibration campaign before any provider call."
        ),
        "deployment": deployment,
        "authoritative_inputs": {
            "source_final_delivery": {
                "path": str(delivery_path),
                "sha256": _sha256_file(delivery_path),
            },
            "calibration_spec": {
                "path": str(spec_path),
                "sha256": _sha256_file(spec_path),
                "calibration_id": spec["calibration_id"],
            },
            "executable_sidecar": {
                "path": str(sidecar_dir),
                "root_manifest_sha256": sidecar_manifest_sha256,
                "status": sidecar_report["status"],
                "tasks": 4,
                "assignments": 8,
                "functional_contracts": 4,
                "functional_contract_set_sha256": spec["functional_contract_set_sha256"],
                "sandbox_limitations": [],
                "provider_calls": 0,
                "security_oracle_calls": 0,
            },
            "calibration_plan": {
                "path": str(plan_dir),
                "plan_id": plan["plan_id"],
                "root_manifest_sha256": plan_manifest_sha256,
                "case_counts": plan["case_counts"],
                "provider_cases_sha256": plan["provider_cases_sha256"],
                "contracts_sha256": plan["contracts_sha256"],
            },
            "baseline_evaluator_config": {
                "path": str(baseline_path),
                "sha256": baseline.source_sha256,
                "candidate_id": baseline.candidate_id,
                "protocol_version": baseline.protocol_version,
                "evaluator_policy_sha256": preflights["baseline_pilot"]["evaluator_policy_sha256"],
            },
            "new_candidate_evaluator_config": {
                "path": str(new_path),
                "sha256": new_candidate.source_sha256,
                "candidate_id": new_candidate.candidate_id,
                "protocol_version": new_candidate.protocol_version,
                "evaluator_policy_sha256": preflights["new_candidate_pilot"][
                    "evaluator_policy_sha256"
                ],
            },
        },
        "old_live_commitments": {
            "source_final_delivery_sha256": spec["source_final_delivery_sha256"],
            "source_live_root_manifest_sha256": spec["source_live_root_manifest_sha256"],
            "source_live_root_provenance_sha256": spec["source_live_root_provenance_sha256"],
        },
        "comparison_policy": {
            "same_model_required": True,
            "same_model_verified": True,
            "shared_evaluator_coordinates": baseline_shared,
            "shared_evaluator_coordinates_sha256": canonical_sha256(baseline_shared),
            "max_attempts_per_case": 1,
            "baseline_never_selectable": True,
        },
        "stages": stages,
        "analysis_output": {
            "future_output_path": str(future["analysis"]),
            "future_output_absent": True,
            "expected_candidate_run_paths": [
                str(future[stage]) for stage, _role, _phase, _count in _PHASE_SPECS
            ],
            "plan_id": plan["plan_id"],
            "plan_root_manifest_sha256": plan_manifest_sha256,
            "provider_attempts": 0,
        },
        "expected_calls": {
            "functional_judge_provider_trace_attempts_by_stage": {
                stage: expected_count for stage, _role, _phase, expected_count in _PHASE_SPECS
            },
            "functional_judge_provider_trace_attempts_total": 48,
            "provider_attempt_scope": _PROVIDER_ATTEMPT_SCOPE,
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
            "freezer_provider_attempts": 0,
            "analyzer_provider_attempts": 0,
        },
        "measurement_boundary": {
            "primary_scalable_functional_guardrail": "Y_F^J",
            "executable_sensitivity_variable": "Y_F^E",
            "executable_sidecar_replaces_judge": False,
            "judge_replaces_security_oracle": False,
        },
        "credential": {
            "value_read_by_freezer": False,
            "value_recorded": False,
            "environment_variable_name_only": baseline.api_key_env,
        },
        "limitations": [
            {
                "limitation_id": "recording_transport_post_return_trace_gap",
                "provider_attempt_scope": _PROVIDER_ATTEMPT_SCOPE,
                "statement": (
                    "RecordingTransport persists a trace only after the provider returns; a "
                    "process crash before that write can omit an actual provider call. Closed "
                    "trace totals therefore do not claim absolute global provider calls."
                ),
            }
        ],
    }
    receipt = {
        "receipt_id": "functional_judge_calibration_campaign_receipt_"
        + canonical_sha256(receipt_core),
        **receipt_core,
    }

    # Recheck immediately before publishing the immutable receipt. The future
    # run roots remain absent; this command does not reserve or mutate them.
    _strict_absent_outputs(future)
    output_dir.mkdir(parents=True, exist_ok=False)
    write_json_atomic_exclusive(output_dir / "campaign-receipt.json", receipt)
    write_json_atomic_exclusive(
        output_dir / "command.json",
        {
            "schema_version": "1.0",
            "argv": command_argv,
            "argv_source": command_argv_source,
            "sys_dont_write_bytecode": sys.dont_write_bytecode,
            "secret_in_argv": False,
            "provider_attempts": 0,
            "generation_provider_attempts": 0,
            "security_oracle_executions": 0,
        },
    )
    write_json_atomic_exclusive(
        output_dir / "environment.json",
        {
            "schema_version": "1.0",
            "captured_at_utc": _utc_now(),
            "working_directory": str(Path.cwd().resolve()),
            "python_executable": sys.executable,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "credential_value_read": False,
            "credential_value_recorded": False,
        },
    )
    write_closed_manifest_atomic(output_dir, label="functional Judge calibration campaign receipt")
    verify_closed_manifest(
        output_dir / "artifact-manifest.json",
        label="published functional Judge calibration campaign receipt",
    )
    _strict_absent_outputs(future)
    return receipt


def _validated_process_invocation(raw_argv: list[str]) -> list[str]:
    """Return the interpreter-preserved invocation after binding it to this CLI."""
    original = getattr(sys, "orig_argv", None)
    if (
        type(original) is not list
        or not original
        or any(type(value) is not str or not value for value in original)
    ):
        raise ValueError("sys.orig_argv is unavailable or malformed")
    if len(original) <= len(raw_argv):
        raise ValueError("sys.orig_argv does not contain an interpreter invocation")
    if raw_argv and original[-len(raw_argv) :] != raw_argv:
        raise ValueError("sys.orig_argv does not match the parsed process arguments")

    invocation_prefix = original[: -len(raw_argv)] if raw_argv else original
    script_path = Path(__file__).resolve()
    direct_script = any(
        not value.startswith("-") and Path(value).resolve() == script_path
        for value in invocation_prefix[1:]
    )
    module_name = "scripts.freeze_functional_judge_calibration_campaign"
    module_script = any(
        value == "-m"
        and index + 1 < len(invocation_prefix)
        and invocation_prefix[index + 1] == module_name
        for index, value in enumerate(invocation_prefix)
    )
    if not (direct_script or module_script):
        raise ValueError("sys.orig_argv is not bound to this campaign freezer")
    return list(original)


def main(argv: list[str] | None = None) -> int:
    process_invocation = argv is None
    raw_argv = list(sys.argv[1:] if process_invocation else argv)
    args = _parse_args(raw_argv)
    try:
        command_argv = (
            _validated_process_invocation(raw_argv)
            if process_invocation
            else [sys.executable, str(Path(__file__).resolve()), *raw_argv]
        )
        receipt = _freeze_campaign(
            args,
            raw_argv=raw_argv,
            command_argv=command_argv,
            command_argv_source=(
                "sys.orig_argv" if process_invocation else "programmatic_explicit_argv"
            ),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:  # noqa: BLE001 - CLI reports only a bounded failure class
        raise SystemExit(
            f"functional Judge calibration campaign freeze failed: {type(error).__name__}"
        ) from None
    print(receipt["receipt_id"])
    print("FUNCTIONAL_JUDGE_CALIBRATION_CAMPAIGN_FROZEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
