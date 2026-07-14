from collections.abc import Sequence
import hashlib
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner, Result

from secaware.cli import app
from secaware.config import AppConfig, load_config, write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.providers import get_provider
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.intervention.attestation import PromptRoleAttestationRecord
from secaware.oracle.runner import AnalyzerProcessResult
from secaware.pipeline.preflight import (
    PreflightReport,
    run_oracle_preflight,
    run_preflight,
)
from secaware.schema.experiments import FunctionalOutcomeContractRecord, PromptRole
from secaware.schema.features import FeatureOperation
from secaware.schema.records import PromptRecord
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
)
import secaware.pipeline.preflight as preflight_module


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_LOCK = PROJECT_ROOT / "policies" / "oracle" / "python" / "policy.lock.json"
CLI_COMMANDS = [
    "preflight",
    "extract-prompt-tsg",
    "generate-observed",
    "plan-generation",
    "import-generation",
    "run-oracle",
    "discover",
    "run-all",
]


def _prompt(prompt_id: str, split: str, prompt: str) -> PromptRecord:
    return PromptRecord(
        prompt_id=prompt_id,
        task_id=f"task-{prompt_id}",
        split=split,
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt=prompt,
        prompt_role=PromptRole.NEUTRAL_BASELINE,
        counterpart_prompt_id=None,
    )


def test_preflight_report_allows_model_count_without_namespace_warning() -> None:
    assert PreflightReport.model_config["protected_namespaces"] == ()


def _config(
    tmp_path: Path,
    prompts_path: Path,
    *,
    models: list[str] | None = None,
    seeds: list[int] | None = None,
    prompt_attestations_path: Path | None = None,
    functional_outcome_contracts_path: Path | None = None,
) -> AppConfig:
    if prompt_attestations_path is None:
        prompt_attestations_path = tmp_path / "prompt-attestations.jsonl"
        if not prompt_attestations_path.exists():
            write_jsonl(prompt_attestations_path, [])
    return AppConfig.model_validate(
        {
            "run": {
                "name": "preflight-test",
                "output_dir": str(tmp_path / "run-that-must-not-be-created"),
            },
            "data": {
                "prompts_path": str(prompts_path),
                "prompt_attestations_path": str(prompt_attestations_path),
                "functional_outcome_contracts_path": (
                    str(functional_outcome_contracts_path)
                    if functional_outcome_contracts_path is not None
                    else None
                ),
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
            "intervention": {"executor": "deterministic"},
            "generation": {
                "models": ["model-a"] if models is None else models,
                "seeds": [7] if seeds is None else seeds,
            },
        }
    )


def _write_valid_prompts(path: Path) -> None:
    write_jsonl(path, [_prompt("prompt-1", "discover", "write a safe helper")])


def _write_attested_confirm_pair(
    prompts_path: Path,
    attestations_path: Path,
    *,
    task_id: str = "task-confirm-a",
    owner: FeatureOperation = FeatureOperation.ADD,
) -> None:
    baseline_text = "Create a Python helper that reads a user-provided path."
    clause = " Normalize the path and restrict it to a base directory."
    baseline = PromptRecord(
        prompt_id=f"{task_id}-baseline",
        task_id=task_id,
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt=baseline_text,
        prompt_role=PromptRole.NEUTRAL_BASELINE,
        counterpart_prompt_id=None,
    )
    variant = PromptRecord(
        prompt_id=f"{task_id}-variant",
        task_id=task_id,
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt=baseline_text + clause,
        prompt_role=PromptRole.POSITIVE_SAFETY_CONTROL,
        counterpart_prompt_id=baseline.prompt_id,
    )
    start = len(baseline.prompt.encode("utf-8"))
    clause_bytes = clause.encode("utf-8")
    attestations = (
        PromptRoleAttestationRecord.from_content(
            prompt_id=baseline.prompt_id,
            task_id=task_id,
            prompt_sha256=baseline.prompt_sha256,
            prompt_role=baseline.prompt_role,
            counterpart_prompt_id=None,
            counterpart_prompt_sha256=None,
            variant_clause_start=None,
            variant_clause_end=None,
            variant_clause_sha256=None,
            contrast_owner_operation=owner,
            catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        ),
        PromptRoleAttestationRecord.from_content(
            prompt_id=variant.prompt_id,
            task_id=task_id,
            prompt_sha256=variant.prompt_sha256,
            prompt_role=variant.prompt_role,
            counterpart_prompt_id=baseline.prompt_id,
            counterpart_prompt_sha256=baseline.prompt_sha256,
            variant_clause_start=start,
            variant_clause_end=start + len(clause_bytes),
            variant_clause_sha256=hashlib.sha256(clause_bytes).hexdigest(),
            contrast_owner_operation=owner,
            catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        ),
    )
    write_jsonl(prompts_path, (baseline, variant))
    write_jsonl(attestations_path, attestations)


class _VersionRunner:
    def __init__(
        self,
        *,
        semgrep: bytes = b"1.168.0\n",
        bandit: bytes = (
            b"bandit 1.9.4\n  python version = 3.12.13 (main) [MSC v.1944 64 bit (AMD64)]\n"
        ),
    ) -> None:
        self.semgrep = semgrep
        self.bandit = bandit
        self.calls: list[tuple[str, ...]] = []
        self.cwds: list[Path] = []

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> AnalyzerProcessResult:
        del timeout_seconds, max_stdout_bytes, max_stderr_bytes
        call = tuple(argv)
        self.calls.append(call)
        self.cwds.append(cwd)
        assert call[1:] == ("--version",)
        stdout = self.semgrep if "semgrep" in call[0] else self.bandit
        return AnalyzerProcessResult(returncode=0, stdout=stdout, argv_sha256="a" * 64)


def _oracle_config(tmp_path: Path, prompts_path: Path) -> AppConfig:
    config = _config(tmp_path, prompts_path)
    payload = config.model_dump(mode="python")
    payload["oracle"].update(
        policy_lock_path=str(POLICY_LOCK),
        semgrep_executable="semgrep-private",
        bandit_executable="bandit-private",
    )
    return AppConfig.model_validate(payload)


def test_oracle_preflight_validates_runtime_before_analyzer_resolution(
    tmp_path: Path,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)
    runner = _VersionRunner()

    def unsupported_runtime() -> None:
        raise SecAwareError(
            code=ErrorCode.ANALYZER_FAILED,
            stage="oracle_analyzer",
            message="analyzer runtime is unavailable",
        )

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_preflight(
            config.oracle,
            runner=runner,
            runtime_validator=unsupported_runtime,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    assert runner.calls == []


def test_oracle_preflight_authenticates_policy_and_exact_versions(tmp_path: Path) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)
    runner = _VersionRunner()
    runtime_calls = 0

    def supported_runtime() -> None:
        nonlocal runtime_calls
        runtime_calls += 1

    policy = run_oracle_preflight(
        config.oracle,
        runner=runner,
        runtime_validator=supported_runtime,
    )

    assert runtime_calls == 1
    assert policy.semgrep_version == "1.168.0"
    assert policy.bandit_version == "1.9.4"
    assert len(runner.calls) == 2
    assert all(cwd != POLICY_LOCK.parent for cwd in runner.cwds)
    assert all(not cwd.exists() for cwd in runner.cwds)


def test_oracle_preflight_accepts_locked_bandit_1_9_4_version_shape(
    tmp_path: Path,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)
    runner = _VersionRunner(
        bandit=(
            b"bandit 1.9.4\n"
            b"  python version = 3.12.13 (main, Mar  3 2026, 15:01:35) "
            b"[MSC v.1944 64 bit (AMD64)]\n"
        )
    )

    policy = run_oracle_preflight(
        config.oracle,
        runner=runner,
        runtime_validator=lambda: None,
    )

    assert policy.bandit_version == "1.9.4"


@pytest.mark.parametrize(
    ("semgrep", "bandit"),
    [
        (
            b"1.167.0\n",
            b"bandit 1.9.4\n  python version = 3.12.13 (main) [MSC v.1944]\n",
        ),
        (
            b"1.168.0\n",
            b"bandit 1.9.3\n  python version = 3.12.13 (main) [MSC v.1944]\n",
        ),
    ],
)
def test_oracle_preflight_rejects_version_drift_without_raw_output(
    tmp_path: Path,
    semgrep: bytes,
    bandit: bytes,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)
    runner = _VersionRunner(semgrep=semgrep, bandit=bandit)

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_preflight(
            config.oracle,
            runner=runner,
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.POLICY_MISMATCH
    assert semgrep.decode().strip() not in str(exc_info.value)
    assert bandit.decode().splitlines()[0] not in str(exc_info.value)
    assert exc_info.value.details == {}


def test_oracle_preflight_rejects_unrecognized_trailing_version_output(
    tmp_path: Path,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)
    runner = _VersionRunner(semgrep=b"1.168.0\nPRIVATE-TRAILING-OUTPUT\n")

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_preflight(
            config.oracle,
            runner=runner,
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_INVALID_OUTPUT
    assert "PRIVATE-TRAILING-OUTPUT" not in str(exc_info.value)


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff\n",
        b"1.168.0\x00\n",
        b"1.168.0\x01\n",
        b" 1.168.0\n",
        b"1.168.0\ntrailing\n",
    ],
)
def test_oracle_preflight_classifies_malformed_version_output_as_invalid(
    tmp_path: Path,
    payload: bytes,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_preflight(
            config.oracle,
            runner=_VersionRunner(semgrep=payload),
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_INVALID_OUTPUT


@pytest.mark.parametrize(
    ("semgrep", "bandit"),
    [
        (
            b"1.167.0\n",
            b"bandit 1.9.4\n  python version = 3.12.13 (main) [MSC v.1944]\n",
        ),
        (
            b"1.168.0\n",
            b"bandit 1.9.3\n  python version = 3.12.13 (main) [MSC v.1944]\n",
        ),
    ],
)
def test_oracle_preflight_classifies_structurally_valid_version_drift_as_policy_mismatch(
    tmp_path: Path,
    semgrep: bytes,
    bandit: bytes,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_preflight(
            config.oracle,
            runner=_VersionRunner(semgrep=semgrep, bandit=bandit),
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.POLICY_MISMATCH


def _write_provider_config(
    tmp_path: Path,
    prompts_path: Path,
    *,
    provider: str,
    file_provider_dir: Path | None = None,
    models: list[str] | None = None,
) -> Path:
    attestations_path = tmp_path / "provider-prompt-attestations.jsonl"
    write_jsonl(attestations_path, [])
    config = AppConfig.model_validate(
        {
            "run": {"name": "provider-test", "output_dir": str(tmp_path / "run")},
            "data": {
                "prompts_path": str(prompts_path),
                "prompt_attestations_path": str(attestations_path),
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
            "intervention": {"executor": "deterministic"},
            "generation": {
                "provider": provider,
                "models": ["model-a"] if models is None else models,
                "seeds": [7],
                "file_provider_dir": (
                    None if file_provider_dir is None else str(file_provider_dir)
                ),
            },
        }
    )
    config_path = tmp_path / "config.yaml"
    write_resolved_config(config, config_path)
    return config_path


def _assert_safe_cli_error(
    result: Result,
    code: ErrorCode,
    *forbidden: str,
) -> None:
    assert result.exit_code == int(code)
    assert f"[{code.name}]" in result.stderr
    rendered = result.output + result.stderr
    assert "Traceback" not in rendered
    assert "details" not in rendered.lower()
    for value in forbidden:
        assert value not in rendered


def test_data_config_requires_explicit_prompt_attestation_artifact() -> None:
    with pytest.raises(Exception):
        AppConfig.model_validate(
            {
                "run": {"name": "missing-attestations", "output_dir": "runs/test"},
                "data": {"prompts_path": "prompts.jsonl"},
                "intervention": {"executor": "deterministic"},
                "generation": {"models": ["model-a"], "seeds": [1]},
            }
        )


def test_preflight_validates_complete_exact_confirm_attestations(tmp_path: Path) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    attestations_path = tmp_path / "attestations.jsonl"
    _write_attested_confirm_pair(prompts_path, attestations_path)
    report = run_preflight(
        _config(
            tmp_path,
            prompts_path,
            prompt_attestations_path=attestations_path,
        )
    )
    assert report.confirm_count == 2


@pytest.mark.parametrize("mutation", ("missing", "duplicate", "stale_hash", "cross_task"))
def test_preflight_rejects_incomplete_or_stale_confirm_attestations(
    tmp_path: Path,
    mutation: str,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    attestations_path = tmp_path / "attestations.jsonl"
    _write_attested_confirm_pair(prompts_path, attestations_path)
    attestations = read_jsonl(attestations_path, PromptRoleAttestationRecord, required=True)
    if mutation == "missing":
        attestations = attestations[:1]
    elif mutation == "duplicate":
        attestations = [*attestations, attestations[-1]]
    elif mutation == "stale_hash":
        payloads = [item.model_dump(mode="json") for item in attestations]
        payloads[0]["prompt_sha256"] = "0" * 64
        attestations = payloads
    else:
        payloads = [item.model_dump(mode="json") for item in attestations]
        payloads[1]["task_id"] = "other-task"
        attestations = payloads
    write_jsonl(attestations_path, attestations)

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(
            _config(
                tmp_path,
                prompts_path,
                prompt_attestations_path=attestations_path,
            )
        )
    assert exc_info.value.code is ErrorCode.CONTRACT


def test_preflight_validates_optional_functional_contract_without_outcome_data(
    tmp_path: Path,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    contracts_path = tmp_path / "functional-contracts.jsonl"
    contract = FunctionalOutcomeContractRecord.from_content(
        task_feature_id="task.database_query",
        outcome_id="y_task_database_functional",
        expected_add_sign="positive",
        expected_remove_sign="negative",
        generic_control_feature_id=None,
        evaluator_policy_sha256="a" * 64,
    )
    write_jsonl(contracts_path, (contract,))
    assert (
        run_preflight(
            _config(
                tmp_path,
                prompts_path,
                functional_outcome_contracts_path=contracts_path,
            )
        ).prompt_count
        == 1
    )

    payload = contract.model_dump(mode="json")
    payload["outcome"] = "post-randomization-result"
    write_jsonl(contracts_path, (payload,))
    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(
            _config(
                tmp_path,
                prompts_path,
                functional_outcome_contracts_path=contracts_path,
            )
        )
    assert exc_info.value.code is ErrorCode.CONTRACT
    assert "post-randomization-result" not in str(exc_info.value)


def _write_functional_contract(path: Path) -> None:
    write_jsonl(
        path,
        (
            FunctionalOutcomeContractRecord.from_content(
                task_feature_id="task.database_query",
                outcome_id="y_task_database_functional",
                expected_add_sign="positive",
                expected_remove_sign="negative",
                generic_control_feature_id=None,
                evaluator_policy_sha256="a" * 64,
            ),
        ),
    )


@pytest.mark.parametrize("artifact", ("prompts", "attestations", "contracts"))
def test_preflight_rejects_artifact_byte_drift_during_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    attestations_path = tmp_path / "attestations.jsonl"
    contracts_path = tmp_path / "contracts.jsonl"
    _write_attested_confirm_pair(prompts_path, attestations_path)
    _write_functional_contract(contracts_path)
    target = {
        "prompts": prompts_path,
        "attestations": attestations_path,
        "contracts": contracts_path,
    }[artifact]
    real_read_jsonl = preflight_module.read_jsonl
    changed = False

    def drifting_read(path: str | Path, *args: object, **kwargs: object):
        nonlocal changed
        result = real_read_jsonl(path, *args, **kwargs)
        if Path(path) == target and not changed:
            with target.open("a", encoding="utf-8", newline="") as handle:
                handle.write("\n")
            changed = True
        return result

    monkeypatch.setattr(preflight_module, "read_jsonl", drifting_read)
    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(
            _config(
                tmp_path,
                prompts_path,
                prompt_attestations_path=attestations_path,
                functional_outcome_contracts_path=contracts_path,
            )
        )
    assert changed is True
    assert exc_info.value.code is ErrorCode.CONTRACT


def test_preflight_supplies_explicit_bounds_for_every_jsonl_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    attestations_path = tmp_path / "attestations.jsonl"
    contracts_path = tmp_path / "contracts.jsonl"
    _write_attested_confirm_pair(prompts_path, attestations_path)
    _write_functional_contract(contracts_path)
    real_read_jsonl = preflight_module.read_jsonl
    observed: dict[Path, dict[str, object]] = {}

    def bounded_read(path: str | Path, *args: object, **kwargs: object):
        observed[Path(path)] = dict(kwargs)
        return real_read_jsonl(path, *args, **kwargs)

    monkeypatch.setattr(preflight_module, "read_jsonl", bounded_read)
    run_preflight(
        _config(
            tmp_path,
            prompts_path,
            prompt_attestations_path=attestations_path,
            functional_outcome_contracts_path=contracts_path,
        )
    )

    assert set(observed) == {prompts_path, attestations_path, contracts_path}
    for limits in observed.values():
        assert type(limits.get("max_records")) is int
        assert int(limits["max_records"]) > 0
        assert type(limits.get("max_line_chars")) is int
        assert int(limits["max_line_chars"]) > 0
        assert type(limits.get("max_total_chars")) is int
        assert int(limits["max_total_chars"]) >= int(limits["max_line_chars"])


@pytest.mark.parametrize("artifact", ("attestations", "contracts"))
def test_preflight_rejects_oversized_attestation_and_contract_lines(
    tmp_path: Path,
    artifact: str,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    attestations_path = tmp_path / "attestations.jsonl"
    contracts_path = tmp_path / "contracts.jsonl"
    _write_attested_confirm_pair(prompts_path, attestations_path)
    _write_functional_contract(contracts_path)
    target = attestations_path if artifact == "attestations" else contracts_path
    lines = target.read_text(encoding="utf-8").splitlines()
    lines[0] += " " * (1024 * 1024 + 1 - len(lines[0]))
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(
            _config(
                tmp_path,
                prompts_path,
                prompt_attestations_path=attestations_path,
                functional_outcome_contracts_path=contracts_path,
            )
        )
    assert exc_info.value.code is ErrorCode.CONTRACT


def test_demo_preflight_returns_expected_counts() -> None:
    config = load_config(PROJECT_ROOT / "configs" / "demo.yaml")

    report = run_preflight(config)

    assert report == PreflightReport(
        prompt_count=30,
        discover_count=6,
        confirm_count=24,
        model_count=1,
        seed_count=2,
        output_dir="runs/demo",
    )


def test_demo_has_two_independent_pairs_per_exercised_semantic_protocol() -> None:
    prompts = read_jsonl(
        PROJECT_ROOT / "data" / "examples" / "prompts_demo.jsonl",
        PromptRecord,
        required=True,
        allow_empty=False,
    )
    attestations = read_jsonl(
        PROJECT_ROOT / "data" / "examples" / "prompt_attestations_demo.jsonl",
        PromptRoleAttestationRecord,
        required=True,
        allow_empty=False,
    )
    prompt_by_id = {item.prompt_id: item for item in prompts}
    tasks_by_protocol: dict[tuple[str, FeatureOperation], set[str]] = {}
    for attestation in attestations:
        if attestation.prompt_role is not PromptRole.POSITIVE_SAFETY_CONTROL:
            continue
        prompt = prompt_by_id[attestation.prompt_id]
        start = attestation.variant_clause_start
        end = attestation.variant_clause_end
        assert start is not None and end is not None
        clause = prompt.prompt.encode("utf-8")[start:end].decode("utf-8").casefold()
        features = {
            spec.feature_id
            for spec in PROMPT_FEATURE_CATALOG
            if spec.feature_family.value == "safety_control"
            and spec.intervenable
            and any(term in clause for term in spec.deterministic_terms)
        }
        assert len(features) == 1
        key = (next(iter(features)), attestation.contrast_owner_operation)
        tasks_by_protocol.setdefault(key, set()).add(attestation.task_id)

    assert tasks_by_protocol == {
        (feature_id, operation): {
            f"{prefix}-{operation.value}-a",
            f"{prefix}-{operation.value}-b",
        }
        for feature_id, prefix in (
            ("safety.path_normalization", "path"),
            ("safety.sql_parameterization", "sql"),
            ("safety.safe_subprocess", "command"),
        )
        for operation in FeatureOperation
    }


@pytest.mark.parametrize("artifact_state", ["missing", "empty"])
def test_preflight_rejects_missing_or_empty_prompt_artifact(
    tmp_path: Path,
    artifact_state: str,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    if artifact_state == "empty":
        prompts_path.write_text("", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(_config(tmp_path, prompts_path))

    assert exc_info.value.code is ErrorCode.CONTRACT


def test_preflight_rejects_duplicate_prompt_ids(tmp_path: Path) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            _prompt("duplicate-id", "discover", "first private prompt"),
            _prompt("duplicate-id", "confirm", "second private prompt"),
        ],
    )

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(_config(tmp_path, prompts_path))

    assert exc_info.value.code is ErrorCode.CONTRACT


def test_preflight_rejects_normalized_prompt_overlap_across_splits(tmp_path: Path) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            _prompt("discover-id", "discover", "  TOP\n secret\tprompt  "),
            _prompt("confirm-id", "confirm", "top secret prompt"),
        ],
    )

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(_config(tmp_path, prompts_path))

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert "TOP" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("models", "seeds"),
    [
        ([], [1]),
        (["model-a", "model-a"], [1]),
        (["model-a"], []),
        (["model-a"], [1, 1]),
    ],
)
def test_preflight_rejects_empty_or_duplicate_generation_axes(
    tmp_path: Path,
    models: list[str],
    seeds: list[int],
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            _prompt("discover-id", "discover", "discover prompt"),
            _prompt("confirm-id", "confirm", "confirm prompt"),
        ],
    )

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(_config(tmp_path, prompts_path, models=models, seeds=seeds))

    assert exc_info.value.code is ErrorCode.CONFIG


def test_preflight_cli_succeeds_without_preparing_run_directory(tmp_path: Path) -> None:
    run_dir = tmp_path / "preflight-only"

    result = CliRunner().invoke(
        app,
        [
            "preflight",
            "--config",
            str(PROJECT_ROOT / "configs" / "demo.yaml"),
            "--run-dir",
            str(run_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "prompts=30" in result.output
    assert "discover=6" in result.output
    assert "confirm=24" in result.output
    assert "models=1" in result.output
    assert "seeds=2" in result.output
    assert not run_dir.exists()


def test_preflight_cli_maps_contract_error_to_stderr_without_details_or_prompt_text(
    tmp_path: Path,
) -> None:
    secret = "DO-NOT-PRINT-this-private-prompt"
    prompts_path = tmp_path / "private-prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            _prompt("private-id", "discover", secret),
            _prompt("private-id", "confirm", f"different {secret}"),
        ],
    )
    config = _config(tmp_path, prompts_path)
    config_path = tmp_path / "config.yaml"
    write_resolved_config(config, config_path)

    result = CliRunner().invoke(app, ["preflight", "--config", str(config_path)])

    assert result.exit_code == int(ErrorCode.CONTRACT)
    assert "[CONTRACT]" in result.stderr
    rendered = result.output + result.stderr
    assert secret not in rendered
    assert "private-id" not in rendered
    assert str(prompts_path) not in rendered


def test_preflight_cli_maps_missing_config_to_safe_config_error(tmp_path: Path) -> None:
    config_path = tmp_path / "missing-private-config.yaml"

    result = CliRunner().invoke(app, ["preflight", "--config", str(config_path)])

    assert result.exit_code == int(ErrorCode.CONFIG)
    assert "[CONFIG] config:" in result.stderr
    rendered = result.output + result.stderr
    assert "Traceback" not in rendered
    assert str(config_path) not in rendered


@pytest.mark.parametrize(
    ("content", "secret"),
    [
        ("run: [\nprivate: YAML-PARSER-SECRET\n", "YAML-PARSER-SECRET"),
        ("- not\n- a\n- mapping\n", ""),
        (
            "run:\n"
            "  name: private\n"
            "data:\n"
            "  prompts_path: prompts.jsonl\n"
            "unknown_field: VALIDATION-SECRET\n",
            "VALIDATION-SECRET",
        ),
    ],
)
def test_preflight_cli_maps_invalid_config_to_safe_config_error(
    tmp_path: Path,
    content: str,
    secret: str,
) -> None:
    config_path = tmp_path / "private-config.yaml"
    config_path.write_text(content, encoding="utf-8")

    result = CliRunner().invoke(app, ["preflight", "--config", str(config_path)])

    assert result.exit_code == int(ErrorCode.CONFIG)
    assert "[CONFIG] config:" in result.stderr
    rendered = result.output + result.stderr
    assert "Traceback" not in rendered
    assert str(config_path) not in rendered
    if secret:
        assert secret not in rendered


@pytest.mark.parametrize("command", CLI_COMMANDS)
def test_every_cli_command_uses_safe_error_boundary(
    tmp_path: Path,
    command: str,
) -> None:
    secret = "top-secret-command-config"
    config_path = tmp_path / "private-config.yaml"
    config_path.write_text(
        f"run:\n  name: private\ndata:\n  prompts_path: prompts.jsonl\nunknown_field: {secret}\n",
        encoding="utf-8",
    )

    args = [command, "--config", str(config_path)]
    if command == "import-generation":
        args.extend(["--results", str(tmp_path / "unused-results.jsonl")])
    result = CliRunner().invoke(app, args)

    assert result.exit_code == int(ErrorCode.CONFIG)
    assert "[CONFIG] config:" in result.stderr
    rendered = result.output + result.stderr
    assert "Traceback" not in rendered
    assert secret not in rendered
    assert str(config_path) not in rendered
    assert "details" not in rendered.lower()


@pytest.mark.parametrize("command", CLI_COMMANDS)
def test_cli_command_help_preserves_declared_signature(command: str) -> None:
    result = CliRunner().invoke(app, [command, "--help"])

    assert result.exit_code == 0, result.output
    assert "--config" in result.output
    assert "--run-dir" in result.output


def test_unknown_secret_provider_is_a_safe_config_error(tmp_path: Path) -> None:
    secret = "top-secret-provider"
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "run": {"name": "unknown-provider", "output_dir": str(tmp_path / "run")},
                "data": {"prompts_path": str(prompts_path)},
                "generation": {"provider": secret},
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["preflight", "--config", str(config_path)])

    _assert_safe_cli_error(result, ErrorCode.CONFIG, secret, str(config_path))


def test_get_provider_rejects_unknown_name_without_echoing_it() -> None:
    secret = "top-secret-provider"

    with pytest.raises(SecAwareError) as exc_info:
        get_provider(secret)

    assert exc_info.value.code is ErrorCode.CONFIG
    assert exc_info.value.stage == "generation"
    assert secret not in str(exc_info.value)


def test_run_all_missing_secret_prompts_is_a_safe_contract_error(tmp_path: Path) -> None:
    prompts_path = tmp_path / "top-secret-prompts.jsonl"
    config_path = tmp_path / "config.yaml"
    write_resolved_config(_config(tmp_path, prompts_path), config_path)

    result = CliRunner().invoke(app, ["run-all", "--config", str(config_path)])

    _assert_safe_cli_error(result, ErrorCode.CONTRACT, str(prompts_path))


def test_file_provider_missing_directory_fails_preflight_safely(tmp_path: Path) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    provider_dir = tmp_path / "top-secret-missing-provider"
    config_path = _write_provider_config(
        tmp_path,
        prompts_path,
        provider="file",
        file_provider_dir=provider_dir,
    )

    result = CliRunner().invoke(app, ["preflight", "--config", str(config_path)])

    _assert_safe_cli_error(result, ErrorCode.CONTRACT, str(provider_dir))


def test_file_provider_missing_generated_file_is_a_safe_contract_error(
    tmp_path: Path,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    provider_dir = tmp_path / "top-secret-empty-provider"
    provider_dir.mkdir()
    config_path = _write_provider_config(
        tmp_path,
        prompts_path,
        provider="file",
        file_provider_dir=provider_dir,
    )

    result = CliRunner().invoke(app, ["generate-observed", "--config", str(config_path)])

    _assert_safe_cli_error(
        result,
        ErrorCode.CONTRACT,
        str(provider_dir),
        "model-a_7.py",
    )


def test_api_provider_stub_is_a_safe_config_error(tmp_path: Path) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config_path = _write_provider_config(tmp_path, prompts_path, provider="api")

    result = CliRunner().invoke(app, ["generate-observed", "--config", str(config_path)])

    _assert_safe_cli_error(result, ErrorCode.CONFIG, "RuntimeError")


@pytest.mark.parametrize("escape_kind", ["traversal", "absolute"])
def test_file_generation_rejects_model_path_escape_safely(
    tmp_path: Path,
    escape_kind: str,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    provider_dir = tmp_path / "provider"
    provider_dir.mkdir()
    if escape_kind == "traversal":
        model_id = "../private/model"
        outside_path = tmp_path / "private" / "model_7.py"
    else:
        outside_stem = tmp_path / "private-absolute" / "model"
        model_id = str(outside_stem)
        outside_path = Path(f"{outside_stem}_7.py")
    outside_path.parent.mkdir(parents=True)
    outside_path.write_text("top-secret outside code\n", encoding="utf-8")
    config_path = _write_provider_config(
        tmp_path,
        prompts_path,
        provider="file",
        file_provider_dir=provider_dir,
        models=[model_id],
    )

    result = CliRunner().invoke(app, ["generate-observed", "--config", str(config_path)])

    _assert_safe_cli_error(
        result,
        ErrorCode.CONTRACT,
        model_id,
        str(outside_path),
        "top-secret",
    )
