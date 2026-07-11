from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
import shutil

import pytest

from secaware.config import OracleConfig
from secaware.generation.result_importer import canonical_generated_code_from_request
from secaware.oracle.aggregator import run_oracle_batch
from secaware.pipeline.preflight import run_oracle_preflight
from secaware.schema.generation import (
    GENERATION_REQUEST_SCHEMA_VERSION,
    GenerationParameters,
    GenerationProvenance,
    GenerationRequestRecord,
    build_generation_request_id,
    sha256_text,
)
from secaware.schema.oracle import SecurityLabel
from secaware.schema.records import CanonicalGeneratedCodeRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = Path(__file__).with_name("oracle_corpus")
POLICY_LOCK = PROJECT_ROOT / "policies" / "oracle" / "python" / "policy.lock.json"
EXACT_TOOLS = {"semgrep": "1.168.0", "bandit": "1.9.4"}


@dataclass(frozen=True)
class _OracleToolGate:
    skip_reason: str | None
    error: str | None
    executables: dict[str, str]


def _inspect_oracle_tool_gate(
    *,
    version_getter: Callable[[str], str] = metadata.version,
    executable_resolver: Callable[[str], str | None] = shutil.which,
) -> _OracleToolGate:
    versions: dict[str, str | None] = {}
    executables: dict[str, str | None] = {}
    for tool in EXACT_TOOLS:
        try:
            versions[tool] = version_getter(tool)
        except metadata.PackageNotFoundError:
            versions[tool] = None
        executables[tool] = executable_resolver(tool)

    if all(version is None for version in versions.values()):
        commands = "; ".join(f"{tool} executable={executables[tool]!r}" for tool in EXACT_TOOLS)
        return _OracleToolGate(
            skip_reason=(
                "exact Oracle tools unavailable in core environment: both distributions "
                f"are absent; {commands}"
            ),
            error=None,
            executables={},
        )

    failures: list[str] = []
    resolved: dict[str, str] = {}
    for tool, expected_version in EXACT_TOOLS.items():
        actual_version = versions[tool]
        executable = executables[tool]
        if actual_version != expected_version:
            failures.append(
                f"{tool} distribution={actual_version!r}, expected={expected_version!r}"
            )
        if executable is None:
            failures.append(f"{tool} executable is missing from PATH")
        else:
            resolved[tool] = executable
    if failures:
        return _OracleToolGate(
            skip_reason=None,
            error="invalid Oracle tool installation: " + "; ".join(failures),
            executables=resolved,
        )
    return _OracleToolGate(skip_reason=None, error=None, executables=resolved)


ORACLE_TOOL_GATE = _inspect_oracle_tool_gate()


@pytest.mark.parametrize(
    ("case", "versions", "executables", "expects_skip", "expects_error"),
    [
        ("none", {}, {}, True, False),
        (
            "partial",
            {"semgrep": "1.168.0"},
            {"semgrep": "/tools/semgrep"},
            False,
            True,
        ),
        (
            "wrong",
            {"semgrep": "1.167.0", "bandit": "1.9.4"},
            {"semgrep": "/tools/semgrep", "bandit": "/tools/bandit"},
            False,
            True,
        ),
        (
            "exact-missing-command",
            EXACT_TOOLS,
            {"semgrep": "/tools/semgrep"},
            False,
            True,
        ),
        (
            "exact-good",
            EXACT_TOOLS,
            {"semgrep": "/tools/semgrep", "bandit": "/tools/bandit"},
            False,
            False,
        ),
    ],
)
def test_oracle_tool_gate_only_skips_when_both_distributions_are_absent(
    case: str,
    versions: dict[str, str],
    executables: dict[str, str],
    expects_skip: bool,
    expects_error: bool,
) -> None:
    def version_getter(tool: str) -> str:
        try:
            return versions[tool]
        except KeyError:
            raise metadata.PackageNotFoundError(tool) from None

    gate = _inspect_oracle_tool_gate(
        version_getter=version_getter,
        executable_resolver=executables.get,
    )

    assert (gate.skip_reason is not None) is expects_skip, case
    assert (gate.error is not None) is expects_error, case
    if case == "exact-good":
        assert gate.executables == executables


def _request(prompt_id: str, seed_id: int) -> GenerationRequestRecord:
    prompt = f"Return the checked-in {prompt_id} Python corpus sample."
    parameters = GenerationParameters(values={"temperature": 0.0})
    prompt_sha256 = sha256_text(prompt)
    endpoint_sha256 = sha256_text("checked-in-oracle-corpus")
    template_sha256 = sha256_text("Return only Python code.")
    request_id = build_generation_request_id(
        schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
        condition="observed",
        prompt_id=prompt_id,
        prompt_sha256=prompt_sha256,
        language="python",
        model_id="checked-in-corpus",
        seed_id=seed_id,
        hypothesis_id=None,
        intervention_id=None,
        endpoint_type="offline",
        endpoint_sha256=endpoint_sha256,
        system_template_version="oracle-corpus-v1",
        system_template_sha256=template_sha256,
        parameters=parameters,
    )
    return GenerationRequestRecord(
        schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
        request_id=request_id,
        condition="observed",
        prompt_id=prompt_id,
        prompt=prompt,
        prompt_sha256=prompt_sha256,
        language="python",
        model_id="checked-in-corpus",
        seed_id=seed_id,
        hypothesis_id=None,
        intervention_id=None,
        endpoint_type="offline",
        endpoint_sha256=endpoint_sha256,
        system_template_version="oracle-corpus-v1",
        system_template_sha256=template_sha256,
        parameters=parameters,
    )


def _corpus_records() -> list[CanonicalGeneratedCodeRecord]:
    provenance = GenerationProvenance(
        producer="checked-in-oracle-corpus",
        producer_version="1",
        source_batch_id="oracle-real-tools-v1",
    )
    records: list[CanonicalGeneratedCodeRecord] = []
    for seed_id, sample in enumerate(("secure", "insecure"), start=1):
        request = _request(f"oracle-corpus-{sample}", seed_id)
        records.append(
            canonical_generated_code_from_request(
                request,
                CORPUS_ROOT.joinpath(f"{sample}.py").read_text(encoding="utf-8"),
                provenance,
            )
        )
    return records


@pytest.mark.oracle_tools
@pytest.mark.skipif(
    ORACLE_TOOL_GATE.skip_reason is not None,
    reason=ORACLE_TOOL_GATE.skip_reason or "exact Oracle tools unavailable",
)
def test_locked_real_tools_classify_checked_in_corpus() -> None:
    if ORACLE_TOOL_GATE.error is not None:
        pytest.fail(ORACLE_TOOL_GATE.error, pytrace=False)
    semgrep_executable = ORACLE_TOOL_GATE.executables.get("semgrep")
    bandit_executable = ORACLE_TOOL_GATE.executables.get("bandit")
    assert semgrep_executable is not None
    assert bandit_executable is not None
    policy = run_oracle_preflight(
        OracleConfig(
            policy_lock_path=str(POLICY_LOCK),
            semgrep_executable=semgrep_executable,
            bandit_executable=bandit_executable,
        )
    )
    secure, insecure = run_oracle_batch(
        _corpus_records(),
        policy,
        semgrep_executable=semgrep_executable,
        bandit_executable=bandit_executable,
    )

    assert [secure.security_label, insecure.security_label] == [
        SecurityLabel.SECURE,
        SecurityLabel.INSECURE,
    ]
    expected_provenance = {
        (tool, version, policy.combined_sha256) for tool, version in EXACT_TOOLS.items()
    }
    for record in (secure, insecure):
        assert {
            (item.analyzer, item.version, item.policy_sha256) for item in record.analyzers
        } == expected_provenance
    assert {finding.analyzer for finding in insecure.findings} == {"semgrep", "bandit"}
