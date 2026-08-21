import ast
from collections.abc import Sequence
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
import typer
from typer.testing import CliRunner

from secaware import cli as cli_module
from secaware.cli import app
from secaware.config import TSGConfig, load_config, write_resolved_config
from secaware import extractors as extractors_module
from secaware.extractors import factory as extractor_factory_module
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl
from secaware.oracle import aggregator as aggregator_module
from secaware.oracle.runner import AnalyzerProcessResult
from secaware.pipeline.manifest import read_stage_manifest, write_stage_manifest
from secaware.pipeline import artifact as artifact_module
from secaware.pipeline.stages import confirmation_generation as confirmation_generation_stage_module
from secaware.pipeline.stages import confirmation_oracle as confirmation_oracle_stage_module
from secaware.pipeline.stages import fci_discovery as fci_stage_module
from secaware.pipeline.stages import jci as jci_stage_module
from secaware.pipeline.stages.prompt_variants import PROMPT_VARIANT_OUTPUTS
from secaware.config import FCIDiscoveryConfig
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    BootstrapDrawRecord,
    CausalTableRecord,
    EndpointMark,
    FrozenHypothesisRecord,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
)
from secaware.schema.experiments import AssignmentExecutionRecord, AssignmentRecord
from secaware.schema.oracle import OracleRecord
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.generation import GenerationRequestRecord
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord
from secaware.schema.outcomes import (
    AssignmentOutcomeRecord,
    ITTEffectRecord,
    JCIOrientationDeltaRecord,
    RFCICapabilityRecord,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_tree_bytes(run_dir: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run_dir).as_posix(): path.read_bytes()
        for path in sorted(run_dir.rglob("*"))
        if path.is_file()
    }


def _empty_run_all_store(root: Path) -> SimpleNamespace:
    return SimpleNamespace(root=root, path=lambda *parts: root.joinpath(*parts))


def test_run_all_executes_the_complete_m6_pipeline_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    config = SimpleNamespace(
        data=SimpleNamespace(functional_outcome_contracts_path=None),
        functional_judge=SimpleNamespace(enabled=True),
        rfci=SimpleNamespace(enabled=False),
    )
    store = _empty_run_all_store(Path("run-all-order"))
    monkeypatch.setattr(cli_module, "_load", lambda _config, _run_dir: (config, store))
    monkeypatch.setattr(cli_module, "_prepare", lambda *_args: calls.append("prepare"))
    monkeypatch.setattr(
        cli_module,
        "extract_prompt_tsg_stage",
        lambda *_args, **_kwargs: calls.append("extract-prompt-tsg"),
    )
    monkeypatch.setattr(
        cli_module,
        "generate_observed_stage",
        lambda *_args, **_kwargs: calls.append("generate-observed"),
    )

    def oracle_stage(*_args: object, condition: str, **_kwargs: object) -> None:
        calls.append(f"run-oracle-{condition}")

    monkeypatch.setattr(cli_module, "run_oracle_stage", oracle_stage)
    monkeypatch.setattr(
        cli_module,
        "discover_stage",
        lambda *_args, **_kwargs: calls.extend(("assemble-causal-tables", "fci-discovery")),
    )
    monkeypatch.setattr(
        cli_module,
        "run_prompt_variant_freeze_stage",
        lambda *_args, **_kwargs: calls.append("build-confirmation-variants"),
        raising=False,
    )
    monkeypatch.setattr(
        cli_module,
        "run_confirmation_randomization_stage",
        lambda *_args, **_kwargs: calls.append("randomize-confirmation"),
        raising=False,
    )
    monkeypatch.setattr(
        cli_module,
        "run_confirmation_generation_stage",
        lambda *_args, **_kwargs: calls.append("generate-confirmation"),
        raising=False,
    )
    monkeypatch.setattr(
        cli_module,
        "run_confirmation_oracle_stage",
        lambda *_args, **_kwargs: calls.append("run-oracle-confirmation"),
    )
    monkeypatch.setattr(
        cli_module,
        "run_functional_judge_stage",
        lambda *_args, **_kwargs: calls.append("judge-functionality"),
    )
    monkeypatch.setattr(
        cli_module,
        "_require_committed_functional_outcomes_for_frozen_protocols",
        lambda *_args, **_kwargs: calls.append("check-functional-outcomes"),
        raising=False,
    )
    monkeypatch.setattr(
        cli_module,
        "effects_stage",
        lambda *_args, **_kwargs: calls.append("confirm"),
        raising=False,
    )
    monkeypatch.setattr(
        cli_module,
        "jci_stage",
        lambda *_args, **_kwargs: calls.append("analyze-jci"),
        raising=False,
    )
    monkeypatch.setattr(
        cli_module,
        "rfci_stage",
        lambda *_args, **_kwargs: calls.append("analyze-rfci"),
        raising=False,
    )
    monkeypatch.setattr(
        cli_module,
        "write_reports",
        lambda *_args, **_kwargs: calls.append("report"),
    )

    result = CliRunner().invoke(app, ["run-all", "--config", "unused.yaml", "--force"])

    assert result.exit_code == 0, result.output
    assert calls == [
        "prepare",
        "extract-prompt-tsg",
        "generate-observed",
        "run-oracle-observed",
        "assemble-causal-tables",
        "fci-discovery",
        "build-confirmation-variants",
        "randomize-confirmation",
        "generate-confirmation",
        "run-oracle-confirmation",
        "judge-functionality",
        "check-functional-outcomes",
        "confirm",
        "analyze-jci",
        "analyze-rfci",
        "report",
    ]


def test_run_all_stops_without_future_m5_calls_after_randomization_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    config = object()
    store = _empty_run_all_store(Path("run-all-failure"))
    monkeypatch.setattr(cli_module, "_load", lambda _config, _run_dir: (config, store))
    for name in (
        "_prepare",
        "extract_prompt_tsg_stage",
        "generate_observed_stage",
        "run_oracle_stage",
        "discover_stage",
        "run_prompt_variant_freeze_stage",
    ):
        monkeypatch.setattr(
            cli_module,
            name,
            lambda *_args, _name=name, **_kwargs: calls.append(_name),
            raising=False,
        )

    def fail_randomization(*_args: object, **_kwargs: object) -> None:
        calls.append("run_confirmation_randomization_stage")
        raise RuntimeError("randomization failed")

    monkeypatch.setattr(
        cli_module,
        "run_confirmation_randomization_stage",
        fail_randomization,
        raising=False,
    )
    monkeypatch.setattr(
        cli_module,
        "run_confirmation_generation_stage",
        lambda *_args, **_kwargs: calls.append("unexpected-generation"),
        raising=False,
    )
    monkeypatch.setattr(
        cli_module,
        "run_confirmation_oracle_stage",
        lambda *_args, **_kwargs: calls.append("unexpected-oracle"),
    )
    for name in ("effects_stage", "jci_stage", "rfci_stage", "write_reports"):
        monkeypatch.setattr(
            cli_module,
            name,
            lambda *_args, _name=name, **_kwargs: calls.append(f"unexpected-{_name}"),
            raising=False,
        )

    result = CliRunner().invoke(app, ["run-all", "--config", "unused.yaml", "--force"])

    assert result.exit_code != 0
    assert calls[-1] == "run_confirmation_randomization_stage"
    assert "unexpected-generation" not in calls
    assert "unexpected-oracle" not in calls
    assert not any(item.startswith("unexpected-") for item in calls)


def test_run_all_requires_committed_functional_outcomes_without_importing_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    config = SimpleNamespace(
        data=SimpleNamespace(functional_outcome_contracts_path=None),
        rfci=SimpleNamespace(enabled=False),
    )

    @contextmanager
    def hold_committed_protocols(
        stage: str,
        outputs: Sequence[Path],
        **_kwargs: object,
    ):
        assert stage == "build-confirmation-variants"
        assert tuple(outputs) == tuple(
            root / "interventions" / name for name, _model in PROMPT_VARIANT_OUTPUTS
        )
        calls.append("hold-frozen-protocols")
        yield {}

    def missing_functional_commit(
        stage: str,
        _outputs: Sequence[Path],
        **_kwargs: object,
    ) -> None:
        assert stage == "import-functional-outcomes"
        raise SecAwareError(
            code=ErrorCode.CONTRACT,
            stage="run-all",
            message="committed functional outcomes are required before confirm",
        )

    root = Path("run-all-functional-contract")
    store = SimpleNamespace(
        root=root,
        path=lambda *parts: root.joinpath(*parts),
        hold_committed_output=hold_committed_protocols,
        require_committed_output=missing_functional_commit,
    )
    monkeypatch.setattr(cli_module, "_load", lambda _config, _run_dir: (config, store))
    for name in (
        "_prepare",
        "extract_prompt_tsg_stage",
        "generate_observed_stage",
        "run_oracle_stage",
        "discover_stage",
        "run_prompt_variant_freeze_stage",
        "run_confirmation_randomization_stage",
        "run_confirmation_generation_stage",
        "run_confirmation_oracle_stage",
    ):
        monkeypatch.setattr(
            cli_module,
            name,
            lambda *_args, _name=name, **_kwargs: calls.append(_name),
        )
    monkeypatch.setattr(
        cli_module,
        "import_functional_outcomes_stage",
        lambda *_args, **_kwargs: pytest.fail("run-all must never derive functional outcomes"),
        raising=False,
    )
    monkeypatch.setattr(
        cli_module,
        "read_jsonl",
        lambda path, _model, **_kwargs: (
            (SimpleNamespace(functional_outcome_contract_id="functional_contract_" + "a" * 64),)
            if path == root / "interventions" / "confirmation_protocols.jsonl"
            else pytest.fail("run-all read an unexpected functional-gate artifact")
        ),
    )
    for name in ("effects_stage", "jci_stage", "rfci_stage", "write_reports"):
        monkeypatch.setattr(
            cli_module,
            name,
            lambda *_args, _name=name, **_kwargs: calls.append(f"unexpected-{_name}"),
            raising=False,
        )

    result = CliRunner().invoke(app, ["run-all", "--config", "unused.yaml", "--force"])

    assert result.exit_code == int(ErrorCode.CONTRACT), result.output
    assert calls[-2:] == ["run_confirmation_oracle_stage", "hold-frozen-protocols"]
    assert not any(item.startswith("unexpected-") for item in calls)


def test_functional_gate_does_not_require_import_for_protocols_without_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path("run-all-no-functional-contract")
    held: list[str] = []

    @contextmanager
    def hold_committed_protocols(
        stage: str,
        outputs: Sequence[Path],
        **_kwargs: object,
    ):
        assert stage == "build-confirmation-variants"
        assert tuple(outputs) == tuple(
            root / "interventions" / name for name, _model in PROMPT_VARIANT_OUTPUTS
        )
        held.append(stage)
        yield {}

    store = SimpleNamespace(
        root=root,
        path=lambda *parts: root.joinpath(*parts),
        hold_committed_output=hold_committed_protocols,
        require_committed_output=lambda *_args, **_kwargs: pytest.fail(
            "functional import must be optional for contract-free frozen protocols"
        ),
    )
    monkeypatch.setattr(
        cli_module,
        "read_jsonl",
        lambda path, _model, **_kwargs: (
            (SimpleNamespace(functional_outcome_contract_id=None),)
            if path == root / "interventions" / "confirmation_protocols.jsonl"
            else pytest.fail("functional gate read an unexpected artifact")
        ),
    )

    cli_module._require_committed_functional_outcomes_for_frozen_protocols(store)

    assert held == ["build-confirmation-variants"]


@pytest.mark.parametrize(
    ("command", "stage_name", "extra_args"),
    (
        (
            "import-functional-outcomes",
            "import_functional_outcomes_stage",
            ("--results", "functional-results.jsonl"),
        ),
        ("confirm", "effects_stage", ()),
        ("analyze-jci", "jci_stage", ()),
        ("analyze-rfci", "rfci_stage", ()),
        ("report", "write_reports", ()),
    ),
)
def test_final_analysis_commands_delegate_to_exactly_one_stage(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    stage_name: str,
    extra_args: tuple[str, ...],
) -> None:
    config = object()
    store = object()
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(cli_module, "_load", lambda _config, _run_dir: (config, store))
    monkeypatch.setattr(
        cli_module,
        stage_name,
        lambda *args, **kwargs: calls.append((args, kwargs)),
        raising=False,
    )
    monkeypatch.setattr(
        cli_module,
        "_prepare",
        lambda *_args, **_kwargs: pytest.fail("analysis command must not re-prepare the run"),
    )

    result = CliRunner().invoke(
        app,
        [command, "--config", "unused.yaml", "--run-dir", "run-dir", "--force", *extra_args],
    )

    assert result.exit_code == 0, result.output
    expected_kwargs: dict[str, object] = {"force": True}
    if command == "import-functional-outcomes":
        expected_kwargs["results_path"] = Path("functional-results.jsonl")
    assert calls == [((config, store), expected_kwargs)]


def _static_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_string(node.left)
        right = _static_string(node.right)
        return left + right if left is not None and right is not None else None
    return None


def _authority_access_violations(path: Path) -> list[tuple[int, str]]:
    forbidden_keys = {"fea" + "tures", "sha" + "dow"}
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    violations: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value in forbidden_keys:
            violations.append((node.lineno, "forbidden-constant"))
        elif isinstance(node, ast.Attribute) and node.attr in forbidden_keys:
            violations.append((node.lineno, "attribute"))
        elif isinstance(node, ast.Subscript) and _static_string(node.slice) in forbidden_keys:
            violations.append((node.lineno, "subscript"))
        elif isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and node.args
                and _static_string(node.args[0]) in forbidden_keys
            ):
                violations.append((node.lineno, "mapping-get"))
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and _static_string(node.args[1]) in forbidden_keys
            ):
                violations.append((node.lineno, "getattr"))
    return violations


def _assert_no_removed_registered_command(application: typer.Typer) -> None:
    removed_command = "extract-" + "code-" + "tsg"
    removed_callback_fragment = "code_" + "tsg"
    pending = [application]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        assert all(command.name != removed_command for command in current.registered_commands)
        assert all(
            command.callback is None or removed_callback_fragment not in command.callback.__name__
            for command in current.registered_commands
        )
        for group in current.registered_groups:
            assert group.name != removed_command
            pending.append(group.typer_instance)


def _declared_cli_commands(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    declared_commands: set[str] = set()
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "command"
        ):
            continue
        declared = _static_string(node.args[0]) if node.args else None
        for keyword in node.keywords:
            if keyword.arg == "name":
                declared = _static_string(keyword.value)
        if declared is not None:
            declared_commands.add(declared)
    return declared_commands


class _RunAllOracleRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

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
        analyzer = "semgrep" if "semgrep" in call[0] else "bandit"
        if call[1:] == ("--version",):
            stdout = (
                b"1.168.0\n"
                if analyzer == "semgrep"
                else (
                    b"bandit 1.9.4\n  python version = 3.12.13 (main) [MSC v.1944 64 bit (AMD64)]\n"
                )
            )
            return AnalyzerProcessResult(0, stdout, "a" * 64)
        files = sorted(path.name for path in cwd.iterdir() if path.suffix == ".py")
        if analyzer == "semgrep":
            insecure_files = [
                path.name
                for path in sorted(cwd.iterdir())
                if path.suffix == ".py" and " + name + " in path.read_text(encoding="utf-8")
            ]
            payload = {
                "version": "1.168.0",
                "results": [
                    {
                        "check_id": "secaware.python.sql-injection",
                        "path": filename,
                        "start": {"line": 1, "col": 1, "offset": 0},
                        "end": {"line": 1, "col": 2, "offset": 1},
                        "extra": {
                            "message": "Deterministic SQL fixture finding.",
                            "metadata": {"cwe": "CWE-89"},
                            "severity": "ERROR",
                        },
                    }
                    for filename in insecure_files
                ],
                "errors": [],
                "paths": {"scanned": files},
                "skipped_rules": [],
            }
        else:
            metrics = {filename: {"loc": 2, "nosec": 0, "skipped_tests": 0} for filename in files}
            metrics["_totals"] = {"loc": 2, "nosec": 0, "skipped_tests": 0}
            payload = {"errors": [], "metrics": metrics, "results": []}
        return AnalyzerProcessResult(0, json.dumps(payload).encode(), "a" * 64)


class _RunAllFCIRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, PAGRunKind]] = []

    def run(
        self,
        matrix: np.ndarray,
        table: CausalTableRecord,
        knowledge: BackgroundKnowledgeRecord,
        config: FCIDiscoveryConfig,
        run_kind: PAGRunKind,
    ) -> PAGRecord:
        assert matrix.shape[1] == len(table.variables)
        assert matrix.shape[0] in {table.row_count, table.independent_task_count}
        self.calls.append((table.table_id, run_kind))
        variables = tuple(item.variable_id for item in table.variables)
        target = {
            "scope.cwe_22": "x.safety.path_normalization",
            "scope.cwe_78": "x.safety.safe_subprocess",
            "scope.cwe_89": "x.safety.sql_parameterization",
        }[table.scope_id]
        assert target in variables
        return PAGRecord.from_content(
            run_kind=run_kind,
            table_id=table.table_id,
            backend=config.backend,
            backend_version=config.backend_version,
            ci_test=config.ci_test,
            config_sha256=artifact_module.canonical_sha256(config.model_dump(mode="json")),
            background_knowledge_sha256=knowledge.knowledge_sha256,
            variable_ids=variables,
            edges=(
                PAGEdgeRecord(
                    left=target,
                    right="y.secure_functional",
                    left_mark=EndpointMark.TAIL,
                    right_mark=EndpointMark.ARROW,
                ),
            ),
        )


def test_run_all_demo_uses_canonical_oracle_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "canonical-demo"
    runner = _RunAllOracleRunner()
    monkeypatch.setattr(cli_module, "run_analyzer_process", runner)
    monkeypatch.setattr(cli_module, "validate_analyzer_runtime", lambda: None)
    monkeypatch.setattr(aggregator_module, "validate_analyzer_runtime", lambda: None)
    monkeypatch.setattr(confirmation_oracle_stage_module, "run_analyzer_process", runner)
    monkeypatch.setattr(
        confirmation_oracle_stage_module,
        "validate_analyzer_runtime",
        lambda: None,
    )
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    fci_runner = _RunAllFCIRunner()
    monkeypatch.setattr(fci_stage_module, "SpawnedFCIRunner", lambda: fci_runner)
    monkeypatch.setattr(jci_stage_module, "SpawnedFCIRunner", lambda **_kwargs: fci_runner)
    real_confirmation_provider_factory = (
        confirmation_generation_stage_module._provider_from_frozen_config
    )

    class CountingConfirmationProvider:
        calls = 0

        def __init__(self, delegate: object) -> None:
            self.delegate = delegate

        def generate_many(self, requests):
            type(self).calls += 1
            return self.delegate.generate_many(requests)

    def counting_confirmation_provider_factory(config, **kwargs):
        return CountingConfirmationProvider(real_confirmation_provider_factory(config, **kwargs))

    monkeypatch.setattr(
        confirmation_generation_stage_module,
        "_provider_from_frozen_config",
        counting_confirmation_provider_factory,
    )

    def reject_llm_transport(**_kwargs: object) -> None:
        pytest.fail("offline deterministic demo must not construct an LLM transport")

    monkeypatch.setattr(
        extractor_factory_module,
        "OpenAICompatibleStructuredTransport",
        reject_llm_transport,
    )

    result = CliRunner().invoke(
        app,
        ["run-all", "--config", "configs/demo.yaml", "--run-dir", str(run_dir), "--force"],
    )

    assert result.exit_code == 0, result.output
    assert "SecAware" in result.output
    observed = read_jsonl(
        run_dir / "oracle" / "observed_oracle.jsonl",
        OracleRecord,
        required=True,
        allow_empty=False,
    )
    observed_code = read_jsonl(
        run_dir / "generation" / "observed_code.jsonl",
        CanonicalGeneratedCodeRecord,
        required=True,
        allow_empty=False,
    )
    assert observed and observed_code
    proposals = read_jsonl(
        run_dir / "tsg" / "prompt_extraction_proposals.jsonl",
        PromptExtractionProposalRecord,
        required=True,
        allow_empty=False,
    )
    assert proposals
    assert {proposal.backend for proposal in proposals} == {
        PromptExtractorBackend.DETERMINISTIC_CATALOG_V1
    }
    assert "OPENAI_API_KEY" not in os.environ
    tables = read_jsonl(
        run_dir / "discovery" / "causal_tables.jsonl",
        CausalTableRecord,
        required=True,
        allow_empty=False,
    )
    draws = read_jsonl(
        run_dir / "discovery" / "bootstrap_draws.jsonl",
        BootstrapDrawRecord,
        required=True,
        allow_empty=False,
    )
    hypotheses = read_jsonl(
        run_dir / "discovery" / "hypotheses_frozen.jsonl",
        FrozenHypothesisRecord,
        required=True,
        allow_empty=False,
    )
    assert len(tables) == 3
    assert len(hypotheses) == 3
    assert len(draws) == len(tables) * (1 + 20)
    observational_calls = tuple(
        item
        for item in fci_runner.calls
        if item[1] in {PAGRunKind.OBSERVATIONAL_REFERENCE, PAGRunKind.OBSERVATIONAL_BOOTSTRAP}
    )
    assert len(observational_calls) == len(tables) * (1 + 20)
    assert read_stage_manifest(run_dir / ".stages" / "run-oracle-observed.json").policy_sha256
    assignments = read_jsonl(
        run_dir / "interventions" / "assignments.jsonl",
        AssignmentRecord,
        required=True,
        allow_empty=False,
    )
    requests = read_jsonl(
        run_dir / "generation" / "confirmation_requests.jsonl",
        GenerationRequestRecord,
        required=True,
        allow_empty=False,
    )
    executions = read_jsonl(
        run_dir / "generation" / "confirmation_execution.jsonl",
        AssignmentExecutionRecord,
        required=True,
        allow_empty=False,
    )
    confirmation_code = read_jsonl(
        run_dir / "generation" / "confirmation_code.jsonl",
        CanonicalGeneratedCodeRecord,
        required=True,
        allow_empty=False,
    )
    confirmation_oracle = read_jsonl(
        run_dir / "oracle" / "confirmation_oracle.jsonl",
        OracleRecord,
        required=True,
        allow_empty=False,
    )
    assignment_ids = {item.assignment_id for item in assignments}
    assert assignment_ids
    assert {item.assignment_id for item in requests} == assignment_ids
    assert {item.assignment_id for item in executions} == assignment_ids
    assert {item.assignment_id for item in confirmation_code} == assignment_ids
    assert {item.assignment_id for item in confirmation_oracle} == assignment_ids
    assert all(item.condition == "confirm_arm" for item in confirmation_oracle)
    assignment_outcomes = read_jsonl(
        run_dir / "analysis" / "assignment_outcomes.jsonl",
        AssignmentOutcomeRecord,
        required=True,
        allow_empty=False,
    )
    itt_effects = read_jsonl(
        run_dir / "analysis" / "itt_effects.jsonl",
        ITTEffectRecord,
        required=True,
        allow_empty=True,
    )
    jci_raw = read_jsonl(
        run_dir / "analysis" / "jci_raw_pags.jsonl",
        PAGRecord,
        required=True,
        allow_empty=True,
    )
    jci_constrained = read_jsonl(
        run_dir / "analysis" / "jci_constrained_pags.jsonl",
        PAGRecord,
        required=True,
        allow_empty=True,
    )
    jci_deltas = read_jsonl(
        run_dir / "analysis" / "jci_orientation_deltas.jsonl",
        JCIOrientationDeltaRecord,
        required=True,
        allow_empty=True,
    )
    rfci_capability = read_jsonl(
        run_dir / "analysis" / "rfci_capability.jsonl",
        RFCICapabilityRecord,
        required=True,
        allow_empty=False,
    )
    assert {item.assignment_id for item in assignment_outcomes} == assignment_ids
    assert itt_effects
    assert len(jci_raw) == len(jci_constrained) == len(jci_deltas)
    assert all(item.run_kind is PAGRunKind.JCI_RAW for item in jci_raw)
    assert all(item.run_kind is PAGRunKind.JCI_CONSTRAINED for item in jci_constrained)
    assert len(rfci_capability) == 1
    assert rfci_capability[0].available is False
    assert (run_dir / "reports" / "summary.md").is_file()
    for stage in (
        "build-confirmation-variants",
        "randomize-confirmation",
        "generate-confirmation",
        "run-oracle-confirmation",
        "estimate-confirmation-effects",
        "jci-confirmation",
        "rfci-confirmation",
        "report",
    ):
        assert read_stage_manifest(run_dir / ".stages" / f"{stage}.json").stage == stage
    for absent in (
        run_dir / "oracle" / "counterfactual_oracle.jsonl",
        run_dir / "generation" / "counterfactual_code.jsonl",
        run_dir / "interventions" / "interventions.jsonl",
        run_dir / "analysis" / "pair_results.jsonl",
        run_dir / "analysis" / "hypothesis_effects.jsonl",
        run_dir / "analysis" / "jci_pag.jsonl",
        run_dir / ".stages" / "import-functional-outcomes.json",
        run_dir / ".stages" / "analyze-jci.json",
        run_dir / ".stages" / "effects.json",
    ):
        assert not absent.exists()

    committed = _run_tree_bytes(run_dir)

    analyzer_calls = tuple(runner.calls)
    provider_calls = CountingConfirmationProvider.calls
    stage_calls: list[str] = []

    def reject_completed_stage(name: str):
        def reject(*_args: object, **_kwargs: object) -> None:
            stage_calls.append(name)
            pytest.fail(f"completed run reached stage {name}")

        return reject

    with pytest.MonkeyPatch.context() as completed_patch:
        for stage_name in (
            "_prepare",
            "extract_prompt_tsg_stage",
            "generate_observed_stage",
            "run_oracle_stage",
            "discover_stage",
            "run_prompt_variant_freeze_stage",
            "run_confirmation_randomization_stage",
            "run_confirmation_generation_stage",
            "run_confirmation_oracle_stage",
            "effects_stage",
            "jci_stage",
            "rfci_stage",
            "write_reports",
        ):
            completed_patch.setattr(
                cli_module,
                stage_name,
                reject_completed_stage(stage_name),
            )

        second = CliRunner().invoke(
            app,
            ["run-all", "--config", "configs/demo.yaml", "--run-dir", str(run_dir)],
        )

        assert second.exit_code == 0, second.output
        assert "SecAware" in second.output
        assert tuple(runner.calls) == analyzer_calls
        assert CountingConfirmationProvider.calls == provider_calls
        assert _run_tree_bytes(run_dir) == committed

        forced_completed = CliRunner().invoke(
            app,
            [
                "run-all",
                "--config",
                "configs/demo.yaml",
                "--run-dir",
                str(run_dir),
                "--force",
            ],
        )

        assert forced_completed.exit_code == int(ErrorCode.MANIFEST_CONFLICT)
        normalized_force_error = " ".join(forced_completed.output.split()).casefold()
        assert "completed run" in normalized_force_error
        assert "immutable" in normalized_force_error
        assert "start a new run" in normalized_force_error
        assert tuple(runner.calls) == analyzer_calls
        assert CountingConfirmationProvider.calls == provider_calls
        assert _run_tree_bytes(run_dir) == committed
    assert stage_calls == []

    terminal_output = run_dir / "reports" / "summary.md"
    terminal_manifest = run_dir / ".stages" / "report.json"
    assignments_path = run_dir / "interventions" / "assignments.jsonl"
    original_output = terminal_output.read_bytes()
    original_manifest = terminal_manifest.read_bytes()
    try:
        tampered_output = original_output.replace(
            b"- Frozen hypotheses: 3",
            b"- Frozen hypotheses: 999999",
        )
        assert tampered_output != original_output
        terminal_output.write_bytes(tampered_output)
        manifest = read_stage_manifest(terminal_manifest)
        output_sha256 = dict(manifest.output_sha256)
        output_sha256["reports/summary.md"] = artifact_module.sha256_path(terminal_output)
        write_stage_manifest(
            terminal_manifest,
            manifest.model_copy(update={"output_sha256": output_sha256}),
        )
        coordinated_tamper = _run_tree_bytes(run_dir)
        with pytest.MonkeyPatch.context() as tamper_patch:
            for stage_name in (
                "_prepare",
                "extract_prompt_tsg_stage",
                "generate_observed_stage",
                "run_oracle_stage",
                "discover_stage",
                "run_prompt_variant_freeze_stage",
                "run_confirmation_randomization_stage",
                "run_confirmation_generation_stage",
                "run_confirmation_oracle_stage",
                "effects_stage",
                "jci_stage",
                "rfci_stage",
                "write_reports",
            ):
                tamper_patch.setattr(
                    cli_module,
                    stage_name,
                    reject_completed_stage(stage_name),
                )
            for force_args in ((), ("--force",)):
                rejected = CliRunner().invoke(
                    app,
                    [
                        "run-all",
                        "--config",
                        "configs/demo.yaml",
                        "--run-dir",
                        str(run_dir),
                        *force_args,
                    ],
                )
                assert rejected.exit_code != 0
                assert tuple(runner.calls) == analyzer_calls
                assert CountingConfirmationProvider.calls == provider_calls
                assert _run_tree_bytes(run_dir) == coordinated_tamper
        assert stage_calls == []
    finally:
        terminal_output.write_bytes(original_output)
        terminal_manifest.write_bytes(original_manifest)

    for tampered_path in (terminal_output, assignments_path):
        original = tampered_path.read_bytes()
        tampered_path.write_bytes(original + b"\n")
        tampered = _run_tree_bytes(run_dir)
        for force_args in ((), ("--force",)):
            rejected = CliRunner().invoke(
                app,
                [
                    "run-all",
                    "--config",
                    "configs/demo.yaml",
                    "--run-dir",
                    str(run_dir),
                    *force_args,
                ],
            )
            assert rejected.exit_code != 0
            assert tuple(runner.calls) == analyzer_calls
            assert CountingConfirmationProvider.calls == provider_calls
            assert _run_tree_bytes(run_dir) == tampered
        tampered_path.write_bytes(original)

    for missing_path in (terminal_output, terminal_manifest):
        original = missing_path.read_bytes()
        missing_path.unlink()
        partial = _run_tree_bytes(run_dir)
        for force_args in ((), ("--force",)):
            rejected = CliRunner().invoke(
                app,
                [
                    "run-all",
                    "--config",
                    "configs/demo.yaml",
                    "--run-dir",
                    str(run_dir),
                    *force_args,
                ],
            )
            assert rejected.exit_code != 0
            assert tuple(runner.calls) == analyzer_calls
            assert CountingConfirmationProvider.calls == provider_calls
            assert _run_tree_bytes(run_dir) == partial
        missing_path.write_bytes(original)

    assert _run_tree_bytes(run_dir) == committed


def test_final_architecture_has_no_flat_projection_or_removed_stage_authority() -> None:
    forbidden_authority_reads = ("." + "features", "." + "shadow")
    for package in ("discovery", "intervention"):
        for path in sorted((REPO_ROOT / "src" / "secaware" / package).rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            assert all(fragment not in source for fragment in forbidden_authority_reads)
            assert _authority_access_violations(path) == []

    removed_fragments = (
        "code" + "_tsg",
        "extract_" + "code_" + "tsg",
        "code_" + "extractor",
        "python_" + "ast_v0",
    )
    for root in (REPO_ROOT / "src", REPO_ROOT / "configs"):
        for path in sorted(
            item for item in root.rglob("*") if item.is_file() and item.suffix in {".py", ".yaml"}
        ):
            source = path.read_text(encoding="utf-8")
            assert all(fragment not in source for fragment in removed_fragments)

    help_result = CliRunner().invoke(app, ["--help"])
    assert help_result.exit_code == 0
    removed_command = "extract-" + "code-" + "tsg"
    assert removed_command not in help_result.output

    _assert_no_removed_registered_command(app)

    cli_path = REPO_ROOT / "src" / "secaware" / "cli.py"
    assert removed_command not in _declared_cli_commands(cli_path)

    removed_module = "code_" + "tsg_" + "extractor"
    removed_symbol = "extract_" + "code_" + "tsg"
    assert not (REPO_ROOT / "src" / "secaware" / "extractors" / f"{removed_module}.py").exists()
    assert importlib.util.find_spec(f"secaware.extractors.{removed_module}") is None
    assert not hasattr(extractors_module, removed_symbol)
    assert not hasattr(cli_module, removed_symbol + "_stage")
    assert not hasattr(cli_module, removed_symbol + "_command")
    assert "code_" + "extractor" not in TSGConfig.model_fields


@pytest.mark.parametrize(
    "expression",
    (
        "record." + "fea" + "tures",
        "record." + "sha" + "dow",
        "record[" + repr("sha" + "dow") + "]",
        "record.get(" + repr("fea" + "tures") + ")",
        "getattr(record, " + repr("sha" + "dow") + ")",
        "record.model_dump()[" + repr("sha" + "dow") + "]",
        "record.model_dump().get(" + repr("fea" + "tures") + ")",
        "record.pop(" + repr("sha" + "dow") + ")",
        "record.setdefault(" + repr("fea" + "tures") + ", False)",
        "operator.getitem(record, " + repr("sha" + "dow") + ")",
    ),
)
def test_authority_ast_gate_rejects_common_indirect_reads(
    tmp_path: Path,
    expression: str,
) -> None:
    candidate = tmp_path / "candidate.py"
    candidate.write_text(f"def probe(record):\n    return {expression}\n", encoding="utf-8")

    assert _authority_access_violations(candidate)


def test_removed_cli_gate_detects_hidden_runtime_and_source_registration(
    tmp_path: Path,
) -> None:
    removed_command = "extract-" + "code-" + "tsg"
    hidden_app = typer.Typer()

    def hidden_callback() -> None:
        return None

    hidden_app.command(removed_command, hidden=True)(hidden_callback)
    with pytest.raises(AssertionError):
        _assert_no_removed_registered_command(hidden_app)

    root_app = typer.Typer()
    child_app = typer.Typer()
    grandchild_app = typer.Typer()
    grandchild_app.command(removed_command, hidden=True)(hidden_callback)
    child_app.add_typer(grandchild_app, name="grandchild")
    root_app.add_typer(child_app, name="child")
    with pytest.raises(AssertionError):
        _assert_no_removed_registered_command(root_app)

    candidate = tmp_path / "candidate_cli.py"
    candidate.write_text(
        "@app.command(" + repr(removed_command) + ", hidden=True)\ndef command():\n    pass\n",
        encoding="utf-8",
    )
    assert removed_command in _declared_cli_commands(candidate)


def test_prompt_graph_outcome_boundary_and_breaking_migration_are_documented() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    readme_prose = " ".join(readme.split())
    migration_path = REPO_ROOT / "docs" / "migrations" / "prompt-tsg-v2.md"

    assert (
        "Prompt TSG supplies semantic task-feature and target-feature relationships" in readme_prose
    )
    assert "Prompt TSG edges are not causal edges" in readme_prose
    assert "never passed to FCI, JCI, or RFCI as causal adjacencies" in readme_prose
    assert "only security outcome" in readme
    assert "Code TSG" in readme and "compatibility path" in readme
    assert "shadow" in readme and "never authoritative" in readme
    assert "fail closed" in readme

    migration = migration_path.read_text(encoding="utf-8")
    normalized_migration = " ".join(migration.split())
    assert "breaking migration" in migration.lower()
    assert "regenerate Prompt TSG v2 and every downstream stage" in normalized_migration
    assert "v1 artifacts are rejected" in migration
    assert "not converted" in migration
    for required_term in ("catalog", "schema", "extractor", "fingerprint"):
        assert required_term in migration
    for removed_surface in ("artifacts", "manifests", "CLI", "configuration"):
        assert removed_surface in migration
    assert "run directory" in migration
    assert "secaware run-all" in migration
    assert "extractor version change" in normalized_migration
    assert 'if (-not (Test-Path -LiteralPath "$run/tsg/prompt_tsg.jsonl")) { throw' in migration
    assert (
        'if (-not (Test-Path -LiteralPath "$run/.stages/extract-prompt-tsg.json")) { throw'
        in migration
    )
    assert "PROMPT_TSG_CATALOG_SHA256" in migration
    assert "re.fullmatch" in migration
    assert "Prompt TSG 2.1" in migration
    assert "task_id" in migration
    for backend in (
        "llm_facts_v1",
        "llm_direct_graph_v1",
        "deterministic_catalog_v1",
    ):
        assert backend in migration
    assert "prompt_extraction_proposals.jsonl" in migration
    assert "prompt_tsg.jsonl" in migration
    assert "no per-prompt fallback" in normalized_migration
    assert "not automatically upgraded" in normalized_migration


def test_completed_randomized_confirmation_run_immutability_is_documented() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    migration = (REPO_ROOT / "docs" / "migrations" / "randomized-confirmation.md").read_text(
        encoding="utf-8"
    )

    for document in (readme, migration):
        normalized = " ".join(document.split()).casefold()
        assert "completed run" in normalized
        assert "immutable" in normalized
        assert "start a new run" in normalized
        assert "--force" in normalized


def test_run_all_demo_fails_closed_before_legacy_oracle_publication(tmp_path: Path) -> None:
    runner = CliRunner()
    run_dir = tmp_path / "demo"
    config = load_config("configs/demo.yaml", run_dir=run_dir)
    payload = config.model_dump(mode="python")
    payload["oracle"]["semgrep_executable"] = "missing-secaware-semgrep"
    payload["oracle"]["bandit_executable"] = "missing-secaware-bandit"
    config_path = tmp_path / "demo.yaml"
    write_resolved_config(config.__class__.model_validate(payload), config_path)

    result = runner.invoke(
        app,
        ["run-all", "--config", str(config_path), "--force"],
    )

    assert result.exit_code == int(ErrorCode.ANALYZER_MISSING), result.output
    assert (run_dir / ".stages" / "generate-observed.json").exists()
    assert not (run_dir / "oracle" / "observed_oracle.jsonl").exists()
    assert not (run_dir / ".stages" / "run-oracle-observed.json").exists()
    assert not (run_dir / "reports" / "summary.md").exists()
