import ast
from collections.abc import Sequence
import importlib.util
import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from secaware import cli as cli_module
from secaware.cli import app
from secaware.config import TSGConfig, load_config, write_resolved_config
from secaware import extractors as extractors_module
from secaware.errors import ErrorCode
from secaware.io.jsonl import read_jsonl
from secaware.oracle import aggregator as aggregator_module
from secaware.oracle.runner import AnalyzerProcessResult
from secaware.pipeline.manifest import read_stage_manifest
from secaware.schema.interventions import InterventionRecord
from secaware.schema.oracle import OracleRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord
from secaware.schema.results import PairResult


REPO_ROOT = Path(__file__).resolve().parents[1]


def _assert_pair_security_matches_oracle(
    pairs: Sequence[PairResult],
    observed: Sequence[OracleRecord],
    counterfactual: Sequence[OracleRecord],
    interventions: Sequence[InterventionRecord],
    observed_code: Sequence[CanonicalGeneratedCodeRecord],
    counterfactual_code: Sequence[CanonicalGeneratedCodeRecord],
) -> None:
    def producer_coordinate(record: OracleRecord | CanonicalGeneratedCodeRecord) -> tuple:
        return (
            record.request_id,
            record.code_id,
            record.code_sha256,
            record.prompt_id,
            record.condition,
            record.model_id,
            record.seed_id,
            record.hypothesis_id,
            record.intervention_id,
        )

    observed_oracle_producers = [producer_coordinate(record) for record in observed]
    observed_code_producers = [producer_coordinate(record) for record in observed_code]
    counter_oracle_producers = [producer_coordinate(record) for record in counterfactual]
    counter_code_producers = [producer_coordinate(record) for record in counterfactual_code]
    for coordinates in (
        observed_oracle_producers,
        observed_code_producers,
        counter_oracle_producers,
        counter_code_producers,
    ):
        assert len(coordinates) == len(set(coordinates))
    for records in (observed, observed_code, counterfactual, counterfactual_code):
        request_ids = [record.request_id for record in records]
        code_ids = [record.code_id for record in records]
        assert len(request_ids) == len(set(request_ids))
        assert len(code_ids) == len(set(code_ids))
    assert set(observed_oracle_producers) == set(observed_code_producers)
    assert set(counter_oracle_producers) == set(counter_code_producers)

    observed_coordinates = [
        (record.prompt_id, record.model_id, record.seed_id) for record in observed
    ]
    observed_code_coordinates = [
        (record.prompt_id, record.model_id, record.seed_id) for record in observed_code
    ]
    intervention_ids = [record.intervention_id for record in interventions]
    intervention_coordinates = [
        (record.prompt_id, record.hypothesis_id) for record in interventions
    ]
    counter_coordinates = [
        (record.prompt_id, record.hypothesis_id, record.model_id, record.seed_id)
        for record in counterfactual
    ]
    counter_code_coordinates = [
        (record.prompt_id, record.hypothesis_id, record.model_id, record.seed_id)
        for record in counterfactual_code
    ]
    pair_ids = [record.pair_id for record in pairs]
    pair_coordinates = [
        (record.prompt_id, record.hypothesis_id, record.model_id, record.seed_id)
        for record in pairs
    ]
    for coordinates in (
        observed_coordinates,
        observed_code_coordinates,
        intervention_ids,
        intervention_coordinates,
        counter_coordinates,
        counter_code_coordinates,
        pair_ids,
        pair_coordinates,
    ):
        assert len(coordinates) == len(set(coordinates))
    assert set(observed_coordinates) == set(observed_code_coordinates)
    assert set(counter_coordinates) == set(counter_code_coordinates) == set(pair_coordinates)
    assert set(intervention_coordinates) == {
        (record.prompt_id, record.hypothesis_id) for record in counterfactual
    }
    assert set(intervention_ids) == {record.intervention_id for record in counterfactual}

    label_value = {"secure": 0, "insecure": 1}
    for pair in pairs:
        matching_observed = [
            record
            for record in observed
            if (record.prompt_id, record.model_id, record.seed_id)
            == (pair.prompt_id, pair.model_id, pair.seed_id)
        ]
        matching_counter = [
            record
            for record in counterfactual
            if (record.prompt_id, record.hypothesis_id, record.model_id, record.seed_id)
            == (pair.prompt_id, pair.hypothesis_id, pair.model_id, pair.seed_id)
        ]
        matching_interventions = [
            record
            for record in interventions
            if (record.prompt_id, record.hypothesis_id) == (pair.prompt_id, pair.hypothesis_id)
        ]
        assert len(matching_observed) == len(matching_counter) == len(matching_interventions) == 1
        observed_record = matching_observed[0]
        counter_record = matching_counter[0]
        intervention = matching_interventions[0]
        assert counter_record.intervention_id == intervention.intervention_id
        assert pair.factor_type == intervention.factor_type.value
        assert pair.expected_direction == intervention.expected_direction
        assert pair.same_task_valid is intervention.semantic_valid
        assert pair.target_changed is intervention.target_changed
        assert pair.side_effect is intervention.side_effect
        assert pair.functional_observed is observed_record.functional_ok
        assert pair.functional_counterfactual is counter_record.functional_ok
        assert pair.security_observed == observed_record.security_label.value
        assert pair.security_counterfactual == counter_record.security_label.value
        expected_delta = (
            label_value[counter_record.security_label.value]
            - label_value[observed_record.security_label.value]
        )
        assert pair.delta == expected_delta
        if pair.security_observed == pair.security_counterfactual:
            expected_flip = "no_flip"
        elif (pair.security_observed, pair.security_counterfactual) == (
            "insecure",
            "secure",
        ):
            expected_flip = "secure_flip"
        else:
            expected_flip = "insecure_flip"
        assert pair.flip_type == expected_flip
        assert pair.eligible_per_protocol is (
            intervention.semantic_valid
            and intervention.target_changed
            and not intervention.side_effect
            and observed_record.functional_ok
            and counter_record.functional_ok
        )
        assert pair.eligible_itt is True
        if intervention.failure_reason is not None:
            expected_failure = intervention.failure_reason.value
        elif not observed_record.parse_ok or not counter_record.parse_ok:
            expected_failure = "parse_failed"
        elif not observed_record.functional_ok or not counter_record.functional_ok:
            expected_failure = "functional_failed"
        else:
            expected_failure = None
        assert pair.failure_reason == expected_failure

    assert {record.security_label.value for record in (*observed, *counterfactual)} == {
        "secure",
        "insecure",
    }
    assert any(pair.security_observed != pair.security_counterfactual for pair in pairs)
    assert ("insecure", "secure") in {
        (pair.security_observed, pair.security_counterfactual) for pair in pairs
    }


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


def test_run_all_demo_uses_canonical_oracle_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "canonical-demo"
    runner = _RunAllOracleRunner()
    monkeypatch.setattr(cli_module, "run_analyzer_process", runner)
    monkeypatch.setattr(cli_module, "validate_analyzer_runtime", lambda: None)
    monkeypatch.setattr(aggregator_module, "validate_analyzer_runtime", lambda: None)

    result = CliRunner().invoke(
        app,
        ["run-all", "--config", "configs/demo.yaml", "--run-dir", str(run_dir), "--force"],
    )

    assert result.exit_code == 0, result.output
    observed = read_jsonl(
        run_dir / "oracle" / "observed_oracle.jsonl",
        OracleRecord,
        required=True,
        allow_empty=False,
    )
    counterfactual = read_jsonl(
        run_dir / "oracle" / "counterfactual_oracle.jsonl",
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
    counterfactual_code = read_jsonl(
        run_dir / "generation" / "counterfactual_code.jsonl",
        CanonicalGeneratedCodeRecord,
        required=True,
        allow_empty=False,
    )
    assert observed and counterfactual
    interventions = read_jsonl(
        run_dir / "interventions" / "interventions.jsonl",
        InterventionRecord,
        required=True,
        allow_empty=False,
    )
    pairs = read_jsonl(
        run_dir / "analysis" / "pair_results.jsonl",
        PairResult,
        required=True,
        allow_empty=False,
    )
    _assert_pair_security_matches_oracle(
        pairs,
        observed,
        counterfactual,
        interventions,
        observed_code,
        counterfactual_code,
    )
    hardcoded_secure = [
        pair.model_copy(update={"security_observed": "secure", "security_counterfactual": "secure"})
        for pair in pairs
    ]
    swapped = [
        pair.model_copy(
            update={
                "security_observed": pair.security_counterfactual,
                "security_counterfactual": pair.security_observed,
            }
        )
        for pair in pairs
    ]
    with pytest.raises(AssertionError):
        _assert_pair_security_matches_oracle(
            hardcoded_secure,
            observed,
            counterfactual,
            interventions,
            observed_code,
            counterfactual_code,
        )
    with pytest.raises(AssertionError):
        _assert_pair_security_matches_oracle(
            swapped,
            observed,
            counterfactual,
            interventions,
            observed_code,
            counterfactual_code,
        )
    extra_digest = "f" * 64
    extra_observed = observed[0].model_copy(
        update={
            "request_id": f"req_{extra_digest}",
            "code_id": f"code_{extra_digest}",
            "prompt_id": "extra-observed",
        }
    )
    for mutation in (
        lambda: _assert_pair_security_matches_oracle(
            pairs,
            [*observed, observed[0]],
            counterfactual,
            interventions,
            observed_code,
            counterfactual_code,
        ),
        lambda: _assert_pair_security_matches_oracle(
            pairs,
            [*observed, extra_observed],
            counterfactual,
            interventions,
            observed_code,
            counterfactual_code,
        ),
        lambda: _assert_pair_security_matches_oracle(
            pairs,
            observed[1:],
            counterfactual,
            interventions,
            observed_code,
            counterfactual_code,
        ),
        lambda: _assert_pair_security_matches_oracle(
            pairs,
            observed,
            counterfactual,
            [*interventions, interventions[0]],
            observed_code,
            counterfactual_code,
        ),
        lambda: _assert_pair_security_matches_oracle(
            pairs,
            observed,
            counterfactual,
            interventions,
            [*observed_code, observed_code[0]],
            counterfactual_code,
        ),
        lambda: _assert_pair_security_matches_oracle(
            pairs,
            observed,
            counterfactual,
            interventions,
            observed_code,
            [*counterfactual_code, counterfactual_code[0]],
        ),
        lambda: _assert_pair_security_matches_oracle(
            pairs,
            observed,
            [*counterfactual, counterfactual[0]],
            interventions,
            observed_code,
            counterfactual_code,
        ),
        lambda: _assert_pair_security_matches_oracle(
            [*pairs, pairs[0]],
            observed,
            counterfactual,
            interventions,
            observed_code,
            counterfactual_code,
        ),
    ):
        with pytest.raises(AssertionError):
            mutation()
    for condition in ("observed", "counterfactual"):
        manifest = read_stage_manifest(run_dir / ".stages" / f"run-oracle-{condition}.json")
        assert manifest.policy_sha256 is not None
    assert (run_dir / "reports" / "summary.md").exists()
    removed_artifacts = [
        run_dir / "tsg" / (condition + "_" + "code_" + "tsg.jsonl")
        for condition in ("observed", "counterfactual")
    ]
    removed_stage_prefix = "extract-" + "code-" + "tsg"
    assert all(not path.exists() for path in removed_artifacts)
    assert all(
        not path.stem.startswith(removed_stage_prefix)
        for path in run_dir.joinpath(".stages").glob("*.json")
    )


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
    migration_path = REPO_ROOT / "docs" / "migrations" / "prompt-tsg-v2.md"

    assert "pre-treatment graph factors" in readme
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
